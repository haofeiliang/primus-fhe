mod compose;
mod decompose;
mod extension;
mod kernels;

use itertools::Itertools;
use primus_factor::{FactorBase, ShoupFactor};
use primus_integer::{BigUint, FheUint, multiply_many_values};
use primus_modulo::prelude::*;
use primus_reduce::{FieldContext, Modulus};

use crate::RNSError;

/// A pairwise-coprime RNS basis with CRT precomputations.
///
/// An integer is represented by one residue for each modulus in `moduli`.
/// If `Q` is the product of all moduli, the Chinese remainder theorem gives a
/// unique representative modulo `Q` for each residue vector. This type stores
/// `Q`, every punctured product `Q / q_i`, and `(Q / q_i)^-1 mod q_i`.
///
/// Batched APIs use modulus-major residue storage: for `k` values, chunk `i`
/// of length `k` stores residues modulo `moduli()[i]`.
#[derive(Clone)]
pub struct RNSBase<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Moduli in basis order. The same order is used by every residue vector.
    moduli: Vec<M>,
    /// Product `Q` of all moduli, stored as little-endian limbs.
    moduli_product: BigUint<Vec<T>>,
    /// Flattened punctured products `Q / q_i`, one `big_uint_value_len` chunk per modulus.
    punctured_product: Vec<T>,
    /// One Shoup factor for `(Q / q_i)^-1 mod q_i` per modulus.
    inv_punctured_product_mod_modulus: Vec<ShoupFactor<T>>,
}

fn checked_moduli_values<T, M>(moduli: &[M]) -> Result<Vec<T>, RNSError>
where
    T: FheUint,
    M: Modulus<ValueT = T>,
{
    moduli
        .iter()
        .copied()
        .enumerate()
        .map(|(index, modulus)| {
            modulus
                .value()
                .ok_or(RNSError::UnrepresentableModulus { index })
        })
        .collect()
}

fn compute_punctured_product_to<T: FheUint>(
    moduli_values: &[T],
    excluded_index: usize,
    output: &mut [T],
) {
    output.fill(T::ZERO);
    output[0] = T::ONE;
    let mut product_len = 1;

    for &modulus in moduli_values[..excluded_index]
        .iter()
        .chain(&moduli_values[excluded_index + 1..])
    {
        let carry = BigUint(&mut output[..product_len]).mul_value_assign(modulus);
        if !carry.is_zero() {
            output[product_len] = carry;
            product_len += 1;
        }
    }
}

impl<T, M> RNSBase<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Creates an RNS basis from pairwise-coprime moduli.
    ///
    /// # Panics
    ///
    /// Panics if modular inverse computation panics unexpectedly.
    ///
    /// # Errors
    ///
    /// Returns [`RNSError::EmptyBase`] when `moduli` is empty.
    /// Returns [`RNSError::UnrepresentableModulus`] when a modulus cannot be
    /// represented as a scalar value.
    /// Returns [`RNSError::CoPrimeError`] when any two moduli are not coprime.
    #[inline]
    pub fn new(moduli: &[M]) -> Result<Self, RNSError> {
        Self::from_owned_moduli(moduli.to_vec())
    }

    /// Creates an RNS basis from an owned `Vec<M>`, avoiding a clone.
    ///
    /// See [`new`](Self::new) for error conditions.
    #[inline]
    pub fn from_owned_moduli(moduli: Vec<M>) -> Result<Self, RNSError> {
        if moduli.is_empty() {
            return Err(RNSError::EmptyBase);
        }

        if moduli.len() == 1 {
            let modulus = moduli[0];
            let value = modulus
                .value()
                .ok_or(RNSError::UnrepresentableModulus { index: 0 })?;
            return Ok(Self {
                moduli,
                moduli_product: BigUint(vec![value]),
                punctured_product: vec![T::ONE],
                inv_punctured_product_mod_modulus: vec![ShoupFactor::new(T::ONE, value)],
            });
        }

        let moduli_values = checked_moduli_values(&moduli)?;

        if moduli_values
            .iter()
            .array_combinations()
            .any(|[&a, &b]| !a.is_coprime(b))
        {
            return Err(RNSError::CoPrimeError);
        }

        let moduli_product = multiply_many_values(&moduli_values);

        let count = moduli.len();
        let big_uint_len = moduli_product.len();
        let mut punctured_product = vec![T::ZERO; big_uint_len * count];
        punctured_product
            .chunks_exact_mut(big_uint_len)
            .enumerate()
            .for_each(|(i, q_div_qi)| {
                compute_punctured_product_to(&moduli_values, i, q_div_qi);
            });

        let inv_punctured_product_mod_modulus = punctured_product
            .chunks_exact(big_uint_len)
            .zip(&moduli)
            .zip(moduli_values.iter().copied())
            .map(|((q_div_qi, &qi), qi_value)| {
                let inv_q_div_qi_mod_qi = q_div_qi.modulo(qi).try_inv_modulo(qi).unwrap();
                ShoupFactor::new(inv_q_div_qi_mod_qi, qi_value)
            })
            .collect::<Vec<ShoupFactor<T>>>();

        Ok(Self {
            moduli,
            moduli_product,
            punctured_product,
            inv_punctured_product_mod_modulus,
        })
    }

    /// Returns the moduli in basis order.
    #[inline]
    pub fn moduli(&self) -> &[M] {
        &self.moduli
    }

    /// Returns the moduli values in basis order.
    #[inline]
    pub fn moduli_values(&self) -> impl Iterator<Item = T> {
        self.moduli.iter().map(|m| unsafe { m.value_unchecked() })
    }

    /// Returns the number of moduli in this basis.
    #[inline]
    pub fn moduli_count(&self) -> usize {
        self.moduli.len()
    }

    /// Returns the product of all moduli as a little-endian big integer.
    #[inline]
    pub fn moduli_product(&self) -> BigUint<&[T]> {
        self.moduli_product.view()
    }

    /// Returns the limb count used by composed big integers for this basis.
    #[inline]
    pub fn big_uint_value_len(&self) -> usize {
        self.moduli_product.len()
    }

    /// Returns all punctured products in flattened basis order.
    ///
    /// The returned slice length is `moduli_count() * big_uint_value_len()`.
    /// Chunk `i` has length [`big_uint_value_len`](Self::big_uint_value_len)
    /// and stores `Q / q_i`, where `q_i == moduli()[i]`.
    #[inline]
    pub fn punctured_product(&self) -> &[T] {
        &self.punctured_product
    }

    /// Iterates over punctured products `Q / q_i` as fixed-width big integers.
    ///
    /// The iterator yields `moduli_count()` chunks. Each chunk has exactly
    /// [`big_uint_value_len`](Self::big_uint_value_len) limbs.
    #[inline]
    pub fn iter_punctured_product(
        &self,
    ) -> impl ExactSizeIterator<Item = BigUint<&[T]>> + DoubleEndedIterator {
        self.punctured_product
            .chunks_exact(self.big_uint_value_len())
            .map(BigUint)
    }

    /// Returns precomputed factors for `(Q / q_i)^-1 mod q_i`.
    ///
    /// The returned slice length is `moduli_count()`. Factor `i` belongs to
    /// `moduli()[i]` and must not be reused with another modulus.
    #[inline]
    pub fn inv_punctured_product_mod_modulus(&self) -> &[ShoupFactor<T>] {
        &self.inv_punctured_product_mod_modulus
    }
}

#[cfg(test)]
mod tests {
    use core::fmt;

    use super::*;

    #[derive(Clone, Copy)]
    struct UnrepresentableModulus;

    impl fmt::Debug for UnrepresentableModulus {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("UnrepresentableModulus")
        }
    }

    impl Modulus for UnrepresentableModulus {
        type ValueT = u64;

        fn value(self) -> Option<Self::ValueT> {
            None
        }

        unsafe fn value_unchecked(self) -> Self::ValueT {
            panic!("unrepresentable modulus")
        }

        fn minus_one(self) -> Self::ValueT {
            u64::MAX
        }
    }

    #[test]
    fn checked_moduli_values_rejects_unrepresentable_modulus() {
        let moduli = [UnrepresentableModulus];
        assert!(matches!(
            checked_moduli_values(&moduli),
            Err(RNSError::UnrepresentableModulus { index: 0 })
        ));
    }
}
