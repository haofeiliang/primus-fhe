use primus_factor::{FactorBase, FactorMul, ShoupFactor};
use primus_integer::{BigUint, FheUint};
use primus_reduce::FieldContext;

use crate::RNSError;

use super::RNSBase;

impl<T, M> RNSBase<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Extends this basis by appending one modulus.
    ///
    /// The new modulus must be coprime with every existing modulus in this
    /// basis.
    ///
    /// This reuses the existing CRT precomputations: old punctured products
    /// are multiplied by the new modulus, and old inverses are updated via
    /// the new modulus's inverse modulo each old modulus — avoiding an O(N²)
    /// recomputation.
    ///
    /// # Errors
    ///
    /// Returns [`RNSError::CoPrimeError`] when the new modulus is not coprime
    /// with at least one existing modulus.
    /// Returns [`RNSError::UnrepresentableModulus`] when the new modulus
    /// cannot be represented as a scalar value.
    pub fn extend(&self, modulus: M) -> Result<Self, RNSError> {
        let p_val = modulus
            .value()
            .ok_or(RNSError::UnrepresentableModulus { index: 0 })?;

        // Check coprimality between new modulus and existing moduli
        for qi in self.moduli_values() {
            if !p_val.is_coprime(qi) {
                return Err(RNSError::CoPrimeError);
            }
        }

        let moduli_count = self.moduli_count() + 1;
        let mut moduli = self.moduli.clone();
        moduli.push(modulus);

        let BigUint(q) = self.moduli_product();
        let mut qp = BigUint(q.to_vec());
        let carry = qp.mul_value_assign(p_val);

        let punctured_product = if carry.is_zero() {
            let big_uint_value_len = self.big_uint_value_len();
            let mut punctured_product = vec![T::ZERO; big_uint_value_len * moduli_count];
            let mut punctured_product_chunks =
                punctured_product.chunks_exact_mut(big_uint_value_len);

            for (old_chunk, new_chunk) in self
                .iter_punctured_product()
                .zip(&mut punctured_product_chunks)
            {
                let _carry = BigUint(old_chunk).mul_value_to(p_val, &mut BigUint(new_chunk));
                debug_assert!(_carry.is_zero());
            }

            let last_chunk = punctured_product_chunks.next().unwrap();
            last_chunk.copy_from_slice(q);

            punctured_product
        } else {
            qp.0.push(carry);

            let old_biguint_len = self.big_uint_value_len();
            let new_biguint_len = old_biguint_len + 1;

            let mut punctured_product = vec![T::ZERO; new_biguint_len * moduli_count];
            let mut punctured_product_chunks = punctured_product.chunks_exact_mut(new_biguint_len);

            for (old_chunk, new_chunk) in self
                .iter_punctured_product()
                .zip(&mut punctured_product_chunks)
            {
                let (carry, res) = new_chunk.split_last_mut().unwrap();
                *carry = BigUint(old_chunk).mul_value_to(p_val, &mut BigUint(res));
            }

            let last_chunk = punctured_product_chunks.next().unwrap();
            last_chunk[..old_biguint_len].copy_from_slice(q);

            punctured_product
        };

        let mut inv_punctured_product_mod_modulus: Vec<ShoupFactor<T>> = self
            .inv_punctured_product_mod_modulus
            .iter()
            .zip(self.moduli())
            .zip(self.moduli_values())
            .map(|((inv_q_div_qi_mod_qi, &qi), qi_val)| {
                let p_mod_qi = if p_val < qi_val {
                    p_val
                } else {
                    qi.reduce(p_val)
                };
                let inv_p_mod_qi = qi.reduce_inv(p_mod_qi);
                let inv_qp_div_qi_mod_qi =
                    inv_q_div_qi_mod_qi.factor_mul_modulo(inv_p_mod_qi, qi_val);
                ShoupFactor::new(inv_qp_div_qi_mod_qi, qi_val)
            })
            .collect();

        let q_mod_p = modulus.reduce(q);
        let inv_q_mod_p = modulus.reduce_inv(q_mod_p);
        inv_punctured_product_mod_modulus.push(ShoupFactor::new(inv_q_mod_p, p_val));

        Ok(Self {
            moduli,
            moduli_product: qp,
            punctured_product,
            inv_punctured_product_mod_modulus,
        })
    }

    /// Extends this basis by appending all moduli from `other`.
    ///
    /// Every modulus in `other` must be coprime with every modulus in `self`.
    ///
    /// # Errors
    ///
    /// Returns [`RNSError::CoPrimeError`] when any modulus in `other` is not
    /// coprime with at least one modulus in `self`.
    #[inline]
    pub fn extend_with(&self, other: &Self) -> Result<Self, RNSError> {
        let p_vals: Vec<T> = other.moduli_values().collect();

        for qi in self.moduli_values() {
            for &pi in p_vals.iter() {
                if !pi.is_coprime(qi) {
                    return Err(RNSError::CoPrimeError);
                }
            }
        }

        let moduli_count = self.moduli_count() + other.moduli_count();
        let mut moduli = self.moduli.clone();
        moduli.extend_from_slice(other.moduli());

        let BigUint(q) = self.moduli_product();
        let BigUint(p) = other.moduli_product();

        let mut limbs_added = 0;
        let mut qp = BigUint(q.to_vec());
        for &pi in p_vals.iter() {
            let carry = qp.mul_value_assign(pi);
            if !carry.is_zero() {
                qp.0.push(carry);
                limbs_added += 1;
            }
        }

        let old_biguint_len = self.big_uint_value_len();
        let new_biguint_len = old_biguint_len + limbs_added;

        let mut punctured_product = vec![T::ZERO; new_biguint_len * moduli_count];
        let mut punctured_product_chunks = punctured_product.chunks_exact_mut(new_biguint_len);

        for (q_div_qi, qp_div_qi) in self
            .iter_punctured_product()
            .zip(&mut punctured_product_chunks)
        {
            qp_div_qi[..old_biguint_len].copy_from_slice(q_div_qi);
            let mut qp_div_qi = BigUint(qp_div_qi);
            for &pi in p_vals.iter() {
                let _carry = qp_div_qi.mul_value_assign(pi);
                debug_assert!(_carry.is_zero());
            }
        }

        for (i, qp_div_pi) in punctured_product_chunks.enumerate() {
            qp_div_pi[..old_biguint_len].copy_from_slice(q);
            let qp_div_pi = &mut BigUint(qp_div_pi);
            for (_, &pj) in p_vals.iter().enumerate().filter(|(j, _)| i != *j) {
                let _carry = qp_div_pi.mul_value_assign(pj);
                debug_assert!(_carry.is_zero());
            }
        }

        let mut inv_punctured_product_mod_modulus: Vec<ShoupFactor<T>> = self
            .inv_punctured_product_mod_modulus
            .iter()
            .zip(self.moduli())
            .zip(self.moduli_values())
            .map(|((inv_q_div_qi_mod_qi, &qi), qi_val)| {
                let p_mod_qi = qi.reduce(p);
                let inv_p_mod_qi = qi.reduce_inv(p_mod_qi);
                let inv_qp_div_qi_mod_qi =
                    inv_q_div_qi_mod_qi.factor_mul_modulo(inv_p_mod_qi, qi_val);
                ShoupFactor::new(inv_qp_div_qi_mod_qi, qi_val)
            })
            .collect();

        for ((qp_div_pi, &pi), &pi_val) in punctured_product
            .chunks_exact(new_biguint_len)
            .skip(self.moduli_count())
            .zip(other.moduli())
            .zip(p_vals.iter())
        {
            let qp_div_pi_mod_pi = pi.reduce(qp_div_pi);
            let inv_qp_div_pi_mod_pi = pi.reduce_inv(qp_div_pi_mod_pi);
            inv_punctured_product_mod_modulus.push(ShoupFactor::new(inv_qp_div_pi_mod_pi, pi_val));
        }

        Ok(Self {
            moduli,
            moduli_product: qp,
            punctured_product,
            inv_punctured_product_mod_modulus,
        })
    }
}
