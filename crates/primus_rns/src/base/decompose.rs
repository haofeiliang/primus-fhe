use itertools::izip;
use primus_data::{Data, DataMut, RawData};
use primus_factor::{Factor, FactorBase};
use primus_integer::{BigUint, FheUint};
use primus_modulo::prelude::*;
use primus_poly::{BigUintPolynomial, CrtPolynomial, Polynomial};
use primus_reduce::FieldContext;

use super::RNSBase;
#[cfg(feature = "simd")]
use super::kernels::simd;
#[cfg(not(feature = "simd"))]
use super::kernels::slice;

impl<T, M> RNSBase<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Decomposes a big integer into residues modulo this basis.
    ///
    /// The input `value` is a little-endian limb slice. The returned vector has
    /// `moduli_count()` elements; element `i` is `value mod moduli()[i]`.
    #[inline]
    pub fn decompose(&self, BigUint(value): BigUint<&[T]>) -> Vec<T> {
        self.moduli
            .iter()
            .map(|&modulus| value.modulo(modulus))
            .collect()
    }

    /// Decomposes a big integer into precomputed residue factors.
    ///
    /// The input `value` is a little-endian limb slice. The returned vector has
    /// `moduli_count()` factors. Factor `i` is created from `value mod q_i`
    /// and must be used only with the matching modulus `q_i == moduli()[i]`.
    #[inline]
    pub fn decompose_to_rns_factor<F>(&self, BigUint(value): BigUint<&[T]>) -> Vec<F>
    where
        F: FactorBase<T>,
    {
        self.moduli
            .iter()
            .map(|&modulus| F::new(value.modulo(modulus), unsafe { modulus.value_unchecked() }))
            .collect()
    }

    /// Decomposes one small value with centered wrapping semantics.
    ///
    /// The returned vector has `moduli_count()` residues. The input `value` is
    /// expected to be reduced modulo `small_value_modulus`. Values below
    /// `ceil(small_value_modulus / 2)` are copied as positive residues. Other
    /// values are interpreted as negative representatives modulo
    /// `small_value_modulus` and lifted into each RNS modulus.
    ///
    /// `small_value_modulus` must be no larger than every RNS modulus; batched
    /// variants require it to be strictly smaller in debug builds.
    pub fn wrapping_decompose(&self, value: T, small_value_modulus: T) -> Vec<T> {
        if small_value_modulus != T::TWO {
            let half = (small_value_modulus + T::ONE) / T::TWO;
            self.moduli_values()
                .map(|modulus| {
                    if value < half {
                        value
                    } else {
                        modulus - small_value_modulus + value
                    }
                })
                .collect()
        } else {
            vec![value; self.moduli_count()]
        }
    }

    /// Decomposes a big integer into caller-provided residue storage.
    ///
    /// The input `value` is a little-endian limb slice. `residues` must contain
    /// exactly `moduli_count()` elements; element `i` receives
    /// `value mod moduli()[i]`.
    #[inline]
    pub fn decompose_to(&self, BigUint(value): BigUint<&[T]>, residues: &mut [T]) {
        assert_eq!(self.moduli_count(), residues.len());

        for (&modulus, residue) in self.moduli.iter().zip(residues) {
            *residue = value.modulo(modulus);
        }
    }

    /// Writes [`wrapping_decompose`](Self::wrapping_decompose) into caller-provided storage.
    ///
    /// `residues` must contain exactly `moduli_count()` elements. `value` is
    /// expected to be reduced modulo `small_value_modulus`; the output uses the
    /// same basis order as [`moduli`](Self::moduli).
    pub fn wrapping_decompose_to(&self, value: T, residues: &mut [T], small_value_modulus: T) {
        debug_assert_eq!(self.moduli_count(), residues.len());

        if small_value_modulus != T::TWO {
            let half = (small_value_modulus + T::ONE) / T::TWO;
            self.moduli_values()
                .zip(residues)
                .for_each(|(modulus, residue)| {
                    *residue = if value < half {
                        value
                    } else {
                        modulus - small_value_modulus + value
                    };
                });
        } else {
            residues.fill(value);
        }
    }

    /// Decomposes many small values into a flattened multi-residue layout.
    ///
    /// `small_values.len()` must equal `value_count`. Each value is expected to
    /// be reduced modulo `small_value_modulus`.
    ///
    /// `multi_residues.len()` must equal `moduli_count() * value_count` and is
    /// written in modulus-major layout: chunk `i` of length `value_count`
    /// receives all values reduced modulo `moduli()[i]`.
    ///
    /// `small_value_modulus` must be smaller than every RNS modulus.
    pub fn wrapping_decompose_small_values_to(
        &self,
        small_values: &[T],
        multi_residues: &mut [T],
        value_count: usize,
        small_value_modulus: T,
    ) {
        debug_assert_eq!(multi_residues.len(), self.moduli_count() * value_count);
        debug_assert_eq!(small_values.len(), value_count);
        debug_assert!(self.moduli_values().all(|m| m > small_value_modulus));
        if small_value_modulus != T::TWO {
            let half = (small_value_modulus + T::ONE) / T::TWO;
            for (residues, modulus) in multi_residues
                .chunks_exact_mut(value_count)
                .zip(self.moduli_values())
            {
                let temp = modulus - small_value_modulus;

                #[cfg(not(feature = "simd"))]
                slice::wrapping_decompose_chunk_to(small_values, residues, half, temp);

                #[cfg(feature = "simd")]
                simd::wrapping_decompose_chunk_to(small_values, residues, half, temp);
            }
        } else {
            for residues in multi_residues.chunks_exact_mut(value_count) {
                residues.copy_from_slice(small_values);
            }
        }
    }

    /// Decomposes a small polynomial into CRT form with centered wrapping semantics.
    ///
    /// `small_poly.as_slice().len()` must equal `poly_length`. Coefficients are
    /// expected to be reduced modulo `small_poly_modulus`.
    ///
    /// `crt_poly.as_mut_slice().len()` must equal `moduli_count() * poly_length`
    /// and is written in modulus-major layout: chunk `i` of length
    /// `poly_length` receives coefficients reduced modulo `moduli()[i]`.
    #[inline]
    pub fn wrapping_decompose_small_polynomial_to<A, B>(
        &self,
        small_poly: &Polynomial<A>,
        crt_poly: &mut CrtPolynomial<B>,
        poly_length: usize,
        small_poly_modulus: T,
    ) where
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        self.wrapping_decompose_small_values_to(
            small_poly.as_slice(),
            crt_poly.as_mut_slice(),
            poly_length,
            small_poly_modulus,
        );
    }

    /// Fused centered decomposition, scaling, and accumulation for small values.
    ///
    /// `small_values.len()` must equal `value_count`. Each value is expected to
    /// be reduced modulo `small_value_modulus`, which must be smaller than
    /// every RNS modulus.
    ///
    /// `acc.len()` must equal `moduli_count() * value_count` and uses
    /// modulus-major layout. The function adds into the existing contents of
    /// `acc`; it does not clear the buffer first.
    ///
    /// `factors.len()` must equal `moduli_count()`. Factor `i` is used for the
    /// chunk modulo `moduli()[i]`.
    pub fn add_wrapping_decompose_small_values_scaled<F: Factor<T>>(
        &self,
        small_values: &[T],
        acc: &mut [T],
        value_count: usize,
        small_value_modulus: T,
        factors: &[F],
    ) {
        debug_assert_eq!(acc.len(), self.moduli_count() * value_count);
        debug_assert_eq!(small_values.len(), value_count);
        debug_assert_eq!(factors.len(), self.moduli_count());
        debug_assert!(self.moduli_values().all(|m| m > small_value_modulus));

        if small_value_modulus != T::TWO {
            let half = (small_value_modulus + T::ONE) / T::TWO;
            izip!(
                acc.chunks_exact_mut(value_count),
                self.moduli_values(),
                factors,
            )
            .for_each(|(acc_chunk, modulus, &factor)| {
                let temp = modulus - small_value_modulus;

                #[cfg(not(feature = "simd"))]
                slice::add_wrapping_decompose_chunk_scaled_assign(
                    small_values,
                    acc_chunk,
                    half,
                    temp,
                    modulus,
                    factor,
                );

                #[cfg(feature = "simd")]
                simd::add_wrapping_decompose_chunk_scaled_assign(
                    small_values,
                    acc_chunk,
                    half,
                    temp,
                    modulus,
                    factor,
                );
            });
        } else {
            izip!(
                acc.chunks_exact_mut(value_count),
                self.moduli_values(),
                factors,
            )
            .for_each(|(acc_chunk, _modulus, &factor)| {
                factor.add_factor_mul_slice_assign(acc_chunk, small_values, _modulus);
            });
        }
    }

    /// Adds a centered small-polynomial decomposition scaled by per-modulus factors.
    ///
    /// `small_poly.as_slice().len()` must equal `poly_length`. Coefficients are
    /// expected to be reduced modulo `small_poly_modulus`.
    ///
    /// `acc.as_mut_slice().len()` must equal `moduli_count() * poly_length` and
    /// uses modulus-major CRT polynomial layout. The function accumulates into
    /// `acc` without clearing it first.
    ///
    /// `factors.len()` must equal `moduli_count()`. Factor `i` is used for the
    /// chunk modulo `moduli()[i]`.
    #[inline]
    pub fn add_wrapping_decompose_small_polynomial_scaled<F: Factor<T>, A, C>(
        &self,
        small_poly: &Polynomial<A>,
        acc: &mut CrtPolynomial<C>,
        poly_length: usize,
        small_poly_modulus: T,
        factors: &[F],
    ) where
        A: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
    {
        self.add_wrapping_decompose_small_values_scaled(
            small_poly.as_slice(),
            acc.as_mut_slice(),
            poly_length,
            small_poly_modulus,
            factors,
        );
    }

    /// Fused unsigned decomposition, scaling, and accumulation for small values.
    ///
    /// Unlike [`add_wrapping_decompose_small_values_scaled`](Self::add_wrapping_decompose_small_values_scaled), this does
    /// unsigned decomposition: each input value is used directly as a residue
    /// under every modulus, without centered lifting. Callers should pass
    /// values that are already valid residues for all basis moduli.
    ///
    /// `small_values.len()` must equal `value_count`. `acc.len()` must equal
    /// `moduli_count() * value_count` and uses modulus-major layout. The
    /// function adds into the existing contents of `acc`.
    ///
    /// `factors.len()` must equal `moduli_count()`. Factor `i` is used for the
    /// chunk modulo `moduli()[i]`.
    pub fn add_decompose_small_values_scaled<F: Factor<T>>(
        &self,
        small_values: &[T],
        acc: &mut [T],
        value_count: usize,
        factors: &[F],
    ) {
        debug_assert_eq!(acc.len(), self.moduli_count() * value_count);
        debug_assert_eq!(small_values.len(), value_count);
        debug_assert_eq!(factors.len(), self.moduli_count());

        izip!(
            acc.chunks_exact_mut(value_count),
            self.moduli_values(),
            factors,
        )
        .for_each(|(acc_chunk, modulus, &factor)| {
            factor.add_factor_mul_slice_assign(acc_chunk, small_values, modulus);
        });
    }

    /// Adds an unsigned small polynomial decomposition scaled by per-modulus factors.
    ///
    /// `small_poly.as_slice().len()` must equal `poly_length`.
    /// `acc.as_mut_slice().len()` must equal `moduli_count() * poly_length`
    /// and uses modulus-major CRT polynomial layout.
    ///
    /// `factors.len()` must equal `moduli_count()`. Factor `i` is used for the
    /// output chunk modulo `moduli()[i]`. The function accumulates into `acc`
    /// without clearing it first.
    #[inline]
    pub fn add_decompose_small_polynomial_scaled<F: Factor<T>, A, C>(
        &self,
        small_poly: &Polynomial<A>,
        acc: &mut CrtPolynomial<C>,
        poly_length: usize,
        factors: &[F],
    ) where
        A: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
    {
        self.add_decompose_small_values_scaled(
            small_poly.as_slice(),
            acc.as_mut_slice(),
            poly_length,
            factors,
        );
    }

    /// Decomposes many big integers into a flattened multi-residue layout.
    ///
    /// `big_uint_values.len()` must equal
    /// `value_count * big_uint_value_len()`. It stores `value_count`
    /// consecutive little-endian integers, each with
    /// [`big_uint_value_len`](Self::big_uint_value_len) limbs.
    ///
    /// `multi_residues.len()` must equal `moduli_count() * value_count` and is
    /// written in modulus-major layout: chunk `i` of length `value_count`
    /// receives all values reduced modulo `moduli()[i]`.
    pub fn decompose_big_uint_values_to(
        &self,
        big_uint_values: &[T],
        multi_residues: &mut [T],
        value_count: usize,
    ) {
        assert_eq!(multi_residues.len(), self.moduli_count() * value_count);
        assert_eq!(
            big_uint_values.len(),
            self.big_uint_value_len() * value_count
        );

        let value_len = self.big_uint_value_len();
        for (residues, &modulus) in multi_residues
            .chunks_exact_mut(value_count)
            .zip(self.moduli())
        {
            for (residue, value) in residues
                .iter_mut()
                .zip(big_uint_values.chunks_exact(value_len))
            {
                *residue = value.modulo(modulus);
            }
        }
    }

    /// Decomposes a polynomial with big-integer coefficients into CRT form.
    ///
    /// `big_uint_poly.as_slice().len()` must equal
    /// `poly_length * big_uint_value_len()`. It stores `poly_length`
    /// consecutive little-endian coefficients.
    ///
    /// `crt_poly.as_mut_slice().len()` must equal `moduli_count() * poly_length`
    /// and is written in modulus-major layout.
    #[inline]
    pub fn decompose_polynomial_to<A, B>(
        &self,
        big_uint_poly: &BigUintPolynomial<A>,
        crt_poly: &mut CrtPolynomial<B>,
        poly_length: usize,
    ) where
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        self.decompose_big_uint_values_to(
            big_uint_poly.as_slice(),
            crt_poly.as_mut_slice(),
            poly_length,
        );
    }
}
