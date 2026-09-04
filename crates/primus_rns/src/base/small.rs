use itertools::izip;
use primus_data::{Data, DataMut};
use primus_factor::Factor;
use primus_integer::FheUint;
use primus_poly::{CrtPolynomial, Polynomial};
use primus_reduce::FieldContext;

use super::RNSBase;
#[cfg(feature = "simd")]
use super::small_kernels::simd;
#[cfg(not(feature = "simd"))]
use super::small_kernels::slice;

impl<T, M> RNSBase<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Decomposes one small value with centered wrapping semantics.
    ///
    /// The returned vector has `moduli_count()` residues. The input `value` is
    /// expected to be reduced modulo `small_value_modulus`. Values below
    /// `ceil(small_value_modulus / 2)` are copied as positive residues. Other
    /// values are interpreted as negative representatives modulo
    /// `small_value_modulus` and lifted into each RNS modulus.
    /// When `small_value_modulus == 2`, the binary values `0` and `1` are
    /// preserved directly; `1` is not interpreted as `-1`.
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
    /// Each value is expected to be reduced modulo `small_value_modulus`.
    /// When `small_value_modulus == 2`, the binary values `0` and `1` are
    /// preserved directly; `1` is not interpreted as `-1`.
    ///
    /// `multi_residues.len()` must equal
    /// `moduli_count() * small_values.len()` and is written in modulus-major
    /// layout: chunk `i` receives all values reduced modulo `moduli()[i]`.
    ///
    /// `small_value_modulus` must be smaller than every RNS modulus.
    pub fn wrapping_decompose_small_values_to(
        &self,
        small_values: &[T],
        multi_residues: &mut [T],
        small_value_modulus: T,
    ) {
        let value_count = small_values.len();
        debug_assert_eq!(multi_residues.len(), self.moduli_count() * value_count);
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
    /// Coefficients are expected to be reduced modulo `small_poly_modulus`.
    /// When `small_poly_modulus == 2`, the binary values `0` and `1` are
    /// preserved directly; `1` is not interpreted as `-1`.
    ///
    /// `crt_poly.as_mut_slice().len()` must equal
    /// `moduli_count() * small_poly.as_slice().len()` and is written in
    /// modulus-major layout.
    #[inline]
    pub fn wrapping_decompose_small_polynomial_to<A, B>(
        &self,
        small_poly: &Polynomial<A>,
        crt_poly: &mut CrtPolynomial<B>,
        small_poly_modulus: T,
    ) where
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.wrapping_decompose_small_values_to(
            small_poly.as_slice(),
            crt_poly.as_mut_slice(),
            small_poly_modulus,
        );
    }

    /// Fused centered decomposition, scaling, and accumulation for small values.
    ///
    /// Each value is expected to be reduced modulo `small_value_modulus`, which
    /// must be smaller than every RNS modulus. When `small_value_modulus == 2`,
    /// the binary values `0` and `1` are preserved directly; `1` is not
    /// interpreted as `-1` before scaling.
    ///
    /// `acc.len()` must equal `moduli_count() * small_values.len()` and uses
    /// modulus-major layout. The function adds into the existing contents of
    /// `acc`; it does not clear the buffer first.
    ///
    /// `factors.len()` must equal `moduli_count()`. Factor `i` is used for the
    /// chunk modulo `moduli()[i]`.
    pub fn add_wrapping_decompose_small_values_scaled_assign<F: Factor<T>>(
        &self,
        small_values: &[T],
        acc: &mut [T],
        small_value_modulus: T,
        factors: &[F],
    ) {
        let value_count = small_values.len();
        debug_assert_eq!(acc.len(), self.moduli_count() * value_count);
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
            .for_each(|(acc_chunk, modulus, &factor)| {
                factor.add_factor_mul_slice_assign(acc_chunk, small_values, modulus);
            });
        }
    }

    /// Adds a centered small-polynomial decomposition scaled by per-modulus factors.
    ///
    /// Coefficients are expected to be reduced modulo `small_poly_modulus`.
    /// When `small_poly_modulus == 2`, the binary values `0` and `1` are
    /// preserved directly; `1` is not interpreted as `-1` before scaling.
    ///
    /// `acc.as_mut_slice().len()` must equal
    /// `moduli_count() * small_poly.as_slice().len()` and uses modulus-major
    /// CRT polynomial layout. The function accumulates into `acc` without
    /// clearing it first.
    ///
    /// `factors.len()` must equal `moduli_count()`. Factor `i` is used for the
    /// chunk modulo `moduli()[i]`.
    #[inline]
    pub fn add_wrapping_decompose_small_polynomial_scaled_assign<F: Factor<T>, A, C>(
        &self,
        small_poly: &Polynomial<A>,
        acc: &mut CrtPolynomial<C>,
        small_poly_modulus: T,
        factors: &[F],
    ) where
        A: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        self.add_wrapping_decompose_small_values_scaled_assign(
            small_poly.as_slice(),
            acc.as_mut_slice(),
            small_poly_modulus,
            factors,
        );
    }

    /// Fused unsigned decomposition, scaling, and accumulation for small values.
    ///
    /// Unlike
    /// [`add_wrapping_decompose_small_values_scaled_assign`](Self::add_wrapping_decompose_small_values_scaled_assign),
    /// this uses each input value directly as a residue under every modulus,
    /// without centered lifting. Callers should pass values that are already
    /// valid residues for all basis moduli.
    ///
    /// `acc.len()` must equal `moduli_count() * small_values.len()` and uses
    /// modulus-major layout. The function adds into the existing contents of
    /// `acc`.
    ///
    /// `factors.len()` must equal `moduli_count()`. Factor `i` is used for the
    /// chunk modulo `moduli()[i]`.
    pub fn add_decompose_small_values_scaled_assign<F: Factor<T>>(
        &self,
        small_values: &[T],
        acc: &mut [T],
        factors: &[F],
    ) {
        let value_count = small_values.len();
        debug_assert_eq!(acc.len(), self.moduli_count() * value_count);
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
    /// `acc.as_mut_slice().len()` must equal
    /// `moduli_count() * small_poly.as_slice().len()` and uses modulus-major CRT
    /// polynomial layout.
    ///
    /// `factors.len()` must equal `moduli_count()`. Factor `i` is used for the
    /// output chunk modulo `moduli()[i]`. The function accumulates into `acc`
    /// without clearing it first.
    #[inline]
    pub fn add_decompose_small_polynomial_scaled_assign<F: Factor<T>, A, C>(
        &self,
        small_poly: &Polynomial<A>,
        acc: &mut CrtPolynomial<C>,
        factors: &[F],
    ) where
        A: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        self.add_decompose_small_values_scaled_assign(
            small_poly.as_slice(),
            acc.as_mut_slice(),
            factors,
        );
    }
}
