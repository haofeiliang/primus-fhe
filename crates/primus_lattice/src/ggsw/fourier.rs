use num_complex::Complex64;
use primus_data::{Data, DataMut, RawData};
use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_poly::FourierPolynomial;

#[allow(unused_imports)]
use super::Ggsw;
#[allow(unused_imports)]
use crate::glev::{FourierGlev, FourierGlevIter, FourierGlevIterMut};

/// Fourier-domain GGSW ciphertext — matrix of
/// [`FourierGlev`], one per row.
///
/// ## Layout
///
/// ```text
/// |--row_0--| ... |--row_k--|
/// ```
///
/// Each row is a [`FourierGlev`] of length
/// `fourier_glev_len`.
/// Total data length: `(k + 1) * fourier_glev_len`.
///
/// # Correctness
///
/// The layout above is a caller-maintained contract. Raw construction and
/// mutable storage access do not validate it; parameter and key metadata
/// are not stored in this wrapper. See the [crate contracts](crate#correctness).
/// Each polynomial occupies `N / 2` complex values in the FFT table's
/// packing order. Ciphertext values use the normalized native-torus scale.
/// Levels must follow the decomposition basis's iterator order; every level
/// uses the same key, polynomial size, modulus, and representation.
#[derive(Clone)]
pub struct FourierGgsw<S>(pub S)
where
    S: RawData<Elem = Complex64>;

impl_fourier_core!(FourierGgsw);

impl_fourier_iters!(FourierGgsw);
impl_fourier_iter_sub!(
    FourierGgsw,
    FourierGlev,
    FourierGlevIter,
    FourierGlevIterMut,
    glev
);

impl_fourier_basic_operation!(FourierGgsw);
impl_fourier_polynomial!(FourierGgsw);

impl_fourier_conversion!(Ggsw, FourierGgsw);

impl<S> FourierGgsw<S>
where
    S: Data<Elem = Complex64>,
{
    /// Writes `self - rhs * X^exponent` in Fourier form.
    ///
    /// Transforms one integer-scale monomial and shares it across all GGSW
    /// polynomials, combining multiplication and subtraction in one pass.
    /// Ciphertexts stay in Fourier form; no storage is allocated.
    ///
    /// # Correctness
    ///
    /// All ciphertexts must have equal lengths and matching row/level layouts,
    /// keys and gadget bases. They must use the engine's exact table instance,
    /// evaluation order and normalized torus scale. Each polynomial occupies
    /// `fft.fourier_length()` complex values. `exponent` must be in `0..2N`,
    /// where `N = fft.poly_length()`.
    ///
    /// `coefficient_scratch` holds `N` signed-integer bit patterns and
    /// `fourier_scratch` holds `N/2` complex values. Both are overwritten before
    /// use and need no initialization. The integer transform preserves the
    /// ciphertext scale; a torus-scaled monomial would give the wrong result.
    ///
    /// # Panics
    ///
    /// Panics if either scratch length differs from the engine's required length.
    /// Scratch may be partially written before a panic; output is written only
    /// after the monomial transform succeeds.
    #[inline]
    pub fn sub_mul_monomial_to<T, Table, A, B>(
        &self,
        rhs: &FourierGgsw<A>,
        exponent: usize,
        output: &mut FourierGgsw<B>,
        fft: &mut FftEngine<'_, Table>,
        coefficient_scratch: &mut [T],
        fourier_scratch: &mut [Complex64],
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = Complex64>,
        B: DataMut<Elem = Complex64>,
    {
        let poly_length = fft.poly_length();
        let fourier_length = fft.fourier_length();
        debug_assert!(exponent < 2 * poly_length);
        debug_assert_eq!(self.as_ref().len(), rhs.as_ref().len());
        debug_assert_eq!(self.as_ref().len(), output.as_ref().len());
        debug_assert_eq!(self.as_ref().len() % fourier_length, 0);

        coefficient_scratch.fill(T::ZERO);
        // X^(N+j) = -X^j; integer conversion interprets T::MAX as -1.
        let (index, coefficient) = if exponent < poly_length {
            (exponent, T::ONE)
        } else {
            (exponent - poly_length, T::MAX)
        };
        coefficient_scratch[index] = coefficient;
        fft.forward_as_integer(coefficient_scratch, fourier_scratch);
        for ((lhs, rhs), output) in self
            .as_ref()
            .chunks_exact(fourier_length)
            .zip(rhs.as_ref().chunks_exact(fourier_length))
            .zip(output.as_mut().chunks_exact_mut(fourier_length))
        {
            for (((&lhs, &rhs), &factor), output) in
                lhs.iter().zip(rhs).zip(&*fourier_scratch).zip(output)
            {
                *output = lhs - rhs * factor;
            }
        }
    }
}

impl<S> FourierGgsw<S>
where
    S: DataMut<Elem = Complex64>,
{
    /// Adds an already gadget-weighted plaintext to the diagonal of one level.
    ///
    /// Storage is `[row][level][component][polynomial entry]`. The number
    /// of components equals the number of rows. `level` is
    /// a zero-based storage index; the caller maps it to its gadget weight.
    /// Every diagonal polynomial at this level receives `plaintext`, while
    /// other levels and off-diagonal components remain unchanged.
    ///
    /// # Correctness
    ///
    /// `plaintext` must be one complete nonempty polynomial already multiplied
    /// by the selected gadget weight and encoded in this ciphertext's domain
    /// and scale. This performs neither encoding nor encryption, and allocates
    /// no temporary storage. Adding all levels implements addition of `m*G`
    /// under the caller's gadget convention.
    /// `size` must describe the complete ciphertext and plaintext layouts.
    /// `level` must be less than its decomposition length. The caller is
    /// responsible for matching the actual buffers to `size`.
    /// Inputs must share the FFT table, evaluation order and torus scale.
    #[inline]
    pub fn add_gadget_diagonal_assign<A>(
        &mut self,
        plaintext: &FourierPolynomial<A>,
        level: usize,
        size: crate::GadgetSize,
    ) where
        A: Data<Elem = Complex64>,
    {
        let glwe_size = size.glwe_size();
        debug_assert!(
            level < size.decompose_length(),
            "gadget level is out of range"
        );
        for diagonal in crate::gadget::diagonal_level_mut(
            self.as_mut(),
            glwe_size.fourier_poly_len(),
            level,
            glwe_size.fourier_glwe_len(),
            size.fourier_glev_len(),
        ) {
            FourierPolynomial(diagonal).add_assign(plaintext);
        }
    }
}
