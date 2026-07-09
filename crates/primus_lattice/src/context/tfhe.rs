use primus_fft::TorusFftValue;

/// Pre-allocated scratch buffers for the TFHE external product.
///
/// All allocations happen at construction time. The hot loop only mutates
/// slices obtained directly from the public fields.
///
/// # GLWE dimension convention
///
/// `glwe_dimension` is the count of *mask* polynomials (`k`). The
/// accumulator is sized for `glwe_dimension + 1` polynomials (k mask
/// + 1 body), matching the convention of
/// [`crate::lwe::Lwe::dimension()`].
///
/// # Fourier buffer layout
///
/// Fourier buffers use split real/imaginary format:
/// `[re_0..re_{m-1}, im_0..im_{m-1}]` where `m = fourier_length`.
/// Each buffer has `2 * fourier_length` elements.
pub struct TfheFftContext<T: TorusFftValue> {
    /// Carry bits, one per coefficient (length = `poly_length`).
    pub carries: Vec<bool>,
    /// Decomposed (signed) digits for one polynomial (length = `poly_length`).
    /// Kept for backward compatibility; the fused path uses
    /// [`decomposed_centered_f64`](Self::decomposed_centered_f64) instead.
    pub decomposed_poly: Vec<T>,
    /// Decomposed digits as centered `f64` (length = `poly_length`).
    /// Used by the fused decomposition→FFT path to avoid an intermediate
    /// `u32` → `f64` conversion inside the FFT twist loop.
    pub decomposed_centered_f64: Vec<f64>,
    /// FFT of the decomposed polynomial, split [re | im] layout
    /// (length = `2 * fourier_length`).
    pub decomposed_fourier: Vec<f64>,
    /// Accumulator in Fourier domain, split [re | im] layout
    /// (length = `(glwe_dimension + 1) * 2 * fourier_length`).
    pub fourier_accumulator: Vec<f64>,
}

impl<T: TorusFftValue> TfheFftContext<T> {
    /// Creates a new context with all buffers pre-allocated.
    ///
    /// `glwe_dimension` is the mask count `k`; the accumulator is sized for
    /// `k + 1` polynomials.
    pub fn new(poly_length: usize, fourier_length: usize, glwe_dimension: usize) -> Self {
        let total_polys = glwe_dimension + 1;
        let blen = 2 * fourier_length;
        Self {
            carries: vec![false; poly_length],
            decomposed_poly: vec![T::ZERO; poly_length],
            decomposed_centered_f64: vec![0.0f64; poly_length],
            decomposed_fourier: vec![0.0f64; blen],
            fourier_accumulator: vec![0.0f64; total_polys * blen],
        }
    }

    /// Resizes all buffers to the given dimensions.
    pub fn resize(&mut self, poly_length: usize, fourier_length: usize, glwe_dimension: usize) {
        let total_polys = glwe_dimension + 1;
        let blen = 2 * fourier_length;
        self.carries.resize(poly_length, false);
        self.decomposed_poly.resize(poly_length, T::ZERO);
        self.decomposed_centered_f64.resize(poly_length, 0.0f64);
        self.decomposed_fourier.resize(blen, 0.0f64);
        self.fourier_accumulator.resize(total_polys * blen, 0.0f64);
    }
}
