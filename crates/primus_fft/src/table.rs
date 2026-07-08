use crate::error::FftError;
use crate::torus::TorusFftValue;

/// Abstract interface for torus negacyclic FFT tables.
///
/// Implementations provide forward and inverse negacyclic transforms for
/// polynomial multiplication in `Z[X] / (X^N + 1)`.
///
/// # Buffer layout
///
/// Fourier data is stored in split real/imaginary format:
/// `[re_0, ..., re_{m-1}, im_0, ..., im_{m-1}]` where `m = fourier_length()`.
/// Total buffer size is `buffer_len() = 2 * fourier_length()`.
///
/// # Thread safety
///
/// Implementations must be `Send + Sync` so tables can be shared across
/// threads (read-only) without additional synchronization.
pub trait FftTable: Send + Sync {
    /// Create a new FFT table for the negacyclic transform of size `N = 2^log_n`.
    fn new(log_n: u32) -> Result<Self, FftError>
    where
        Self: Sized;

    /// The polynomial length `N`.
    fn poly_length(&self) -> usize;

    /// The number of logical complex frequency values.
    ///
    /// For the full-length backend this equals `poly_length()`.
    /// A future packed backend may return `poly_length() / 2`.
    fn fourier_length(&self) -> usize;

    /// Total buffer length in `f64` elements.
    ///
    /// Equals `2 * fourier_length()` for the split `[re | im]` layout.
    #[inline]
    fn buffer_len(&self) -> usize {
        2 * self.fourier_length()
    }

    /// Forward negacyclic transform: torus coefficients → split Fourier domain.
    ///
    /// `input` must have length [`poly_length()`](FftTable::poly_length).
    /// `output` receives `buffer_len()` f64 values in split `[re | im]` layout.
    fn forward_torus_slice<T: TorusFftValue>(&self, input: &[T], output: &mut [f64]);

    /// Inverse negacyclic transform: split Fourier domain → torus coefficients.
    ///
    /// `input` must have length [`buffer_len()`](FftTable::buffer_len) in split
    /// `[re | im]` layout.
    /// `output` receives [`poly_length()`](FftTable::poly_length) torus values.
    fn inverse_torus_slice<T: TorusFftValue>(&self, input: &[f64], output: &mut [T]);
}
