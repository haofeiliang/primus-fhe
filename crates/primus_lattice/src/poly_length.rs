//! Checked polynomial lengths for GLWE/NTRU layouts.
//!
//! [`PolyLength`] describes `Z_q[X]/(X^N + 1)` with `N >= 2`. It does not
//! establish a modulus, transform convention, buffer layout or security level.
//! Transform constructors retain their own supported-size bounds.

/// Smallest supported polynomial length for GLWE/NTRU layouts.
pub const MIN_POLY_LENGTH: usize = 2;

/// Largest supported polynomial length for GLWE/NTRU layouts.
pub const MAX_POLY_LENGTH: usize = 1 << 17;

/// A polynomial length outside the supported power-of-two range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "polynomial length must be a power of two in {MIN_POLY_LENGTH}..={MAX_POLY_LENGTH}, got {poly_length}"
)]
pub struct PolyLengthError {
    /// The rejected polynomial length.
    pub poly_length: usize,
}

/// Checked coefficient count `N` for a ring modulo `X^N + 1`.
///
/// Accepts powers of two in [`MIN_POLY_LENGTH`]..=[`MAX_POLY_LENGTH`], the
/// supported GLWE/NTRU layout range. This bound also ensures `2N` fits in
/// `usize`; allocating a buffer or constructing a transform requires its own
/// checks.
///
/// ```
/// use primus_lattice::PolyLength;
///
/// let length = PolyLength::try_new(1024)?;
/// assert_eq!(length.get(), 1024);
/// assert_eq!(length.log_n(), 10);
/// assert_eq!(length.fourier_poly_len(), 512);
/// # Ok::<(), primus_lattice::PolyLengthError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolyLength(usize);

impl PolyLength {
    /// Checks the supported polynomial length and power-of-two requirement.
    ///
    /// # Errors
    ///
    /// Returns [`PolyLengthError`] if the length is outside
    /// [`MIN_POLY_LENGTH`]..=[`MAX_POLY_LENGTH`] or not a power of two.
    pub const fn try_new(poly_length: usize) -> Result<Self, PolyLengthError> {
        if poly_length >= MIN_POLY_LENGTH
            && poly_length <= MAX_POLY_LENGTH
            && poly_length.is_power_of_two()
        {
            Ok(Self(poly_length))
        } else {
            Err(PolyLengthError { poly_length })
        }
    }

    /// Creates a checked polynomial length.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_new`] rejects the coefficient count.
    #[must_use]
    pub fn new(poly_length: usize) -> Self {
        Self::try_new(poly_length).unwrap_or_else(|error| panic!("{error}"))
    }

    /// Returns `N`, the number of coefficients modulo `X^N + 1`.
    #[must_use]
    #[inline]
    pub const fn get(self) -> usize {
        self.0
    }

    /// Returns `log2(N)`, as used by transform constructors.
    #[must_use]
    #[inline]
    pub const fn log_n(self) -> u32 {
        self.0.trailing_zeros()
    }

    /// Returns `N/2`, the complex element count of a packed Fourier polynomial.
    ///
    /// This count does not establish a particular Fourier backend's supported range.
    #[must_use]
    #[inline]
    pub const fn fourier_poly_len(self) -> usize {
        self.0 / 2
    }
}

impl TryFrom<usize> for PolyLength {
    type Error = PolyLengthError;

    #[inline]
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl From<PolyLength> for usize {
    #[inline]
    fn from(value: PolyLength) -> Self {
        value.get()
    }
}
