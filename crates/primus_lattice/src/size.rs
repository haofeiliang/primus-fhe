/// Smallest supported polynomial length for GLWE-family layouts.
pub const MIN_POLY_LENGTH: usize = 2;

/// Largest supported polynomial length for GLWE-family layouts.
pub const MAX_POLY_LENGTH: usize = 1 << 17;

/// An error produced while constructing a checked GLWE-family size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GlweSizeError {
    /// The GLWE mask dimension is zero.
    #[error("GLWE dimension must be non-zero")]
    ZeroDimension,
    /// The polynomial length is outside the supported power-of-two range.
    #[error(
        "GLWE polynomial length must be a power of two in {MIN_POLY_LENGTH}..={MAX_POLY_LENGTH}"
    )]
    InvalidPolynomialLength,
    /// An RNS layout has no moduli.
    #[error("RNS modulus count must be non-zero")]
    ZeroModuliCount,
    /// A gadget layout has no decomposition levels.
    #[error("gadget decomposition length must be non-zero")]
    ZeroDecomposeLength,
    /// A derived flattened length does not fit in `usize`.
    #[error("{0} length overflow")]
    LengthOverflow(&'static str),
}

/// Checked sizes for a coefficient- or NTT-domain GLWE ciphertext.
///
/// A GLWE ciphertext contains `dimension` mask polynomials followed by one
/// body polynomial, each with `poly_length` coefficients. Fourier-domain
/// lengths are derived by halving the corresponding ordinary length and are
/// not stored separately.
#[derive(Debug, Clone, Copy, Eq)]
pub struct GlweSize {
    dimension: usize,
    poly_length: usize,
    mask_len: usize,
    glwe_len: usize,
}

impl PartialEq for GlweSize {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.dimension == other.dimension && self.poly_length == other.poly_length
    }
}

impl GlweSize {
    /// Creates checked GLWE sizes.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero dimension, an invalid polynomial length,
    /// or an overflowing flattened length.
    pub fn try_new(dimension: usize, poly_length: usize) -> Result<Self, GlweSizeError> {
        if dimension == 0 {
            return Err(GlweSizeError::ZeroDimension);
        }
        if !(MIN_POLY_LENGTH..=MAX_POLY_LENGTH).contains(&poly_length)
            || !poly_length.is_power_of_two()
        {
            return Err(GlweSizeError::InvalidPolynomialLength);
        }

        let component_count = dimension
            .checked_add(1)
            .ok_or(GlweSizeError::LengthOverflow("GLWE component"))?;
        let mask_len = dimension
            .checked_mul(poly_length)
            .ok_or(GlweSizeError::LengthOverflow("GLWE mask"))?;
        let glwe_len = component_count
            .checked_mul(poly_length)
            .ok_or(GlweSizeError::LengthOverflow("GLWE ciphertext"))?;

        Ok(Self {
            dimension,
            poly_length,
            mask_len,
            glwe_len,
        })
    }

    /// Creates GLWE sizes, panicking when [`Self::try_new`] fails.
    #[must_use]
    pub fn new(dimension: usize, poly_length: usize) -> Self {
        Self::try_new(dimension, poly_length).unwrap_or_else(|error| panic!("{error}"))
    }

    /// Returns the number of mask polynomials.
    #[must_use]
    #[inline]
    pub const fn dimension(self) -> usize {
        self.dimension
    }

    /// Returns the number of coefficients in each polynomial.
    #[must_use]
    #[inline]
    pub const fn poly_length(self) -> usize {
        self.poly_length
    }

    /// Returns the number of complex values in each Fourier-domain polynomial.
    #[must_use]
    #[inline]
    pub const fn fourier_poly_len(self) -> usize {
        self.poly_length >> 1
    }

    /// Returns the number of mask and body polynomials combined.
    #[must_use]
    #[inline]
    pub const fn component_count(self) -> usize {
        self.dimension + 1
    }

    /// Returns the flattened mask length.
    #[must_use]
    #[inline]
    pub const fn mask_len(self) -> usize {
        self.mask_len
    }

    /// Returns the flattened Fourier-domain mask length.
    #[must_use]
    #[inline]
    pub const fn fourier_mask_len(self) -> usize {
        self.mask_len >> 1
    }

    /// Returns the flattened ciphertext length.
    #[must_use]
    #[inline]
    pub const fn glwe_len(self) -> usize {
        self.glwe_len
    }

    /// Returns the flattened Fourier-domain ciphertext length.
    #[must_use]
    #[inline]
    pub const fn fourier_glwe_len(self) -> usize {
        self.glwe_len >> 1
    }
}

/// Checked sizes for a CRT- or DCRT-domain GLWE ciphertext.
#[derive(Debug, Clone, Copy, Eq)]
pub struct RnsGlweSize {
    glwe_size: GlweSize,
    moduli_count: usize,
    rns_poly_len: usize,
    rns_mask_len: usize,
    rns_glwe_len: usize,
}

impl PartialEq for RnsGlweSize {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.glwe_size == other.glwe_size && self.moduli_count == other.moduli_count
    }
}

impl RnsGlweSize {
    /// Creates checked RNS GLWE sizes.
    pub fn try_new(glwe_size: GlweSize, moduli_count: usize) -> Result<Self, GlweSizeError> {
        if moduli_count == 0 {
            return Err(GlweSizeError::ZeroModuliCount);
        }

        let rns_poly_len = glwe_size
            .poly_length()
            .checked_mul(moduli_count)
            .ok_or(GlweSizeError::LengthOverflow("RNS polynomial"))?;
        let rns_mask_len = glwe_size
            .dimension()
            .checked_mul(rns_poly_len)
            .ok_or(GlweSizeError::LengthOverflow("RNS GLWE mask"))?;
        let rns_glwe_len = rns_mask_len
            .checked_add(rns_poly_len)
            .ok_or(GlweSizeError::LengthOverflow("RNS GLWE ciphertext"))?;

        Ok(Self {
            glwe_size,
            moduli_count,
            rns_poly_len,
            rns_mask_len,
            rns_glwe_len,
        })
    }

    /// Creates RNS GLWE sizes, panicking when [`Self::try_new`] fails.
    #[must_use]
    pub fn new(glwe_size: GlweSize, moduli_count: usize) -> Self {
        Self::try_new(glwe_size, moduli_count).unwrap_or_else(|error| panic!("{error}"))
    }

    /// Returns the underlying single-modulus GLWE sizes.
    #[must_use]
    #[inline]
    pub const fn glwe_size(self) -> GlweSize {
        self.glwe_size
    }

    /// Returns the number of mask polynomials.
    #[must_use]
    #[inline]
    pub const fn dimension(self) -> usize {
        self.glwe_size.dimension()
    }

    /// Returns the polynomial length for one modulus limb.
    #[must_use]
    #[inline]
    pub const fn poly_length(self) -> usize {
        self.glwe_size.poly_length()
    }

    /// Returns the number of RNS moduli.
    #[must_use]
    #[inline]
    pub const fn moduli_count(self) -> usize {
        self.moduli_count
    }

    /// Returns the flattened length of one RNS polynomial.
    #[must_use]
    #[inline]
    pub const fn rns_poly_len(self) -> usize {
        self.rns_poly_len
    }

    /// Returns the flattened RNS mask length.
    #[must_use]
    #[inline]
    pub const fn rns_mask_len(self) -> usize {
        self.rns_mask_len
    }

    /// Returns the flattened RNS ciphertext length.
    #[must_use]
    #[inline]
    pub const fn rns_glwe_len(self) -> usize {
        self.rns_glwe_len
    }
}

/// Checked sizes for single-modulus GLev and GGSW ciphertexts.
#[derive(Debug, Clone, Copy, Eq)]
pub struct GadgetSize {
    glwe_size: GlweSize,
    decompose_length: usize,
    glev_len: usize,
    ggsw_len: usize,
}

impl PartialEq for GadgetSize {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.glwe_size == other.glwe_size && self.decompose_length == other.decompose_length
    }
}

impl GadgetSize {
    /// Creates checked gadget ciphertext sizes.
    pub fn try_new(glwe_size: GlweSize, decompose_length: usize) -> Result<Self, GlweSizeError> {
        if decompose_length == 0 {
            return Err(GlweSizeError::ZeroDecomposeLength);
        }

        let glev_len = decompose_length
            .checked_mul(glwe_size.glwe_len())
            .ok_or(GlweSizeError::LengthOverflow("GLev ciphertext"))?;
        let ggsw_len = glwe_size
            .component_count()
            .checked_mul(glev_len)
            .ok_or(GlweSizeError::LengthOverflow("GGSW ciphertext"))?;

        Ok(Self {
            glwe_size,
            decompose_length,
            glev_len,
            ggsw_len,
        })
    }

    /// Creates gadget sizes, panicking when [`Self::try_new`] fails.
    #[must_use]
    pub fn new(glwe_size: GlweSize, decompose_length: usize) -> Self {
        Self::try_new(glwe_size, decompose_length).unwrap_or_else(|error| panic!("{error}"))
    }

    /// Returns the underlying GLWE sizes.
    #[must_use]
    #[inline]
    pub const fn glwe_size(self) -> GlweSize {
        self.glwe_size
    }

    /// Returns the number of decomposition levels.
    #[must_use]
    #[inline]
    pub const fn decompose_length(self) -> usize {
        self.decompose_length
    }

    /// Returns the flattened GLev ciphertext length.
    #[must_use]
    #[inline]
    pub const fn glev_len(self) -> usize {
        self.glev_len
    }

    /// Returns the flattened Fourier-domain GLev ciphertext length.
    #[must_use]
    #[inline]
    pub const fn fourier_glev_len(self) -> usize {
        self.glev_len >> 1
    }

    /// Returns the flattened GGSW ciphertext length.
    #[must_use]
    #[inline]
    pub const fn ggsw_len(self) -> usize {
        self.ggsw_len
    }

    /// Returns the flattened Fourier-domain GGSW ciphertext length.
    #[must_use]
    #[inline]
    pub const fn fourier_ggsw_len(self) -> usize {
        self.ggsw_len >> 1
    }

    /// Returns the flattened ciphertext length.
    #[must_use]
    #[inline]
    pub const fn glwe_len(self) -> usize {
        self.glwe_size.glwe_len()
    }
}

/// Checked sizes for RNS GLev and GGSW ciphertexts.
#[derive(Debug, Clone, Copy, Eq)]
pub struct RnsGadgetSize {
    rns_glwe_size: RnsGlweSize,
    decompose_length: usize,
    rns_glev_len: usize,
    rns_ggsw_len: usize,
}

impl PartialEq for RnsGadgetSize {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.rns_glwe_size == other.rns_glwe_size && self.decompose_length == other.decompose_length
    }
}

impl RnsGadgetSize {
    /// Creates checked RNS gadget ciphertext sizes.
    pub fn try_new(
        rns_glwe_size: RnsGlweSize,
        decompose_length: usize,
    ) -> Result<Self, GlweSizeError> {
        if decompose_length == 0 {
            return Err(GlweSizeError::ZeroDecomposeLength);
        }

        let rns_glev_len = decompose_length
            .checked_mul(rns_glwe_size.rns_glwe_len())
            .ok_or(GlweSizeError::LengthOverflow("RNS GLev ciphertext"))?;
        let rns_ggsw_len = rns_glwe_size
            .glwe_size()
            .component_count()
            .checked_mul(rns_glev_len)
            .ok_or(GlweSizeError::LengthOverflow("RNS GGSW ciphertext"))?;

        Ok(Self {
            rns_glwe_size,
            decompose_length,
            rns_glev_len,
            rns_ggsw_len,
        })
    }

    /// Creates RNS gadget sizes, panicking when [`Self::try_new`] fails.
    #[must_use]
    pub fn new(rns_glwe_size: RnsGlweSize, decompose_length: usize) -> Self {
        Self::try_new(rns_glwe_size, decompose_length).unwrap_or_else(|error| panic!("{error}"))
    }

    /// Returns the underlying RNS GLWE sizes.
    #[must_use]
    #[inline]
    pub const fn rns_glwe_size(self) -> RnsGlweSize {
        self.rns_glwe_size
    }

    /// Returns the number of decomposition levels.
    #[must_use]
    #[inline]
    pub const fn decompose_length(self) -> usize {
        self.decompose_length
    }

    /// Returns the flattened RNS GLev ciphertext length.
    #[must_use]
    #[inline]
    pub const fn rns_glev_len(self) -> usize {
        self.rns_glev_len
    }

    /// Returns the flattened RNS GGSW ciphertext length.
    #[must_use]
    #[inline]
    pub const fn rns_ggsw_len(self) -> usize {
        self.rns_ggsw_len
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GadgetSize, GlweSize, GlweSizeError, MAX_POLY_LENGTH, MIN_POLY_LENGTH, RnsGlweSize,
    };

    #[test]
    fn checked_sizes_reject_empty_and_overflowing_layouts() {
        assert_eq!(GlweSize::try_new(0, 2), Err(GlweSizeError::ZeroDimension));
        assert_eq!(
            GlweSize::try_new(1, 0),
            Err(GlweSizeError::InvalidPolynomialLength)
        );
        assert!(GlweSize::try_new(1, MIN_POLY_LENGTH).is_ok());
        assert!(GlweSize::try_new(1, MAX_POLY_LENGTH).is_ok());
        assert_eq!(
            GlweSize::try_new(1, MAX_POLY_LENGTH << 1),
            Err(GlweSizeError::InvalidPolynomialLength)
        );

        let glwe = GlweSize::new(1, 2);
        assert_eq!(
            RnsGlweSize::try_new(glwe, 0),
            Err(GlweSizeError::ZeroModuliCount)
        );
        assert_eq!(
            GadgetSize::try_new(glwe, 0),
            Err(GlweSizeError::ZeroDecomposeLength)
        );
        assert!(matches!(
            GlweSize::try_new(usize::MAX, 2),
            Err(GlweSizeError::LengthOverflow(_))
        ));
        assert!(matches!(
            RnsGlweSize::try_new(glwe, usize::MAX),
            Err(GlweSizeError::LengthOverflow(_))
        ));
    }
}
