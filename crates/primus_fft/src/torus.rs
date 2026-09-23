use primus_integer::FheUint;

/// Conversion between unsigned torus bit patterns and `f64`.
pub trait TorusFftValue: FheUint {
    /// Exact `2^-BITS` scaling factor used by the forward torus conversion.
    const TORUS_SCALE: f64;
    /// Exact `2^BITS` scaling factor used by the backward torus conversion.
    const TORUS_SCALE_INVERSE: f64;

    /// Reinterprets the bit pattern as a signed integer and converts it to `f64`.
    fn into_signed_f64(self) -> f64;
    /// Converts the bit pattern to a normalized torus value in `[-0.5, 0.5)`.
    #[inline]
    fn into_torus_f64(self) -> f64 {
        self.into_signed_f64() * Self::TORUS_SCALE
    }
    /// Converts a normalized torus value back to its unsigned bit pattern.
    ///
    /// Built-in implementations scale by `2^BITS`, round half-way cases away
    /// from zero, saturate to a signed integer with twice the word width, then
    /// retain the low `BITS` bits. NaN converts to zero. Values outside one
    /// torus period are accepted; this is not a saturating unsigned conversion.
    fn from_torus_f64(value: f64) -> Self;
}

macro_rules! impl_torus_fft_value {
    ($unsigned:ty, $signed:ty, $wide:ty, $scale:expr, $scale_inverse:expr) => {
        impl TorusFftValue for $unsigned {
            const TORUS_SCALE: f64 = $scale;
            const TORUS_SCALE_INVERSE: f64 = $scale_inverse;

            #[inline]
            fn into_signed_f64(self) -> f64 {
                (self as $signed) as f64
            }
            #[inline]
            fn from_torus_f64(value: f64) -> Self {
                let scaled = value * Self::TORUS_SCALE_INVERSE;
                (scaled.round() as $wide) as Self
            }
        }
    };
}

impl_torus_fft_value!(u16, i16, i32, 1.0 / 65_536.0, 65_536.0);
impl_torus_fft_value!(u32, i32, i64, 1.0 / 4_294_967_296.0, 4_294_967_296.0);
impl TorusFftValue for u64 {
    const TORUS_SCALE: f64 = 1.0 / 18_446_744_073_709_551_616.0;
    const TORUS_SCALE_INVERSE: f64 = 18_446_744_073_709_551_616.0;

    #[inline]
    fn into_signed_f64(self) -> f64 {
        (self as i64) as f64
    }

    #[inline]
    fn from_torus_f64(value: f64) -> Self {
        // Keep the old round -> saturating i128 -> wrapping u64 semantics,
        // but extract the integer's low bits without a software i128 cast.
        let bits = (value * Self::TORUS_SCALE_INVERSE).round().to_bits();
        let exponent = ((bits >> 52) & 0x7ff) as u32;
        let fraction = bits & ((1u64 << 52) - 1);
        let negative = bits >> 63 != 0;
        if exponent >= 1023 + 127 {
            // NaN casts to zero; positive overflow saturates to i128::MAX,
            // negative overflow to i128::MIN (whose low 64 bits are zero).
            return if negative || (exponent == 0x7ff && fraction != 0) {
                0
            } else {
                u64::MAX
            };
        }
        let significand = fraction | (1u64 << 52);
        let magnitude = if exponent < 1023 {
            0
        } else if exponent < 1023 + 52 {
            significand >> (1023 + 52 - exponent)
        } else {
            significand.checked_shl(exponent - (1023 + 52)).unwrap_or(0)
        };
        if negative {
            magnitude.wrapping_neg()
        } else {
            magnitude
        }
    }
}
