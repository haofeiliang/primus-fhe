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
impl_torus_fft_value!(
    u64,
    i64,
    i128,
    1.0 / 18_446_744_073_709_551_616.0,
    18_446_744_073_709_551_616.0
);
