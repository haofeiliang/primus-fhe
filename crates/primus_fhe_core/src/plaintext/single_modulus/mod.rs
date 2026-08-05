use primus_factor::ShoupFactor;
use primus_integer::FheUint;
use primus_modulus::PowOf2Modulus;

mod accumulate;
mod decode;
mod encode;
mod helpers;
mod strategy;

use strategy::{
    CodecStrategy, ExplicitPow2Codec, ExplicitScaledCodec, NativePow2Codec, NativeScaledCodec,
    ScaledArithmetic,
};

/// Broad encoding strategy selected by [`PlaintextCodec::new`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlaintextCodecKind {
    /// Native power-of-two torus encoding implemented with shifts.
    NativePow2,
    /// Explicit power-of-two modulus encoding implemented with shifts.
    ExplicitPow2,
    /// Native torus encoding using a rounded scale factor.
    NativeScaled,
    /// Explicit scaled encoding whose intermediate product fits in one limb.
    ExplicitScaledNarrow,
    /// Explicit scaled encoding requiring wide intermediate arithmetic.
    ExplicitScaledWide,
}

/// Preselected plaintext encoding/decoding strategy for fixed parameters.
///
/// This keeps modulus-shape checks and shift/mask computation out of hot
/// coefficient loops while hiding strategy-specific precomputation.
#[derive(Clone, Copy, Debug)]
pub struct PlaintextCodec<T: FheUint> {
    t: T,
    centered_half: T,
    strategy: CodecStrategy<T>,
}

impl<T: FheUint> PlaintextCodec<T> {
    /// Creates a codec for plaintext modulus `t` and ciphertext modulus `q`.
    ///
    /// `q = None` selects the native wrapping modulus `2^T::BITS`.
    ///
    /// # Panics
    ///
    /// Panics if `t <= 1`, if an explicit `q` is not greater than `t`, or if
    /// a power-of-two pair leaves fewer than two encoding bits.
    #[inline]
    pub fn new(t: T, q: Option<T>) -> Self {
        assert!(t > T::ONE);

        let strategy = match q {
            None if t.is_power_of_two() => {
                let encode_shift = T::BITS - t.trailing_zeros();
                assert!(encode_shift > 1);
                CodecStrategy::NativePow2(NativePow2Codec {
                    encode_shift,
                    decode_shift: encode_shift - 1,
                    plain_mask: t - T::ONE,
                })
            }
            None => {
                // delta = round(2^BITS / t) = floor((2^BITS + t/2) / t)
                let delta = T::div_wide(t >> 1u32, T::ONE, t);
                CodecStrategy::NativeScaled(NativeScaledCodec { delta })
            }
            Some(q) if q.is_power_of_two() && t.is_power_of_two() => {
                assert!(q > t);
                let encode_shift = q.trailing_zeros() - t.trailing_zeros();
                assert!(encode_shift > 1);
                CodecStrategy::ExplicitPow2(ExplicitPow2Codec {
                    encode_shift,
                    decode_shift: encode_shift - 1,
                    plain_mask: t - T::ONE,
                    modulus: PowOf2Modulus::new(q),
                })
            }
            Some(q) => {
                assert!(q > t);
                let (mut delta, rem) = q.div_rem(t);
                if rem > (t - T::ONE) / T::TWO {
                    delta += T::ONE;
                }
                let delta_factor = ShoupFactor::new(delta, q);
                let arithmetic = if q.checked_mul(t).is_some() {
                    ScaledArithmetic::Narrow
                } else {
                    ScaledArithmetic::Wide
                };
                CodecStrategy::ExplicitScaled(ExplicitScaledCodec {
                    q,
                    delta_factor,
                    arithmetic,
                })
            }
        };

        Self {
            t,
            centered_half: helpers::centered_half(t),
            strategy,
        }
    }

    /// Returns the plaintext modulus `t` used by this codec.
    #[inline]
    pub fn t(&self) -> T {
        self.t
    }

    /// Returns the preselected arithmetic strategy.
    #[inline]
    pub fn kind(&self) -> PlaintextCodecKind {
        match self.strategy {
            CodecStrategy::NativePow2(_) => PlaintextCodecKind::NativePow2,
            CodecStrategy::ExplicitPow2(_) => PlaintextCodecKind::ExplicitPow2,
            CodecStrategy::NativeScaled(_) => PlaintextCodecKind::NativeScaled,
            CodecStrategy::ExplicitScaled(codec) => match codec.arithmetic {
                ScaledArithmetic::Narrow => PlaintextCodecKind::ExplicitScaledNarrow,
                ScaledArithmetic::Wide => PlaintextCodecKind::ExplicitScaledWide,
            },
        }
    }
}
