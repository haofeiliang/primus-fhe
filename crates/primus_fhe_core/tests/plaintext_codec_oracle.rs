//! Independent mathematical oracle tests for the first TFHE plaintext-codec profiles.
//!
//! The reference functions deliberately use only `u128` arithmetic and do not
//! call production codec helpers.

use core::fmt::Debug;

use primus_fhe_core::plaintext::{PlaintextCodec, PlaintextEmbedding};
use primus_integer::FheUint;

const POWER_OF_TWO_PLAINTEXT_MODULI: [u128; 5] = [2, 4, 8, 16, 256];

#[inline]
fn round_half_up(numerator: u128, denominator: u128) -> u128 {
    (numerator + denominator / 2) / denominator
}

#[inline]
fn centered_lift(message: u128, t: u128) -> (u128, bool) {
    let centered_half = t.div_ceil(2);
    if message < centered_half {
        (message, false)
    } else {
        (t - message, true)
    }
}

#[inline]
fn negate_mod(value: u128, q: u128) -> u128 {
    if value == 0 { 0 } else { q - value }
}

fn encode_exact_oracle(message: u128, t: u128, q: u128, embedding: PlaintextEmbedding) -> u128 {
    let (magnitude, is_negative) = match embedding {
        PlaintextEmbedding::Unsigned => (message, false),
        PlaintextEmbedding::Centered => centered_lift(message, t),
    };
    let encoded = round_half_up(magnitude * q, t) % q;
    if is_negative {
        negate_mod(encoded, q)
    } else {
        encoded
    }
}

fn encode_delta_oracle(message: u128, t: u128, q: u128, embedding: PlaintextEmbedding) -> u128 {
    let (magnitude, is_negative) = match embedding {
        PlaintextEmbedding::Unsigned => (message, false),
        PlaintextEmbedding::Centered => centered_lift(message, t),
    };
    let delta = round_half_up(q, t);
    let encoded = (magnitude * delta) % q;
    if is_negative {
        negate_mod(encoded, q)
    } else {
        encoded
    }
}

#[inline]
fn decode_oracle(encoded: u128, t: u128, q: u128) -> u128 {
    round_half_up(encoded * t, q) % t
}

fn to_value<T>(value: u128) -> T
where
    T: TryFrom<u128>,
{
    T::try_from(value).ok().unwrap()
}

fn assert_codec_matches_oracle<T>(explicit_q: Option<T>, q: u128)
where
    T: FheUint + Into<u128> + TryFrom<u128>,
    <T as TryFrom<u128>>::Error: Debug,
{
    for t in POWER_OF_TWO_PLAINTEXT_MODULI {
        let codec = PlaintextCodec::new(to_value(t), explicit_q);

        for message in 0..t {
            for embedding in [PlaintextEmbedding::Unsigned, PlaintextEmbedding::Centered] {
                let encoded = codec.encode_value::<T>(to_value(message), embedding).into();
                assert_eq!(
                    encoded,
                    encode_exact_oracle(message, t, q, embedding),
                    "exact encoding mismatch: t={t}, message={message}, embedding={embedding:?}"
                );

                let delta_encoded = codec
                    .encode_value_with_delta::<T>(to_value(message), embedding)
                    .into();
                assert_eq!(
                    delta_encoded,
                    encode_delta_oracle(message, t, q, embedding),
                    "delta encoding mismatch: t={t}, message={message}, embedding={embedding:?}"
                );

                assert_eq!(codec.decode_value::<T>(to_value(encoded)).into(), message);
                assert_eq!(
                    codec.decode_value::<T>(to_value(delta_encoded)).into(),
                    message
                );
            }
        }

        // Exercise values immediately around ideal decoding boundaries. These
        // checks are oracle comparisons rather than roundtrip checks.
        let half_step = q / (2 * t);
        for message in 0..t {
            let center = encode_exact_oracle(message, t, q, PlaintextEmbedding::Unsigned);
            for distance in [
                half_step.saturating_sub(1),
                half_step,
                half_step.saturating_add(1),
            ] {
                for candidate in [(center + distance) % q, (center + q - distance % q) % q] {
                    let decoded: u128 = codec.decode_value::<T>(to_value(candidate)).into();
                    assert_eq!(
                        decoded,
                        decode_oracle(candidate, t, q),
                        "decode mismatch: t={t}, encoded={candidate}"
                    );
                }
            }
        }
    }
}

#[test]
fn native_u32_matches_u128_oracle() {
    assert_codec_matches_oracle::<u32>(None, 1u128 << u32::BITS);
}

#[test]
fn native_u64_matches_u128_oracle() {
    assert_codec_matches_oracle::<u64>(None, 1u128 << u64::BITS);
}

#[test]
fn ntt_prime_u32_matches_u128_oracle() {
    const Q: u32 = 1_073_692_673;
    assert_codec_matches_oracle(Some(Q), Q.into());
}

#[test]
fn ntt_prime_u64_matches_u128_oracle() {
    const Q: u64 = 1_152_921_504_606_830_593;
    assert_codec_matches_oracle(Some(Q), Q.into());
}
