//! Tests for TFHE/torus message encoding using `PlaintextCodec` with native
//! torus modulus `2^BITS` (`q = None`).
//!
//! These tests demonstrate:
//! - `PlaintextCodec` correctly encodes/decodes messages for TFHE torus use.
//! - Message encoding is independent of FFT conversion — the same codec works
//!   with any FFT size, and the same FFT works with any message modulus.

use primus_fft::{FftTable, FftTableImpl};
use primus_fhe_core::{PlaintextCodec, PlaintextEmbedding};
use primus_integer::FheUint;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute `delta = round(2^BITS / t)` for native torus modulus.
fn torus_delta<T: FheUint>(t: T) -> T {
    if t.is_power_of_two() {
        T::ONE << (T::BITS - t.trailing_zeros())
    } else {
        // delta = round(2^BITS / t) = floor((2^BITS + t/2) / t)
        T::div_wide(t >> 1u32, T::ONE, t)
    }
}

/// Noise tolerance for correct decoding: `delta / 2`.
fn noise_tolerance<T: FheUint>(t: T) -> T {
    torus_delta(t) >> 1u32
}

/// Assert that encode → decode roundtrip is exact for all messages in `[0, t)`.
fn assert_roundtrip<T: FheUint>(codec: &PlaintextCodec<T>, t: T) {
    let t_usize: usize = t.try_into().unwrap();
    let messages: Vec<T> = (0..t_usize).map(|i| T::try_from(i).unwrap()).collect();

    for embedding in [PlaintextEmbedding::Unsigned, PlaintextEmbedding::Centered] {
        // Per-element encode → decode
        for &m in &messages {
            let encoded = codec.encode_value(m, embedding);
            let decoded: T = codec.decode_value(encoded);
            assert_eq!(
                decoded, m,
                "roundtrip failed: m={:?}, embedding={:?}, t={:?}",
                m, embedding, t
            );
        }

        // Batch encode → decode slice
        let mut encoded = vec![T::ZERO; t_usize];
        codec.encode_slice_to(&messages, &mut encoded, embedding);
        let mut decoded = vec![T::ZERO; t_usize];
        codec.decode_slice_to(&encoded, &mut decoded);
        assert_eq!(decoded, messages, "batch slice roundtrip failed");

        // Inplace encode → decode
        let mut inplace = messages.clone();
        codec.encode_slice_inplace(&mut inplace, embedding);
        codec.decode_slice_inplace(&mut inplace);
        assert_eq!(inplace, messages, "inplace roundtrip failed");
    }
}

/// Run a polynomial through FFT forward-then-inverse and return the result.
fn fft_roundtrip_u32(values: &[u32], fft: &FftTableImpl) -> Vec<u32> {
    let n = fft.poly_length();
    let blen = fft.buffer_len();
    assert_eq!(values.len(), n);

    let mut fourier = vec![0.0f64; blen];
    fft.forward_torus_slice(values, &mut fourier);
    let mut recovered = vec![0u32; n];
    fft.inverse_torus_slice(&fourier, &mut recovered);
    recovered
}

// ---------------------------------------------------------------------------
// Test 1: Power-of-two message modulus roundtrip (native torus)
// ---------------------------------------------------------------------------

#[test]
fn native_pow2_roundtrip_u32() {
    for t in [4u32, 8, 16, 256] {
        let codec = PlaintextCodec::new(t, None);
        assert_roundtrip(&codec, t);
    }
}

#[test]
fn native_pow2_roundtrip_u64() {
    for t in [4u64, 8, 16, 256] {
        let codec = PlaintextCodec::new(t, None);
        assert_roundtrip(&codec, t);
    }
}

// ---------------------------------------------------------------------------
// Test 2: Non-power-of-two message modulus roundtrip (native torus)
// ---------------------------------------------------------------------------

#[test]
fn native_scaled_roundtrip_u32() {
    for t in [3u32, 5, 7, 12289] {
        let codec = PlaintextCodec::new(t, None);
        assert_roundtrip(&codec, t);
    }
}

#[test]
fn native_scaled_roundtrip_u64() {
    for t in [3u64, 5, 7, 12289] {
        let codec = PlaintextCodec::new(t, None);
        assert_roundtrip(&codec, t);
    }
}

// ---------------------------------------------------------------------------
// Test 3: FFT independence — same codec, different FFT sizes
// ---------------------------------------------------------------------------

#[test]
fn fft_independence_same_codec_different_fft() {
    // 3-bit messages (q = 8), native torus u32
    let t = 8u32;
    let codec = PlaintextCodec::new(t, None);

    for log_n in [2u32, 3, 4] {
        let fft = FftTableImpl::new(log_n).unwrap();
        let n = fft.poly_length();

        // Create a polynomial of messages: [0, 1, 2, ..., t-1, 0, 1, ...]
        let messages: Vec<u32> = (0..n).map(|i| (i as u32) % t).collect();

        // Encode
        let mut encoded = vec![0u32; n];
        codec.encode_slice_to(&messages, &mut encoded, PlaintextEmbedding::Unsigned);

        // FFT roundtrip — this does NOT know about message modulus
        let recovered = fft_roundtrip_u32(&encoded, &fft);

        // Decode — should recover the original messages
        let mut decoded = vec![0u32; n];
        codec.decode_slice_to(&recovered, &mut decoded);
        assert_eq!(
            decoded, messages,
            "FFT independence failed at log_n={}",
            log_n
        );
    }
}

// ---------------------------------------------------------------------------
// Test 4: FFT independence — different message moduli, same FFT
// ---------------------------------------------------------------------------

#[test]
fn fft_independence_different_moduli_same_fft() {
    let fft = FftTableImpl::new(3).unwrap();
    let n = fft.poly_length();

    // Power-of-two message modulus
    {
        let t = 4u32;
        let codec = PlaintextCodec::new(t, None);
        let messages: Vec<u32> = (0..n).map(|i| (i as u32) % t).collect();

        let mut encoded = vec![0u32; n];
        codec.encode_slice_to(&messages, &mut encoded, PlaintextEmbedding::Unsigned);
        let recovered = fft_roundtrip_u32(&encoded, &fft);

        let mut decoded = vec![0u32; n];
        codec.decode_slice_to(&recovered, &mut decoded);
        assert_eq!(decoded, messages, "pow2 moduli with same FFT failed");
    }

    // Non-power-of-two message modulus
    {
        let t = 7u32;
        let codec = PlaintextCodec::new(t, None);
        let messages: Vec<u32> = (0..n).map(|i| (i as u32) % t).collect();

        let mut encoded = vec![0u32; n];
        codec.encode_slice_to(&messages, &mut encoded, PlaintextEmbedding::Unsigned);
        let recovered = fft_roundtrip_u32(&encoded, &fft);

        let mut decoded = vec![0u32; n];
        codec.decode_slice_to(&recovered, &mut decoded);
        assert_eq!(decoded, messages, "non-pow2 moduli with same FFT failed");
    }
}

// ---------------------------------------------------------------------------
// Test 5: Decode noise margin
// ---------------------------------------------------------------------------

#[test]
fn decode_noise_margin_pow2() {
    // t=8, u32: delta = 1 << 29 = 536870912, noise_tolerance = delta/2 = 268435456
    let t = 8u32;
    let codec = PlaintextCodec::new(t, None);
    let tol = noise_tolerance(t);

    // Encode each message, verify decode works with sub-tolerance noise
    for m in 0u32..t {
        let encoded = codec.encode_value(m, PlaintextEmbedding::Unsigned);

        // Add noise within tolerance
        for noise in [0u32, 1, tol / 2, tol - 1] {
            let noisy = encoded.wrapping_add(noise);
            let decoded: u32 = codec.decode_value(noisy);
            assert_eq!(
                decoded, m,
                "decode failed: m={}, noise=+{} (tol={})",
                m, noise, tol
            );

            // Also try subtracting (wrapping)
            if noise > 0 {
                let noisy_sub = encoded.wrapping_sub(noise);
                let decoded_sub: u32 = codec.decode_value(noisy_sub);
                assert_eq!(
                    decoded_sub, m,
                    "decode failed: m={}, noise=-{} (tol={})",
                    m, noise, tol
                );
            }
        }
    }
}

#[test]
fn decode_noise_margin_scaled() {
    // t=5, u32: delta = round(2^32 / 5) = 858993460, tol = 429496730
    let t = 5u32;
    let codec = PlaintextCodec::new(t, None);
    let tol = noise_tolerance(t);

    for m in 0u32..t {
        let encoded = codec.encode_value(m, PlaintextEmbedding::Unsigned);

        for noise in [0u32, 1, tol / 2, tol - 1] {
            let noisy = encoded.wrapping_add(noise);
            let decoded: u32 = codec.decode_value(noisy);
            assert_eq!(
                decoded, m,
                "decode failed: m={}, noise=+{} (tol={})",
                m, noise, tol
            );

            if noise > 0 {
                let noisy_sub = encoded.wrapping_sub(noise);
                let decoded_sub: u32 = codec.decode_value(noisy_sub);
                assert_eq!(
                    decoded_sub, m,
                    "decode failed: m={}, noise=-{} (tol={})",
                    m, noise, tol
                );
            }
        }
    }
}

#[test]
fn decode_noise_exceeds_tolerance() {
    // When noise exceeds tolerance, decoding may wrap to a different message.
    // We verify that tolerance+1 noise can (but doesn't always) cause errors.
    let t = 8u32;
    let codec = PlaintextCodec::new(t, None);
    let tol = noise_tolerance(t);

    // For message 0 and message t-1, noise just over tolerance should push
    // the value across the decoding boundary.
    {
        let m = 0u32;
        let encoded = codec.encode_value(m, PlaintextEmbedding::Unsigned);
        let noisy = encoded.wrapping_add(tol + 1);
        let decoded: u32 = codec.decode_value(noisy);
        // With noise > tol, the result may not be m anymore
        // (It will be m+1 if the noise pushes past the rounding threshold)
        assert!(
            decoded != m,
            "expected decode to fail with noise > tolerance, but got m={}",
            decoded
        );
    }

    {
        let m = t - 1;
        let encoded = codec.encode_value(m, PlaintextEmbedding::Unsigned);
        let noisy = encoded.wrapping_sub(tol + 1);
        let decoded: u32 = codec.decode_value(noisy);
        assert!(
            decoded != m,
            "expected decode to fail with noise > tolerance, but got m={}",
            decoded
        );
    }
}
