use primus_factor::{FactorBase, ShoupFactor};
use primus_fhe_core::{PlaintextCodec, PlaintextEmbedding, RnsCoeffCodec};
use primus_integer::FheUint;
use primus_modulus::BarrettModulus;
use primus_poly::{CrtPolynomial, DcrtPolynomial, Polynomial};
use primus_rns::RNSBase;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};

fn message_values<T: FheUint>(t: T) -> Vec<T> {
    let len: usize = t.try_into().unwrap();
    (0..len).map(|value| T::try_from(value).unwrap()).collect()
}

fn assert_codec_roundtrip<T: FheUint>(codec: PlaintextCodec<T>, t: T) {
    let messages = message_values(t);

    for embedding in [PlaintextEmbedding::Unsigned, PlaintextEmbedding::Centered] {
        let mut encoded = vec![T::ZERO; messages.len()];
        codec.encode_slice_to(&messages, &mut encoded, embedding);

        for (&message, &encoded_value) in messages.iter().zip(&encoded) {
            assert_eq!(codec.encode_value(message, embedding), encoded_value);
            assert_eq!(codec.decode_value::<T>(encoded_value), message);
        }

        let mut decoded = vec![T::ZERO; messages.len()];
        codec.decode_slice_to(&encoded, &mut decoded);
        assert_eq!(decoded, messages);

        let mut inplace = messages.clone();
        codec.encode_slice_inplace(&mut inplace, embedding);
        assert_eq!(inplace, encoded);
        codec.decode_slice_inplace(&mut inplace);
        assert_eq!(inplace, messages);

        let mut accumulated = vec![T::ZERO; messages.len()];
        codec.add_encode_slice_assign(&mut accumulated, &messages, embedding);
        assert_eq!(accumulated, encoded);

        let mut delta_encoded = vec![T::ZERO; messages.len()];
        codec.add_encode_slice_assign_with_delta(&mut delta_encoded, &messages, embedding);

        for (&message, &encoded_value) in messages.iter().zip(&delta_encoded) {
            assert_eq!(
                codec.encode_value_with_delta(message, embedding),
                encoded_value
            );
            assert_eq!(codec.decode_value::<T>(encoded_value), message);
        }

        let mut delta_decoded = vec![T::ZERO; messages.len()];
        codec.decode_slice_to(&delta_encoded, &mut delta_decoded);
        assert_eq!(delta_decoded, messages);
    }
}

fn seeded_rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

fn random_non_power_of_two<T: FheUint>(rng: &mut StdRng, min: T, max: T) -> T {
    loop {
        let value = rng.random_range(min..=max);
        if !value.is_power_of_two() {
            return value;
        }
    }
}

fn random_scaled_narrow<T: FheUint>(rng: &mut StdRng, min_t: T, max_t: T) -> (T, T) {
    loop {
        let t = random_non_power_of_two(rng, min_t, max_t);
        let Some(min_q) = t
            .checked_mul(t)
            .and_then(|value| value.checked_mul(T::try_from(4usize).unwrap()))
        else {
            continue;
        };
        let max_q = T::MAX / t;
        if min_q > max_q {
            continue;
        }

        let q = random_non_power_of_two(rng, min_q, max_q);
        assert!(q.checked_mul(t).is_some());
        return (t, q);
    }
}

fn random_scaled_wide<T: FheUint>(rng: &mut StdRng, min_t: T, max_t: T) -> (T, T) {
    loop {
        let t = random_non_power_of_two(rng, min_t, max_t);
        let q = random_non_power_of_two(rng, T::MAX / T::TWO, T::MAX - T::ONE);
        if q.checked_mul(t).is_none() {
            return (t, q);
        }
    }
}

#[test]
fn scaled_narrow_matches_wide_scaled_near_product_limit() {
    let t = 12_289u64;
    let q = u64::MAX / t;
    assert!(q.checked_mul(t).is_some());
    assert!(q.checked_add(1).unwrap().checked_mul(t).is_none());

    let narrow = PlaintextCodec::new(t, Some(q));
    assert!(matches!(narrow, PlaintextCodec::ScaledNarrow { .. }));

    let mut delta = q / t;
    let rem = q % t;
    if rem > (t - 1) / 2 {
        delta += 1;
    }
    let wide = PlaintextCodec::Scaled {
        t,
        q,
        delta_factor: ShoupFactor::new(delta, q),
    };

    let messages: Vec<_> = (0..t).collect();
    for embedding in [PlaintextEmbedding::Unsigned, PlaintextEmbedding::Centered] {
        let mut narrow_encoded = vec![0u64; messages.len()];
        let mut wide_encoded = vec![0u64; messages.len()];
        narrow.encode_slice_to(&messages, &mut narrow_encoded, embedding);
        wide.encode_slice_to(&messages, &mut wide_encoded, embedding);
        assert_eq!(narrow_encoded, wide_encoded);

        let mut narrow_inplace = messages.clone();
        let mut wide_inplace = messages.clone();
        narrow.encode_slice_inplace(&mut narrow_inplace, embedding);
        wide.encode_slice_inplace(&mut wide_inplace, embedding);
        assert_eq!(narrow_inplace, wide_inplace);

        let mut narrow_acc = vec![q - 1; messages.len()];
        let mut wide_acc = vec![q - 1; messages.len()];
        narrow.add_encode_slice_assign(&mut narrow_acc, &messages, embedding);
        wide.add_encode_slice_assign(&mut wide_acc, &messages, embedding);
        assert_eq!(narrow_acc, wide_acc);
    }

    let mut values = vec![0, 1, q / 2, q - 1, q];
    let mut expected = values.clone();
    narrow.decode_slice_inplace(&mut values);
    wide.decode_slice_inplace(&mut expected);
    assert_eq!(values, expected);

    for value in [0, 1, q / 2, q - 1, q] {
        assert_eq!(
            narrow.decode_value::<u64>(value),
            wide.decode_value::<u64>(value)
        );
    }
}

#[test]
fn rns_coeff_codec_decodes_without_t_gamma_workspace() {
    type ValueT = u64;

    let moduli_value: [ValueT; 2] = [1125899906826241, 1125899906629633];
    let moduli = moduli_value.map(BarrettModulus::new);
    let base_q = RNSBase::new(&moduli).unwrap();
    let t = 12289;
    let gamma = 2305843009213554689;
    let codec = RnsCoeffCodec::new(BarrettModulus::new(t), base_q, BarrettModulus::new(gamma));
    let poly_length = 32;
    let rns_poly_len = codec.moduli_count() * poly_length;
    let input_values: Vec<ValueT> = (0..poly_length)
        .map(|i| ((i * i + 3 * i + 7) as ValueT) % t)
        .collect();
    let input = Polynomial::new(input_values.clone());
    let mut encoded: CrtPolynomial<Vec<ValueT>> = CrtPolynomial::zero(rns_poly_len);

    codec.centered_encode_coeffs(&input, &mut encoded, poly_length);

    let mut fused_q = DcrtPolynomial::new(encoded.into_owned());
    let mut fused_decoded: Polynomial<Vec<ValueT>> = Polynomial::zero(poly_length);
    let mut fused_fast_convert_buffer = vec![0; rns_poly_len];
    codec.decode_coeffs(
        &mut fused_q,
        &mut fused_decoded,
        poly_length,
        &mut fused_fast_convert_buffer,
    );
    assert_eq!(fused_decoded.as_ref(), input_values);
}

macro_rules! plain_codec_tests {
    (
        $ty:ty,
        $native_pow2:ident,
        $native_scaled:ident,
        $explicit_pow2:ident,
        $explicit_scaled_narrow:ident,
        $explicit_scaled_wide:ident,
        $native_pow2_t:expr,
        $random_min_t:expr,
        $random_max_t:expr,
        $pow2_q_log:expr,
        $pow2_t_log:expr,
        $seed:expr
    ) => {
        #[test]
        fn $native_pow2() {
            let t = $native_pow2_t as $ty;
            let codec = PlaintextCodec::new(t, None);
            assert_codec_roundtrip(codec, t);
        }

        #[test]
        fn $native_scaled() {
            let mut rng = seeded_rng($seed);
            let t = random_non_power_of_two(&mut rng, $random_min_t as $ty, $random_max_t as $ty);
            let codec = PlaintextCodec::new(t, None);
            assert_codec_roundtrip(codec, t);
        }

        #[test]
        fn $explicit_pow2() {
            let t = (1 as $ty) << $pow2_t_log;
            let q = (1 as $ty) << $pow2_q_log;
            let codec = PlaintextCodec::new(t, Some(q));
            assert_codec_roundtrip(codec, t);
        }

        #[test]
        fn $explicit_scaled_narrow() {
            let mut rng = seeded_rng($seed + 1);
            let (t, q) = random_scaled_narrow(&mut rng, $random_min_t as $ty, $random_max_t as $ty);
            let codec = PlaintextCodec::new(t, Some(q));
            assert!(matches!(codec, PlaintextCodec::ScaledNarrow { .. }));
            assert_codec_roundtrip(codec, t);
        }

        #[test]
        fn $explicit_scaled_wide() {
            let mut rng = seeded_rng($seed + 2);
            let (t, q) = random_scaled_wide(&mut rng, $random_min_t as $ty, $random_max_t as $ty);
            let codec = PlaintextCodec::new(t, Some(q));
            assert!(matches!(codec, PlaintextCodec::Scaled { .. }));
            assert_codec_roundtrip(codec, t);
        }
    };
}

plain_codec_tests!(
    u16,
    u16_native_pow2_encode_decode,
    u16_native_scaled_encode_decode,
    u16_explicit_pow2_encode_decode,
    u16_explicit_scaled_narrow_encode_decode,
    u16_explicit_scaled_wide_encode_decode,
    256,
    5,
    251,
    15,
    8,
    0x16
);

plain_codec_tests!(
    u32,
    u32_native_pow2_encode_decode,
    u32_native_scaled_encode_decode,
    u32_explicit_pow2_encode_decode,
    u32_explicit_scaled_narrow_encode_decode,
    u32_explicit_scaled_wide_encode_decode,
    256,
    5,
    251,
    31,
    8,
    0x32
);

plain_codec_tests!(
    u64,
    u64_native_pow2_encode_decode,
    u64_native_scaled_encode_decode,
    u64_explicit_pow2_encode_decode,
    u64_explicit_scaled_narrow_encode_decode,
    u64_explicit_scaled_wide_encode_decode,
    256,
    5,
    251,
    63,
    8,
    0x64
);
