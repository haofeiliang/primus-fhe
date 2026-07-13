use primus_fhe_core::{PlaintextCodec, PlaintextCodecKind, PlaintextEmbedding};
use primus_integer::FheUint;

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

#[test]
fn scaled_narrow_roundtrip_near_product_limit() {
    let t = 12_289u64;
    let q = u64::MAX / t;
    assert!(q.checked_mul(t).is_some());
    assert!(q.checked_add(1).unwrap().checked_mul(t).is_none());

    let narrow = PlaintextCodec::new(t, Some(q));
    assert_eq!(narrow.kind(), PlaintextCodecKind::ExplicitScaledNarrow);
    assert_codec_roundtrip(narrow, t);
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
        $scaled_t:expr,
        $narrow_q:expr,
        $wide_q:expr,
        $pow2_q_log:expr,
        $pow2_t_log:expr
    ) => {
        #[test]
        fn $native_pow2() {
            let t = $native_pow2_t as $ty;
            let codec = PlaintextCodec::new(t, None);
            assert_codec_roundtrip(codec, t);
        }

        #[test]
        fn $native_scaled() {
            let t = $scaled_t as $ty;
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
            let t = $scaled_t as $ty;
            let q = $narrow_q as $ty;
            assert!(q.checked_mul(t).is_some());
            let codec = PlaintextCodec::new(t, Some(q));
            assert_eq!(codec.kind(), PlaintextCodecKind::ExplicitScaledNarrow);
            assert_codec_roundtrip(codec, t);
        }

        #[test]
        fn $explicit_scaled_wide() {
            let t = $scaled_t as $ty;
            let q = $wide_q as $ty;
            assert!(q.checked_mul(t).is_none());
            let codec = PlaintextCodec::new(t, Some(q));
            assert_eq!(codec.kind(), PlaintextCodecKind::ExplicitScaledWide);
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
    7,
    4093,
    65521,
    15,
    8
);

plain_codec_tests!(
    u32,
    u32_native_pow2_encode_decode,
    u32_native_scaled_encode_decode,
    u32_explicit_pow2_encode_decode,
    u32_explicit_scaled_narrow_encode_decode,
    u32_explicit_scaled_wide_encode_decode,
    256,
    251,
    16_777_213,
    4_294_967_291,
    31,
    8
);

plain_codec_tests!(
    u64,
    u64_native_pow2_encode_decode,
    u64_native_scaled_encode_decode,
    u64_explicit_pow2_encode_decode,
    u64_explicit_scaled_narrow_encode_decode,
    u64_explicit_scaled_wide_encode_decode,
    256,
    251,
    u64::MAX / 251,
    u64::MAX - 58,
    63,
    8
);
