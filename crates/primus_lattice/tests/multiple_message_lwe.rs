use primus_lattice::{GlweSize, glwe::TruncatedGlwe, lwe::MultiMsgLwe};
use primus_modulus::NativeModulus;

#[test]
#[should_panic(expected = "packed multi-message LWE extraction requires GLWE dimension 1")]
fn packed_extraction_rejects_multiple_glwe_masks() {
    let ciphertext = TruncatedGlwe::new(vec![1u32, 2, 3, 4, 5, 6, 7, 8, 10, 20]);
    ciphertext.into_multi_msg_lwe(2, GlweSize::new(2, 4), NativeModulus::new());
}

#[test]
fn extract_all_matches_individual_rlwe_extraction() {
    let modulus = NativeModulus::new();

    for (dimension, bodies) in [(4, vec![10u32]), (4, vec![10, 11, 12, 13])] {
        let msg_count = bodies.len();
        let mut data: Vec<u32> = (1..=dimension as u32).collect();
        data.extend(bodies);
        let multi_message = MultiMsgLwe(data);

        let extracted = multi_message.extract_all(msg_count, modulus);
        assert_eq!(extracted.len(), msg_count);
        for (index, lwe) in extracted.iter().enumerate() {
            assert_eq!(
                lwe,
                &multi_message.extract_lwe_at(index, dimension, modulus)
            );
        }
    }

    let invalid = MultiMsgLwe(vec![1u32, 2, 3, 4]);
    assert!(std::panic::catch_unwind(|| invalid.extract_all(0, modulus)).is_err());
    assert!(std::panic::catch_unwind(|| invalid.extract_all(3, modulus)).is_err());
}

#[test]
fn packed_and_consuming_extraction_match_individual_samples() {
    use primus_lattice::rlwe::Rlwe;
    use primus_modulus::BarrettModulus;

    let modulus = BarrettModulus::new(97u32);
    let ciphertext = Rlwe(vec![1u32, 2, 3, 4, 11, 12, 13, 14]);
    let size = GlweSize::new(1, 4);
    assert_eq!(
        ciphertext.clone().into_lwe(modulus),
        ciphertext.extract_lwe(modulus)
    );
    let truncated = TruncatedGlwe(ciphertext.as_ref()[..6].to_vec());
    assert_eq!(
        truncated.clone().into_lwe(size, modulus),
        ciphertext.extract_lwe(modulus)
    );

    for count in [0, 1, 2, 4] {
        let packed = ciphertext.extract_multi_msg_lwe(count, modulus);
        let owned = ciphertext.clone();
        let allocation = owned.as_ref().as_ptr();
        let consumed = owned.into_multi_msg_lwe(count, modulus);
        assert_eq!(consumed.as_ref().as_ptr(), allocation);
        assert_eq!(packed, consumed);
        if count <= 2 {
            assert_eq!(
                truncated.clone().into_multi_msg_lwe(count, size, modulus),
                packed
            );
        }
        let borrowed = MultiMsgLwe(packed.as_ref());
        for index in 0..count {
            assert_eq!(
                borrowed.extract_lwe_at(index, 4, modulus),
                ciphertext.extract_lwe_at(index, modulus)
            );
        }
    }
}
