//! Sample order and phase signs, compact padding, and packed allocation reuse.

use primus_lattice::{
    GlweSize,
    glwe::{Glwe, TruncatedGlwe},
    lwe::{Lwe, MultiMsgLwe},
    ntru::Ntru,
};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_reduce::{ReduceDotProduct, ReduceSub};

#[test]
fn indexed_extraction_matches_negacyclic_rotation_and_compact_prefix() {
    let glwe = Glwe(vec![
        1u32, 2, 3, 4, // first mask
        5, 6, 7, 8, // second mask
        9, 10, 11, 12, // body
    ]);
    let modulus = NativeModulus::new();
    let expected = [
        [1i32, -4, -3, -2, 5, -8, -7, -6, 9],
        [2, 1, -4, -3, 6, 5, -8, -7, 10],
        [3, 2, 1, -4, 7, 6, 5, -8, 11],
        [4, 3, 2, 1, 8, 7, 6, 5, 12],
    ]
    .map(|sample| sample.map(|x| x as u32));

    for (index, expected) in expected.iter().enumerate() {
        let mut full: Lwe<Vec<u32>> = Lwe::zero(8);
        glwe.extract_lwe_at_to(index, &mut full, 4, modulus);
        assert_eq!(full.0.as_slice(), expected);

        for active_key_len in [1, 3, 4, 5, 7, 8] {
            let mut compact: Lwe<Vec<u32>> = Lwe::zero(active_key_len);
            glwe.extract_compact_lwe_at_to(index, &mut compact, 4, modulus);

            assert_eq!(compact.a(), &expected[..active_key_len]);
            assert_eq!(compact.b(), expected[8]);
        }
    }
}

#[test]
fn inverse_extraction_is_the_exact_inverse_of_sample_extraction() {
    let lwe = Lwe(vec![1u32, 2, 3, 4, 5, 6, 7, 8, 9]);
    let mut glwe = Glwe(vec![u32::MAX; 12]);

    lwe.inverse_extract_glwe_to(&mut glwe, 4, NativeModulus::new());

    assert_eq!(
        glwe.as_ref(),
        [1i32, -4, -3, -2, 5, -8, -7, -6, 9, 0, 0, 0].map(|x| x as u32)
    );

    let mut extracted = Lwe::zero(8);
    glwe.extract_lwe_to(&mut extracted, 4, NativeModulus::new());
    assert_eq!(extracted, lwe);
}

#[test]
fn inverse_extraction_round_trips_with_an_explicit_modulus() {
    let modulus = BarrettModulus::new(257u32);
    let lwe = Lwe(vec![1u32, 2, 128, 256, 5, 17, 42]);
    let mut glwe = Glwe::new(vec![u32::MAX; 12]);

    lwe.inverse_extract_glwe_to(&mut glwe, 4, modulus);

    assert_eq!(glwe.0, vec![1, 1, 129, 255, 5, 0, 0, 240, 42, 0, 0, 0]);

    let mut extracted = Lwe::zero(6);
    glwe.extract_compact_lwe_to(&mut extracted, 4, modulus);
    assert_eq!(extracted, lwe);
}

#[test]
fn indexed_extraction_preserves_ntru_and_dimension_one_glwe_phases() {
    const Q: u32 = 97;
    let modulus = BarrettModulus::new(Q);
    let ntru = Ntru::new(vec![13u32, 21, 34, 55, 8, 19, 27, 41]);
    let n = ntru.as_ref().len();
    let body: Vec<u32> = (0..n).map(|i| (i * 3 + 7) as u32).collect();
    let glwe = Glwe::new([ntru.as_ref(), &body].concat());
    // Active lengths exercise both sides of the indexed extraction split.
    for active in [1, 3, 5, n] {
        let secret: Vec<u32> = (0..n)
            .map(|i| if i < active { (i % 3 + 1) as u32 } else { 0 })
            .collect();
        let mut phase = vec![0i64; n];
        for (i, &a) in ntru.as_ref().iter().enumerate() {
            for (j, &b) in secret.iter().enumerate() {
                phase[(i + j) % n] += if i + j < n {
                    i64::from(a * b)
                } else {
                    -i64::from(a * b)
                };
            }
        }
        let phase: Vec<u32> = phase
            .into_iter()
            .map(|v| v.rem_euclid(i64::from(Q)) as u32)
            .collect();
        let mut full: Lwe<Vec<u32>> = Lwe::zero(n);
        let mut compact: Lwe<Vec<u32>> = Lwe::zero(active);
        for index in 0..n {
            ntru.extract_lwe_at_to(index, &mut full, modulus);
            ntru.extract_compact_lwe_at_to(index, &mut compact, modulus);
            for sample in [&full, &compact] {
                assert_eq!(
                    modulus.reduce_sub(
                        sample.b(),
                        modulus.reduce_dot_product(sample.a(), &secret[..sample.dimension()])
                    ),
                    phase[index]
                );
            }
            glwe.extract_lwe_at_to(index, &mut full, n, modulus);
            glwe.extract_compact_lwe_at_to(index, &mut compact, n, modulus);
            let expected = (body[index] + Q - phase[index]) % Q;
            for sample in [&full, &compact] {
                assert_eq!(
                    modulus.reduce_sub(
                        sample.b(),
                        modulus.reduce_dot_product(sample.a(), &secret[..sample.dimension()])
                    ),
                    expected
                );
            }
        }
    }
}

#[test]
#[should_panic(expected = "packed multi-message LWE extraction requires GLWE dimension 1")]
fn packed_extraction_rejects_multiple_glwe_masks() {
    let ciphertext = TruncatedGlwe::new(vec![1u32, 2, 3, 4, 5, 6, 7, 8, 10, 20]);
    let _ = ciphertext.into_multi_msg_lwe(2, GlweSize::new(2, 4), NativeModulus::new());
}

#[test]
fn packed_and_consuming_extraction_match_individual_samples() {
    let modulus = BarrettModulus::new(97u32);
    let ciphertext = Glwe(vec![1u32, 2, 3, 4, 11, 12, 13, 14]);
    let size = GlweSize::new(1, 4);
    let mut sample = Lwe::zero(size.mask_len());
    ciphertext.extract_lwe_to(&mut sample, size.poly_length(), modulus);
    let truncated = TruncatedGlwe(ciphertext.as_ref()[..6].to_vec());
    assert_eq!(truncated.clone().into_lwe(size, modulus), sample);

    for count in [0, 1, 2, 4] {
        let owned = TruncatedGlwe(ciphertext.as_ref().to_vec());
        let allocation = owned.as_ref().as_ptr();
        let packed = owned.into_multi_msg_lwe(count, size, modulus);
        assert_eq!(packed.as_ref().as_ptr(), allocation);
        assert_eq!(packed.as_ref().len(), size.mask_len() + count);
        assert_eq!(&packed.as_ref()[..4], &[1, 93, 94, 95]);
        if count <= 2 {
            assert_eq!(
                truncated.clone().into_multi_msg_lwe(count, size, modulus),
                packed
            );
        }
        let borrowed = MultiMsgLwe(packed.as_ref());
        if count > 0 {
            let all = borrowed.extract_all(count, modulus);
            assert_eq!(all.len(), count);
            for (index, extracted) in all.iter().enumerate() {
                ciphertext.extract_lwe_at_to(index, &mut sample, size.poly_length(), modulus);
                assert_eq!(*extracted, sample);
                assert_eq!(borrowed.extract_lwe_at(index, 4, modulus), sample);
            }
        }
    }
}

#[test]
fn packed_extraction_rejects_invalid_message_counts() {
    let packed = MultiMsgLwe(vec![1u32, 2, 3, 4]);
    for count in [0, 3] {
        assert!(
            std::panic::catch_unwind(|| packed.extract_all(count, NativeModulus::new())).is_err()
        );
    }
}
