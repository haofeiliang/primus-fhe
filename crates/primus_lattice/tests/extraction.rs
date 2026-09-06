//! Sample order and phase signs, compact padding, and packed allocation reuse.

use primus_lattice::{
    GlweSize,
    glwe::{Glwe, TruncatedGlwe},
    lwe::{Lwe, MultiMsgLwe},
    ntru::Ntru,
    rlwe::Rlwe,
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
        vec![
            1,
            4u32.wrapping_neg(),
            3u32.wrapping_neg(),
            2u32.wrapping_neg(),
            5,
            8u32.wrapping_neg(),
            7u32.wrapping_neg(),
            6u32.wrapping_neg(),
            9,
        ],
        vec![
            2,
            1,
            4u32.wrapping_neg(),
            3u32.wrapping_neg(),
            6,
            5,
            8u32.wrapping_neg(),
            7u32.wrapping_neg(),
            10,
        ],
        vec![
            3,
            2,
            1,
            4u32.wrapping_neg(),
            7,
            6,
            5,
            8u32.wrapping_neg(),
            11,
        ],
        vec![4, 3, 2, 1, 8, 7, 6, 5, 12],
    ];

    for (index, expected) in expected.iter().enumerate() {
        let mut full: Lwe<Vec<u32>> = Lwe::zero(8);
        glwe.extract_lwe_at_to(index, &mut full, 4, modulus);
        assert_eq!(full.0.as_slice(), expected);
        if index == 0 {
            glwe.extract_lwe_to(&mut full, 4, modulus);
            assert_eq!(full.as_ref(), expected);
        }

        for active_key_len in [1, 3, 4, 5, 7, 8] {
            let mut compact: Lwe<Vec<u32>> = Lwe::zero(active_key_len);
            glwe.extract_compact_lwe_at_to(index, &mut compact, 4, modulus);

            assert_eq!(compact.a(), &expected[..active_key_len]);
            assert_eq!(compact.b(), expected[8]);
            if index == 0 {
                glwe.extract_compact_lwe_to(&mut compact, 4, modulus);
                assert_eq!(compact.a(), &expected[..active_key_len]);
                assert_eq!(compact.b(), expected[8]);
            }
        }
    }
}

#[test]
fn inverse_extraction_is_the_exact_inverse_of_sample_extraction() {
    let lwe = Lwe(vec![1u32, 2, 3, 4, 5, 6, 7, 8, 9]);
    let mut glwe = Glwe(vec![u32::MAX; 12]);

    lwe.inverse_extract_glwe_to(&mut glwe, 4, NativeModulus::new());

    assert_eq!(
        glwe.0,
        vec![
            1,
            4u32.wrapping_neg(),
            3u32.wrapping_neg(),
            2u32.wrapping_neg(),
            5,
            8u32.wrapping_neg(),
            7u32.wrapping_neg(),
            6u32.wrapping_neg(),
            9,
            0,
            0,
            0,
        ]
    );

    let mut extracted = Lwe::zero(8);
    glwe.extract_lwe_to(&mut extracted, 4, NativeModulus::new());
    assert_eq!(extracted, lwe);
}

#[test]
fn inverse_extraction_round_trips_with_an_explicit_modulus() {
    let modulus = BarrettModulus::new(257u32);
    let lwe = Lwe(vec![1u32, 2, 128, 256, 5, 17, 42]);
    let mut glwe: Glwe<Vec<u32>> = Glwe::zero(12);

    lwe.inverse_extract_glwe_to(&mut glwe, 4, modulus);

    assert_eq!(glwe.0, vec![1, 1, 129, 255, 5, 0, 0, 240, 42, 0, 0, 0]);

    let mut extracted = Lwe::zero(6);
    glwe.extract_compact_lwe_to(&mut extracted, 4, modulus);
    assert_eq!(extracted, lwe);
}

#[test]
fn indexed_extraction_preserves_ntru_and_rlwe_phases() {
    const Q: u32 = 97;
    let modulus = BarrettModulus::new(Q);
    let ntru = Ntru::new(vec![13u32, 21, 34, 55, 8, 19, 27, 41]);
    let n = ntru.as_ref().len();
    let body: Vec<u32> = (0..n).map(|i| (i * 3 + 7) as u32).collect();
    let rlwe = Rlwe::new([ntru.as_ref(), &body].concat());
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
            assert_eq!(
                modulus.reduce_sub(full.b(), modulus.reduce_dot_product(full.a(), &secret)),
                phase[index]
            );
            assert_eq!(
                modulus.reduce_sub(
                    compact.b(),
                    modulus.reduce_dot_product(compact.a(), &secret[..active])
                ),
                phase[index]
            );
            if index == 0 {
                ntru.extract_lwe_to(&mut full, modulus);
                ntru.extract_compact_lwe_to(&mut compact, modulus);
                assert_eq!(compact.a(), &full.a()[..active]);
            }
            rlwe.extract_lwe_at_to(index, &mut full, modulus);
            assert_eq!(rlwe.extract_lwe_at(index, modulus), full);
            rlwe.extract_compact_lwe_at_to(index, &mut compact, modulus);
            let expected = (body[index] + Q - phase[index]) % Q;
            assert_eq!(
                modulus.reduce_sub(full.b(), modulus.reduce_dot_product(full.a(), &secret)),
                expected
            );
            assert_eq!(
                modulus.reduce_sub(
                    compact.b(),
                    modulus.reduce_dot_product(compact.a(), &secret[..active])
                ),
                expected
            );
            if index == 0 {
                rlwe.extract_lwe_to(&mut full, modulus);
                rlwe.extract_compact_lwe_to(&mut compact, modulus);
                assert_eq!(compact.a(), &full.a()[..active]);
                assert_eq!(compact.b(), full.b());
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
        if count > 0 {
            let all = borrowed.extract_all(count, modulus);
            assert_eq!(all.len(), count);
            for (index, sample) in all.iter().enumerate() {
                assert_eq!(*sample, ciphertext.extract_lwe_at(index, modulus));
            }
        }
        for index in 0..count {
            assert_eq!(
                borrowed.extract_lwe_at(index, 4, modulus),
                ciphertext.extract_lwe_at(index, modulus)
            );
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
