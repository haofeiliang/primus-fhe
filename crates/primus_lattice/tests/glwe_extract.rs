use primus_modulus::{BarrettModulus, NativeModulus};

use primus_lattice::{glwe::Glwe, lwe::Lwe};

#[test]
fn extracts_all_glwe_mask_polynomials_into_one_lwe() {
    let glwe = Glwe(vec![
        1u32, 2, 3, 4, // first mask
        5, 6, 7, 8, // second mask
        9, 10, 11, 12, // body
    ]);
    let mut lwe: Lwe<Vec<u32>> = Lwe::zero(8);

    glwe.extract_lwe_to(&mut lwe, 4, NativeModulus::new());

    assert_eq!(
        lwe.0,
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
        ]
    );
}

#[test]
fn compact_extraction_matches_the_active_prefix_of_full_extraction() {
    let glwe = Glwe(vec![
        1u32, 2, 3, 4, // first mask
        5, 6, 7, 8, // second mask
        9, 10, 11, 12, // body
    ]);
    let modulus = NativeModulus::new();
    let mut full: Lwe<Vec<u32>> = Lwe::zero(8);
    glwe.extract_lwe_to(&mut full, 4, modulus);

    for active_key_len in [1, 4, 5, 7, 8] {
        let mut compact: Lwe<Vec<u32>> = Lwe::zero(active_key_len);
        glwe.extract_compact_lwe_to(&mut compact, 4, modulus);

        assert_eq!(compact.a(), &full.a()[..active_key_len]);
        assert_eq!(compact.b(), full.b());
    }
}

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
