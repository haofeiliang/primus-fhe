use primus_fhe_core::{
    GlweSecretKey, GlweSecretKeyError, LweSecretKey, LweSecretKeyType, RingSecretKeyType,
};
use primus_lattice::{glwe::Glwe, lwe::Lwe};
use primus_modulus::BarrettModulus;

fn padded_error(result: Result<GlweSecretKey<u32>, GlweSecretKeyError>) -> GlweSecretKeyError {
    match result {
        Ok(_) => panic!("expected padded GLWE secret-key construction to fail"),
        Err(error) => error,
    }
}

#[test]
fn derives_the_smallest_glwe_layout_and_zero_pads_the_tail() {
    for (lwe_dimension, poly_length, expected_glwe_dimension) in [
        (3usize, 8usize, 1usize), // n < N
        (8, 8, 1),                // n = N
        (9, 8, 2),                // N < n < 2N
        (13, 8, 2),               // n does not divide N
        (16, 8, 2),               // n = 2N
    ] {
        let values: Vec<u32> = (0..lwe_dimension as u32).collect();
        let lwe = LweSecretKey::new(values.clone(), LweSecretKeyType::Binary);
        let glwe = GlweSecretKey::from_padded_lwe(&lwe, poly_length).unwrap();

        assert_eq!(glwe.dimension(), expected_glwe_dimension);
        assert_eq!(glwe.poly_length(), poly_length);
        assert_eq!(
            glwe.as_slice().len(),
            lwe_dimension.next_multiple_of(poly_length)
        );
        assert_eq!(glwe.distr(), RingSecretKeyType::Binary);
        assert_eq!(&glwe.as_slice()[..lwe_dimension], values);
        assert!(glwe.as_slice()[lwe_dimension..].iter().all(|&x| x == 0));
    }
}

#[test]
fn preserves_ternary_coefficients_and_maps_distribution() {
    let values = vec![0u32, 1, u32::MAX, 0, u32::MAX];
    let lwe = LweSecretKey::new(values.clone(), LweSecretKeyType::Ternary);
    let glwe = GlweSecretKey::from_padded_lwe(&lwe, 8).unwrap();

    assert_eq!(glwe.distr(), RingSecretKeyType::Ternary);
    assert_eq!(&glwe.as_slice()[..values.len()], values);
    assert_eq!(&glwe.as_slice()[values.len()..], &[0, 0, 0]);
}

#[test]
fn natural_secret_order_matches_the_current_sample_extraction_layout() {
    const MODULUS: u32 = 132_120_577;
    const POLY_LENGTH: usize = 8;

    let modulus = BarrettModulus::new(MODULUS);
    let lwe_values = vec![
        1,
        0,
        MODULUS - 1,
        1,
        1,
        0,
        MODULUS - 1,
        0,
        1,
        1,
        0,
        MODULUS - 1,
        1,
    ];
    let lwe_secret_key = LweSecretKey::new(lwe_values, LweSecretKeyType::Ternary);
    let glwe_secret_key = GlweSecretKey::from_padded_lwe(&lwe_secret_key, POLY_LENGTH).unwrap();

    let glwe_values: Vec<u32> = (0..(glwe_secret_key.dimension() + 1) * POLY_LENGTH)
        .map(|index| (index as u32 * 1_234_567 + 89) % MODULUS)
        .collect();
    let glwe = Glwe::new(glwe_values);
    let mut extracted: Lwe<Vec<u32>> = Lwe::zero(glwe_secret_key.as_slice().len());
    glwe.extract_lwe_to(&mut extracted, POLY_LENGTH, modulus);

    let q = u64::from(MODULUS);
    let dot = extracted
        .a()
        .iter()
        .zip(glwe_secret_key.as_slice())
        .fold(0u64, |sum, (&a, &s)| {
            (sum + u64::from(a) * u64::from(s)) % q
        });
    let extracted_phase = (u64::from(extracted.b()) + q - dot) % q;

    let glwe_mid = glwe_secret_key.dimension() * POLY_LENGTH;
    let mut product_constant = 0u64;
    for (mask, secret) in glwe.as_ref()[..glwe_mid]
        .chunks_exact(POLY_LENGTH)
        .zip(glwe_secret_key.as_slice().chunks_exact(POLY_LENGTH))
    {
        product_constant = (product_constant + u64::from(mask[0]) * u64::from(secret[0])) % q;
        for index in 1..POLY_LENGTH {
            let product = u64::from(mask[index]) * u64::from(secret[POLY_LENGTH - index]) % q;
            product_constant = (product_constant + q - product) % q;
        }
    }
    let glwe_phase = (u64::from(glwe.as_ref()[glwe_mid]) + q - product_constant) % q;

    assert_eq!(extracted_phase, glwe_phase);
}

#[test]
fn rejects_invalid_source_and_polynomial_length() {
    let empty = LweSecretKey::new(Vec::<u32>::new(), LweSecretKeyType::Binary);
    let lwe = LweSecretKey::new(vec![1u32; 1], LweSecretKeyType::Binary);

    assert_eq!(
        padded_error(GlweSecretKey::from_padded_lwe(&empty, 8)),
        GlweSecretKeyError::ZeroLweDimension
    );
    assert_eq!(
        padded_error(GlweSecretKey::from_padded_lwe(&lwe, 6)),
        GlweSecretKeyError::InvalidPolynomialLength { poly_length: 6 }
    );
}
