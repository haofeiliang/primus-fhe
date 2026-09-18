use primus_encoding::PlaintextEmbedding;
use primus_glwe::{
    GlweCiphertext, GlweParameters, NttGlweCiphertext, NttGlweSecretKey, SecretKeyDistr,
};
use primus_integer::FheUint;
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, PrimitiveRoot, UintNttTable};
use primus_poly::{Polynomial, PolynomialOwned};
use primus_reduce::ReduceAdd;
use rand::{Rng, SeedableRng, rngs::StdRng};
use zeroize::Zeroizing;

const DIMENSION: usize = 2;
const POLY_LENGTH: usize = 256;
const PLAIN_MODULUS: usize = 16;

fn assert_roundtrip<T>(cipher_modulus: T)
where
    T: FheUint + PrimitiveRoot,
{
    let modulus = BarrettModulus::new(cipher_modulus);
    let ntt = UintNttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let messages: Vec<T> = (0..POLY_LENGTH)
        .map(|index| T::try_from(index % PLAIN_MODULUS).unwrap())
        .collect();
    let message = Polynomial::new(messages.clone());

    for secret_key_distr in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::SparseTernary,
        SecretKeyDistr::gaussian(3.2),
        // A weight greater than N must be sampled over all k*N coefficients.
        SecretKeyDistr::fixed_hamming_weight_ternary(DIMENSION * POLY_LENGTH, POLY_LENGTH + 7),
    ] {
        let params = GlweParameters::new(
            DIMENSION,
            POLY_LENGTH,
            T::try_from(PLAIN_MODULUS).unwrap(),
            modulus,
            secret_key_distr,
            0.7,
        );
        let (_, secret_key) = NttGlweSecretKey::generate_pair(&params, &ntt, &mut rng);
        let mut cipher = NttGlweCiphertext::<Vec<T>>::zero(params.glwe_len());
        let mut coefficients = GlweCiphertext::<Vec<T>>::zero(params.glwe_len());
        let mut expected_coefficients = GlweCiphertext::<Vec<T>>::zero(params.glwe_len());
        let mut phase = PolynomialOwned::zero(POLY_LENGTH);
        let mut expected_phase = PolynomialOwned::zero(POLY_LENGTH);
        let mut scratch = Zeroizing::new(vec![T::MAX; POLY_LENGTH]);
        let mut direct_rng = StdRng::seed_from_u64(17);
        let mut reference_rng = StdRng::seed_from_u64(17);
        // Exact ciphertext/phase equality also checks noise and mask sampling order.
        // Reuse dirty output and scratch for a zero message after a nonzero one.
        for input in [&message, &PolynomialOwned::zero(POLY_LENGTH)] {
            secret_key.encrypt_to(input, &mut cipher, &params, &ntt, &mut reference_rng);
            cipher.write_coeff_form(&mut expected_coefficients, &ntt);
            secret_key.encrypt_coeff_to(
                input,
                &mut coefficients,
                &params,
                &ntt,
                &mut direct_rng,
                &mut scratch,
            );
            assert_eq!(coefficients.as_ref(), expected_coefficients.as_ref());
            secret_key.phase_to(&cipher, &mut expected_phase, modulus, &ntt);
            secret_key.phase_coeff_to(&coefficients, &mut phase, modulus, &ntt, &mut scratch);
            assert_eq!(phase.as_ref(), expected_phase.as_ref());
            secret_key.decrypt_coeff_to(&coefficients, &mut phase, &params, &ntt, &mut scratch);
            assert_eq!(phase.as_ref(), input.as_ref());
        }
        assert_eq!(direct_rng.next_u64(), reference_rng.next_u64());

        secret_key.encrypt_centered_to(&message, &mut cipher, &params, &ntt, &mut rng);
        assert_eq!(
            secret_key.decrypt(&cipher, &params, &ntt).as_ref(),
            messages
        );

        secret_key.encrypt_zeros_to(&mut cipher, &params, &ntt, &mut rng);
        assert_eq!(
            secret_key.decrypt(&cipher, &params, &ntt).as_ref(),
            vec![T::ZERO; POLY_LENGTH]
        );

        let mut encoded = vec![T::ZERO; POLY_LENGTH];
        params.plaintext_codec().add_encode_slice_assign(
            &mut encoded,
            &messages,
            PlaintextEmbedding::Unsigned,
        );
        secret_key.encrypt_encoded_to(
            &Polynomial::new(encoded),
            &mut cipher,
            &params,
            &ntt,
            &mut rng,
        );

        let mut reused_output = PolynomialOwned::new(vec![T::MAX; POLY_LENGTH]);
        secret_key.decrypt_to(&cipher, &mut reused_output, &params, &ntt);
        assert_eq!(reused_output.as_ref(), messages);
    }
}

#[test]
fn ntt_glwe_secret_key_roundtrip_u32() {
    assert_roundtrip(132_120_577u32);
}

#[test]
fn ntt_glwe_secret_key_roundtrip_u64() {
    assert_roundtrip(1_125_899_906_826_241u64);
}

#[test]
fn noise_diagnostics_report_signed_phase_distance() {
    let modulus = BarrettModulus::new(1_125_899_906_826_241u64);
    let params = GlweParameters::new(
        DIMENSION,
        POLY_LENGTH,
        PLAIN_MODULUS as u64,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let table = UintNttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let secret_key = NttGlweSecretKey::new(
        vec![0; params.secret_key_len()],
        params.size(),
        SecretKeyDistr::UniformBinary,
    );
    let message: Vec<u64> = (0..POLY_LENGTH)
        .map(|i| (i % PLAIN_MODULUS) as u64)
        .collect();
    let expected_noise: Vec<u64> = (0..POLY_LENGTH).map(|i| [0, 3, 5][i % 3]).collect();
    let mut ciphertext = NttGlweCiphertext::<Vec<u64>>::zero(params.glwe_len());
    for embedding in [PlaintextEmbedding::Unsigned, PlaintextEmbedding::Centered] {
        // A zero mask lets us specify exact positive/negative phase errors.
        let (_, body) = ciphertext.a_b_mut_slices(POLY_LENGTH);
        params
            .plaintext_codec()
            .encode_slice_to(&message, body, embedding);
        for (index, value) in body.iter_mut().enumerate() {
            let error = [0, 3, 1_125_899_906_826_241 - 5][index % 3];
            *value = modulus.reduce_add(*value, error);
        }
        table.transform_slice(body);
        let (decoded, noise) =
            secret_key.decrypt_with_noise_and_embedding(&ciphertext, &params, &table, embedding);
        assert_eq!(decoded.as_ref(), message);
        assert_eq!(noise.as_ref(), expected_noise);
    }
}

#[test]
fn truncated_decryption_returns_only_retained_coefficients() {
    let modulus = BarrettModulus::new(1_125_899_906_826_241u64);
    let params = GlweParameters::new(
        DIMENSION,
        POLY_LENGTH,
        PLAIN_MODULUS as u64,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let table = UintNttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let (_, secret_key) = NttGlweSecretKey::generate_pair(&params, &table, &mut rng);
    for count in [0, 32, POLY_LENGTH] {
        let mut ciphertext = secret_key.encrypt_truncated_zeros(count, &params, &table, &mut rng);
        let message: Vec<_> = (0..count)
            .map(|i| ((3 * i + 1) % PLAIN_MODULUS) as u64)
            .collect();
        // A nonzero prefix checks coefficient contents/order as well as truncation.
        params.plaintext_codec().add_encode_slice_assign(
            &mut ciphertext.as_mut()[params.size().mask_len()..],
            &message,
            PlaintextEmbedding::Unsigned,
        );
        assert_eq!(
            secret_key.decrypt_truncated(&ciphertext, &params, &table),
            message
        );
    }
}
