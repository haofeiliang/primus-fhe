use primus_fft::{FftEngine, FftTable, RustFftTable};
use primus_glwe::{
    FourierGadgetEncryptContext, FourierGlweDecryptContext, FourierGlweEncryptContext,
    FourierGlweSecretKey, GlevParameters, GlweParameters, SecretKeyDistr,
};
use primus_lattice::{
    glwe::{FourierGlweOwned, TorusGlwe},
    lwe::Lwe,
};
use primus_lwe::{LweParameters, LweSecretKey};
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;
use primus_tfhe_glwe_fourier::{FourierBlindRotationContext, FourierFunctionalBootstrappingKey};

const LWE_DIMENSION: usize = 4;
const GLWE_DIMENSION: usize = 1;
const POLY_LENGTH: usize = 256;
const PLAINTEXT_MODULUS: u32 = 16;
const TWO_N: usize = 2 * POLY_LENGTH;

fn accumulator_message() -> Vec<u32> {
    (0..POLY_LENGTH)
        .map(|index| (3 * index as u32 + 1) % PLAINTEXT_MODULUS)
        .collect()
}

fn rotate_plaintext(input: &[u32], exponent: usize) -> Vec<u32> {
    let shift = exponent & (POLY_LENGTH - 1);
    let negate_rotation = exponent >= POLY_LENGTH;
    (0..POLY_LENGTH)
        .map(|destination| {
            let wraps = destination < shift;
            let source = destination.wrapping_sub(shift) & (POLY_LENGTH - 1);
            let value = input[source];
            if wraps ^ negate_rotation {
                (PLAINTEXT_MODULUS - value) % PLAINTEXT_MODULUS
            } else {
                value
            }
        })
        .collect()
}

#[test]
fn functional_bootstrapping_key_blind_rotates() {
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    let mut rng = rand::rng();
    let lwe_params = LweParameters::new(
        LWE_DIMENSION,
        PLAINTEXT_MODULUS,
        NativeModulus::new(),
        SecretKeyDistr::Binary,
        0.7,
    );
    let glwe_params = GlweParameters::new(
        GLWE_DIMENSION,
        POLY_LENGTH,
        PLAINTEXT_MODULUS,
        NativeModulus::new(),
        SecretKeyDistr::Binary,
        0.7,
    );
    let ggsw_params = GlevParameters::with_glwe_params(&glwe_params, 8, None);
    let input_secret_key = LweSecretKey::new(vec![1u32, 0, 1, 1], SecretKeyDistr::Binary);
    let output_secret_key = FourierGlweSecretKey::generate(&glwe_params, &mut fft, &mut rng);
    let mut gadget_context = FourierGadgetEncryptContext::new(ggsw_params.size());
    let key = FourierFunctionalBootstrappingKey::generate_fourier(
        &input_secret_key,
        &lwe_params,
        &output_secret_key,
        &ggsw_params,
        &mut fft,
        &mut rng,
        &mut gadget_context,
    );

    let switched_a = [3usize, 0, 7, 11];
    let switched_b = 23usize;
    let shift = u32::BITS - TWO_N.trailing_zeros();
    let mut lwe_data: Vec<u32> = switched_a
        .iter()
        .map(|&value| (value as u32) << shift)
        .collect();
    lwe_data.push((switched_b as u32) << shift);
    let input = Lwe::new(lwe_data);

    let message = accumulator_message();
    let mut accumulator_fourier = FourierGlweOwned::zero(ggsw_params.fourier_glwe_len());
    let mut encrypt_context = FourierGlweEncryptContext::new(POLY_LENGTH);
    output_secret_key.encrypt_to(
        &Polynomial::new(message.as_slice()),
        &mut accumulator_fourier,
        &glwe_params,
        &mut fft,
        &mut rng,
        &mut encrypt_context,
    );
    let mut accumulator: TorusGlwe<Vec<u32>> = TorusGlwe::zero(ggsw_params.glwe_len());
    accumulator_fourier.write_torus_form(&mut accumulator, &mut fft);

    let mut output: TorusGlwe<Vec<u32>> = TorusGlwe::zero(ggsw_params.glwe_len());
    let mut blind_rotation_context = FourierBlindRotationContext::new(ggsw_params.size());
    key.fourier_blind_rotate_to(
        &input,
        &accumulator,
        &mut output,
        &ggsw_params,
        &mut fft,
        &mut blind_rotation_context,
    );

    let expected_exponent = (TWO_N + 3 + 7 + 11 - switched_b) & (TWO_N - 1);
    let mut output_fourier = FourierGlweOwned::zero(ggsw_params.fourier_glwe_len());
    output.write_fourier_form(&mut output_fourier, &mut fft);
    let mut decrypt_context = FourierGlweDecryptContext::new(POLY_LENGTH);
    assert_eq!(
        output_secret_key
            .decrypt(
                &output_fourier,
                &glwe_params,
                &mut fft,
                &mut decrypt_context,
            )
            .as_ref(),
        rotate_plaintext(&message, expected_exponent)
    );

    let exponent_input = Lwe::new(vec![3u32, 0, 7, 11, 23]);
    key.fourier_blind_rotate_exponents_to(
        &exponent_input,
        &accumulator,
        &mut output,
        &ggsw_params,
        &mut fft,
        &mut blind_rotation_context,
    );
    output.write_fourier_form(&mut output_fourier, &mut fft);
    assert_eq!(
        output_secret_key
            .decrypt(
                &output_fourier,
                &glwe_params,
                &mut fft,
                &mut decrypt_context,
            )
            .as_ref(),
        rotate_plaintext(&message, expected_exponent)
    );
}
