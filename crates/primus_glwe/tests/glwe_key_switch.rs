use primus_fft::{FftEngine, FftTable, RustFftTable};
use primus_glwe::{
    FourierGadgetEncryptContext, FourierGlweDecryptContext, FourierGlweEncryptContext,
    FourierGlweKeySwitchingContext, FourierGlweKeySwitchingKey, FourierGlweSecretKey,
    GlevParameters, GlweKeySwitchingParameters, GlweParameters, GlweSecretKey, NttGadgetDomain,
    NttGadgetEncryptContext, NttGlweKeySwitchingContext, NttGlweKeySwitchingKey, NttGlweSecretKey,
    SecretKeyDistr,
};
use primus_lattice::glwe::{FourierGlweOwned, Glwe, NttGlwe};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;

const INPUT_DIMENSION: usize = 2;
const POLY_LENGTH: usize = 256;
const PLAINTEXT_MODULUS: u32 = 16;

fn plaintext() -> Vec<u32> {
    (0..POLY_LENGTH)
        .map(|index| (index as u32 * 7 + 3) % PLAINTEXT_MODULUS)
        .collect()
}

#[test]
fn ntt_glwe_key_switches_for_equal_and_smaller_output_dimensions() {
    const MODULUS: u32 = 132_120_577;

    let modulus = BarrettModulus::new(MODULUS);
    let ntt = UintNttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let mut rng = rand::rng();
    let input_params = GlweParameters::new(
        INPUT_DIMENSION,
        POLY_LENGTH,
        PLAINTEXT_MODULUS,
        modulus,
        SecretKeyDistr::Binary,
        0.7,
    );
    let input_coeff_key = GlweSecretKey::generate(&input_params, &mut rng);
    let input_key = NttGlweSecretKey::from_coeff_secret_key(&input_coeff_key, &ntt);
    let message_values = plaintext();
    let message = Polynomial::new(message_values.clone());
    let mut encrypted: NttGlwe<Vec<u32>> = NttGlwe::zero(input_params.glwe_len());
    input_key.encrypt_to(&message, &mut encrypted, &input_params, &ntt, &mut rng);
    let input = encrypted.into_coeff_form(&ntt);

    for output_dimension in [INPUT_DIMENSION, 1] {
        let output_params = GlweParameters::new(
            output_dimension,
            POLY_LENGTH,
            PLAINTEXT_MODULUS,
            modulus,
            SecretKeyDistr::Binary,
            0.7,
        );
        let generated_output_key = GlweSecretKey::generate(&output_params, &mut rng);
        let output_coeff_key = if output_dimension == 1 {
            // Model the padded key used by the future KeyswitchBootstrap
            // pipeline: an active LWE-key prefix followed by zero coefficients.
            let active_key_len = POLY_LENGTH - 13;
            let mut padded = vec![0; POLY_LENGTH];
            padded[..active_key_len]
                .copy_from_slice(&generated_output_key.as_slice()[..active_key_len]);
            GlweSecretKey::new(padded, output_params.size(), SecretKeyDistr::Binary)
        } else {
            generated_output_key
        };
        let output_key = NttGlweSecretKey::from_coeff_secret_key(&output_coeff_key, &ntt);
        let glev = GlevParameters::with_glwe_params(&output_params, 8, None);
        let parameters = GlweKeySwitchingParameters::new(INPUT_DIMENSION, glev);
        let domain = NttGadgetDomain::try_new(parameters.output(), &ntt).unwrap();
        let mut encrypt_context = NttGadgetEncryptContext::new(domain.size());
        let key = NttGlweKeySwitchingKey::generate(
            &input_coeff_key,
            &output_key,
            &domain,
            &mut rng,
            &mut encrypt_context,
        );

        assert_eq!(key.input_dimension(), INPUT_DIMENSION);
        assert_eq!(key.output_dimension(), output_dimension);
        assert_eq!(
            key.as_slice().len(),
            parameters.input_dimension() * parameters.output_size().glev_len()
        );

        let mut context = NttGlweKeySwitchingContext::new(domain.size().glwe_size());
        let switched = key.key_switch(&input, &domain, &mut context);
        let switched_ntt = switched.into_ntt_form(&ntt);
        assert_eq!(
            output_key
                .decrypt(&switched_ntt, &output_params, &ntt)
                .as_ref(),
            message_values
        );
    }
}

#[test]
fn fourier_glwe_key_switches_for_equal_and_smaller_output_dimensions() {
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    let mut rng = rand::rng();
    let input_params = GlweParameters::new(
        INPUT_DIMENSION,
        POLY_LENGTH,
        PLAINTEXT_MODULUS,
        NativeModulus::new(),
        SecretKeyDistr::Binary,
        0.7,
    );
    let input_coeff_key = GlweSecretKey::generate(&input_params, &mut rng);
    let input_key = FourierGlweSecretKey::from_coeff_secret_key(&input_coeff_key, &mut fft);
    let message_values = plaintext();
    let message = Polynomial::new(message_values.clone());
    let mut encrypted = FourierGlweOwned::zero(input_params.fourier_glwe_len());
    let mut glwe_encrypt_context = FourierGlweEncryptContext::new(POLY_LENGTH);
    input_key.encrypt_to(
        &message,
        &mut encrypted,
        &input_params,
        &mut fft,
        &mut rng,
        &mut glwe_encrypt_context,
    );
    let mut input: Glwe<Vec<u32>> = Glwe::zero(input_params.glwe_len());
    encrypted.write_torus_form(&mut input, &mut fft);

    for output_dimension in [INPUT_DIMENSION, 1] {
        let output_params = GlweParameters::new(
            output_dimension,
            POLY_LENGTH,
            PLAINTEXT_MODULUS,
            NativeModulus::new(),
            SecretKeyDistr::Binary,
            0.7,
        );
        let generated_output_key = GlweSecretKey::generate(&output_params, &mut rng);
        let output_coeff_key = if output_dimension == 1 {
            let active_key_len = POLY_LENGTH - 13;
            let mut padded = vec![0; POLY_LENGTH];
            padded[..active_key_len]
                .copy_from_slice(&generated_output_key.as_slice()[..active_key_len]);
            GlweSecretKey::new(padded, output_params.size(), SecretKeyDistr::Binary)
        } else {
            generated_output_key
        };
        let output_key = FourierGlweSecretKey::from_coeff_secret_key(&output_coeff_key, &mut fft);
        let glev = GlevParameters::with_glwe_params(&output_params, 8, None);
        let parameters = GlweKeySwitchingParameters::new(INPUT_DIMENSION, glev);
        let mut encrypt_context = FourierGadgetEncryptContext::new(parameters.output().size());
        let key = FourierGlweKeySwitchingKey::generate(
            &input_coeff_key,
            &output_key,
            parameters.output(),
            &mut fft,
            &mut rng,
            &mut encrypt_context,
        );

        assert_eq!(key.input_dimension(), INPUT_DIMENSION);
        assert_eq!(key.output_dimension(), output_dimension);
        assert_eq!(
            key.as_slice().len(),
            parameters.input_dimension() * parameters.output_size().fourier_glev_len()
        );

        let mut context = FourierGlweKeySwitchingContext::new(parameters.output().glwe_size());
        let switched = key.key_switch(&input, parameters.output(), &mut fft, &mut context);
        let mut switched_fourier = FourierGlweOwned::zero(output_params.fourier_glwe_len());
        switched.write_fourier_form(&mut switched_fourier, &mut fft);
        let mut decrypt_context = FourierGlweDecryptContext::new(POLY_LENGTH);
        assert_eq!(
            output_key
                .decrypt(
                    &switched_fourier,
                    &output_params,
                    &mut fft,
                    &mut decrypt_context,
                )
                .as_ref(),
            message_values
        );
    }
}
