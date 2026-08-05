use primus_decompose::primitive::ApproxSignedBasis;
use primus_lwe::{
    LweKeySwitchingKey, LweKeySwitchingParameters, LweParameters, LweSecretKey, SecretKeyDistr,
};
use primus_modulus::{BarrettModulus, NativeModulus};

#[test]
fn key_switches_between_lwe_secret_keys() {
    let modulus = NativeModulus::<u32>::new();
    let input_parameters = LweParameters::new(8, 4u32, modulus, SecretKeyDistr::Binary, 3.2);
    let output_parameters = LweParameters::new(5, 4u32, modulus, SecretKeyDistr::Binary, 3.2);
    let key_switching_parameters = LweKeySwitchingParameters::new(
        input_parameters.dimension(),
        output_parameters.dimension(),
        ApproxSignedBasis::new(None, 4, None),
    );
    let mut rng = rand::rng();
    let input_secret_key = LweSecretKey::generate(&input_parameters, &mut rng);
    let output_secret_key = LweSecretKey::generate(&output_parameters, &mut rng);
    let key_switching_key = LweKeySwitchingKey::generate(
        input_secret_key.as_ref(),
        &output_secret_key,
        &output_parameters,
        &key_switching_parameters,
        &mut rng,
    );

    for message in 0u32..4 {
        let input = input_secret_key.encrypt(message, &input_parameters, &mut rng);
        let output = key_switching_key.key_switch(&input, modulus);
        assert_eq!(
            output_secret_key.decrypt::<_, u32>(&output, &output_parameters),
            message
        );
    }
}

#[test]
fn key_switches_with_base_four_signed_digits() {
    const MODULUS: u32 = 132_120_577;

    let modulus = BarrettModulus::new(MODULUS);
    let input_parameters = LweParameters::new(8, 4u32, modulus, SecretKeyDistr::Binary, 0.7);
    let output_parameters = LweParameters::new(5, 4u32, modulus, SecretKeyDistr::Binary, 0.7);
    let key_switching_parameters = LweKeySwitchingParameters::new(
        input_parameters.dimension(),
        output_parameters.dimension(),
        ApproxSignedBasis::new(Some(MODULUS), 2, Some(13)),
    );
    let mut rng = rand::rng();
    let input_secret_key = LweSecretKey::generate(&input_parameters, &mut rng);
    let output_secret_key = LweSecretKey::generate(&output_parameters, &mut rng);
    let key_switching_key = LweKeySwitchingKey::generate(
        input_secret_key.as_ref(),
        &output_secret_key,
        &output_parameters,
        &key_switching_parameters,
        &mut rng,
    );

    for message in 0u32..4 {
        let input = input_secret_key.encrypt(message, &input_parameters, &mut rng);
        let output = key_switching_key.key_switch(&input, modulus);
        assert_eq!(
            output_secret_key.decrypt::<_, u32>(&output, &output_parameters),
            message
        );
    }
}
