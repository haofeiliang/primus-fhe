use primus_decompose::primitive::ApproxSignedBasis;
use primus_fhe_core::{
    LweKeySwitchingKey, LweKeySwitchingParameters, LweParameters, LweSecretKey, LweSecretKeyType,
};
use primus_modulus::NativeModulus;

#[test]
fn key_switches_between_lwe_secret_keys() {
    let modulus = NativeModulus::<u32>::new();
    let input_parameters = LweParameters::new(8, 4u32, modulus, LweSecretKeyType::Binary, 3.2);
    let output_parameters = LweParameters::new(5, 4u32, modulus, LweSecretKeyType::Binary, 3.2);
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
