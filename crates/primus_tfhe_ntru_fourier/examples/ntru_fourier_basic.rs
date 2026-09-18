//! Minimal complete NTRU/Fourier programmable-bootstrap workflow.
//!
//! These small parameters are for demonstration only, not for production.

use primus_encoding::RoundedCodec;
use primus_fft::RustFftTable;
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::NativeModulus;
use primus_ntru::SecretKeyDistr;
use primus_tfhe_ntru_fourier::{DecompositionConfig, TfheConfig, TfheContext, TfheParameters};

fn main() {
    const N: usize = 256;
    const LWE_DIMENSION: usize = 8;
    let modulus = NativeModulus::new();
    let external_lwe = LweParameters::new(
        LWE_DIMENSION,
        16,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let parameters = TfheParameters::try_from_config(TfheConfig {
        external_lwe,
        poly_length: N,
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 0.7,
        blind_rotation: DecompositionConfig {
            log_basis: 8,
            level_count: Some(4),
        },
        key_switching: DecompositionConfig {
            log_basis: 8,
            level_count: Some(4),
        },
        key_switching_noise_standard_deviation: 0.7,
    })
    .unwrap();
    let context = TfheContext::<_, RustFftTable>::try_from_parameters(parameters).unwrap();

    let mut rng = rand::rng();
    let (client_key, server_key) = context.try_generate_keys(&mut rng).unwrap();
    // Publish this LWE key to encrypt inputs; keep the client key for decryption.
    // These demonstration parameters have no public-key security/noise assessment.
    let public_key = client_key
        .try_generate_public_key(context.parameters(), &mut rng)
        .unwrap();
    let encryptor = context.encryptor(&public_key).unwrap();
    let decryptor = context.decryptor(&client_key).unwrap();
    // Input t=16 leaves programmable inputs 0..8. Encode message, carry and
    // parity with output t=4; three outputs occupy four interleaved slots.
    let output_codec = RoundedCodec::new(4, context.parameters().external_lwe().cipher_modulus());
    let lut = context
        .parameters()
        .compile_interleaved_lookup_table_fn(&output_codec, 3, |input, output| match output {
            0 => (input % 4) as u32,
            1 => (input / 4) as u32,
            _ => (input % 2) as u32,
        })
        .unwrap();
    let mut input = LweCiphertext::zero(LWE_DIMENSION);
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let mut outputs = vec![input.clone(); lut.output_count()];
    for message in [7u32, 2] {
        encryptor
            .encrypt_padded_to(message, &mut input, &mut rng)
            .unwrap();
        evaluator.apply_interleaved_lookup_table_to(&input, &lut, &mut outputs);
        assert_eq!(
            output_codec.decode_value(decryptor.decrypt_phase(&outputs[0]).unwrap()),
            message % 4
        );
        assert_eq!(
            output_codec.decode_value(decryptor.decrypt_phase(&outputs[1]).unwrap()),
            message / 4
        );
        assert_eq!(
            output_codec.decode_value(decryptor.decrypt_phase(&outputs[2]).unwrap()),
            message % 2
        );
    }
    println!("NTRU/Fourier programmable bootstrap succeeded");
}
