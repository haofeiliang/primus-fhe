//! NTRU/Fourier circuit bootstrapping followed by CMUX.
//!
//! Fixed seed and small functional parameters for demonstration only. CBS noise
//! and secret-dependent-message security require a separate production assessment.

use primus_fft::RustFftTable;
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_ntru::SecretKeyDistr;
use primus_tfhe_ntru_fourier::{
    CircuitBootstrapConfig, DecompositionConfig, TfheConfig, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 256;

fn main() {
    let modulus = NativeModulus::<u64>::new();
    let lwe = LweParameters::new(16, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let parameters = TfheParameters::try_from_config(TfheConfig {
        external_lwe: lwe,
        poly_length: N,
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 0.7,
        blind_rotation: DecompositionConfig {
            log_basis: 10,
            level_count: None,
        },
        key_switching: DecompositionConfig {
            log_basis: 10,
            level_count: None,
        },
        key_switching_noise_standard_deviation: 0.7,
    })
    .unwrap();
    let context = TfheContext::<_, RustFftTable>::try_from_parameters(parameters).unwrap();
    let mut rng = StdRng::seed_from_u64(0x004e_5454_5f43_4253);
    // CBS adds independent output, trace and scheme-switch bases.
    let cbs_config = CircuitBootstrapConfig {
        output: DecompositionConfig {
            log_basis: 8,
            level_count: Some(2),
        },
        trace: DecompositionConfig {
            log_basis: 10,
            level_count: None,
        },
        trace_noise_standard_deviation: 0.7,
        scheme_switch: DecompositionConfig {
            log_basis: 10,
            level_count: None,
        },
        scheme_switch_noise_standard_deviation: 0.7,
    };
    let (client_key, server_key) = context
        .try_generate_keys(Some(cbs_config), &mut rng)
        .unwrap();
    let encryptor = context.encryptor(&client_key).unwrap();
    // CMUX candidates use f_acc, the CBS output secret.
    let mut accumulator = context.accumulator_client(&client_key).unwrap();
    let choices = [1, 3].map(|message| accumulator.encrypt(&[message; N], &mut rng));
    let mut evaluator = context.circuit_bootstrap_evaluator(&server_key).unwrap();
    let mut control = evaluator.allocate_output();
    let mut selected = accumulator.allocate_ciphertext();
    let mut decoded = vec![0; N];
    let mut input = primus_tfhe::LweCiphertext::zero(context.parameters().external_lwe_dimension());
    for bit in [0u64, 1, 0] {
        encryptor
            .encrypt_padded_to(bit, &mut input, &mut rng)
            .unwrap();
        // Server-side: ordinary LWE bit -> gadget-scaled NGSW -> selected NTRU.
        evaluator.circuit_bootstrap_to(&input, &mut control);
        evaluator.cmux_to(&control, &choices[0], &choices[1], &mut selected);
        accumulator.decrypt_to(&selected, &mut decoded);
        assert_eq!(decoded, [if bit == 0 { 1 } else { 3 }; N]);
    }
    println!("CBS -> CMUX selected 1, 3, 1");
}
