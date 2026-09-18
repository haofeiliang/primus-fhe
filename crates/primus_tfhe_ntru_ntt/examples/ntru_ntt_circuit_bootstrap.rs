//! NTRU/NTT circuit bootstrapping followed by CMUX.
//!
//! Fixed seed and small functional parameters for demonstration only. CBS noise
//! and secret-dependent-message security require a separate production assessment.

use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntru::{
    NtruCiphertext, NttNgswCiphertext, NttNtruCiphertext, NttNtruExternalProductContext,
    NttNtruSecretKey, SecretKeyDistr,
};
use primus_ntt::U64NttTable;
use primus_poly::Polynomial;
use primus_tfhe_ntru_ntt::{
    CircuitBootstrapConfig, CircuitBootstrapParameters, DecompositionConfig, TfheConfig,
    TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 256;
const Q: u64 = 1_125_899_906_826_241;

fn main() {
    let modulus = BarrettModulus::new(Q);
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
    let context = TfheContext::<_, U64NttTable>::try_from_parameters(parameters).unwrap();
    let accumulator = context.parameters().accumulator_ntru();
    let mut rng = StdRng::seed_from_u64(0x004e_5454_5f43_4253);
    let (client_key, server_key) = context.try_generate_keys(&mut rng).unwrap();
    // CMUX candidates are encrypted under f_acc, the CBS output secret.
    let accumulator_key = NttNtruSecretKey::try_from_coeff_secret_key(
        client_key.accumulator_ntru_secret_key(),
        modulus,
        context.table(),
    )
    .unwrap();
    let encryptor = context.encryptor(&client_key).unwrap();
    let choices = [1, 3].map(|message| {
        let transformed = accumulator_key.encrypt(
            &Polynomial::new(vec![message; N]),
            accumulator,
            context.table(),
            &mut rng,
        );
        let mut output = NtruCiphertext::<Vec<u64>>::zero(N);
        transformed.write_coeff_form(&mut output, context.table());
        output
    });
    // CBS adds independent output, trace and scheme-switch bases.
    let cbs_parameters = CircuitBootstrapParameters::try_from_config(
        context.parameters(),
        CircuitBootstrapConfig {
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
        },
    )
    .unwrap();
    let cbs_key = context
        .try_generate_circuit_bootstrap_key(&client_key, &cbs_parameters, &mut rng)
        .unwrap();
    let mut evaluator = context
        .circuit_bootstrap_evaluator(&server_key, &cbs_parameters, &cbs_key)
        .unwrap();
    let mut control = NttNgswCiphertext::<Vec<u64>>::zero(cbs_parameters.output_nlev_len());
    let mut selected = NtruCiphertext::<Vec<u64>>::zero(N);
    let mut transformed = NttNtruCiphertext::<Vec<u64>>::zero(N);
    let mut scratch = NttNtruExternalProductContext::new(N);
    let mut input = primus_tfhe::LweCiphertext::zero(context.parameters().external_lwe_dimension());
    for bit in [0u64, 1, 0] {
        encryptor
            .encrypt_padded_to(bit, &mut input, &mut rng)
            .unwrap();
        // Server-side: ordinary LWE bit -> gadget-scaled NGSW -> selected NTRU.
        evaluator.circuit_bootstrap_to(&input, &mut control);
        control.cmux_to(
            &choices[0],
            &choices[1],
            &mut selected,
            cbs_parameters.output_basis(),
            modulus,
            context.table(),
            &mut scratch,
        );
        // Client-side verification in the transform representation.
        selected.write_ntt_form(&mut transformed, context.table());
        assert_eq!(
            accumulator_key
                .decrypt(&transformed, accumulator, context.table())
                .as_ref(),
            &[if bit == 0 { 1 } else { 3 }; N]
        );
    }
    println!("CBS -> CMUX selected 1, 3, 1");
}
