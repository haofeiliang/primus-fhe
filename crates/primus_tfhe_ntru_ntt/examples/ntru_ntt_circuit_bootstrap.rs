//! NTRU/NTT circuit bootstrapping followed by CMUX.
//!
//! Fixed seed and small functional parameters for demonstration only. CBS noise
//! and secret-dependent-message security require a separate production assessment.

use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntru::SecretKeyDistr;
use primus_ntt::U64NttTable;
use primus_tfhe_ntru_ntt::{
    CircuitBootstrapConfig, DecompositionConfig, TfheConfig, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 256;
const Q: u64 = 1_125_899_906_826_241;

fn main() {
    let context = TfheContext::<_, U64NttTable>::try_from_parameters(parameters()).unwrap();
    // Client setup: generate paired keys and keep the decryption material local.
    let mut rng = StdRng::seed_from_u64(0x004e_5454_5f43_4253);
    let (client_key, server_key) = context
        .try_generate_keys(Some(circuit_bootstrap_config()), &mut rng)
        .unwrap();
    let encryptor = context.encryptor(&client_key).unwrap();
    // The ring candidates and CBS control share the accumulator secret.
    let mut ring_client = context.accumulator_client(&client_key).unwrap();
    let lhs_message = vec![1u64; N];
    let rhs_message = vec![3u64; N];
    let lhs = ring_client.encrypt(&lhs_message, &mut rng);
    let rhs = ring_client.encrypt(&rhs_message, &mut rng);
    let mut input = context.allocate_lwe_ciphertext();
    let mut decoded = vec![0; N];

    // Server setup: only public context, server key and ciphertexts are needed.
    let mut cbs = context.circuit_bootstrap_evaluator(&server_key).unwrap();
    let mut control = cbs.allocate_output();
    let mut selected = context.allocate_accumulator_ciphertext();

    for bit in [0u64, 1, 0] {
        // Client sends the encrypted bit (the encrypted candidates can be reused).
        encryptor
            .encrypt_padded_to(bit, &mut input, &mut rng)
            .unwrap();

        // Server computes the control and returns the selected ciphertext.
        cbs.circuit_bootstrap_to(&input, &mut control);
        cbs.cmux_to(&control, &lhs, &rhs, &mut selected);

        // Client decrypts the response; all buffers survive the next request.
        ring_client.decrypt_to(&selected, &mut decoded);
        let expected = if bit == 0 { &lhs_message } else { &rhs_message };
        assert_eq!(&decoded, expected);
        println!("NTRU/NTT: bit {bit} selected coefficients {}", expected[0]);
    }
}

fn parameters() -> TfheParameters<u64> {
    let modulus = BarrettModulus::new(Q);
    let lwe = LweParameters::new(16, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
    TfheParameters::try_from_config(TfheConfig {
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
    .unwrap()
}

fn circuit_bootstrap_config() -> CircuitBootstrapConfig {
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
    }
}
