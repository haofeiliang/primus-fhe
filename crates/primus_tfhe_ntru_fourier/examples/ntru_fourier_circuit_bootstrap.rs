//! Use an encrypted LWE bit to select between two encrypted ring messages via CBS and CMux.
//!
//! Run: `cargo run --release -p primus_tfhe_ntru_fourier --example ntru_fourier_circuit_bootstrap`
//! For u64, change Word to u64; for TFHE-FFT, use TfheFftTable as Table.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_fft::RustFftTable as Table;
use primus_lwe::LweParameters;
use primus_modulus::{NativeModulus, PowOf2Modulus};
use primus_ntru::SecretKeyDistr;
use primus_tfhe_ntru_fourier::{
    CircuitBootstrapConfig, DecompositionConfig, TfheConfig, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

// The explicit parameters below select bases and moduli for this coefficient word.
type Word = u32;
const N: usize = 1024;

// Public parameters: n=800, N=1024, t=4; independent external LWE q=2^24.
// Noise sigmas below are in coefficient units; these are arithmetic examples, not security presets.
fn parameters() -> TfheParameters<Word, PowOf2Modulus<Word>> {
    let modulus = NativeModulus::<Word>::new();
    let lwe_modulus: Word = 1 << 24;

    // None retains floor(modulus_bits / log_basis) levels; it need not cover every low bit.
    let full = DecompositionConfig {
        log_basis: if Word::BITS == 32 { 2 } else { 8 },
        level_count: None,
    };

    TfheParameters::try_from_config(TfheConfig {
        external_lwe: LweParameters::new(
            800,
            4, // Padded inputs occupy 0..2.
            PowOf2Modulus::new(lwe_modulus),
            SecretKeyDistr::UniformBinary,
            lwe_modulus as f64 * 2.046151696979124e-6,
        ),
        accumulator_modulus: modulus, // Ring Q; distinct from the external LWE q.
        poly_length: N,
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 0.7,
        blind_rotation: full,
        key_switching: DecompositionConfig {
            log_basis: 3,
            level_count: None,
        },
        key_switching_noise_standard_deviation: 3.2, // Return key switch in the q domain.
    })
    .unwrap()
}

// CBS emits a gadget ciphertext; its output basis is separate from the two evaluation-key bases.
fn circuit_config() -> CircuitBootstrapConfig {
    let internal = DecompositionConfig {
        log_basis: if Word::BITS == 32 { 2 } else { 8 },
        level_count: None,
    };
    CircuitBootstrapConfig {
        output: DecompositionConfig {
            log_basis: if Word::BITS == 32 { 3 } else { 8 },
            level_count: Some(if Word::BITS == 32 { 4 } else { 3 }),
        },
        trace: internal,
        trace_noise_standard_deviation: 0.7,
        scheme_switch: internal,
        scheme_switch_noise_standard_deviation: 0.7,
    }
}

fn main() {
    let parameters = parameters();
    let context = TfheContext::<Word, Table, _>::try_from_parameters(parameters).unwrap();

    // Client: generate CBS material with the paired keys; send server_key only.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context
        .try_generate_keys(Some(circuit_config()), &mut rng)
        .unwrap();
    let encryptor = context.encryptor(&client_key).unwrap();
    let mut ring_client = context.accumulator_client(&client_key).unwrap();
    // Encrypt both candidates with the accumulator secret used by the CBS output.
    let lhs_message = vec![1 as Word; N];
    let rhs_message = vec![3 as Word; N];
    let lhs = ring_client.encrypt(&lhs_message, &mut rng);
    let rhs = ring_client.encrypt(&rhs_message, &mut rng);
    let mut input = context.allocate_lwe_ciphertext();
    let mut decoded = vec![0; N];

    // Server: receive the encrypted candidates; allocate the control and result.
    let mut cbs = context.circuit_bootstrap_evaluator(&server_key).unwrap();
    let mut control = cbs.allocate_output();
    let mut selected = context.allocate_accumulator_ciphertext();

    for bit in [1 as Word, 0] {
        // Client -> server: send the encrypted selection bit.
        encryptor
            .encrypt_padded_to(bit, &mut input, &mut rng)
            .unwrap();

        // Server: CBS produces a gadget control; CMux selects rhs for 1, lhs for 0.
        cbs.circuit_bootstrap_to(&input, &mut control);
        cbs.cmux_to(&control, &lhs, &rhs, &mut selected);

        // Client: decrypt the returned ring ciphertext, reusing the decoding buffer.
        ring_client.decrypt_to(&selected, &mut decoded);
        let expected = if bit == 0 { &lhs_message } else { &rhs_message };
        assert_eq!(&decoded, expected);
        println!("bit {bit}: selected coefficients {}", decoded[0]);
    }
}
