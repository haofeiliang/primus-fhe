//! Build four one-hot gadget controls from a two-bit input; use delta_2 in a CMux.
//!
//! Run: `cargo run --release -p primus_tfhe_ntru_fourier --example ntru_fourier_one_hot --features rustfft`
//! To use TfheFftTable, switch the Table import, this target's
//! required-features and the command above to tfhe-fft.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_fft::RustFftTable as Table;
use primus_lattice::LweDimension;
use primus_modulus::{NativeModulus, PowOf2Modulus};
use primus_ntru::SecretKeyDistr;
use primus_poly::PolyLength;
use primus_tfhe_ntru::{BlindRotationConfig, LweConfig};
use primus_tfhe_ntru_fourier::{
    BlindRotationAlgorithm, CbsGadgetConfig, DecompositionConfig, GadgetEncryptionConfig,
    OneHotCircuitBootstrapEvaluator, PbsParameters, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};

// This example uses u64 coefficients with the explicit parameters below.
type Word = u64;
const N: usize = 1024;
const TARGET: usize = 2; // Public selector r in 0..4; delta_r encrypts [input == r].

fn main() {
    let context = TfheContext::<Word, Table, _>::from_parameters(parameters());
    // Padded t=8 encodes four selector values independently of the ring messages.
    let (selector_codec, ring_message_codec) =
        context.parameters().circuit_bootstrap_codecs(8, 8).unwrap();

    // Client: independent LWE/NTRU secrets; send evaluation material and both encrypted choices.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context
        .try_generate_circuit_bootstrap_keys(
            BlindRotationAlgorithm::Classic,
            circuit_config(),
            &mut rng,
        )
        .unwrap();
    // The selector is encrypted with the external LWE secret.
    let external_secret = client_key.external_lwe_secret_key();
    let encryptor = context.encryptor(external_secret, &selector_codec).unwrap();

    // Candidate ring messages use their own t=8 space at accumulator Q.
    let mut ring_client = context
        .accumulator_client(client_key.accumulator_ntru_secret_key(), ring_message_codec)
        .unwrap();
    let lhs = ring_client.encrypt(&vec![1; N], &mut rng);
    let rhs = ring_client.encrypt(&vec![3; N], &mut rng);
    let mut input = context.allocate_lwe_ciphertext();
    let mut decoded = vec![0; N];

    // Server: reserve one transformed NGSW per value in 0..4 and one ring result.
    let mut resources = server_key.bootstrap_resources(&context).unwrap();
    let mut cbs = OneHotCircuitBootstrapEvaluator::try_new(
        &resources,
        server_key.circuit_bootstrap_key(),
        &selector_codec,
    )
    .unwrap();
    let mut selectors = cbs.allocate_ngsw_output();
    let mut selected = context.allocate_accumulator_ciphertext();

    for message in [TARGET as Word, 0] {
        // Client -> server: one padded two-bit input; the server never sees message.
        encryptor
            .encrypt_padded_to(message, input.as_mut_view(), &mut rng)
            .unwrap();

        // Server: selector r encrypts [message == r]; r=0 is included in this full batch.
        cbs.one_hot_ngsw_to(input.as_view(), &mut selectors, &mut resources);
        let control = cbs.ngsw_selectors(&selectors).selector(TARGET).unwrap();
        cbs.cmux_to(&control, &lhs, &rhs, &mut selected, &mut resources);

        // Client: equality selects rhs=3; all other inputs select lhs=1.
        ring_client.decrypt_to(&selected, &mut decoded);
        let expected = if message == TARGET as Word { 3 } else { 1 };
        assert!(decoded.iter().all(|&value| value == expected));
        println!("input {message}: delta_{TARGET} selected {expected}");
    }
}

// Key parameters: n=800, N=1024; independent external LWE q=2^24.
// Noise sigmas below are in coefficient units; these are arithmetic examples, not security presets.
fn parameters() -> PbsParameters<Word, PowOf2Modulus<Word>> {
    let modulus = NativeModulus::<Word>::new();
    let lwe_modulus: Word = 1 << 24;

    // None retains floor(modulus_bits / log_basis) levels; it need not cover every low bit.
    let full = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };

    BlindRotationConfig {
        external_lwe: LweConfig {
            dimension: LweDimension::new(800),
            cipher_modulus: PowOf2Modulus::new(lwe_modulus).into(),
            secret_key_distr: SecretKeyDistr::fixed_hamming_weight_binary(800, 32),
            noise_standard_deviation: lwe_modulus as f64 * 2.046151696979124e-6,
        },
        acc_modulus: modulus.into(),
        acc_poly_length: PolyLength::new(N),
        bsk_secret_distr: SecretKeyDistr::SparseTernary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: full,
            noise_standard_deviation: 0.7,
        },
        algorithm: BlindRotationAlgorithm::Classic,
    }
    .try_prepare()
    .unwrap()
}

// CBS emits a gadget ciphertext; its output basis is separate from the two evaluation-key bases.
fn circuit_config() -> CbsGadgetConfig {
    let internal = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };
    CbsGadgetConfig {
        output: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(3)),
        },
        trace: internal,
        scheme_switch: internal,
    }
}
