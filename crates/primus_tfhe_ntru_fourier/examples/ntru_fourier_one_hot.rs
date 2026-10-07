//! Build four one-hot gadget controls from a two-bit input; use delta_2 in a CMux.
//!
//! Run: `cargo run --release -p primus_tfhe_ntru_fourier --example ntru_fourier_one_hot --features rustfft`
//! To use TfheFftTable, switch the Table import, this target's
//! required-features and the command above to tfhe-fft.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_encoding::{RoundedCodec, ScaledCodec};
use primus_fft::RustFftTable as Table;
use primus_lattice::LweDimension;
use primus_lattice::ngsw::FourierNgswIter;
use primus_lwe::LweEncryptionParameters;
use primus_modulus::{NativeModulus, PowOf2Modulus};
use primus_ntru::SecretKeyDistr;
use primus_poly::PolyLength;
use primus_tfhe_ntru_fourier::{
    BlindRotationConfig, CircuitBootstrapConfig, DecompositionConfig, GadgetEncryptionConfig,
    OneHotCircuitBootstrapEvaluator, TfheConfig, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

// This example uses u64 coefficients with the explicit parameters below.
type Word = u64;
const N: usize = 1024;
const TARGET: usize = 2; // Public selector r in 0..4; delta_r encrypts [input == r].

fn main() {
    let context = TfheContext::<Word, Table, _>::from_parameters(parameters());
    // Padded t=8 encodes four selector values independently of the ring messages.
    let selector_codec = RoundedCodec::new(8, context.parameters().external_lwe().cipher_modulus());

    // Client: independent LWE/NTRU secrets; send evaluation material and both encrypted choices.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context
        .try_generate_circuit_bootstrap_keys(
            BlindRotationConfig::Classic,
            circuit_config(),
            &mut rng,
        )
        .unwrap();
    // The selector is encrypted with the external LWE secret.
    let external_secret = client_key.external_lwe_secret_key();
    let encryptor = context.encryptor(external_secret, &selector_codec).unwrap();

    // Candidate ring messages use their own t=8 space at accumulator Q.
    let ring_message_codec =
        ScaledCodec::new(8, context.parameters().accumulator_ntru().cipher_modulus());
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
    let cbs_parameters = cbs.parameters();
    let selector_len = cbs.ngsw_selector_len(); // L*(N/2) complex values per NGSW.
    let mut selected = context.allocate_accumulator_ciphertext();

    for message in [TARGET as Word, 0] {
        // Client -> server: one padded two-bit input; the server never sees message.
        encryptor
            .encrypt_padded_to(message, input.as_mut_view(), &mut rng)
            .unwrap();

        // Server: selector r encrypts [message == r]; r=0 is included in this full batch.
        cbs.one_hot_ngsw_to(input.as_view(), &mut selectors, &mut resources);
        let control = FourierNgswIter::new(&selectors, selector_len)
            .nth(TARGET)
            .unwrap();
        let (fft, external_product) = resources.external_product_workspaces();
        control.cmux_to(
            &lhs,
            &rhs,
            &mut selected,
            cbs_parameters.output_basis(),
            fft,
            external_product,
        );

        // Client: equality selects rhs=3; all other inputs select lhs=1.
        ring_client.decrypt_to(&selected, &mut decoded);
        let expected = if message == TARGET as Word { 3 } else { 1 };
        assert!(decoded.iter().all(|&value| value == expected));
        println!("input {message}: delta_{TARGET} selected {expected}");
    }
}

// Key parameters: n=800, N=1024; independent external LWE q=2^24.
// Noise sigmas below are in coefficient units; these are arithmetic examples, not security presets.
fn parameters() -> TfheParameters<Word, PowOf2Modulus<Word>> {
    let modulus = NativeModulus::<Word>::new();
    let lwe_modulus: Word = 1 << 24;

    // None retains floor(modulus_bits / log_basis) levels; it need not cover every low bit.
    let full = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };

    TfheParameters::try_from_config(TfheConfig {
        external_lwe: LweEncryptionParameters::new(
            LweDimension::new(800),
            PowOf2Modulus::new(lwe_modulus),
            SecretKeyDistr::fixed_hamming_weight_binary(800, 32),
            lwe_modulus as f64 * 2.046151696979124e-6,
        ),
        accumulator_modulus: modulus, // Ring Q; distinct from the external LWE q.
        poly_length: PolyLength::new(N),
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        blind_rotation: GadgetEncryptionConfig {
            decomposition: full,
            noise_standard_deviation: 0.7,
        },
        // Return key switch in the q domain.
        key_switching: GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(3),
                level_count: None,
            },
            noise_standard_deviation: 3.2,
        },
    })
    .unwrap()
}

// CBS emits a gadget ciphertext; its output basis is separate from the two evaluation-key bases.
fn circuit_config() -> CircuitBootstrapConfig {
    let internal = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };
    CircuitBootstrapConfig {
        output: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(3)),
        },
        trace: GadgetEncryptionConfig {
            decomposition: internal,
            noise_standard_deviation: 0.7,
        },
        scheme_switch: GadgetEncryptionConfig {
            decomposition: internal,
            noise_standard_deviation: 0.7,
        },
    }
}
