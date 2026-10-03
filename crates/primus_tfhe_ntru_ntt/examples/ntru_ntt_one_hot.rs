//! Build four one-hot gadget controls from a two-bit input; use delta_2 in a CMux.
//!
//! Run: `cargo run --release -p primus_tfhe_ntru_ntt --example ntru_ntt_one_hot`
//! For u64, change Word to u64 and U32NttTable to U64NttTable.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_encoding::RoundedCodec;
use primus_encoding::ScaledCodec;
use primus_lattice::LweDimension;
use primus_lattice::ngsw::NttNgswIter;
use primus_lwe::LweParametersInner;
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_ntru::SecretKeyDistr;
use primus_ntt::U32NttTable as Table;
use primus_tfhe_ntru_ntt::{
    CircuitBootstrapConfig, DecompositionConfig, OneHotCircuitBootstrapEvaluator, TfheConfig,
    TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

// The explicit parameters below select bases and moduli for this coefficient word.
type Word = u32;
const N: usize = 1024;
const TARGET: usize = 2; // Public selector r in 0..4; delta_r encrypts [input == r].

// Key parameters: n=800, N=1024; independent external LWE q=2^24.
// Noise sigmas below are in coefficient units; these are arithmetic examples, not security presets.
fn parameters() -> TfheParameters<Word, PowOf2Modulus<Word>> {
    // NTT requires a prime admitting a 2N-th root, rather than a power-of-two modulus.
    let ring_modulus = if Word::BITS == 32 {
        998_244_353
    } else {
        1_125_899_906_826_241u64
    } as Word;
    let modulus = BarrettModulus::new(ring_modulus);
    let lwe_modulus: Word = 1 << 24;

    // None retains floor(modulus_bits / log_basis) levels; it need not cover every low bit.
    let full = DecompositionConfig {
        log_basis: if Word::BITS == 32 {
            DecompositionBaseLog::new(2)
        } else {
            DecompositionBaseLog::new(8)
        },
        level_count: None,
    };

    TfheParameters::try_from_config(TfheConfig {
        external_lwe: LweParametersInner::new(
            LweDimension::new(800),
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
            log_basis: DecompositionBaseLog::new(3),
            level_count: None,
        },
        key_switching_noise_standard_deviation: 3.2, // Return key switch in the q domain.
    })
    .unwrap()
}

// CBS emits a gadget ciphertext; its output basis is separate from the two evaluation-key bases.
fn circuit_config() -> CircuitBootstrapConfig {
    let internal = DecompositionConfig {
        log_basis: if Word::BITS == 32 {
            DecompositionBaseLog::new(2)
        } else {
            DecompositionBaseLog::new(8)
        },
        level_count: None,
    };
    CircuitBootstrapConfig {
        output: DecompositionConfig {
            log_basis: if Word::BITS == 32 {
                DecompositionBaseLog::new(3)
            } else {
                DecompositionBaseLog::new(8)
            },
            level_count: Some(if Word::BITS == 32 {
                DecompositionLevelCount::new(4)
            } else {
                DecompositionLevelCount::new(3)
            }),
        },
        trace: internal,
        trace_noise_standard_deviation: 0.7,
        scheme_switch: internal,
        scheme_switch_noise_standard_deviation: 0.7,
    }
}

fn main() {
    let context = TfheContext::<Word, Table, _>::try_from_parameters(parameters()).unwrap();
    // Public message encoding at external q, chosen independently of key generation.
    let input_codec = RoundedCodec::new(8, context.parameters().external_lwe().cipher_modulus());

    // Client: independent LWE/NTRU secrets; send evaluation material and both encrypted choices.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context
        .try_generate_keys(Some(circuit_config()), &mut rng)
        .unwrap();
    // Ordinary messages borrow only the external secret from the setup bundle.
    let external_secret = client_key.external_lwe_secret_key();
    let encryptor = context.encryptor(external_secret, &input_codec).unwrap();
    let ring_codec = ScaledCodec::new(
        input_codec.plaintext_modulus(),
        context.parameters().accumulator_ntru().cipher_modulus(),
    );
    let mut ring_client = context
        .accumulator_client(client_key.accumulator_ntru_secret_key(), ring_codec)
        .unwrap();
    let lhs = ring_client.encrypt(&vec![1; N], &mut rng);
    let rhs = ring_client.encrypt(&vec![3; N], &mut rng);
    let mut input = context.allocate_lwe_ciphertext();
    let mut decoded = vec![0; N];

    // Server: reserve one transformed NGSW per value in 0..4 and one ring result.
    let mut resources = context
        .bootstrap_resources(server_key.blind_rotation_key())
        .unwrap();
    let mut cbs = OneHotCircuitBootstrapEvaluator::try_new(
        &resources,
        server_key.circuit_bootstrap_key().unwrap(),
        &input_codec,
    )
    .unwrap();
    let mut selectors = cbs.allocate_ngsw_output();
    let cbs_parameters = cbs.parameters();
    let selector_len = cbs.ngsw_selector_len(); // L*N NTT values per NGSW.
    let mut selected = context.allocate_accumulator_ciphertext();

    for message in [TARGET as Word, 0] {
        // Client -> server: one padded two-bit input; the server never sees message.
        encryptor
            .encrypt_padded_to(message, input.as_mut_view(), &mut rng)
            .unwrap();

        // Server: selector r encrypts [message == r]; r=0 is included in this full batch.
        cbs.one_hot_ngsw_to(input.as_view(), &mut selectors, &mut resources);
        let control = NttNgswIter::new(&selectors, selector_len)
            .nth(TARGET)
            .unwrap();
        control.cmux_to(
            &lhs,
            &rhs,
            &mut selected,
            cbs_parameters.output_basis(),
            context.parameters().accumulator_ntru().cipher_modulus(),
            context.table(),
            resources.external_product_workspace(),
        );

        // Client: equality selects rhs=3; all other inputs select lhs=1.
        ring_client.decrypt_to(&selected, &mut decoded);
        let expected = if message == TARGET as Word { 3 } else { 1 };
        assert!(decoded.iter().all(|&value| value == expected));
        println!("input {message}: delta_{TARGET} selected {expected}");
    }
}
