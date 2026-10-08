//! Evaluate an encrypted integer predicate with CBS, then select a ring message via CMux.
//!
//! Run: `cargo run --release -p primus_tfhe_ntru_ntt --example ntru_ntt_circuit_bootstrap`
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_lattice::LweDimension;
use primus_lwe::LweEncryptionParameters;
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_ntru::SecretKeyDistr;
use primus_ntt::U64NttTable as Table;
use primus_poly::PolyLength;
use primus_tfhe_ntru_ntt::{
    BlindRotationConfig, CircuitBootstrapConfig, CircuitBootstrapEvaluator, DecompositionConfig,
    GadgetEncryptionConfig, TfheConfig, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

// This example uses u64 coefficients with the explicit parameters below.
type Word = u64;
const N: usize = 1024;

fn main() {
    let parameters = parameters();
    let context = TfheContext::<Word, Table, _>::try_from_parameters(parameters).unwrap();
    // Padded t=8 accepts integers 0..4, independently of the candidate ring messages.
    let (input_codec, ring_message_codec) =
        context.parameters().circuit_bootstrap_codecs(8, 8).unwrap();

    // Client: generate BR and CBS material; this ring-output workflow needs no return key.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context
        .try_generate_circuit_bootstrap_keys(
            BlindRotationConfig::Classic,
            circuit_config(),
            &mut rng,
        )
        .unwrap();
    // The integer input is encrypted with the external LWE secret.
    let external_secret = client_key.external_lwe_secret_key();
    let encryptor = context.encryptor(external_secret, &input_codec).unwrap();

    // Candidate ring messages use an independent t=8 space at accumulator Q.
    let mut ring_client = context
        .accumulator_client(client_key.accumulator_ntru_secret_key(), ring_message_codec)
        .unwrap();
    // Encrypt both candidates with the accumulator secret used by the CBS output.
    let lhs_message = vec![1; N];
    let rhs_message = vec![3; N];
    let lhs = ring_client.encrypt(&lhs_message, &mut rng);
    let rhs = ring_client.encrypt(&rhs_message, &mut rng);
    let mut input = context.allocate_lwe_ciphertext();
    let mut decoded = vec![0; N];

    // Server: receive the encrypted candidates; allocate the control and result.
    let mut resources = server_key.bootstrap_resources(&context).unwrap();
    // Compile F(m) = [m >= 2] once. CBS emits gadget-scaled F(m), so CMux
    // consumes a bit even when the encrypted input itself is not a bit.
    let program = server_key
        .circuit_bootstrap_key()
        .parameters()
        .compile_lookup_table_fn(&input_codec, |m| Word::from(m >= 2))
        .unwrap();
    let mut cbs = CircuitBootstrapEvaluator::try_with_lookup_table(
        &resources,
        server_key.circuit_bootstrap_key(),
        program,
    )
    .unwrap();
    let mut control = cbs.allocate_output();
    let mut selected = context.allocate_accumulator_ciphertext();

    for message in [3, 1] {
        // Client -> server: send the encrypted integer.
        encryptor
            .encrypt_padded_to(message, input.as_mut_view(), &mut rng)
            .unwrap();

        // Server: one CBS computes the predicate; CMux selects rhs when it is true.
        cbs.circuit_bootstrap_to(input.as_view(), &mut control, &mut resources);
        cbs.cmux_to(&control, &lhs, &rhs, &mut selected, &mut resources);

        // Client: decrypt the returned ring ciphertext, reusing the decoding buffer.
        ring_client.decrypt_to(&selected, &mut decoded);
        let expected = if message >= 2 {
            &rhs_message
        } else {
            &lhs_message
        };
        assert_eq!(&decoded, expected);
        println!(
            "input {message}, predicate m >= 2: selected coefficients {}",
            decoded[0]
        );
    }
}

// Key parameters: n=800, N=1024; independent external LWE q=2^24.
// Noise sigmas below are in coefficient units; these are arithmetic examples, not security presets.
fn parameters() -> TfheParameters<Word, PowOf2Modulus<Word>> {
    // NTT requires a prime admitting a 2N-th root, rather than a power-of-two modulus.
    let ring_modulus: Word = 1_125_899_906_826_241;
    let modulus = BarrettModulus::new(ring_modulus);
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
            SecretKeyDistr::UniformBinary,
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
        trace: internal,
        scheme_switch: internal,
    }
}
