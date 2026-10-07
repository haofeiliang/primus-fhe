//! Use an encrypted LWE bit to select between two encrypted ring messages via sparse CBS and CMux.
//!
//! Run: `cargo run --release -p primus_tfhe_glwe_ntt --example ntt_sparse_circuit_bootstrap`
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_encoding::{RoundedCodec, ScaledCodec};
use primus_glwe::SecretKeyDistr;
use primus_lattice::{GlweDimension, LweDimension};
use primus_lwe::LweEncryptionParameters;
use primus_modulus::BarrettModulus;
use primus_ntt::U64NttTable as Table;
use primus_poly::PolyLength;
use primus_tfhe_glwe_ntt::{
    BlindRotationConfig, CircuitBootstrapConfig, CircuitBootstrapEvaluator, DecompositionConfig,
    GadgetEncryptionConfig, PbsOrder, TfheConfig, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

// This example uses u64 coefficients with the explicit parameters below.
type Word = u64;
const N: usize = 1024;

fn main() {
    let parameters = parameters();
    let context = TfheContext::<Word, Table>::try_from_parameters(parameters).unwrap();

    // Padded t=4 encodes a selection bit independently of the ring messages.
    let selector_codec = RoundedCodec::new(4, context.parameters().cipher_modulus());

    // Client: generate sparse BR/CBS material, without an unused return key.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context
        .try_generate_circuit_bootstrap_keys(
            BlindRotationConfig::Sparse {
                copy_count: 3,
                bucket_count: 64,
            },
            circuit_config(),
            &mut rng,
        )
        .unwrap();
    // The selector is encrypted with the external LWE secret.
    let external_secret = client_key.external_lwe_secret_key();
    let encryptor = context.encryptor(external_secret, &selector_codec).unwrap();

    // Candidate ring messages use their own t=4 space under the accumulator secret.
    let ring_message_codec = ScaledCodec::new(4, context.parameters().cipher_modulus());
    let mut ring_client = context
        .accumulator_client(client_key.glwe_secret_key(), ring_message_codec)
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
    let mut cbs = CircuitBootstrapEvaluator::try_new(
        &resources,
        server_key.circuit_bootstrap_key(),
        &selector_codec,
    )
    .unwrap();
    let mut control = cbs.allocate_output();
    let mut selected = context.allocate_accumulator_ciphertext();

    for bit in [1, 0] {
        // Client -> server: send the encrypted selection bit.
        encryptor
            .encrypt_padded_to(bit, input.as_mut_view(), &mut rng)
            .unwrap();

        // Server: CBS produces a gadget control; CMux selects rhs for 1, lhs for 0.
        cbs.circuit_bootstrap_to(input.as_view(), &mut control, &mut resources);
        cbs.cmux_to(&control, &lhs, &rhs, &mut selected, &mut resources);

        // Client: decrypt the returned ring ciphertext, reusing the decoding buffer.
        ring_client.decrypt_to(&selected, &mut decoded);
        let expected = if bit == 0 { &lhs_message } else { &rhs_message };
        assert_eq!(&decoded, expected);
        println!("bit {bit}: selected coefficients {}", decoded[0]);
    }
}

// Key parameters: n=728, N=1024; LWE and GLWE share the ciphertext modulus.
// Noise sigmas below are in coefficient units; these are arithmetic examples, not security presets.
fn parameters() -> TfheParameters<Word> {
    // NTT requires a prime admitting a 2N-th root, rather than a power-of-two modulus.
    let ring_modulus: Word = 1_125_899_906_826_241;
    let modulus = BarrettModulus::new(ring_modulus);
    let q = ring_modulus as f64;

    // None retains floor(modulus_bits / log_basis) levels; it need not cover every low bit.
    let full = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };

    TfheParameters::try_from_config(TfheConfig {
        small_lwe: LweEncryptionParameters::new(
            LweDimension::new(728),
            modulus,
            SecretKeyDistr::fixed_hamming_weight_binary(728, 32),
            3.2 * q / 16384.0,
        ),
        accumulator_dimension: GlweDimension::new(1),
        poly_length: PolyLength::new(N),
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        blind_rotation: GadgetEncryptionConfig {
            decomposition: full,
            noise_standard_deviation: 6.4,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: full,
            noise_standard_deviation: 6.4,
        },
        pbs_order: PbsOrder::BootstrapKeyswitch,
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
            level_count: Some(DecompositionLevelCount::new(2)),
        },
        trace: GadgetEncryptionConfig {
            decomposition: internal,
            noise_standard_deviation: 6.4,
        },
        scheme_switch: GadgetEncryptionConfig {
            decomposition: internal,
            noise_standard_deviation: 6.4,
        },
    }
}
