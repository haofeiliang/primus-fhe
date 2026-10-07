//! Use an encrypted LWE bit to select between two encrypted ring messages via sparse CBS and CMux.
//!
//! Run: `cargo run --release -p primus_tfhe_glwe_fourier --example fourier_sparse_circuit_bootstrap --features rustfft`
//! To use TfheFftTable, switch the Table import, this target's
//! required-features and the command above to tfhe-fft.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_encoding::{RoundedCodec, ScaledCodec};
use primus_fft::RustFftTable as Table;
use primus_glwe::SecretKeyDistr;
use primus_lattice::{GlweDimension, LweDimension};
use primus_lwe::LweEncryptionParameters;
use primus_modulus::NativeModulus;
use primus_poly::PolyLength;
use primus_tfhe_glwe_fourier::{
    BlindRotationConfig, CircuitBootstrapConfig, CircuitBootstrapEvaluator, ClientKey,
    DecompositionConfig, GadgetEncryptionConfig, KeyGenerator, PbsOrder, TfheConfig, TfheContext,
    TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

// This example uses u64 coefficients with the explicit parameters below.
type Word = u64;
const N: usize = 1024;

fn main() {
    let parameters = parameters();
    let context = TfheContext::<Word, Table>::from_parameters(parameters);

    // Padded t=4 encodes a selection bit independently of the ring messages.
    let selector_codec = RoundedCodec::new(4, context.parameters().cipher_modulus());

    // Client: generate CBS material with the paired keys; send server_key only.
    let mut rng = StdRng::seed_from_u64(42);
    let client_key = ClientKey::generate(context.parameters(), &mut rng);
    let mut generator = KeyGenerator::new(&context);
    // Sparse CBS uses three copies and 64 buckets for the fixed-weight LWE secret.
    let server_key = generator
        .try_generate_server_key(
            &client_key,
            BlindRotationConfig::Sparse {
                copy_count: 3,
                bucket_count: 64,
            },
            Some(circuit_config()),
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
    let mut resources = context
        .bootstrap_resources_from_server_key(&server_key)
        .unwrap();
    let circuit_key = server_key.circuit_bootstrap_key().unwrap();
    let mut cbs =
        CircuitBootstrapEvaluator::try_new(&resources, circuit_key, &selector_codec).unwrap();
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
    let modulus = NativeModulus::<Word>::new();
    let q = 2f64.powi(64); // Native u64 modulus, represented only for noise scaling.

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
