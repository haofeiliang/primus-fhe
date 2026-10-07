//! Use sparse GLWE PBS to return message, carry and parity from one encrypted input.
//!
//! Run: `cargo run --release -p primus_tfhe_glwe_ntt --example ntt_sparse`
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_decompose::DecompositionBaseLog;
use primus_glwe::SecretKeyDistr;
use primus_lattice::{GlweDimension, LweDimension};
use primus_lwe::LweEncryptionParameters;
use primus_modulus::BarrettModulus;
use primus_ntt::U64NttTable as Table;
use primus_poly::PolyLength;
use primus_tfhe_glwe_ntt::{
    BlindRotationConfig, DecompositionConfig, GadgetEncryptionConfig, PbsMessageConfig, PbsOrder,
    TfheConfig, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

// This example uses u64 coefficients with the explicit parameters below.
type Word = u64;
const N: usize = 1024;

fn main() {
    let parameters = parameters();
    let context = TfheContext::<Word, Table>::try_from_parameters(parameters).unwrap();

    // Padded input t=16 and all three Rounded outputs t=8 share one configuration.
    let codecs = context
        .parameters()
        .pbs_codecs(PbsMessageConfig::new(16).with_output_modulus(8))
        .unwrap();

    // Client: generate sparse BR material from the fixed-weight secret.
    let mut rng = StdRng::seed_from_u64(42);
    // Three copies, 64 buckets. Map retries retain the same client secret.
    let (client_key, server_key) = context
        .try_generate_keys(
            BlindRotationConfig::Sparse {
                copy_count: 3,
                bucket_count: 64,
            },
            None,
            &mut rng,
        )
        .unwrap();
    // Ordinary messages borrow only the external secret from the setup bundle.
    let external_secret = client_key.external_lwe_secret_key();
    let encryptor = context
        .encryptor(external_secret, codecs.input_codec())
        .unwrap();
    let output_decryptor = context
        .decryptor(external_secret, codecs.output_codec())
        .unwrap();
    let mut input = context.allocate_lwe_ciphertext();

    // Server: receive server_key; compile three public functions sharing one rotation.
    let compiler = context.parameters().lookup_table_compiler(&codecs).unwrap();
    let lut = compiler
        .compile_interleaved_fn(3, |m, i| match i {
            0 => (m % 4) as Word,
            1 => (m / 4) as Word,
            _ => (m % 2) as Word,
        })
        .unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let mut outputs = vec![context.allocate_lwe_ciphertext(); 3];

    for message in [7, 2] {
        // Client -> server: send an encrypted padded input in 0..8.
        encryptor
            .encrypt_padded_to(message, input.as_mut_view(), &mut rng)
            .unwrap();

        // Server -> client: return message, carry and parity, reusing the evaluator.
        evaluator.apply_interleaved_lookup_table_to(input.as_view(), &lut, &mut outputs);

        // Client: decrypt all three results in the configured t=8 output space.
        for (output, expected) in outputs.iter().zip([message % 4, message / 4, message % 2]) {
            let value = output_decryptor.decrypt(output.as_view()).unwrap();
            assert_eq!(value, expected);
        }
        println!("input {message}: message/carry/parity decoded correctly");
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
