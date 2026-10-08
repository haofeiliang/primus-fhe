//! Compute x % 4 and x / 4 from one encrypted input with interleaved ManyLUT.
//!
//! Run: `cargo run --release -p primus_tfhe_glwe_ntt --example ntt_many_lut`
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

    // One padded input in 0..8 uses Rounded t=16; both outputs use Rounded t=8.
    // with_output_modulus(8) configures the two returned message spaces.
    let codecs = context
        .parameters()
        .pbs_codecs(PbsMessageConfig::new(16).with_output_modulus(8))
        .unwrap();

    // Client: keep the external secret; send server_key to the server.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context
        .try_generate_keys(BlindRotationConfig::Classic, None, &mut rng)
        .unwrap();
    // Ordinary messages borrow only the external secret from the setup bundle.
    let external_secret = client_key.external_lwe_secret_key();
    let encryptor = context
        .encryptor(external_secret, codecs.input_codec())
        .unwrap();
    let decryptor = context
        .decryptor(external_secret, codecs.output_codec())
        .unwrap();
    let mut input = context.allocate_lwe_ciphertext();

    // Server: interleave two functions in one LUT to share a blind rotation.
    let compiler = context.parameters().lookup_table_compiler(&codecs).unwrap();
    let lut = compiler
        .compile_interleaved_fn(2, |x, output| {
            if output == 0 {
                (x % 4) as Word
            } else {
                (x / 4) as Word
            }
        })
        .unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let mut outputs = vec![context.allocate_lwe_ciphertext(); 2];

    for message in [7, 2] {
        // Client -> server: send an encrypted padded input in 0..8.
        encryptor
            .encrypt_padded_to(message, input.as_mut_view(), &mut rng)
            .unwrap();

        // Server -> client: return two ciphertexts, reusing the LUT and buffers.
        evaluator.apply_interleaved_lookup_table_to(input.as_view(), &lut, &mut outputs);

        // Client: decrypt both results with the Rounded t=8 output codec.
        let results = [
            decryptor.decrypt(outputs[0].as_view()).unwrap(),
            decryptor.decrypt(outputs[1].as_view()).unwrap(),
        ];
        assert_eq!(results, [message % 4, message / 4]);
        println!(
            "input {message}: x % 4 = {}, x / 4 = {}",
            results[0], results[1]
        );
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
