//! Compute x % 4 with one LUT and reuse the PBS evaluator for a second request.
//!
//! Run: `cargo run --release -p primus_tfhe_glwe_fourier --example fourier_basic --features rustfft`
//! For u64, change Word to u64. To use TfheFftTable, also switch this target's
//! required-features and the command above to tfhe-fft.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_encoding::RoundedCodec;
use primus_fft::RustFftTable as Table;
use primus_glwe::SecretKeyDistr;
use primus_lattice::{GlweDimension, LweDimension};
use primus_lwe::LweEncryptionParameters;
use primus_modulus::NativeModulus;
use primus_poly::PolyLength;
use primus_tfhe_glwe_fourier::{
    DecompositionConfig, PbsOrder, TfheConfig, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

// The explicit parameters below select bases and moduli for this coefficient word.
type Word = u32;
const N: usize = 2048;
const ORDER: PbsOrder = PbsOrder::BootstrapKeyswitch;

// Key parameters: n=866, N=2048; LWE and GLWE share the ciphertext modulus.
// Noise sigmas below are in coefficient units; these are arithmetic examples, not security presets.
fn parameters() -> TfheParameters<Word> {
    let modulus = NativeModulus::<Word>::new();
    let q = 2f64.powi(Word::BITS as i32);

    // (log2 radix, retained levels) for blind rotation and key switching.
    let (br_log, br_levels, ks_log, ks_levels) = if Word::BITS == 32 {
        (8, 3, 2, 13)
    } else {
        (23, 1, 3, 5)
    };

    TfheParameters::try_from_config(TfheConfig {
        small_lwe: LweEncryptionParameters::new(
            LweDimension::new(866),
            modulus,
            SecretKeyDistr::UniformBinary,
            q * 2.046151696979124e-6,
        ),
        accumulator_dimension: GlweDimension::new(1),
        poly_length: PolyLength::new(N),
        accumulator_secret_key_distr: SecretKeyDistr::UniformBinary,
        accumulator_noise_standard_deviation: (q * 2.845267479601915e-15).max(6.4),
        blind_rotation: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(br_log),
            level_count: Some(DecompositionLevelCount::new(br_levels)),
        },
        key_switching: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(ks_log),
            level_count: Some(DecompositionLevelCount::new(ks_levels)),
        },
        key_switching_noise_standard_deviation: (q * 2.845267479601915e-15).max(6.4),
        pbs_order: ORDER,
    })
    .unwrap()
}

fn main() {
    let parameters = parameters();
    let context = TfheContext::<Word, Table>::from_parameters(parameters);

    // Public message encoding is independent of the evaluation keys.
    let input_codec = RoundedCodec::new(32 as Word, context.parameters().cipher_modulus());

    // Client: keep client_key secret; send only server_key to the server.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context.try_generate_keys(None, &mut rng).unwrap();
    // Ordinary messages borrow only the external secret from the setup bundle.
    let external_secret = client_key.external_lwe_secret_key();
    let encryptor = context.encryptor(external_secret, &input_codec).unwrap();
    let decryptor = context.decryptor(external_secret, &input_codec).unwrap();
    let mut input = context.allocate_lwe_ciphertext();

    // Server: compile the public function and allocate reusable evaluation state.
    // Outputs use the same t=32 codec, so the client's ordinary decrypt decodes them.
    let compiler = context
        .parameters()
        .lookup_table_compiler(&input_codec)
        .unwrap();
    let lut = compiler.compile_fn(|x| (x % 4) as Word).unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let mut output = context.allocate_lwe_ciphertext();

    for message in [7 as Word, 2] {
        // Client -> server: send one encrypted, padded input.
        encryptor
            .encrypt_padded_to(message, input.as_mut_view(), &mut rng)
            .unwrap();

        // Server -> client: return the result, reusing the LUT and buffers.
        evaluator.apply_lookup_table_to(input.as_view(), &lut, output.as_mut_view());

        // Client: decrypt with the original external LWE secret.
        let result = decryptor.decrypt(output.as_view()).unwrap();
        assert_eq!(result, message % 4);
        println!("f({message}) = {result}");
    }
}
