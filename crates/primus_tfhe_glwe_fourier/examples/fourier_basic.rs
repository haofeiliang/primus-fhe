//! Compute x % 4 with one LUT and reuse the PBS evaluator for a second request.
//!
//! Run: `cargo run --release -p primus_tfhe_glwe_fourier --example fourier_basic --features rustfft`
//! To use TfheFftTable, switch the Table import, this target's
//! required-features and the command above to tfhe-fft.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_fft::RustFftTable as Table;
use primus_glwe::SecretKeyDistr;
use primus_lattice::{GlweDimension, LweDimension};
use primus_lwe::LweEncryptionParameters;
use primus_modulus::NativeModulus;
use primus_poly::PolyLength;
use primus_tfhe_glwe_fourier::{
    DecompositionConfig, Evaluator, GadgetEncryptionConfig, LookupTable, PbsMessageConfig,
    PbsOrder, RoundedPbsCodecs, ServerKey, TfheConfig, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

// This example uses u64 coefficients with the explicit parameters below.
type Word = u64;
const N: usize = 2048;

fn main() {
    let parameters = parameters();
    let context = TfheContext::<Word, Table>::from_parameters(parameters);

    // Input and output messages both use t=32, independently of the keys.
    let codecs = context
        .parameters()
        .pbs_codecs(PbsMessageConfig::new(32))
        .unwrap();

    // Client: keep client_key secret; send only server_key to the server.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context.try_generate_keys(None, &mut rng).unwrap();
    // Ordinary messages borrow only the external secret from the setup bundle.
    let external_secret = client_key.external_lwe_secret_key();
    let encryptor = context
        .encryptor(external_secret, codecs.input_codec())
        .unwrap();
    let decryptor = context
        .decryptor(external_secret, codecs.output_codec())
        .unwrap();
    let mut input = context.allocate_lwe_ciphertext();

    // Server: prepare public LUT and reusable buffers without the client secret.
    let (lut, mut evaluator) = prepare_server(&context, &server_key, &codecs);
    let mut output = context.allocate_lwe_ciphertext();

    for message in [7, 2] {
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

// Server setup receives only public context, encoding and evaluation keys.
// The LUT and workspace are prepared once, then reused for both requests.
fn prepare_server<'a>(
    context: &'a TfheContext<Word, Table>,
    server_key: &'a ServerKey<Word>,
    codecs: &RoundedPbsCodecs<Word, NativeModulus<Word>>,
) -> (LookupTable<Word>, Evaluator<'a, Word, Table>) {
    let compiler = context.parameters().lookup_table_compiler(codecs).unwrap();
    let lut = compiler.compile_fn(|x| (x % 4) as Word).unwrap();
    let evaluator = context.evaluator(server_key).unwrap();
    (lut, evaluator)
}

// Key parameters: n=866, N=2048; LWE and GLWE share the ciphertext modulus.
// Noise sigmas below are in coefficient units; these are arithmetic examples, not security presets.
fn parameters() -> TfheParameters<Word> {
    let modulus = NativeModulus::<Word>::new();
    let q = 2f64.powi(64); // Native u64 modulus, represented only for noise scaling.

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
        blind_rotation: GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(23),
                level_count: Some(DecompositionLevelCount::new(1)),
            },
            noise_standard_deviation: (q * 2.845267479601915e-15).max(6.4),
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(3),
                level_count: Some(DecompositionLevelCount::new(5)),
            },
            noise_standard_deviation: (q * 2.845267479601915e-15).max(6.4),
        },
        pbs_order: PbsOrder::BootstrapKeyswitch,
    })
    .unwrap()
}
