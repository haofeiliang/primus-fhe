//! Use sparse GLWE PBS to return message, carry and parity from one encrypted input.
//!
//! Run: `cargo run --release -p primus_tfhe_glwe_fourier --example fourier_sparse`
//! For u64, change Word to u64; for TFHE-FFT, use TfheFftTable as Table.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_decompose::DecompositionBaseLog;
use primus_encoding::RoundedCodec;
use primus_fft::RustFftTable as Table;
use primus_glwe::SecretKeyDistr;
use primus_lattice::{GlweDimension, LweDimension};
use primus_lwe::LweParametersInner;
use primus_modulus::NativeModulus;
use primus_tfhe_glwe_fourier::{
    ClientKey, DecompositionConfig, KeyGenerator, PbsOrder, TfheConfig, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

// Set false to run the same interleaved ManyLUT with classic PBS.
const SPARSE: bool = true;

// The explicit parameters below select bases and moduli for this coefficient word.
type Word = u32;
const N: usize = 1024;
const ORDER: PbsOrder = PbsOrder::BootstrapKeyswitch;

// Key parameters: n=728, N=1024; LWE and GLWE share the ciphertext modulus.
// Noise sigmas below are in coefficient units; these are arithmetic examples, not security presets.
fn parameters() -> TfheParameters<Word> {
    let modulus = NativeModulus::<Word>::new();
    let q = 2f64.powi(Word::BITS as i32);

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
        small_lwe: LweParametersInner::new(
            LweDimension::new(728),
            modulus,
            SecretKeyDistr::fixed_hamming_weight_binary(728, 32),
            3.2 * q / 16384.0,
        ),
        accumulator_dimension: GlweDimension::new(1),
        poly_length: N,
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 6.4,
        blind_rotation: full,
        key_switching: full,
        pbs_order: ORDER,
    })
    .unwrap()
}

fn main() {
    let parameters = parameters();
    let context = TfheContext::<Word, Table>::from_parameters(parameters);
    // The input uses padded t=16; all three outputs use t=8 at the same modulus.
    let output_codec = RoundedCodec::new(8, context.parameters().small_lwe().cipher_modulus());

    // Public message encoding is independent of the evaluation keys.
    let input_codec = RoundedCodec::new(16 as Word, context.parameters().cipher_modulus());

    // Client: explicitly request sparse evaluation material from this fixed-weight secret.
    let mut rng = StdRng::seed_from_u64(42);
    let mut generator = KeyGenerator::new(&context);
    let client_key = ClientKey::generate(context.parameters(), &mut rng);
    // Three copies, 64 buckets. Map retries retain the same client secret.
    let server_key = if SPARSE {
        generator.try_generate_sparse_server_key(&client_key, 3, 64, None, &mut rng)
    } else {
        generator.try_generate_server_key(&client_key, None, &mut rng)
    }
    .unwrap();
    // Ordinary messages borrow only the external secret from the setup bundle.
    let external_secret = client_key.external_lwe_secret_key();
    let encryptor = context.encryptor(external_secret, &input_codec).unwrap();
    let decryptor = context.decryptor(external_secret, &input_codec).unwrap();
    let mut input = context.allocate_lwe_ciphertext();

    // Server: receive server_key; compile three public functions sharing one rotation.
    let compiler = context
        .parameters()
        .lookup_table_compiler(&input_codec)
        .unwrap()
        .try_with_output_codec(&output_codec)
        .unwrap();
    let lut = compiler
        .compile_interleaved_fn(3, |m, i| match i {
            0 => (m % 4) as Word,
            1 => (m / 4) as Word,
            _ => (m % 2) as Word,
        })
        .unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let mut outputs = vec![context.allocate_lwe_ciphertext(); 3];

    for message in [7 as Word, 2] {
        // Client -> server: send an encrypted padded input in 0..8.
        encryptor
            .encrypt_padded_to(message, input.as_mut_view(), &mut rng)
            .unwrap();

        // Server -> client: return message, carry and parity, reusing the evaluator.
        evaluator.apply_interleaved_lookup_table_to(input.as_view(), &lut, &mut outputs);

        // Client: decode with the output codec, not the input's t=16 codec.
        for (output, expected) in outputs.iter().zip([message % 4, message / 4, message % 2]) {
            let value =
                output_codec.decode_value(decryptor.decrypt_phase(output.as_view()).unwrap());
            assert_eq!(value, expected);
        }
        println!("input {message}: message/carry/parity decoded correctly");
    }
}
