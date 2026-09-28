//! Turn an encrypted score in 0..64 into 17 numeric threshold flags with one MVB.
//!
//! Run: `cargo run --release -p primus_tfhe_glwe_fourier --example fourier_mvb_thresholds`
//! For u64, change Word to u64; for TFHE-FFT, use TfheFftTable as Table.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_encoding::ScaledCodec;
use primus_fft::RustFftTable as Table;
use primus_glwe::SecretKeyDistr;
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_tfhe_glwe_fourier::{
    ClientKey, DecompositionConfig, KeyGenerator, PbsOrder, TfheConfig, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

// Set true to evaluate the same factorized MVB program with sparse PBS.
const SPARSE: bool = false;

// The explicit parameters below select bases and moduli for this coefficient word.
type Word = u32;
const N: usize = 1024;
const ORDER: PbsOrder = PbsOrder::KeyswitchBootstrap;

const DOMAIN: usize = 64;
const OUTPUTS: usize = 17;

// Public parameters: n=728, N=1024, t=128; LWE and GLWE share the ciphertext modulus.
// Noise sigmas below are in coefficient units; these are arithmetic examples, not security presets.
fn parameters() -> TfheParameters<Word> {
    let modulus = NativeModulus::<Word>::new();
    let q = 2f64.powi(Word::BITS as i32);

    // None retains floor(modulus_bits / log_basis) levels; it need not cover every low bit.
    let full = DecompositionConfig {
        log_basis: if Word::BITS == 32 { 2 } else { 8 },
        level_count: None,
    };

    TfheParameters::try_from_config(TfheConfig {
        small_lwe: LweParameters::new(
            728,
            128, // Padded inputs occupy 0..64.
            modulus,
            SecretKeyDistr::fixed_hamming_weight_binary(728, 32),
            3.2 * q / 16384.0,
        ),
        accumulator_dimension: 1,
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
    let context = TfheContext::<Word, Table>::try_from_parameters(parameters).unwrap();
    let thresholds: Vec<_> = (1..=OUTPUTS).map(|i| i * DOMAIN / (OUTPUTS + 1)).collect();
    // Numeric 0/1 flags use Scaled encoding, distinct from the Boolean gate codec.
    let output_codec = ScaledCodec::new(2, context.parameters().small_lwe().cipher_modulus());

    // Client: keep client_key and the decryptor; give server_key to the server.
    let mut rng = StdRng::seed_from_u64(42);
    let client_key = ClientKey::generate(context.parameters(), &mut rng);
    let mut generator = KeyGenerator::new(&context);
    let server_key = if SPARSE {
        generator.try_generate_sparse_server_key(&client_key, 3, 64, None, &mut rng)
    } else {
        generator.try_generate_server_key(&client_key, None, &mut rng)
    }
    .unwrap();
    let encryptor = context.encryptor(&client_key).unwrap();
    let decryptor = context.decryptor(&client_key).unwrap();
    let mut input = context.allocate_lwe_ciphertext();
    let mut flags = vec![0; OUTPUTS];

    // Server: MVB keeps all 64 inputs; interleaving 17 outputs fits only 32 here.
    let program = context
        .compile_factorized_lookup_table_fn(&output_codec, DOMAIN, OUTPUTS, |score, i| {
            Word::from(score >= thresholds[i])
        })
        .unwrap();
    let mut evaluator = context.factorized_evaluator(&server_key).unwrap();
    let mut outputs = vec![context.allocate_lwe_ciphertext(); OUTPUTS];

    for score in [12 as Word, 45] {
        // Client -> server: send the encrypted score.
        encryptor
            .encrypt_padded_to(score, &mut input, &mut rng)
            .unwrap();

        // Server -> client: return one ciphertext per threshold, reusing all buffers.
        evaluator.apply_lookup_table_to(&input, &program, &mut outputs);

        // Client: decrypt phases and decode with the agreed output codec.
        for (flag, output) in flags.iter_mut().zip(&outputs) {
            *flag = output_codec.decode_value(decryptor.decrypt_phase(output).unwrap());
        }
        for (&flag, &threshold) in flags.iter().zip(&thresholds) {
            assert_eq!(flag, Word::from(score as usize >= threshold));
        }
        println!("score={score}, thresholds={thresholds:?}, flags={flags:?}");
    }
}
