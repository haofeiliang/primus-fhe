//! Turn an encrypted score in 0..64 into 17 numeric threshold flags with one MVB.
//!
//! Run: `cargo run --release -p primus_tfhe_glwe_fourier --example fourier_mvb_thresholds --features rustfft`
//! For u64, change Word to u64. To use TfheFftTable, also switch this target's
//! required-features and the command above to tfhe-fft.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_decompose::DecompositionBaseLog;
use primus_encoding::RoundedCodec;
use primus_encoding::ScaledCodec;
use primus_fft::RustFftTable as Table;
use primus_glwe::SecretKeyDistr;
use primus_lattice::{GlweDimension, LweDimension};
use primus_lwe::LweEncryptionParameters;
use primus_modulus::NativeModulus;
use primus_poly::PolyLength;
use primus_tfhe_glwe_fourier::{
    BlindRotationConfig, ClientKey, DecompositionConfig, FactorizedEvaluator, KeyGenerator,
    PbsOrder, TfheConfig, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

// To use sparse BR, choose BlindRotationConfig::Sparse { copy_count: 3, bucket_count: 64 }.
const BLIND_ROTATION: BlindRotationConfig = BlindRotationConfig::Classic;

// The explicit parameters below select bases and moduli for this coefficient word.
type Word = u32;
const N: usize = 1024;
const ORDER: PbsOrder = PbsOrder::KeyswitchBootstrap;

const DOMAIN: usize = 64;
const OUTPUTS: usize = 17;

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
        small_lwe: LweEncryptionParameters::new(
            LweDimension::new(728),
            modulus,
            SecretKeyDistr::fixed_hamming_weight_binary(728, 32),
            3.2 * q / 16384.0,
        ),
        accumulator_dimension: GlweDimension::new(1),
        poly_length: PolyLength::new(N),
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
    let thresholds: Vec<_> = (1..=OUTPUTS).map(|i| i * DOMAIN / (OUTPUTS + 1)).collect();
    // Numeric 0/1 flags use Scaled encoding, distinct from the Boolean gate codec.
    let output_codec = ScaledCodec::new(2, context.parameters().small_lwe().cipher_modulus());

    // Public message encoding is independent of the evaluation keys.
    let input_codec = RoundedCodec::new(128 as Word, context.parameters().cipher_modulus());

    // Client: keep client_key and the decryptor; give server_key to the server.
    let mut rng = StdRng::seed_from_u64(42);
    let client_key = ClientKey::generate(context.parameters(), &mut rng);
    let mut generator = KeyGenerator::new(&context);
    let server_key = generator
        .try_generate_server_key(&client_key, BLIND_ROTATION, None, &mut rng)
        .unwrap();
    // Ordinary messages borrow only the external secret from the setup bundle.
    let external_secret = client_key.external_lwe_secret_key();
    let encryptor = context.encryptor(external_secret, &input_codec).unwrap();
    let decryptor = context.decryptor(external_secret, &input_codec).unwrap();
    let mut input = context.allocate_lwe_ciphertext();
    let mut flags = vec![0; OUTPUTS];

    // Server: MVB keeps all 64 inputs; interleaving 17 outputs fits only 32 here.
    let program = context
        .compile_factorized_lookup_table_fn(
            &input_codec,
            &output_codec,
            DOMAIN,
            OUTPUTS,
            |score, i| Word::from(score >= thresholds[i]),
        )
        .unwrap();
    let mut pbs = context.evaluator(&server_key).unwrap();
    let mut evaluator = FactorizedEvaluator::new(&pbs);
    let mut outputs = vec![context.allocate_lwe_ciphertext(); OUTPUTS];

    for score in [12 as Word, 45] {
        // Client -> server: send the encrypted score.
        encryptor
            .encrypt_padded_to(score, input.as_mut_view(), &mut rng)
            .unwrap();

        // Server -> client: return one ciphertext per threshold, reusing all buffers.
        evaluator.apply_lookup_table_to(input.as_view(), &program, &mut outputs, &mut pbs);

        // Client: decrypt phases and decode with the agreed output codec.
        for (flag, output) in flags.iter_mut().zip(&outputs) {
            *flag = output_codec.decode_value(decryptor.decrypt_phase(output.as_view()).unwrap());
        }
        for (&flag, &threshold) in flags.iter().zip(&thresholds) {
            assert_eq!(flag, Word::from(score as usize >= threshold));
        }
        println!("score={score}, thresholds={thresholds:?}, flags={flags:?}");
    }
}
