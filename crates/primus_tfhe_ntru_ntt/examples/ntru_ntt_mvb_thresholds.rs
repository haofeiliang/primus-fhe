//! Turn an encrypted score in 0..64 into 17 numeric threshold flags with one MVB.
//!
//! Run: `cargo run --release -p primus_tfhe_ntru_ntt --example ntru_ntt_mvb_thresholds`
//! For u64, change Word to u64 and U32NttTable to U64NttTable.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_decompose::DecompositionBaseLog;
use primus_encoding::RoundedCodec;
use primus_encoding::ScaledCodec;
use primus_lattice::LweDimension;
use primus_lwe::LweParametersInner;
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_ntru::SecretKeyDistr;
use primus_ntt::U32NttTable as Table;
use primus_tfhe_ntru_ntt::{
    DecompositionConfig, KeyGenerator, TfheConfig, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

// Set true to evaluate the same factorized MVB program with sparse PBS.
const SPARSE: bool = false;

// The explicit parameters below select bases and moduli for this coefficient word.
type Word = u32;
const N: usize = 1024;

const DOMAIN: usize = 64;
const OUTPUTS: usize = 17;

// Key parameters: n=728, N=1024; independent external LWE q=2^24.
// Noise sigmas below are in coefficient units; these are arithmetic examples, not security presets.
fn parameters() -> TfheParameters<Word, PowOf2Modulus<Word>> {
    // NTT requires a prime admitting a 2N-th root, rather than a power-of-two modulus.
    let ring_modulus = if Word::BITS == 32 {
        132_120_577
    } else {
        1_125_899_906_826_241u64
    } as Word;
    let modulus = BarrettModulus::new(ring_modulus);
    let lwe_modulus: Word = 1 << 24;

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
        external_lwe: LweParametersInner::new(
            LweDimension::new(728),
            PowOf2Modulus::new(lwe_modulus),
            SecretKeyDistr::fixed_hamming_weight_binary(728, 32),
            3.2 * lwe_modulus as f64 / 16384.0,
        ),
        accumulator_modulus: modulus, // Ring Q; distinct from the external LWE q.
        poly_length: N,
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 0.7,
        blind_rotation: full,
        key_switching: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(3),
            level_count: None,
        },
        key_switching_noise_standard_deviation: 3.2, // Return key switch in the q domain.
    })
    .unwrap()
}

fn main() {
    let parameters = parameters();
    let context = TfheContext::<Word, Table, _>::try_from_parameters(parameters).unwrap();
    // Public message encoding at external q, chosen independently of key generation.
    let input_codec = RoundedCodec::new(128, context.parameters().external_lwe().cipher_modulus());
    let thresholds: Vec<_> = (1..=OUTPUTS).map(|i| i * DOMAIN / (OUTPUTS + 1)).collect();
    // MVB compiles at Q and returns at q=2^24: retain one Scaled codec for each.
    let table_codec = ScaledCodec::new(2, context.parameters().accumulator_ntru().cipher_modulus());
    let output_codec = ScaledCodec::new(2, context.parameters().external_lwe().cipher_modulus());

    // Client: keep client_key and the decryptor; give server_key to the server.
    let mut rng = StdRng::seed_from_u64(42);
    let mut generator = KeyGenerator::new(&context);
    let client_key = generator.try_generate_client_key(&mut rng).unwrap();
    let server_key = if SPARSE {
        generator
            .try_generate_sparse_server_key(&client_key, 3, 64, None, &mut rng)
            .unwrap()
    } else {
        generator
            .try_generate_server_key(&client_key, None, &mut rng)
            .unwrap()
    };
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
            &table_codec,
            DOMAIN,
            OUTPUTS,
            |score, i| Word::from(score >= thresholds[i]),
        )
        .unwrap();
    let mut pbs = context.evaluator(&server_key).unwrap();
    let mut evaluator = primus_tfhe_ntru_ntt::FactorizedEvaluator::new(&pbs);
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
