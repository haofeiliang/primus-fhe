//! Turn an encrypted score in 0..64 into 17 numeric threshold flags with one MVB.
//!
//! Run: `cargo run --release -p primus_tfhe_glwe_ntt --example mvb_thresholds`
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_decompose::DecompositionBaseLog;
use primus_glwe::SecretKeyDistr;
use primus_lattice::{GlweDimension, LweDimension};
use primus_modulus::BarrettModulus;
use primus_ntt::U64NttTable as Table;
use primus_poly::PolyLength;
use primus_tfhe::BlindRotationAlgorithm;
use primus_tfhe_glwe::{BlindRotationConfig, LweConfig};
use primus_tfhe_glwe_ntt::{
    DecompositionConfig, FactorizedEvaluator, GadgetEncryptionConfig, PbsMessageConfig, PbsOrder,
    PbsParameters, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};

// This example uses u64 coefficients with the explicit parameters below.
type Word = u64;
const N: usize = 1024;

const DOMAIN: usize = 64;
const OUTPUTS: usize = 17;

fn main() {
    let parameters = parameters();
    let context = TfheContext::<Word, Table>::try_from_parameters(parameters).unwrap();

    // Numeric threshold flags use Scaled t=2; the input keeps Rounded t=128.
    let codecs = context
        .parameters()
        .factorized_pbs_codecs(PbsMessageConfig::new(128).with_output_modulus(2))
        .unwrap();
    let thresholds: Vec<_> = (1..=OUTPUTS).map(|i| i * DOMAIN / (OUTPUTS + 1)).collect();

    // Client: keep client_key and the decryptor; give server_key to the server.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context
        .try_generate_keys(BlindRotationAlgorithm::Classic, None, &mut rng)
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
    let mut flags = [0; OUTPUTS];

    // Server: MVB keeps all 64 inputs; interleaving 17 outputs fits only 32 here.
    let program = context
        .compile_factorized_lookup_table_fn(&codecs, DOMAIN, OUTPUTS, |score, i| {
            Word::from(score >= thresholds[i])
        })
        .unwrap();
    let mut pbs = context.evaluator(&server_key).unwrap();
    let mut evaluator = FactorizedEvaluator::new(&pbs);
    let mut outputs = vec![context.allocate_lwe_ciphertext(); OUTPUTS];

    for score in [12, 45] {
        // Client -> server: send the encrypted score.
        encryptor
            .encrypt_padded_to(score, input.as_mut_view(), &mut rng)
            .unwrap();

        // Server -> client: return one ciphertext per threshold, reusing all buffers.
        evaluator.apply_lookup_table_to(input.as_view(), &program, &mut outputs, &mut pbs);

        // Client: decrypt with the agreed Scaled output codec.
        for (i, output) in outputs.iter().enumerate() {
            flags[i] = decryptor.decrypt(output.as_view()).unwrap();
            assert_eq!(flags[i], Word::from(score as usize >= thresholds[i]));
        }
        println!("score={score}, thresholds={thresholds:?}, flags={flags:?}");
    }
}

// Key parameters: n=728, N=1024; LWE and GLWE share the ciphertext modulus.
// Noise sigmas below are in coefficient units; these are arithmetic examples, not security presets.
fn parameters() -> PbsParameters<Word> {
    // NTT requires a prime admitting a 2N-th root, rather than a power-of-two modulus.
    let ring_modulus: Word = 1_125_899_906_826_241;
    let modulus = BarrettModulus::new(ring_modulus);
    let q = ring_modulus as f64;

    // None retains floor(modulus_bits / log_basis) levels; it need not cover every low bit.
    let full = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };

    BlindRotationConfig {
        small_lwe: LweConfig {
            dimension: LweDimension::new(728),
            cipher_modulus: modulus.into(),
            secret_key_distr: SecretKeyDistr::fixed_hamming_weight_binary(728, 32),
            noise_standard_deviation: 3.2 * q / 16384.0,
        },
        acc_dimension: GlweDimension::new(1),
        acc_poly_length: PolyLength::new(N),
        bsk_secret_distr: SecretKeyDistr::SparseTernary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: full,
            noise_standard_deviation: 6.4,
        },
        algorithm: BlindRotationAlgorithm::Classic,
    }
    .try_prepare()
    .and_then(|parameters| {
        parameters.try_with_key_switching(
            GadgetEncryptionConfig {
                decomposition: full,
                noise_standard_deviation: 6.4,
            },
            PbsOrder::KeyswitchBootstrap,
        )
    })
    .unwrap()
}
