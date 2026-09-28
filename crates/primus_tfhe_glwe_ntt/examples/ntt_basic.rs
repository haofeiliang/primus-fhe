//! Compute x % 4 with one LUT and reuse the PBS evaluator for a second request.
//!
//! Run: `cargo run --release -p primus_tfhe_glwe_ntt --example ntt_basic`
//! For u64, change Word to u64 and U32NttTable to U64NttTable.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_glwe::SecretKeyDistr;
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntt::U32NttTable as Table;
use primus_tfhe_glwe_ntt::{
    DecompositionConfig, PbsOrder, TfheConfig, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

// The explicit parameters below select bases and moduli for this coefficient word.
type Word = u32;
const N: usize = 2048;
const ORDER: PbsOrder = PbsOrder::BootstrapKeyswitch;

// Public parameters: n=866, N=2048, t=32; LWE and GLWE share the ciphertext modulus.
// Noise sigmas below are in coefficient units; these are arithmetic examples, not security presets.
fn parameters() -> TfheParameters<Word> {
    // NTT requires a prime admitting a 2N-th root, rather than a power-of-two modulus.
    let ring_modulus = if Word::BITS == 32 {
        132_120_577
    } else {
        1_125_899_906_826_241u64
    } as Word;
    let modulus = BarrettModulus::new(ring_modulus);
    let q = ring_modulus as f64;

    // (log2 radix, retained levels) for blind rotation and key switching.
    let (br_log, br_levels, ks_log, ks_levels) = if Word::BITS == 32 {
        (5, 5, 2, 13)
    } else {
        (23, 1, 3, 5)
    };

    TfheParameters::try_from_config(TfheConfig {
        small_lwe: LweParameters::new(
            866,
            32, // Padded inputs occupy 0..16.
            modulus,
            SecretKeyDistr::UniformBinary,
            q * 2.046151696979124e-6,
        ),
        accumulator_dimension: 1,
        poly_length: N,
        accumulator_secret_key_distr: SecretKeyDistr::UniformBinary,
        accumulator_noise_standard_deviation: (q * 2.845267479601915e-15).max(6.4),
        blind_rotation: DecompositionConfig {
            log_basis: br_log,
            level_count: Some(br_levels),
        },
        key_switching: DecompositionConfig {
            log_basis: ks_log,
            level_count: Some(ks_levels),
        },
        pbs_order: ORDER,
    })
    .unwrap()
}

fn main() {
    let parameters = parameters();
    let context = TfheContext::<Word, Table>::try_from_parameters(parameters).unwrap();

    // Client: keep client_key secret; send only server_key to the server.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context.try_generate_keys(None, &mut rng).unwrap();
    let encryptor = context.encryptor(&client_key).unwrap();
    let decryptor = context.decryptor(&client_key).unwrap();
    let mut input = context.allocate_lwe_ciphertext();

    // Server: compile the public function and allocate reusable evaluation state.
    // Outputs use the same t=32 codec, so the client's ordinary decrypt decodes them.
    let lut = context
        .parameters()
        .compile_lookup_table_fn(|x| (x % 4) as Word)
        .unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let mut output = context.allocate_lwe_ciphertext();

    for message in [7 as Word, 2] {
        // Client -> server: send one encrypted, padded input.
        encryptor
            .encrypt_padded_to(message, &mut input, &mut rng)
            .unwrap();

        // Server -> client: return the result, reusing the LUT and buffers.
        evaluator.apply_lookup_table_to(&input, &lut, &mut output);

        // Client: decrypt with the original external LWE secret.
        let result = decryptor.decrypt(&output).unwrap();
        assert_eq!(result, message % 4);
        println!("f({message}) = {result}");
    }
}
