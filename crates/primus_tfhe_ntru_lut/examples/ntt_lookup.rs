//! Independent LWE chunks -> public LUT -> reusable server evaluator -> LWE chunks.
//! Small fixed-seed functional parameters, not a production security parameter set.

use primus_lwe::LweParameters;
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_ntru::SecretKeyDistr;
use primus_ntt::U64NttTable;
use primus_tfhe_ntru::{CircuitBootstrapConfig, DecompositionConfig, TfheConfig, TfheParameters};
use primus_tfhe_ntru_lut::{HighPrecisionLookupTable, LookupTableConfig, NttLookupTableEvaluator};
use primus_tfhe_ntru_ntt::TfheContext;
use rand::{SeedableRng, rngs::StdRng};

// Six base-4 inputs cover 4096 values, exceeding the 256-coefficient ring.
// Four low chunks choose a coefficient; two high chunks choose among 16 tables.
const CONFIG: LookupTableConfig = LookupTableConfig {
    input_chunk_count: 6,
    output_chunk_count: 4,
    coefficient_chunk_count: 4,
};
const CHUNK_BITS: usize = 2;

// Return eight low bits, split into four output chunks independently of input count.
fn function(x: usize) -> usize {
    (x * x + 3 * x + x / 17 + 7) & 255
}

fn main() {
    let backend = "NTT";
    let full = DecompositionConfig {
        log_basis: 8,
        level_count: None,
    };
    let parameters = TfheParameters::try_from_config(TfheConfig {
        external_lwe: LweParameters::new(
            16,
            8,
            PowOf2Modulus::new(1u64 << 24),
            SecretKeyDistr::UniformBinary,
            0.7,
        ),
        accumulator_modulus: BarrettModulus::new(1_125_899_906_826_241u64),
        poly_length: 256,
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 0.7,
        blind_rotation: full,
        key_switching: full,
        key_switching_noise_standard_deviation: 0.7,
    })
    .unwrap();
    let context = TfheContext::<_, U64NttTable, _>::try_from_parameters(parameters).unwrap();
    let mut rng = StdRng::seed_from_u64(0x0048_504c_5554);
    // Client owns independent s (LWE at q) and f (NTRU at Q). Generate the server
    // material from this same pair; only f undergoes ring invertibility screening.
    let (client, server) = context
        .try_generate_keys(
            Some(CircuitBootstrapConfig {
                output: DecompositionConfig {
                    log_basis: 8,
                    level_count: Some(3),
                },
                trace: full,
                trace_noise_standard_deviation: 0.7,
                scheme_switch: full,
                scheme_switch_noise_standard_deviation: 0.7,
            }),
            &mut rng,
        )
        .unwrap();
    let encryptor = context.encryptor(&client).unwrap();
    let decryptor = context.decryptor(&client).unwrap();

    // Public server setup: callback receives the complete input and requested
    // output chunk. Evaluation borrows only context, server key and compiled LUT.
    let table = HighPrecisionLookupTable::try_new(context.parameters(), CONFIG, |x, output| {
        ((function(x) >> (CHUNK_BITS * output)) & 3) as u64
    })
    .unwrap();
    let mut evaluator = NttLookupTableEvaluator::try_new(&context, &server, &table).unwrap();
    let mut input: Vec<_> = (0..CONFIG.input_chunk_count)
        .map(|_| context.allocate_lwe_ciphertext())
        .collect();
    let mut output = evaluator.allocate_output();
    for x in [0, 1, 0x123, 4095, 0] {
        // Client decomposes before encryption; chunks are least-significant first.
        for (i, chunk) in input.iter_mut().enumerate() {
            encryptor
                .encrypt_padded_to(((x >> (CHUNK_BITS * i)) & 3) as u64, chunk, &mut rng)
                .unwrap();
        }
        // Same table, evaluation workspace and output buffers serve every request.
        evaluator.evaluate_to(&input, &mut output);
        let result = output.iter().enumerate().fold(0usize, |value, (i, chunk)| {
            value | ((decryptor.decrypt(chunk).unwrap() as usize) << (CHUNK_BITS * i))
        });
        assert_eq!(result, function(x));
        println!("{backend}: f({x}) = {result}");
    }
}
