//! Complete classic/sparse CBS, including input KS for KeyswitchBootstrap.
//! B6.1 u64 profile: n/h/N=728/32/1024, BR (10,5), output (8,3), c=3, 64 buckets.
//! Functional/cost parameters, not a certified security or failure-probability set.
//! Keys, four encrypted inputs and all workspace are prepared outside timing.
//!
//! cargo bench -p primus_tfhe_glwe_ntt --bench circuit_bootstrap

use std::hint::black_box;

use criterion::{Criterion, SamplingMode, criterion_group, criterion_main};
use primus_glwe::{NttGlweSecretKey, SecretKeyDistr};
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntt::U64NttTable;
use primus_poly::Polynomial;
use primus_test_allocations as allocations;
use primus_tfhe_glwe_ntt::{
    CircuitBootstrapConfig, CircuitBootstrapEvaluator, CircuitBootstrapParameters, ClientKey,
    DecompositionConfig, KeyGenerator, PbsOrder, TfheConfig, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

const N: usize = 1024;
const DIMENSION: usize = 728;
const WEIGHT: usize = 32;
const Q: u64 = 1_125_899_906_826_241;

fn circuit_bootstrap(c: &mut Criterion) {
    let modulus = BarrettModulus::new(Q);
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let parameters = TfheParameters::try_from_config(TfheConfig {
            small_lwe: LweParameters::new(
                DIMENSION,
                4,
                modulus,
                SecretKeyDistr::fixed_hamming_weight_binary(DIMENSION, WEIGHT),
                3.2 * Q as f64 / 16384.0,
            ),
            accumulator_dimension: 1,
            poly_length: N,
            accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
            accumulator_noise_standard_deviation: 0.7,
            blind_rotation: DecompositionConfig {
                log_basis: 10,
                level_count: None,
            },
            key_switching: DecompositionConfig {
                log_basis: 10,
                level_count: Some(4),
            },
            pbs_order: order,
        })
        .unwrap();
        let context = TfheContext::<_, U64NttTable>::try_from_parameters(parameters).unwrap();
        let mut rng = StdRng::seed_from_u64(0x4236_3101);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        let mut generator = KeyGenerator::new(&context);
        let classic = generator
            .try_generate_server_key(&client, None, &mut rng)
            .unwrap();
        let sparse = generator
            .try_generate_sparse_server_key(&client, 3, 2 * WEIGHT, None, &mut rng)
            .unwrap();
        // Share CBS material so that only the BR key and each order's KSK differ.
        let parameters = CircuitBootstrapParameters::try_from_config(
            context.parameters(),
            CircuitBootstrapConfig {
                output: DecompositionConfig {
                    log_basis: 8,
                    level_count: Some(3),
                },
                trace: DecompositionConfig {
                    log_basis: 10,
                    level_count: None,
                },
                trace_noise_standard_deviation: 0.7,
                scheme_switch: DecompositionConfig {
                    log_basis: 10,
                    level_count: None,
                },
                scheme_switch_noise_standard_deviation: 0.7,
            },
        )
        .unwrap();
        let key = generator
            .try_generate_circuit_bootstrap_key(&client, parameters.clone(), &mut rng)
            .unwrap();
        let encryptor = context.encryptor(&client).unwrap();
        let bits = [1u64, 0, 1, 0];
        let inputs = bits.map(|bit| encryptor.encrypt_padded(bit, &mut rng).unwrap());
        let mut accumulator = context.accumulator_client(&client).unwrap();
        let messages = [0, 1].map(|offset| {
            (0..N)
                .map(|i| ((i + offset) % 4) as u64)
                .collect::<Vec<_>>()
        });
        let choices = messages
            .each_ref()
            .map(|message| accumulator.encrypt(message, &mut rng));
        let secret =
            NttGlweSecretKey::from_coeff_secret_key(client.glwe_secret_key(), context.table());
        let mut phase = Polynomial::new(vec![0u64; N]);
        let mut selected = accumulator.allocate_ciphertext();
        let mut decoded = vec![0; N];
        let mut group = c.benchmark_group(format!(
            "glwe_ntt/cbs/u64/n{DIMENSION}/h{WEIGHT}/N{N}/{order:?}/output_logb8_l3"
        ));
        group.sampling_mode(SamplingMode::Flat);
        for (name, server) in [("classic", &classic), ("sparse", &sparse)] {
            let (mut evaluator, workspace) = allocations::measure(|| {
                CircuitBootstrapEvaluator::try_from_parts(&context, server, &parameters, &key)
                    .unwrap()
            });
            let mut output = evaluator.allocate_output();
            // Check every gadget row/level and nonconstant CMUX before timing;
            // this larger diagnostic stays outside the CI test suite.
            for (&bit, input) in bits.iter().zip(&inputs) {
                let (_, online) = allocations::measure(|| {
                    evaluator.circuit_bootstrap_to(input, &mut output);
                    evaluator.cmux_to(&output, &choices[0], &choices[1], &mut selected);
                    accumulator.decrypt_to(&selected, &mut decoded);
                });
                assert_eq!(online.count, 0);
                assert_eq!(decoded, messages[bit as usize]);
                let size = parameters.output_size();
                for (row, glev) in output.iter_ntt_glev(size.glev_len()).enumerate() {
                    let row_secret = client.glwe_secret_key().iter().nth(row);
                    for (scalar, level) in parameters
                        .output_basis()
                        .scalar_iter()
                        .zip(glev.iter_ntt_glwe(size.glwe_size().glwe_len()))
                    {
                        secret.phase_to(&level, &mut phase, modulus, context.table());
                        for (i, &actual) in phase.as_ref().iter().enumerate() {
                            let coefficient =
                                row_secret.map_or(i128::from(i == 0), |s| -i128::from(s[i]));
                            let expected = (coefficient * i128::from(scalar) * i128::from(bit))
                                .rem_euclid(i128::from(Q))
                                as u64;
                            let error = actual.abs_diff(expected);
                            assert!(
                                error.min(Q - error) < scalar / 8,
                                "{order:?}/{name}, row {row}, scale {scalar}"
                            );
                        }
                    }
                }
            }
            eprintln!(
                "{order:?}/{name}: evaluator resident requested bytes={}, output bytes={}",
                workspace.allocated_bytes - workspace.released_bytes,
                std::mem::size_of_val(output.as_ref())
            );
            let mut next_input = 0;
            group.bench_function(name, |b| {
                b.iter(|| {
                    evaluator.circuit_bootstrap_to(
                        black_box(&inputs[next_input]),
                        black_box(&mut output),
                    );
                    next_input = (next_input + 1) % inputs.len();
                    black_box(&output);
                })
            });
        }
        group.finish();
    }
}

criterion_group!(benches, circuit_bootstrap);
criterion_main!(benches);
