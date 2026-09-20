//! Complete classic/sparse CBS in both orders and FFT engines at n/h/N=728/32/1024.
//! Keys, four encrypted inputs, validation and allocation are outside timing.
//! Functional/cost profile, not production security or failure-rate parameters.
//!
//! cargo bench -p primus_tfhe_glwe_fourier --bench circuit_bootstrap
//! cargo +nightly bench -p primus_tfhe_glwe_fourier --bench circuit_bootstrap --features simd

#[path = "../examples/support/circuit_bootstrap.rs"]
mod profile;

use criterion::{Criterion, SamplingMode, criterion_group, criterion_main};
use primus_fft::{FftTable, RustFftTable, TfheFftTable};
use primus_glwe::{FourierGlweDecryptContext, FourierGlweSecretKey};
use primus_poly::Polynomial;
use primus_test_allocations as allocations;
use primus_tfhe_glwe_fourier::{
    CircuitBootstrapEvaluator, CircuitBootstrapParameters, ClientKey, KeyGenerator, PbsOrder,
};
use rand::{SeedableRng, rngs::StdRng};
use std::hint::black_box;

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

fn bench_backend<Table: FftTable>(c: &mut Criterion, backend: &str) {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let context = profile::context::<Table>(order);
        let mut rng = StdRng::seed_from_u64(profile::SEED);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        let mut generator = KeyGenerator::new(&context);
        let (classic, classic_bytes) = allocations::measure(|| {
            generator
                .try_generate_server_key(&client, None, &mut rng)
                .unwrap()
        });
        let (sparse, sparse_bytes) = allocations::measure(|| {
            generator
                .try_generate_sparse_server_key(&client, 3, 2 * profile::WEIGHT, None, &mut rng)
                .unwrap()
        });
        let parameters = CircuitBootstrapParameters::try_from_config(
            context.parameters(),
            profile::circuit_bootstrap(),
        )
        .unwrap();
        // Share CBS material. The temporary generator and its scratch are released
        // inside the measurement window, leaving only the returned key's storage.
        let (key, cbs_bytes) = allocations::measure(|| {
            context
                .try_generate_circuit_bootstrap_key(&client, parameters, &mut rng)
                .unwrap()
        });
        let parameters = key.parameters();
        let encryptor = context.encryptor(&client).unwrap();
        let bits = [1u64, 0, 1, 0];
        let inputs = bits.map(|bit| encryptor.encrypt_padded(bit, &mut rng).unwrap());
        let mut accumulator = context.accumulator_client(&client).unwrap();
        let messages = [0, 1].map(|offset| {
            (0..profile::N)
                .map(|i| ((i + offset) % 4) as u64)
                .collect::<Vec<_>>()
        });
        let choices = messages
            .each_ref()
            .map(|message| accumulator.encrypt(message, &mut rng));
        let mut selected = context.allocate_accumulator_ciphertext();
        let mut decoded = vec![0; profile::N];
        let glwe = context.parameters().accumulator_glwe();
        let mut fft = context.new_fft_engine();
        let secret =
            FourierGlweSecretKey::from_coeff_secret_key(client.glwe_secret_key(), &mut fft);
        let mut decrypt = FourierGlweDecryptContext::new(profile::N);
        let mut phase = Polynomial::<Vec<u64>>::zero(profile::N);
        let tolerance = parameters.output_basis().scalar_iter().min().unwrap() / 4;
        eprintln!(
            "{backend}/{order:?}: server bytes classic={}, sparse={}; CBS key bytes={}",
            classic_bytes.allocated_bytes - classic_bytes.released_bytes,
            sparse_bytes.allocated_bytes - sparse_bytes.released_bytes,
            cbs_bytes.allocated_bytes - cbs_bytes.released_bytes
        );
        let mut group = c.benchmark_group(format!(
            "fourier_cbs/{backend}/{order:?}/n728/h32/N1024/output_logb8_l3"
        ));
        group.sampling_mode(SamplingMode::Flat);
        for (name, server) in [("classic", &classic), ("sparse", &sparse)] {
            let (mut evaluator, workspace) = allocations::measure(|| {
                CircuitBootstrapEvaluator::try_from_parts(&context, server, parameters, &key)
                    .unwrap()
            });
            let mut output = evaluator.allocate_output();
            // Check both bits, every output row/level and a nonconstant CMUX.
            // Large diagnostics stay in setup, outside timing and ordinary CI tests.
            for (&bit, input) in bits.iter().zip(&inputs) {
                let (_, online) = allocations::measure(|| {
                    evaluator.circuit_bootstrap_to(input, &mut output);
                    evaluator.cmux_to(&output, &choices[0], &choices[1], &mut selected);
                    accumulator.decrypt_to(&selected, &mut decoded);
                });
                assert_eq!(online.count, 0);
                assert_eq!(decoded, messages[bit as usize]);
                for (row, levels) in output
                    .iter_glev(parameters.output_size().fourier_glev_len())
                    .enumerate()
                {
                    for (scalar, ciphertext) in parameters
                        .output_basis()
                        .scalar_iter()
                        .zip(levels.iter_glwe(glwe.size().fourier_glwe_len()))
                    {
                        secret.phase_to(&ciphertext, &mut phase, &mut fft, &mut decrypt);
                        for (i, &actual) in phase.as_ref().iter().enumerate() {
                            let coefficient = if row == 1 {
                                u64::from(i == 0)
                            } else {
                                (client.glwe_secret_key().as_slice()[i] as u64).wrapping_neg()
                            };
                            let error = actual
                                .wrapping_sub(coefficient.wrapping_mul(scalar).wrapping_mul(bit));
                            assert!(
                                error.min(error.wrapping_neg()) < tolerance,
                                "{backend}/{order:?}/{name}, row {row}, scale {scalar}"
                            );
                        }
                    }
                }
            }
            eprintln!(
                "{backend}/{order:?}/{name}: evaluator bytes={}, output bytes={}",
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
fn circuit_bootstrap(c: &mut Criterion) {
    bench_backend::<RustFftTable>(c, "rustfft");
    bench_backend::<TfheFftTable>(c, "tfhe_fft");
}
criterion_group!(benches, circuit_bootstrap);
criterion_main!(benches);
