//! Fourier evaluation uses the public API and shared representative parameters.

use std::hint::black_box;

use criterion::{Criterion, SamplingMode, Throughput};
use primus_encoding::RoundedCodec;
use primus_fft::{FftTable, TorusFftValue};
use primus_modulus::{NativeModulus, PowOf2Modulus};
use primus_ntru::SecretKeyDistr;
use primus_tfhe::BlindRotationConfig;
use primus_tfhe_ntru_fourier::{KeyGenerator, TfheContext};
use primus_tfhe_ntru_lut::{FourierLookupTableEvaluator, HighPrecisionLookupTable};
use primus_tfhe_test_support::parameters::ntru;
use rand::{SeedableRng, rngs::StdRng};

use super::{
    CONFIG, INPUT, Workload, benchmark_lut_creation, check_repetition, diagnostics::Diagnostics,
};

// Registers repeated, dense and cross-output shared LUT workloads for this backend and word width.
pub fn benchmark<T: TorusFftValue, Table: FftTable>(c: &mut Criterion, backend: &str) {
    for sparse in [false, true] {
        for workload in [Workload::Polynomial, Workload::Dense, Workload::Shared] {
            benchmark_workload::<T, Table>(c, backend, workload, sparse);
        }
    }
}

// Measures LUT construction and evaluation separately. Criterion filters defer costly
// evaluation fixtures until needed; setup and validation remain outside timed iterations.
fn benchmark_workload<T: TorusFftValue, Table: FftTable>(
    c: &mut Criterion,
    backend: &str,
    workload: Workload,
    sparse: bool,
) {
    let parameters = ntru::circuit(
        NativeModulus::<T>::new(),
        SecretKeyDistr::fixed_hamming_weight_binary(800, 32),
    );
    let input_codec =
        RoundedCodec::new(T::as_from(8u32), parameters.external_lwe().cipher_modulus());
    let kind = if sparse { "sparse" } else { "classic" };
    let name = format!(
        "lookup/{backend}/u{}/{kind}/n800_h32_N1024/c8_d5_o8{}",
        T::BITS,
        workload.suffix()
    );
    if !sparse {
        benchmark_lut_creation(c, &name, &parameters, workload);
    }
    let diagnostics = Diagnostics::new(&name);
    let mut fixture = None;
    let mut verified = false;
    let mut group = c.benchmark_group(&name);
    group.sampling_mode(SamplingMode::Flat);
    group.throughput(Throughput::Elements(CONFIG.output_chunk_count as u64));
    group.bench_function("evaluate", |b| {
        let (context, client, server, table, lift, input) = fixture.get_or_insert_with(|| {
            let context =
                TfheContext::<T, Table, PowOf2Modulus<T>>::from_parameters(parameters.clone());
            let mut rng = StdRng::seed_from_u64(42);
            let (client, server) = diagnostics.setup("client_and_server_keys", || {
                let mut generator = KeyGenerator::new(&context);
                let client = generator.try_generate_client_key(&mut rng).unwrap();
                let blind_rotation = if sparse {
                    BlindRotationConfig::Sparse {
                        copy_count: 3,
                        bucket_count: 64,
                    }
                } else {
                    BlindRotationConfig::Classic
                };
                let server = generator
                    .try_generate_server_key(
                        &client,
                        blind_rotation,
                        Some(ntru::cbs::<T>()),
                        &mut rng,
                    )
                    .unwrap();
                (client, server)
            });
            let table = diagnostics.setup("public_lut", || {
                HighPrecisionLookupTable::try_new(
                    context.parameters().poly_length(),
                    context.parameters().accumulator_ntru().cipher_modulus(),
                    &input_codec,
                    CONFIG,
                    |x, output| workload.digit::<T>(x, output),
                )
                .unwrap()
            });
            check_repetition(&table, workload);
            // Lift generation is independent of sparse buckets and only paid by
            // plans that need it. This fixture selects BR's basis and sigma=0.7.
            let lift = diagnostics.setup("public_lift", || {
                if sparse && table.needs_public_lift() {
                    Some(
                        KeyGenerator::new(&context)
                            .try_generate_public_lift_key(
                                client.accumulator_ntru_secret_key(),
                                context.parameters().blind_rotation(),
                                &mut rng,
                            )
                            .unwrap(),
                    )
                } else {
                    None
                }
            });
            // Identical encrypted input for classic/sparse over the same fixed client.
            let mut rng = StdRng::seed_from_u64(43);
            let encryptor = context
                .encryptor(client.external_lwe_secret_key(), &input_codec)
                .unwrap();
            let input: Vec<_> = (0..CONFIG.input_chunk_count)
                .map(|i| {
                    encryptor
                        .encrypt_padded(T::as_from((INPUT >> (2 * i)) & 3), &mut rng)
                        .unwrap()
                })
                .collect();
            (context, client, server, table, lift, input)
        });
        let mut evaluator = diagnostics.setup("workspace", || {
            FourierLookupTableEvaluator::try_new(
                context,
                server,
                lift.as_ref()
                    .map(|key| (key.as_view(), context.parameters().blind_rotation())),
                table,
            )
            .unwrap()
        });
        let mut output = diagnostics.setup("outputs", || evaluator.allocate_output());
        if !verified {
            diagnostics.evaluate(|| evaluator.evaluate_to(input, &mut output));
            let decryptor = context
                .decryptor(client.external_lwe_secret_key(), &input_codec)
                .unwrap();
            for (i, chunk) in output.iter().enumerate() {
                assert_eq!(
                    decryptor.decrypt(chunk.as_view()).unwrap(),
                    workload.digit::<T>(INPUT, i)
                );
            }
            diagnostics.phases(output.iter().enumerate().map(|(i, chunk)| {
                (
                    decryptor.decrypt_phase(chunk.as_view()).unwrap().as_into(),
                    workload.digit::<T>(INPUT, i).as_into(),
                )
            }));
            verified = true;
        }
        b.iter(|| evaluator.evaluate_to(black_box(input), black_box(&mut output)));
    });
    group.finish();
}
