use primus_encoding::RoundedCodec;
// Ntt evaluation uses the public API and shared representative parameters.
use std::hint::black_box;

use super::{CONFIG, INPUT, Workload, benchmark_lut_creation, check_repetition, heap};
use criterion::{Criterion, SamplingMode, Throughput};
use primus_integer::FheUint;
use primus_modulus::PowOf2Modulus;
use primus_ntru::SecretKeyDistr;
use primus_ntt::MonomialNttTable;
use primus_test_allocations::measure;
use primus_tfhe_ntru_lut::{HighPrecisionLookupTable, NttLookupTableEvaluator};
use primus_tfhe_ntru_ntt::{KeyGenerator, TfheContext};
use primus_tfhe_test_support::parameters::ntru;
use primus_tfhe_test_support::parameters::ntt_circuit_modulus;
use rand::{SeedableRng, rngs::StdRng};

// Registers repeated, dense and cross-output shared LUT workloads for this backend and word width.
pub fn benchmark<T: FheUint, Table: MonomialNttTable<ValueT = T>>(c: &mut Criterion) {
    for sparse in [false, true] {
        for workload in [Workload::Polynomial, Workload::Dense, Workload::Shared] {
            benchmark_workload::<T, Table>(c, workload, sparse);
        }
    }
}

// Measures LUT construction and evaluation separately. Criterion filters defer costly
// evaluation fixtures until needed; setup and validation remain outside timed iterations.
fn benchmark_workload<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    c: &mut Criterion,
    workload: Workload,
    sparse: bool,
) {
    let backend = "ntt";
    let parameters = ntru::circuit(
        ntt_circuit_modulus::<T>(),
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
    let mut fixture = None;
    let mut reported = false;
    let mut group = c.benchmark_group(&name);
    group.sampling_mode(SamplingMode::Flat);
    group.throughput(Throughput::Elements(CONFIG.output_chunk_count as u64));
    group.bench_function("evaluate", |b| {
        let (context, client, server, table, lift, input) = fixture.get_or_insert_with(|| {
            let context =
                TfheContext::<T, Table, PowOf2Modulus<T>>::try_from_parameters(parameters.clone())
                    .unwrap();
            let mut rng = StdRng::seed_from_u64(42);
            let ((client, server), keys) = measure(|| {
                let mut generator = KeyGenerator::new(&context);
                let client = generator.try_generate_client_key(&mut rng).unwrap();
                let server = if sparse {
                    generator.try_generate_sparse_server_key(
                        &client,
                        3,
                        64,
                        Some(ntru::cbs::<T>()),
                        &mut rng,
                    )
                } else {
                    generator.try_generate_server_key(&client, Some(ntru::cbs::<T>()), &mut rng)
                }
                .unwrap();
                (client, server)
            });
            heap(&format!("{name}/client_and_server_keys"), keys);
            let (table, storage) = measure(|| {
                HighPrecisionLookupTable::try_new(
                    context.parameters(),
                    &input_codec,
                    CONFIG,
                    |x, output| workload.digit::<T>(x, output),
                )
                .unwrap()
            });
            heap(&format!("{name}/public_lut"), storage);
            check_repetition(&table, workload);
            // Lift generation is independent of sparse buckets and only paid by
            // plans that need it. This fixture selects BR's basis and sigma=0.7.
            let (lift, storage) = measure(|| {
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
            heap(&format!("{name}/public_lift"), storage);
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
        let (mut evaluator, workspace) = measure(|| {
            NttLookupTableEvaluator::try_new(
                context,
                server,
                lift.as_ref()
                    .map(|key| (key.as_view(), context.parameters().blind_rotation())),
                table,
            )
            .unwrap()
        });
        let (mut output, output_memory) = measure(|| evaluator.allocate_output());
        if !reported {
            heap(&format!("{name}/workspace"), workspace);
            heap(&format!("{name}/outputs"), output_memory);
            // Instrument only this untimed call. Keep decryption outside the
            // allocation probe so its client workspace is not charged to lookup.
            let (_, online) = measure(|| evaluator.evaluate_to(input, &mut output));
            assert_eq!(online.count, 0);
            eprintln!("online_allocations,{name},{}", online.count);
            let decryptor = context
                .decryptor(client.external_lwe_secret_key(), &input_codec)
                .unwrap();
            let mut max_phase_error = 0u64;
            for (i, chunk) in output.iter().enumerate() {
                assert_eq!(
                    decryptor.decrypt(chunk.as_view()).unwrap(),
                    workload.digit::<T>(INPUT, i)
                );
                let phase: u64 = decryptor.decrypt_phase(chunk.as_view()).unwrap().as_into();
                let expected: u64 = workload.digit::<T>(INPUT, i).as_into();
                let distance = phase.abs_diff(expected * (1u64 << 21)); // q/t, q=2^24 and t=8.
                max_phase_error = max_phase_error.max(distance.min((1u64 << 24) - distance));
            }
            eprintln!("phase_error_max,{name},{max_phase_error}");
            reported = true;
        }
        b.iter(|| evaluator.evaluate_to(black_box(input), black_box(&mut output)));
    });
    group.finish();
}
