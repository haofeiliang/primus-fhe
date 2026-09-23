//! Complete PBS: `NLev[1]` initialization, blind rotation, key switching and extraction.
//! PBS outputs/scratch and key-generator workspace are reused; input encryption is not timed.
//! u32/u64, the native torus with RustFFT/TfheFFT; fixed-seed Boolean and 2+2 bit workloads.
//! Binary/ternary PBS and server-key generation (drop outside timing).
//! Regression workload, not a matched-security backend comparison.
//!
//! SIMD: use cargo +nightly bench with --features simd.
//! cargo bench -p primus_tfhe_ntru_fourier --bench pbs

use primus_test_allocations::{CountingAllocator, measure};
use primus_tfhe_test_support::benchmark::{PBS_WORKLOADS, PbsWorkload};
use std::hint::black_box;

use rand::{SeedableRng, rngs::StdRng};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use primus_fft::{FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_tfhe_ntru_fourier::{BooleanGate, TfheContext, TfheParameters};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn backend<T: TorusFftValue, Table: FftTable>(
    c: &mut Criterion,
    label: &str,
    distr: SecretKeyDistr,
    workload: PbsWorkload,
) {
    let n = workload.poly_length;
    let label = format!(
        "{label}/{}/n{n}/small_lwe{}",
        workload.name, workload.lwe_dimension
    );
    let modulus = NativeModulus::new();
    let external_lwe = LweParameters::new(
        workload.lwe_dimension,
        T::as_from(workload.plaintext_modulus),
        modulus,
        distr,
        0.7,
    );
    let accumulator = NtruParameters::new(
        n,
        T::as_from(workload.plaintext_modulus),
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let client = NtruParameters::new(
        n,
        T::as_from(workload.plaintext_modulus),
        modulus,
        distr,
        0.7,
    );
    let parameters = TfheParameters::try_new(
        external_lwe,
        NlevParameters::with_ntru_params(&accumulator, 9, None),
        NlevParameters::with_ntru_params(&client, 9, None),
    )
    .unwrap();
    let table = Table::new(n.trailing_zeros()).unwrap();
    let context = TfheContext::try_new(parameters, table).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let ((client_key, server_key), keys) =
        measure(|| context.try_generate_keys(None, &mut rng).unwrap());
    let encryptor = context.encryptor(&client_key).unwrap();
    let input_domain = workload.plaintext_modulus as usize / 2;
    let input = encryptor.encrypt_padded(T::ONE, &mut rng).unwrap();
    let lut = context
        .parameters()
        .compile_lookup_table_fn(|x| T::as_from((x + input_domain - 1) % (input_domain)))
        .unwrap();
    let mut output = input.clone();
    let (mut evaluator, scratch) = measure(|| context.evaluator(&server_key).unwrap());
    let (_, online) = measure(|| evaluator.apply_lookup_table_to(&input, &lut, &mut output));
    assert_eq!(online.count, 0);
    let phase = context
        .decryptor(&client_key)
        .unwrap()
        .decrypt_phase(&output)
        .unwrap();
    let error = phase.into_torus_f64().abs();
    assert!(
        error < 0.5 / f64::from(workload.plaintext_modulus),
        "fixed fixture exceeds the decoding margin"
    );
    eprintln!(
        "{label}: client+server heap={} B, evaluator heap={} B, phase error/q={error:.6e}",
        keys.allocated_bytes - keys.released_bytes,
        scratch.allocated_bytes - scratch.released_bytes
    );
    let decryptor = context.decryptor(&client_key).unwrap();
    for message in 0..input_domain {
        let probe = encryptor
            .encrypt_padded(T::as_from(message), &mut rng)
            .unwrap();
        evaluator.apply_lookup_table_to(&probe, &lut, &mut output);
        assert_eq!(
            decryptor.decrypt(&output).unwrap(),
            T::as_from((message + input_domain - 1) % (input_domain))
        );
    }
    let mut key_generator = primus_tfhe_ntru_fourier::KeyGenerator::new(&context);
    c.bench_function(&format!("{label}/server_keygen"), |b| {
        b.iter_batched(
            || (),
            |_| {
                key_generator
                    .try_generate_server_key(&client_key, None, &mut rng)
                    .unwrap()
            },
            BatchSize::PerIteration,
        );
    });

    c.bench_function(&format!("{label}/complete_pbs_reused_output"), |bencher| {
        bencher.iter(|| {
            evaluator.apply_lookup_table_to(
                black_box(&input),
                black_box(&lut),
                black_box(&mut output),
            );
        });
    });
    if workload.plaintext_modulus == 4 {
        let boolean_encryptor = context.boolean_encryptor(&client_key).unwrap();
        let lhs = boolean_encryptor.encrypt(true, &mut rng).unwrap();
        let rhs = boolean_encryptor.encrypt(false, &mut rng).unwrap();
        let mut result = lhs.clone();
        let mut boolean_evaluator = context.boolean_evaluator(&server_key).unwrap();
        let boolean_decryptor = context.boolean_decryptor(&client_key).unwrap();
        boolean_evaluator.evaluate_binary_to(BooleanGate::And, &lhs, &rhs, &mut result);
        assert!(!boolean_decryptor.decrypt(&result).unwrap());
        boolean_evaluator.mux_to(&lhs, &lhs, &rhs, &mut result);
        assert!(boolean_decryptor.decrypt(&result).unwrap());

        c.bench_function(&format!("{label}/boolean_and"), |b| {
            b.iter(|| {
                boolean_evaluator.evaluate_binary_to(
                    BooleanGate::And,
                    black_box(&lhs),
                    black_box(&rhs),
                    black_box(&mut result),
                )
            });
        });
        c.bench_function(&format!("{label}/boolean_mux"), |b| {
            b.iter(|| {
                boolean_evaluator.mux_to(
                    black_box(&lhs),
                    black_box(&lhs),
                    black_box(&rhs),
                    black_box(&mut result),
                )
            });
        });
    }
    // Each iteration produces the same 3/4 function outputs. Compare shared
    // BR/KS against separate PBS calls; k=3 also exercises a padded fourth slot.
    // All tables, keys and outputs are reused. Four interleaved lanes need
    // a separate noise/geometry budget at t=32, so keep this on Boolean.
    if distr.is_ternary() || workload.plaintext_modulus != 4 {
        return;
    }
    for count in [3, 4] {
        let value = |input: usize, output| T::as_from((input + output) % input_domain);
        let many = context
            .parameters()
            .compile_interleaved_lookup_table_fn(count, value)
            .unwrap();
        let singles: Vec<_> = (0..count)
            .map(|output| {
                context
                    .parameters()
                    .compile_lookup_table_fn(|input| value(input, output))
                    .unwrap()
            })
            .collect();
        let mut outputs = vec![input.clone(); count];
        for message in 0..input_domain {
            let probe = encryptor
                .encrypt_padded(T::as_from(message), &mut rng)
                .unwrap();
            evaluator.apply_interleaved_lookup_table_to(&probe, &many, &mut outputs);
            for (index, (single, output)) in singles.iter().zip(&mut outputs).enumerate() {
                let expected = value(message, index);
                assert_eq!(decryptor.decrypt(output).unwrap(), expected);
                evaluator.apply_lookup_table_to(&probe, single, output);
                assert_eq!(decryptor.decrypt(output).unwrap(), expected);
            }
        }

        for shared in [false, true] {
            let kind = if shared { "many" } else { "separate" };
            c.bench_function(
                &format!("{label}/complete_pbs_{kind}_{count}_reused_outputs"),
                |b| {
                    b.iter(|| {
                        if shared {
                            evaluator.apply_interleaved_lookup_table_to(
                                black_box(&input),
                                black_box(&many),
                                black_box(&mut outputs),
                            );
                        } else {
                            for (table, output) in singles.iter().zip(&mut outputs) {
                                evaluator.apply_lookup_table_to(
                                    black_box(&input),
                                    black_box(table),
                                    black_box(output),
                                );
                            }
                        }
                        black_box(&outputs);
                    });
                },
            );
        }
    }
}

fn pbs(c: &mut Criterion) {
    for workload in PBS_WORKLOADS {
        for (suffix, distr) in [
            ("binary", SecretKeyDistr::UniformBinary),
            ("ternary", SecretKeyDistr::UniformTernary),
        ] {
            backend::<u32, RustFftTable>(
                c,
                &format!("ntru_fourier/rustfft/u32/{suffix}"),
                distr,
                workload,
            );
            backend::<u32, TfheFftTable>(
                c,
                &format!("ntru_fourier/tfhe/u32/{suffix}"),
                distr,
                workload,
            );
            backend::<u64, RustFftTable>(
                c,
                &format!("ntru_fourier/rustfft/u64/{suffix}"),
                distr,
                workload,
            );
            backend::<u64, TfheFftTable>(
                c,
                &format!("ntru_fourier/tfhe/u64/{suffix}"),
                distr,
                workload,
            );
        }
    }
}

criterion_group! { name = benches; config = Criterion::default().sample_size(20).warm_up_time(std::time::Duration::from_secs(1)).measurement_time(std::time::Duration::from_secs(5)); targets = pbs }
criterion_main!(benches);
