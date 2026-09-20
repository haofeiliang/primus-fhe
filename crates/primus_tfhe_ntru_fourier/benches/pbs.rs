//! Complete PBS: `NLev[1]` initialization, blind rotation, key switching and extraction.
//! PBS outputs/scratch and key-generator workspace are reused; input encryption is not timed.
//! u32/u64, the native torus with RustFFT/TfheFFT; fixed seed, N = 1024, LWE dimension 800.
//! Binary/ternary PBS and server-key generation (drop outside timing).
//! Regression workload, not a matched-security backend comparison.
//!
//! SIMD: use cargo +nightly bench with --features simd.
//! cargo bench -p primus_tfhe_ntru_fourier --bench pbs

use primus_test_allocations::{CountingAllocator, measure};
use std::hint::black_box;

use rand::{SeedableRng, rngs::StdRng};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use primus_fft::{FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_tfhe_ntru_fourier::{TfheContext, TfheParameters};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn backend<T: TorusFftValue, Table: FftTable>(
    c: &mut Criterion,
    label: &str,
    distr: SecretKeyDistr,
) {
    const N: usize = 1024;
    const LWE_DIMENSION: usize = 800;
    let modulus = NativeModulus::new();
    let external_lwe = LweParameters::new(LWE_DIMENSION, T::as_from(4usize), modulus, distr, 0.7);
    let accumulator = NtruParameters::new(
        N,
        T::as_from(4usize),
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let client = NtruParameters::new(N, T::as_from(4usize), modulus, distr, 0.7);
    let parameters = TfheParameters::try_new(
        external_lwe,
        NlevParameters::with_ntru_params(&accumulator, 9, None),
        NlevParameters::with_ntru_params(&client, 9, None),
    )
    .unwrap();
    let table = Table::new(N.trailing_zeros()).unwrap();
    let context = TfheContext::try_new(parameters, table).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let ((client_key, server_key), keys) =
        measure(|| context.try_generate_keys(None, &mut rng).unwrap());
    let encryptor = context.encryptor(&client_key).unwrap();
    let input = encryptor.encrypt_padded(T::ONE, &mut rng).unwrap();
    let lut = context
        .parameters()
        .compile_lookup_table_slice(&[T::ONE, T::ZERO])
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
        error < 0.125,
        "fixed fixture exceeds the t=4 decoding margin"
    );
    eprintln!(
        "{label}: client+server heap={} B, evaluator heap={} B, phase error/q={error:.6e}",
        keys.allocated_bytes - keys.released_bytes,
        scratch.allocated_bytes - scratch.released_bytes
    );
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
    // Each iteration produces the same 3/4 function outputs. Compare shared
    // BR/KS against separate PBS calls; k=3 also exercises a padded fourth slot.
    // All tables, keys and outputs are reused.
    if T::BITS != 32 || distr.is_ternary() {
        return;
    }
    for count in [3, 4] {
        let value = |input: usize, output| T::as_from((input + output) % 4);
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
    for (suffix, distr) in [
        ("", SecretKeyDistr::UniformBinary),
        ("/ternary", SecretKeyDistr::UniformTernary),
    ] {
        backend::<u32, RustFftTable>(c, &format!("ntru_fourier/rustfft{suffix}"), distr);
        backend::<u32, TfheFftTable>(c, &format!("ntru_fourier/tfhe{suffix}"), distr);
        backend::<u64, RustFftTable>(c, &format!("ntru_fourier/rustfft/u64{suffix}"), distr);
        backend::<u64, TfheFftTable>(c, &format!("ntru_fourier/tfhe/u64{suffix}"), distr);
    }
}

criterion_group!(benches, pbs);
criterion_main!(benches);
