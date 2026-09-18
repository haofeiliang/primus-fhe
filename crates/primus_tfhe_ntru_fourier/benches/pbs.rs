//! Complete PBS: `NLev[1]` initialization, blind rotation, key switching and extraction.
//! Outputs and scratch are reused; setup and encryption are not timed.
//! u32, the native torus with RustFFT/TfheFFT; fixed seed, N = 1024, LWE dimension 800.
//! Regression workload, not a matched-security backend comparison.
//!
//! cargo bench -p primus_tfhe_ntru_fourier --bench pbs

use std::hint::black_box;

use rand::{SeedableRng, rngs::StdRng};

use criterion::{Criterion, criterion_group, criterion_main};
use primus_fft::{FftTable, RustFftTable, TfheFftTable};
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_tfhe_ntru_fourier::{TfheContext, TfheParameters};

fn backend<Table: FftTable>(c: &mut Criterion, backend: &str) {
    const N: usize = 1024;
    const LWE_DIMENSION: usize = 800;
    let modulus = NativeModulus::new();
    let external_lwe = LweParameters::new(
        LWE_DIMENSION,
        4,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let accumulator = NtruParameters::new(N, 4, modulus, SecretKeyDistr::SparseTernary, 0.7);
    let client = NtruParameters::new(N, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let parameters = TfheParameters::try_new(
        external_lwe,
        NlevParameters::with_ntru_params(&accumulator, 9, None),
        NlevParameters::with_ntru_params(&client, 9, None),
    )
    .unwrap();
    let table = Table::new(N.trailing_zeros()).unwrap();
    let context = TfheContext::try_new(parameters, table).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context.try_generate_keys(None, &mut rng).unwrap();
    let encryptor = context.encryptor(&client_key).unwrap();
    let input = encryptor.encrypt_padded(1u32, &mut rng).unwrap();
    let lut = context
        .parameters()
        .compile_lookup_table_slice(context.parameters().input_plaintext_codec(), &[1u32, 0])
        .unwrap();
    let mut output = input.clone();
    let mut evaluator = context.evaluator(&server_key).unwrap();

    c.bench_function(
        &format!("ntru_fourier/{backend}/complete_pbs_reused_output"),
        |bencher| {
            bencher.iter(|| {
                evaluator.apply_lookup_table_to(
                    black_box(&input),
                    black_box(&lut),
                    black_box(&mut output),
                );
            });
        },
    );
    // Each iteration produces the same 3/4 function outputs. Compare shared
    // BR/KS against separate PBS calls; k=3 also exercises a padded fourth slot.
    // All tables, keys and outputs are reused.
    for count in [3, 4] {
        let value = |input: usize, output| ((input + output) % 4) as u32;
        let many = context
            .parameters()
            .compile_interleaved_lookup_table_fn(
                context.parameters().input_plaintext_codec(),
                count,
                value,
            )
            .unwrap();
        let singles: Vec<_> = (0..count)
            .map(|output| {
                context
                    .parameters()
                    .compile_lookup_table_fn(
                        context.parameters().input_plaintext_codec(),
                        |input| value(input, output),
                    )
                    .unwrap()
            })
            .collect();
        let mut outputs = vec![input.clone(); count];
        for shared in [false, true] {
            let kind = if shared { "many" } else { "separate" };
            c.bench_function(
                &format!("ntru_fourier/{backend}/complete_pbs_{kind}_{count}_reused_outputs"),
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
    backend::<RustFftTable>(c, "rustfft");
    backend::<TfheFftTable>(c, "tfhe");
}

criterion_group!(benches, pbs);
criterion_main!(benches);
