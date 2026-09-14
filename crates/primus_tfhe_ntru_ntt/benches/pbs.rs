//! Complete PBS: `NLev[1]` initialization, blind rotation, key switching and extraction.
//! Reuses output and evaluator; key/LUT construction and encryption are not timed.
//! u32, q = 132_120_577; fixed seed, N = 1024, LWE dimension 800.
//! Regression workload, not a matched-security backend comparison.
//!
//! cargo bench -p primus_tfhe_ntru_ntt --bench pbs

use std::hint::black_box;

use rand::{SeedableRng, rngs::StdRng};

use criterion::{Criterion, criterion_group, criterion_main};
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_ntt::{NttTable, U32NttTable};
use primus_tfhe_ntru_ntt::{NtruTfheParameters, TfheContext};

fn pbs(c: &mut Criterion) {
    const N: usize = 1024;
    const LWE_DIMENSION: usize = 800;
    const Q: u32 = 132_120_577;
    let modulus = BarrettModulus::new(Q);
    let external_lwe = LweParameters::new(
        LWE_DIMENSION,
        4,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let accumulator = NtruParameters::new(N, 4, modulus, SecretKeyDistr::SparseTernary, 0.7);
    let client = NtruParameters::new(N, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let parameters = NtruTfheParameters::try_new(
        external_lwe,
        NlevParameters::with_ntru_params(&accumulator, 9, None),
        NlevParameters::with_ntru_params(&client, 9, None),
    )
    .unwrap();
    let table = U32NttTable::new(N.trailing_zeros(), modulus).unwrap();
    let context = TfheContext::try_new(parameters, table).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context.generate_keys(&mut rng).unwrap();
    let encryptor = context.encryptor(&client_key).unwrap();
    let input = encryptor.encrypt_padded(1u32, &mut rng).unwrap();
    let lut = context.compile_lookup_table_slice(&[1u32, 0]).unwrap();
    let mut output = input.clone();
    let mut evaluator = context.evaluator(&server_key).unwrap();

    c.bench_function("ntru_ntt/complete_pbs_reused_output", |bencher| {
        bencher.iter(|| {
            evaluator.apply_lookup_table_to(
                black_box(&input),
                black_box(&lut),
                black_box(&mut output),
            );
        });
    }); // Each iteration produces the same 2/4 function outputs. Compare shared
    // BR/KS against separate PBS calls; all tables, keys and outputs are reused.
    for count in [2, 4] {
        let value = |input: usize, output| ((input + output) % 4) as u32;
        let many = context.compile_many_lookup_table_fn(count, value).unwrap();
        let singles: Vec<_> = (0..count)
            .map(|output| {
                context
                    .compile_lookup_table_fn(|input| value(input, output))
                    .unwrap()
            })
            .collect();
        let mut outputs = vec![input.clone(); count];
        for shared in [false, true] {
            let kind = if shared { "many" } else { "separate" };
            c.bench_function(
                &format!("ntru_ntt/complete_pbs_{kind}_{count}_reused_outputs"),
                |b| {
                    b.iter(|| {
                        if shared {
                            evaluator.apply_many_lookup_table_to(
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

criterion_group!(benches, pbs);
criterion_main!(benches);
