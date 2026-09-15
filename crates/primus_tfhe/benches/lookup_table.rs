//! Compile and drop one owned raw-output LUT per iteration. Encoding geometry,
//! validation, allocation and coefficient filling are timed; modulus setup is not.
//! N = 1024, u32: varying domain size and output count isolates compilation costs.
//!
//! cargo bench -p primus_tfhe --bench lookup_table

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_reduce::RingContext;
use primus_tfhe::{compile_encoded_lookup_table, compile_encoded_many_lookup_table};

fn compile<M: RingContext<u32>>(c: &mut Criterion, name: &str, modulus: M) {
    const N: usize = 1024;
    let input_modulus = modulus.explicit_value();
    let mut group = c.benchmark_group(format!("lut_compile/u32/{name}/n{N}"));
    for (t, count) in [(4u32, 4), (16, 1), (16, 4), (16, 16), (255, 4)] {
        let domain = t.div_ceil(2) as usize;
        let id = BenchmarkId::new(format!("t{t}"), format!("k{count}"));
        if count == 1 {
            group.bench_function(id, |b| {
                b.iter(|| {
                    black_box(
                        compile_encoded_lookup_table(
                            black_box(domain),
                            black_box(N),
                            black_box(t),
                            input_modulus,
                            modulus,
                            |input| Ok(13 * input as u32),
                        )
                        .unwrap(),
                    )
                });
            });
        } else {
            group.bench_function(id, |b| {
                b.iter(|| {
                    black_box(
                        compile_encoded_many_lookup_table(
                            black_box(domain),
                            black_box(N),
                            black_box(count),
                            black_box(t),
                            input_modulus,
                            modulus,
                            |input, output| Ok(13 * input as u32 + output as u32),
                        )
                        .unwrap(),
                    )
                });
            });
        }
    }
    group.finish();
}

fn lookup_table(c: &mut Criterion) {
    compile(c, "native", NativeModulus::new());
    compile(c, "barrett", BarrettModulus::new(132_120_577));
}

criterion_group!(benches, lookup_table);
criterion_main!(benches);
