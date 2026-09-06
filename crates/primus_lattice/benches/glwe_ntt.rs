use std::hint::black_box;

mod support;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_lattice::{
    GadgetSize, GlweSize,
    context::NttGlweExternalProductContext,
    ggsw::Ggsw,
    glwe::{Glwe, NttGlwe},
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, UintNttTable};
use support::{LOG_B, PRODUCT_CASES};

fn ntt(c: &mut Criterion, log_n: u32, levels: usize, dimension: usize) {
    const Q: u32 = 132_120_577;
    let modulus = BarrettModulus::new(Q);
    let table = UintNttTable::new(log_n, modulus).unwrap();
    let exponent = table.poly_length() / 3;
    let basis = ApproxSignedBasis::new(Some(Q), LOG_B, Some(levels));
    let size = GadgetSize::new(GlweSize::new(dimension, table.poly_length()), levels);
    let glwe_len = size.glwe_size().glwe_len();
    let input = Glwe::new(
        (0..glwe_len)
            .map(|i| ((i as u64 * 0x9e37_79b9 + 1) % u64::from(Q)) as u32)
            .collect::<Vec<_>>(),
    );
    let key = Ggsw::new(
        (0..size.ggsw_len())
            .map(|i| ((i as u64 * 65_537 + 7) % u64::from(Q)) as u32)
            .collect::<Vec<_>>(),
    )
    .into_ntt_form(&table);
    let mut output = Glwe::new(vec![0u32; glwe_len]);
    let mut ntt_output = NttGlwe::new(vec![0u32; glwe_len]);
    let mut context = NttGlweExternalProductContext::new(size);

    let mut group = c.benchmark_group(format!(
        "glwe/ntt/u32/q{Q}/n{}/k{dimension}/logb{LOG_B}/l{levels}",
        table.poly_length()
    ));
    group.throughput(Throughput::Elements(glwe_len as u64));
    group.bench_function("external_product_coeff", |b| {
        b.iter(|| {
            black_box(&key).external_product_to(
                black_box(&input),
                black_box(&mut output),
                black_box(&basis),
                black_box(modulus),
                black_box(&table),
                black_box(&mut context),
            )
        });
    });
    group.bench_function("external_product_ntt", |b| {
        b.iter(|| {
            black_box(&key).external_product_ntt_to(
                black_box(&input),
                black_box(&mut ntt_output),
                black_box(&basis),
                black_box(modulus),
                black_box(&table),
                black_box(&mut context),
            )
        });
    });
    group.bench_function(format!("cmux_monomial_e{exponent}"), |b| {
        b.iter(|| {
            black_box(&key).cmux_monomial_to(
                black_box(&input),
                black_box(exponent),
                black_box(&mut output),
                black_box(&basis),
                black_box(modulus),
                black_box(&table),
                black_box(&mut context),
            )
        });
    });
    group.finish();
}

fn benchmarks(c: &mut Criterion) {
    for &(log_n, levels) in PRODUCT_CASES {
        ntt(c, log_n, levels, 1);
    }
    ntt(c, 10, 3, 2);
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);
