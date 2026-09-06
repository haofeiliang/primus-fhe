use std::hint::black_box;

mod support;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftEngine, FftTable, RustFftTable, TfheFftTable};
use primus_lattice::{
    GadgetSize, GlweSize,
    context::FourierGlweExternalProductContext,
    ggsw::{FourierGgswOwned, Ggsw},
    glwe::Glwe,
};
use support::{LOG_B, PRODUCT_CASES};

fn fourier(
    c: &mut Criterion,
    backend: &str,
    table: impl FftTable,
    levels: usize,
    dimension: usize,
) {
    let mut fft = FftEngine::new(&table);
    let exponent = fft.poly_length() / 3;
    let basis = ApproxSignedBasis::<u64>::new(None, LOG_B, Some(levels));
    let size = GadgetSize::new(GlweSize::new(dimension, fft.poly_length()), levels);
    let glwe_len = size.glwe_size().glwe_len();
    // Deterministic coefficient data gives both FFT backends the same workload
    // in their own evaluation order and normalized torus representation.
    let input = Glwe::new(
        (0..glwe_len)
            .map(|i| {
                (i as u64)
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    .wrapping_add(1)
            })
            .collect::<Vec<_>>(),
    );
    let coeff_key = Ggsw::new(
        (0..size.ggsw_len())
            .map(|i| {
                (i as u64)
                    .wrapping_mul(0xd1b5_4a32_d192_ed03)
                    .wrapping_add(7)
            })
            .collect::<Vec<_>>(),
    );
    let mut key = FourierGgswOwned::zero(size.fourier_ggsw_len());
    coeff_key.write_fourier_form(&mut key, &mut fft);
    let mut output = Glwe::new(vec![0u64; glwe_len]);
    let mut context = FourierGlweExternalProductContext::new(size);

    let mut group = c.benchmark_group(format!(
        "glwe/fourier/{backend}/u64/native/n{}/k{dimension}/logb{LOG_B}/l{levels}",
        fft.poly_length()
    ));
    group.throughput(Throughput::Elements(glwe_len as u64));
    group.bench_function("external_product_coeff", |b| {
        b.iter(|| {
            black_box(&key).external_product_to(
                black_box(&input),
                black_box(&mut output),
                black_box(&basis),
                black_box(&mut fft),
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
                black_box(&mut fft),
                black_box(&mut context),
            )
        });
    });
    group.finish();
}

fn benchmarks(c: &mut Criterion) {
    for &(log_n, levels) in PRODUCT_CASES {
        fourier(c, "rustfft", RustFftTable::new(log_n).unwrap(), levels, 1);
        fourier(c, "tfhe", TfheFftTable::new(log_n).unwrap(), levels, 1);
    }
    fourier(c, "rustfft", RustFftTable::new(10).unwrap(), 3, 2);
    fourier(c, "tfhe", TfheFftTable::new(10).unwrap(), 3, 2);
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);
