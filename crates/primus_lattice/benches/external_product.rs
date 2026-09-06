// cargo bench -p primus_lattice --bench external_product

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable, TfheFftTable};
use primus_lattice::{
    GadgetSize, GlweSize,
    context::{FourierGlweExternalProductContext, NttGlweExternalProductContext},
    ggsw::{FourierGgswOwned, NttGgsw},
    glwe::{Glwe, NttGlwe},
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, UintNttTable};

fn fourier_external_product(c: &mut Criterion) {
    fourier_with_table(c, "rustfft", RustFftTable::new(10).unwrap());
    fourier_with_table(c, "tfhe", TfheFftTable::new(10).unwrap());
}

fn fourier_with_table(c: &mut Criterion, backend: &str, fft: impl FftTable) {
    let mut engine = FftEngine::new(&fft);
    let dimension = 1;
    let components = dimension + 1;
    let basis = ApproxSignedBasis::<u64>::new(None, 8, Some(3));
    let glwe_len = components * fft.poly_length();
    let input: Glwe<Vec<u64>> = Glwe::new(
        (0..glwe_len)
            .map(|i| {
                (i as u64)
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    .wrapping_add(1)
            })
            .collect(),
    );
    let key_len = components * basis.decompose_length() * components * fft.fourier_length();
    let key = FourierGgswOwned::new(
        (0..key_len)
            .map(|i| {
                let value = (i % 31 + 1) as f64 / 32.0;
                Complex64::new(value, -value * 0.5)
            })
            .collect(),
    );
    let mut output = Glwe::new(vec![0u64; components * fft.poly_length()]);
    let mut context = FourierGlweExternalProductContext::new(GadgetSize::new(
        GlweSize::new(dimension, fft.poly_length()),
        basis.decompose_length(),
    ));
    c.bench_function(
        &format!("external_product/fourier/{backend}/n1024/k1/logb8/l3"),
        |b| {
            b.iter(|| {
                black_box(&key).external_product_to(
                    black_box(&input),
                    black_box(&mut output),
                    black_box(&basis),
                    black_box(&mut engine),
                    black_box(&mut context),
                )
            });
        },
    );
}

fn ntt_external_product(c: &mut Criterion) {
    const MODULUS: u32 = 132_120_577;

    let modulus = BarrettModulus::new(MODULUS);
    let ntt = UintNttTable::new(10, modulus).unwrap();
    let dimension = 1;
    let components = dimension + 1;
    let basis = ApproxSignedBasis::new(Some(MODULUS), 8, Some(3));
    let glwe_len = components * ntt.poly_length();
    let input: Glwe<Vec<u32>> = Glwe::new(
        (0..glwe_len)
            .map(|i| {
                (i as u32)
                    .wrapping_mul(0x9e37_79b9)
                    .wrapping_add(0xd192_ed03)
                    % MODULUS
            })
            .collect(),
    );
    let key_len = components * basis.decompose_length() * components * ntt.poly_length();
    let key: NttGgsw<Vec<u32>> = NttGgsw::new(
        (0..key_len)
            .map(|i| ((i as u64 * 65_537 + 1) % MODULUS as u64) as u32)
            .collect(),
    );
    let mut output = Glwe::new(vec![0u32; glwe_len]);
    let mut ntt_output = NttGlwe::new(vec![0u32; glwe_len]);
    let mut context = NttGlweExternalProductContext::new(GadgetSize::new(
        GlweSize::new(dimension, ntt.poly_length()),
        basis.decompose_length(),
    ));

    c.bench_function("external_product/ntt/n1024/k1/logb8/l3", |b| {
        b.iter(|| {
            black_box(&key).external_product_to(
                black_box(&input),
                black_box(&mut output),
                black_box(&basis),
                black_box(modulus),
                black_box(&ntt),
                black_box(&mut context),
            )
        });
    });
    c.bench_function("external_product/ntt_output/n1024/k1/logb8/l3", |b| {
        b.iter(|| {
            black_box(&key).external_product_ntt_to(
                black_box(&input),
                black_box(&mut ntt_output),
                black_box(&basis),
                black_box(modulus),
                black_box(&ntt),
                black_box(&mut context),
            )
        });
    });
}

criterion_group!(benches, fourier_external_product, ntt_external_product);
criterion_main!(benches);
