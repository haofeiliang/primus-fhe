// cargo bench -p primus_lattice --bench cmux

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable};
use primus_lattice::{
    GadgetSize, GlweSize,
    context::{FourierGlweExternalProductContext, NttGlweExternalProductContext},
    ggsw::{FourierGgswOwned, NttGgsw},
    glwe::{Glwe, TorusGlwe},
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, UintNttTable};

fn fourier_cmux(c: &mut Criterion) {
    let fft = RustFftTable::new(10).unwrap();
    let mut engine = FftEngine::new(&fft);
    let dimension = 1;
    let components = dimension + 1;
    let basis = ApproxSignedBasis::<u64>::new(None, 8, Some(3));
    let control_len = components * basis.decompose_length() * components * fft.fourier_length();
    let control = FourierGgswOwned::new(
        (0..control_len)
            .map(|i| {
                let value = (i % 31 + 1) as f64 / 32.0;
                Complex64::new(value, -value * 0.5)
            })
            .collect(),
    );
    let glwe_len = components * fft.poly_length();
    let ct0: TorusGlwe<Vec<u64>> = TorusGlwe::new(
        (0..glwe_len)
            .map(|i| (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15))
            .collect(),
    );
    let ct1: TorusGlwe<Vec<u64>> = TorusGlwe::new(
        (0..glwe_len)
            .map(|i| {
                (i as u64)
                    .wrapping_mul(0xd1b5_4a32_d192_ed03)
                    .wrapping_add(1)
            })
            .collect(),
    );
    let mut output: TorusGlwe<Vec<u64>> = TorusGlwe::zero(components * fft.poly_length());
    let mut context = FourierGlweExternalProductContext::new(GadgetSize::new(
        GlweSize::new(dimension, fft.poly_length()),
        basis.decompose_length(),
    ));

    c.bench_function("cmux/fourier/n1024/k1/logb8/l3", |b| {
        b.iter(|| {
            black_box(&control).cmux_to(
                black_box(&ct0),
                black_box(&ct1),
                black_box(&mut output),
                black_box(&basis),
                black_box(&mut engine),
                black_box(&mut context),
            )
        });
    });
}

fn ntt_cmux(c: &mut Criterion) {
    const MODULUS: u32 = 132_120_577;

    let modulus = BarrettModulus::new(MODULUS);
    let ntt = UintNttTable::new(10, modulus).unwrap();
    let dimension = 1;
    let components = dimension + 1;
    let basis = ApproxSignedBasis::new(Some(MODULUS), 8, Some(3));
    let control_len = components * basis.decompose_length() * components * ntt.poly_length();
    let control: NttGgsw<Vec<u32>> = NttGgsw::new(
        (0..control_len)
            .map(|i| ((i as u64 * 65_537 + 1) % MODULUS as u64) as u32)
            .collect(),
    );
    let glwe_len = components * ntt.poly_length();
    let ct0: Glwe<Vec<u32>> = Glwe::new(
        (0..glwe_len)
            .map(|i| ((i as u64 * 17 + 1) % MODULUS as u64) as u32)
            .collect(),
    );
    let ct1: Glwe<Vec<u32>> = Glwe::new(
        (0..glwe_len)
            .map(|i| ((i as u64 * 29 + 2) % MODULUS as u64) as u32)
            .collect(),
    );
    let mut output: Glwe<Vec<u32>> = Glwe::zero(components * ntt.poly_length());
    let mut context = NttGlweExternalProductContext::new(GadgetSize::new(
        GlweSize::new(dimension, ntt.poly_length()),
        basis.decompose_length(),
    ));

    c.bench_function("cmux/ntt/n1024/k1/logb8/l3", |b| {
        b.iter(|| {
            black_box(&control).cmux_to(
                black_box(&ct0),
                black_box(&ct1),
                black_box(&mut output),
                black_box(&basis),
                black_box(modulus),
                black_box(&ntt),
                black_box(&mut context),
            )
        });
    });
}

criterion_group!(benches, fourier_cmux, ntt_cmux);
criterion_main!(benches);
