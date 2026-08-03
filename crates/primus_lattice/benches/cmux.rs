use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftEngine, FftTable, RustFftTable};
use primus_lattice::{
    context::{FourierExternalProductContext, NttExternalProductContext},
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
    let basis = ApproxSignedBasis::<u64>::new(None, 8, Some(4));
    let control = FourierGgswOwned::zero(
        components * basis.decompose_length() * components * fft.fourier_length(),
    );
    let ct0 = TorusGlwe::new(vec![1u64; components * fft.poly_length()]);
    let ct1 = TorusGlwe::new(vec![2u64; components * fft.poly_length()]);
    let mut output: TorusGlwe<Vec<u64>> = TorusGlwe::zero(components * fft.poly_length());
    let mut context = FourierExternalProductContext::new(dimension, fft.poly_length());

    c.bench_function("cmux/fourier/n1024/k1/l4", |b| {
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
    let basis = ApproxSignedBasis::new(Some(MODULUS), 8, Some(4));
    let control: NttGgsw<Vec<u32>> =
        NttGgsw::zero(components * basis.decompose_length() * components * ntt.poly_length());
    let ct0 = Glwe::new(vec![1u32; components * ntt.poly_length()]);
    let ct1 = Glwe::new(vec![2u32; components * ntt.poly_length()]);
    let mut output: Glwe<Vec<u32>> = Glwe::zero(components * ntt.poly_length());
    let mut context = NttExternalProductContext::new(dimension, ntt.poly_length());

    c.bench_function("cmux/ntt/n1024/k1/l4", |b| {
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
