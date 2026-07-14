use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftEngine, FftTable, RustFftTable};
use primus_lattice::{
    context::tfhe::TfheFftContext, ggsw::FourierGgswOwned, glwe::Glwe,
    tfhe::external_product::fourier_external_product_to,
};

fn external_product(c: &mut Criterion) {
    let fft = RustFftTable::new(10).unwrap();
    let mut engine = FftEngine::new(&fft);
    let dimension = 1;
    let components = dimension + 1;
    let basis = ApproxSignedBasis::<u64>::new(None, 8, Some(4));
    let input = Glwe::new(vec![1u64; components * fft.poly_length()]);
    let key = FourierGgswOwned::zero(
        components * basis.decompose_length() * components * fft.fourier_length(),
    );
    let mut output = Glwe::new(vec![0u64; components * fft.poly_length()]);
    let mut context = TfheFftContext::new(dimension, fft.poly_length());
    c.bench_function("external_product/rustfft/n1024/k1/l4", |b| {
        b.iter(|| {
            fourier_external_product_to(
                black_box(&input),
                black_box(&key),
                black_box(&mut output),
                black_box(&basis),
                black_box(&mut engine),
                black_box(&mut context),
            )
        });
    });
}

criterion_group!(benches, external_product);
criterion_main!(benches);
