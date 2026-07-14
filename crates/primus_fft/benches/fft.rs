use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable, TfheFftTable};

fn bench_forward<Table: FftTable>(c: &mut Criterion, name: &str) {
    let mut group = c.benchmark_group(name);
    for log_n in [9, 10, 11, 12] {
        let fft = Table::new(log_n).unwrap();
        let mut engine = FftEngine::new(&fft);
        let input = vec![1u64; fft.poly_length()];
        let mut output = vec![Complex64::default(); fft.fourier_length()];
        group.bench_with_input(
            BenchmarkId::from_parameter(fft.poly_length()),
            &log_n,
            |b, _| {
                b.iter(|| engine.forward_as_torus(black_box(&input), black_box(&mut output)));
            },
        );
    }
    group.finish();
}

fn bench_inverse<Table: FftTable>(c: &mut Criterion, name: &str) {
    let mut group = c.benchmark_group(name);
    for log_n in [9, 10, 11, 12] {
        let fft = Table::new(log_n).unwrap();
        let mut engine = FftEngine::new(&fft);
        let input = vec![1u64; fft.poly_length()];
        let mut fourier = vec![Complex64::default(); fft.fourier_length()];
        let mut output = vec![0u64; fft.poly_length()];
        engine.forward_as_torus(&input, &mut fourier);
        group.bench_with_input(
            BenchmarkId::from_parameter(fft.poly_length()),
            &log_n,
            |b, _| {
                b.iter(|| engine.backward_as_torus(black_box(&fourier), black_box(&mut output)));
            },
        );
    }
    group.finish();
}

fn fft(c: &mut Criterion) {
    bench_forward::<RustFftTable>(c, "rustfft_forward_torus");
    bench_inverse::<RustFftTable>(c, "rustfft_backward_torus");
    bench_forward::<TfheFftTable>(c, "tfhe_fft_forward_torus");
    bench_inverse::<TfheFftTable>(c, "tfhe_fft_backward_torus");
}

criterion_group!(benches, fft);
criterion_main!(benches);
