//! Benchmarks for `primus_fft` — forward, inverse, and roundtrip FFT.
//!
//! Run: `cargo bench -p primus_fft`

use std::hint::black_box;
use std::time::Duration;

use criterion::{BatchSize, Criterion};
use primus_fft::{FftTable, FftTableImpl, PackedFftTable};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Sizes to benchmark: N = 2^log_n for log_n in this list.
const LOG_N_CASES: &[u32] = &[8, 10, 12, 14];

fn quick_criterion() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(3))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn random_u32_vec(len: usize) -> Vec<u32> {
    (0..len).map(|_| rand::random()).collect()
}

fn zero_f64_vec(len: usize) -> Vec<f64> {
    vec![0.0; len]
}

// ---------------------------------------------------------------------------
// Forward FFT
// ---------------------------------------------------------------------------

fn bench_forward(c: &mut Criterion) {
    let mut group = c.benchmark_group("forward");

    for &log_n in LOG_N_CASES {
        let fft = FftTableImpl::new(log_n).unwrap();
        let n = fft.poly_length();
        let blen = fft.buffer_len();
        let input = random_u32_vec(n);
        let mut output = zero_f64_vec(blen);

        group.bench_function(format!("N={}", n), |b| {
            b.iter(|| fft.forward_torus_slice(black_box(&input), black_box(&mut output)))
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Inverse FFT
// ---------------------------------------------------------------------------

fn bench_inverse(c: &mut Criterion) {
    let mut group = c.benchmark_group("inverse");

    for &log_n in LOG_N_CASES {
        let fft = FftTableImpl::new(log_n).unwrap();
        let n = fft.poly_length();
        let blen = fft.buffer_len();

        // Generate Fourier data from a random polynomial
        let coeff = random_u32_vec(n);
        let mut fourier = zero_f64_vec(blen);
        fft.forward_torus_slice(&coeff, &mut fourier);

        let mut output = vec![0u32; n];

        group.bench_function(format!("N={}", n), |b| {
            b.iter(|| fft.inverse_torus_slice(black_box(&fourier), black_box(&mut output)))
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Roundtrip (forward + inverse)
// ---------------------------------------------------------------------------

fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("roundtrip");

    for &log_n in LOG_N_CASES {
        let fft = FftTableImpl::new(log_n).unwrap();
        let n = fft.poly_length();
        let blen = fft.buffer_len();

        group.bench_function(format!("N={}", n), |b| {
            b.iter_batched_ref(
                || {
                    let input = random_u32_vec(n);
                    let fourier = zero_f64_vec(blen);
                    let output = vec![0u32; n];
                    (input, fourier, output)
                },
                |(input, fourier, output)| {
                    fft.forward_torus_slice(
                        black_box(input.as_slice()),
                        black_box(fourier.as_mut_slice()),
                    );
                    fft.inverse_torus_slice(
                        black_box(fourier.as_slice()),
                        black_box(output.as_mut_slice()),
                    );
                },
                BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Packed backend — forward FFT
// ---------------------------------------------------------------------------

fn bench_packed_forward(c: &mut Criterion) {
    let mut group = c.benchmark_group("packed_forward");

    for &log_n in LOG_N_CASES {
        let Ok(fft) = PackedFftTable::new(log_n) else {
            continue; // skip if not supported (e.g. log_n=1)
        };
        let n = fft.poly_length();
        let blen = fft.buffer_len(); // = N
        let input = random_u32_vec(n);
        let mut output = zero_f64_vec(blen);

        group.bench_function(format!("N={}", n), |b| {
            b.iter(|| fft.forward_torus_slice(black_box(&input), black_box(&mut output)))
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Packed backend — inverse FFT
// ---------------------------------------------------------------------------

fn bench_packed_inverse(c: &mut Criterion) {
    let mut group = c.benchmark_group("packed_inverse");

    for &log_n in LOG_N_CASES {
        let Ok(fft) = PackedFftTable::new(log_n) else {
            continue;
        };
        let n = fft.poly_length();
        let blen = fft.buffer_len();

        let coeff = random_u32_vec(n);
        let mut fourier = zero_f64_vec(blen);
        fft.forward_torus_slice(&coeff, &mut fourier);

        let mut output = vec![0u32; n];

        group.bench_function(format!("N={}", n), |b| {
            b.iter(|| fft.inverse_torus_slice(black_box(&fourier), black_box(&mut output)))
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Packed backend — roundtrip (forward + inverse)
// ---------------------------------------------------------------------------

fn bench_packed_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("packed_roundtrip");

    for &log_n in LOG_N_CASES {
        let Ok(fft) = PackedFftTable::new(log_n) else {
            continue;
        };
        let n = fft.poly_length();
        let blen = fft.buffer_len();

        group.bench_function(format!("N={}", n), |b| {
            b.iter_batched_ref(
                || {
                    let input = random_u32_vec(n);
                    let fourier = zero_f64_vec(blen);
                    let output = vec![0u32; n];
                    (input, fourier, output)
                },
                |(input, fourier, output)| {
                    fft.forward_torus_slice(
                        black_box(input.as_slice()),
                        black_box(fourier.as_mut_slice()),
                    );
                    fft.inverse_torus_slice(
                        black_box(fourier.as_slice()),
                        black_box(output.as_mut_slice()),
                    );
                },
                BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

criterion::criterion_group! {
    name = benches;
    config = quick_criterion();
    targets = bench_forward, bench_inverse, bench_roundtrip,
              bench_packed_forward, bench_packed_inverse, bench_packed_roundtrip
}
criterion::criterion_main!(benches);
