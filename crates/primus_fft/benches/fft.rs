//! Benchmarks for `primus_fft` — forward, inverse, and roundtrip FFT.
//!
//! Run: `cargo bench -p primus_fft`

use std::hint::black_box;
use std::time::Duration;

use criterion::{BatchSize, Criterion};
use primus_fft::{FftTable, FftTableImpl, PackedFftTable, PackedFftTableExperimental};

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
              bench_packed_forward, bench_packed_inverse, bench_packed_roundtrip,
              bench_exp_forward, bench_exp_inverse, bench_exp_roundtrip
}

// ---------------------------------------------------------------------------
// Experimental packed backend — forward FFT
// ---------------------------------------------------------------------------

fn bench_exp_forward(c: &mut Criterion) {
    let mut group = c.benchmark_group("experimental_forward");

    for &log_n in LOG_N_CASES {
        let Ok(fft) = PackedFftTableExperimental::new(log_n) else {
            continue;
        };
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
// Experimental packed backend — inverse FFT
// ---------------------------------------------------------------------------

fn bench_exp_inverse(c: &mut Criterion) {
    let mut group = c.benchmark_group("experimental_inverse");

    for &log_n in LOG_N_CASES {
        let Ok(fft) = PackedFftTableExperimental::new(log_n) else {
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
// Experimental packed backend — roundtrip
// ---------------------------------------------------------------------------

fn bench_exp_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("experimental_roundtrip");

    for &log_n in LOG_N_CASES {
        let Ok(fft) = PackedFftTableExperimental::new(log_n) else {
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
// Half-size FFT comparison — StockhamFft vs rustfft (apples-to-apples)
// ---------------------------------------------------------------------------

fn bench_halfsize_stockham(c: &mut Criterion) {
    let mut group = c.benchmark_group("halfsize_stockham");
    for &log_h in &[7, 9, 11, 13] {
        // h = N/2, corresponds to log_n = log_h + 1
        let h = 1usize << log_h;
        let stockham = primus_fft::experimental::stockham::StockhamFft::new(h);
        let mut data: Vec<num_complex::Complex64> = (0..h)
            .map(|_| num_complex::Complex64::new(rand::random(), rand::random()))
            .collect();

        group.bench_function(format!("h={}", h), |b| {
            b.iter_batched_ref(
                || data.clone(),
                |data| stockham.forward(data),
                criterion::BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_halfsize_rustfft(c: &mut Criterion) {
    let mut group = c.benchmark_group("halfsize_rustfft");
    for &log_h in &[7, 9, 11, 13] {
        let h = 1usize << log_h;
        let mut planner = rustfft::FftPlanner::new();
        let fft = planner.plan_fft_forward(h);
        let mut scratch = vec![num_complex::Complex64::default(); fft.get_inplace_scratch_len()];
        let data: Vec<num_complex::Complex64> = (0..h)
            .map(|_| num_complex::Complex64::new(rand::random(), rand::random()))
            .collect();

        group.bench_function(format!("h={}", h), |b| {
            b.iter_batched_ref(
                || data.clone(),
                |data| fft.process_with_scratch(data, &mut scratch),
                criterion::BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_halfsize_tfhe_fft_unordered(c: &mut Criterion) {
    let mut group = c.benchmark_group("halfsize_tfhe_fft_unordered");
    // Unordered plan: decomposes large n into smaller base FFTs (base ≤ 1024).
    // Supports any power-of-two size.
    for &log_h in &[7, 9, 11, 13] {
        let h = 1usize << log_h;
        use tfhe_fft::unordered::{Method, Plan};
        let plan = Plan::new(h, Method::Measure(std::time::Duration::from_millis(10)));
        let mut mem = dyn_stack::PodBuffer::try_new(plan.fft_scratch()).unwrap();
        let data: Vec<num_complex::Complex64> = (0..h)
            .map(|_| num_complex::Complex64::new(rand::random(), rand::random()))
            .collect();

        group.bench_function(format!("h={}", h), |b| {
            b.iter_batched_ref(
                || data.clone(),
                |data| {
                    let stack = dyn_stack::PodStack::new(&mut mem);
                    plan.fwd(data, stack);
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

criterion::criterion_group! {
    name = halfsize_benches;
    config = quick_criterion();
    targets = bench_halfsize_stockham, bench_halfsize_rustfft, bench_halfsize_tfhe_fft_unordered
}

criterion::criterion_main!(benches, halfsize_benches);
