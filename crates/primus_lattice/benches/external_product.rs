//! Benchmarks for TFHE external product.
//!
//! Run: `cargo bench -p primus_lattice`

use std::hint::black_box;
use std::time::Duration;

use criterion::Criterion;
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, FftTableImpl};
use primus_lattice::context::tfhe::TfheFftContext;
use primus_lattice::ggsw::Ggsw;
use primus_lattice::ggsw::fourier::FourierGgswOwned;
use primus_lattice::glwe::Glwe;
use primus_lattice::tfhe::external_product::external_product_to;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

fn quick_criterion() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(5))
}

// ---------------------------------------------------------------------------
// Benchmark harness
// ---------------------------------------------------------------------------

/// Run a single external product benchmark case.
fn bench_case(c: &mut Criterion, log_n: u32, glwe_dimension: usize, log_basis: u32) {
    let fft = FftTableImpl::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let fourier_len = fft.fourier_length();
    let total_components = glwe_dimension + 1;
    let level = 32 / log_basis; // for power-of-two modulus, value_bits = 32

    let basis = ApproxSignedBasis::<u32>::new(None, log_basis, Some(level as usize));

    // Random coefficient GGSW key
    let glwe_len = total_components * poly_len;
    let glev_len = level as usize * glwe_len;
    let ggsw_len = total_components * glev_len;
    let ggsw_coeff: Vec<u32> = (0..ggsw_len).map(|_| rand::random()).collect();
    let ggsw_coeff = Ggsw::new(ggsw_coeff);

    // Convert to Fourier
    let fourier_glwe_len = total_components * fourier_len;
    let fourier_glev_len = level as usize * fourier_glwe_len;
    let fourier_ggsw_len = total_components * fourier_glev_len;
    let mut fourier_key = FourierGgswOwned::zero(fourier_ggsw_len);
    ggsw_coeff.write_fourier_form(&mut fourier_key, &fft);

    // Random input GLWE
    let input: Vec<u32> = (0..glwe_len).map(|_| rand::random()).collect();
    let input_glwe = Glwe::new(input);

    let mut ctx = TfheFftContext::<u32>::new(poly_len, fourier_len, glwe_dimension);
    let mut output_glwe = Glwe::<Vec<u32>>::zero(glwe_len);

    let name = format!("N={}_k={}_level={}", poly_len, glwe_dimension, level);

    c.bench_function(&name, |b| {
        b.iter(|| {
            // Reset accumulator before each external product
            ctx.fourier_accumulator.fill(0.0);

            external_product_to(
                black_box(&input_glwe),
                black_box(&fourier_key),
                black_box(&mut output_glwe),
                black_box(&basis),
                black_box(&fft),
                black_box(&mut ctx),
                black_box(glwe_dimension),
            );
        })
    });
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn bench_external_product(c: &mut Criterion) {
    // Case 1: N=1024, k=1, level=4 (log_basis=8)
    bench_case(c, 10, 1, 8);

    // Case 2: N=2048, k=1, level=4
    bench_case(c, 11, 1, 8);

    // Case 3: N=1024, k=2, level=4
    bench_case(c, 10, 2, 8);
}

criterion::criterion_group! {
    name = benches;
    config = quick_criterion();
    targets = bench_external_product
}
criterion::criterion_main!(benches);
