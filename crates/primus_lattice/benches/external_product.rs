//! Benchmarks for TFHE external product.
//!
//! Run: `cargo bench -p primus_lattice --bench external_product`

use std::hint::black_box;
use std::time::Duration;

use criterion::Criterion;
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, FftTableImpl, PackedFftTable, TorusFftValue};
use primus_lattice::context::tfhe::TfheFftContext;
use primus_lattice::ggsw::{FourierGgswOwned, Ggsw};
use primus_lattice::glwe::Glwe;
use primus_lattice::tfhe::external_product::{accumulate_k1, external_product_to};
use primus_poly::FourierPolynomial;

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
// Shared setup helpers
// ---------------------------------------------------------------------------

/// Generate a random coefficient GGSW key and convert to Fourier.
fn make_fourier_key<Table: FftTable>(
    fft: &Table,
    glwe_dimension: usize,
    level: usize,
) -> FourierGgswOwned {
    let poly_len = fft.poly_length();
    let fourier_len = fft.fourier_length();
    let total_components = glwe_dimension + 1;

    let glwe_len = total_components * poly_len;
    let glev_len = level * glwe_len;
    let ggsw_len = total_components * glev_len;
    let ggsw_coeff: Vec<u32> = (0..ggsw_len).map(|_| rand::random()).collect();
    let ggsw_coeff = Ggsw::new(ggsw_coeff);

    let fourier_glwe_len = total_components * fourier_len;
    let fourier_glev_len = level * fourier_glwe_len;
    let fourier_ggsw_len = total_components * fourier_glev_len;
    let mut fourier_key = FourierGgswOwned::zero(fourier_ggsw_len);
    ggsw_coeff.write_fourier_form(&mut fourier_key, fft);

    fourier_key
}

/// Generate a random coefficient GLWE input.
fn make_input_glwe<Table: FftTable>(fft: &Table, glwe_dimension: usize) -> Glwe<Vec<u32>> {
    let poly_len = fft.poly_length();
    let total_components = glwe_dimension + 1;
    let glwe_len = total_components * poly_len;
    let input: Vec<u32> = (0..glwe_len).map(|_| rand::random()).collect();
    Glwe::new(input)
}

// ---------------------------------------------------------------------------
// Full external product (keeps existing benchmark names)
// ---------------------------------------------------------------------------

fn bench_full(c: &mut Criterion, log_n: u32, glwe_dimension: usize, log_basis: u32) {
    let fft = FftTableImpl::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let fourier_len = fft.fourier_length();
    let total_components = glwe_dimension + 1;
    let level = (32 / log_basis) as usize;

    let basis = ApproxSignedBasis::<u32>::new(None, log_basis, Some(level));
    let fourier_key = make_fourier_key(&fft, glwe_dimension, level);
    let input_glwe = make_input_glwe(&fft, glwe_dimension);

    let mut ctx = TfheFftContext::<u32>::new(poly_len, fourier_len, glwe_dimension);
    let glwe_len = total_components * poly_len;
    let mut output_glwe = Glwe::<Vec<u32>>::zero(glwe_len);

    let name = format!("N={}_k={}_level={}", poly_len, glwe_dimension, level);

    c.bench_function(&name, |b| {
        b.iter(|| {
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
// Full external product — packed backend
// ---------------------------------------------------------------------------

fn bench_full_packed(c: &mut Criterion, log_n: u32, glwe_dimension: usize, log_basis: u32) {
    let fft = PackedFftTable::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let fourier_len = fft.fourier_length();
    let total_components = glwe_dimension + 1;
    let level = (32 / log_basis) as usize;

    let basis = ApproxSignedBasis::<u32>::new(None, log_basis, Some(level));
    let fourier_key = make_fourier_key(&fft, glwe_dimension, level);
    let input_glwe = make_input_glwe(&fft, glwe_dimension);

    let mut ctx = TfheFftContext::<u32>::new(poly_len, fourier_len, glwe_dimension);
    let glwe_len = total_components * poly_len;
    let mut output_glwe = Glwe::<Vec<u32>>::zero(glwe_len);

    let name = format!("packed/N={}_k={}_level={}", poly_len, glwe_dimension, level);

    c.bench_function(&name, |b| {
        b.iter(|| {
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
// Sub-benchmark: decomposition only
// ---------------------------------------------------------------------------

fn bench_decomposition(c: &mut Criterion, log_n: u32, glwe_dimension: usize, log_basis: u32) {
    let fft = FftTableImpl::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let level = (32 / log_basis) as usize;

    let basis = ApproxSignedBasis::<u32>::new(None, log_basis, Some(level));
    let input_glwe = make_input_glwe(&fft, glwe_dimension);

    let mut carries = vec![false; poly_len];
    let mut decomposed_poly = vec![0u32; poly_len];

    let name = format!(
        "decomposition/N={}_k={}_level={}",
        poly_len, glwe_dimension, level
    );

    c.bench_function(&name, |b| {
        b.iter(|| {
            for coeff_poly in input_glwe.iter_poly(poly_len) {
                basis.init_carry_slice(coeff_poly.0, &mut carries);
                for decomposer in basis.decompose_iter() {
                    decomposer.decompose_slice_to(coeff_poly.0, &mut decomposed_poly, &mut carries);
                }
            }
            black_box(&mut carries);
            black_box(&mut decomposed_poly);
        })
    });
}

// ---------------------------------------------------------------------------
// Sub-benchmark: decomposition + forward FFT (combined)
// ---------------------------------------------------------------------------

fn bench_decomposition_forward_fft(
    c: &mut Criterion,
    log_n: u32,
    glwe_dimension: usize,
    log_basis: u32,
) {
    let fft = FftTableImpl::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let _fourier_len = fft.fourier_length();
    let blen = fft.buffer_len();
    let level = (32 / log_basis) as usize;

    let basis = ApproxSignedBasis::<u32>::new(None, log_basis, Some(level));
    let input_glwe = make_input_glwe(&fft, glwe_dimension);

    let mut carries = vec![false; poly_len];
    let mut decomposed_poly = vec![0u32; poly_len];
    let mut decomposed_fourier = vec![0.0f64; blen];

    let name = format!(
        "decomposition_forward_fft/N={}_k={}_level={}",
        poly_len, glwe_dimension, level
    );

    c.bench_function(&name, |b| {
        b.iter(|| {
            for coeff_poly in input_glwe.iter_poly(poly_len) {
                basis.init_carry_slice(coeff_poly.0, &mut carries);
                for decomposer in basis.decompose_iter() {
                    decomposer.decompose_slice_to(coeff_poly.0, &mut decomposed_poly, &mut carries);
                    fft.forward_torus_slice(&decomposed_poly, &mut decomposed_fourier);
                }
            }
            black_box(&mut decomposed_fourier);
        })
    });
}

// ---------------------------------------------------------------------------
// Sub-benchmark: forward FFT only (pre-computed decomposed polynomials)
// ---------------------------------------------------------------------------

fn bench_forward_fft(c: &mut Criterion, log_n: u32, glwe_dimension: usize, log_basis: u32) {
    let fft = FftTableImpl::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let _fourier_len = fft.fourier_length();
    let blen = fft.buffer_len();
    let total_components = glwe_dimension + 1;
    let level = (32 / log_basis) as usize;

    let basis = ApproxSignedBasis::<u32>::new(None, log_basis, Some(level));
    let input_glwe = make_input_glwe(&fft, glwe_dimension);

    // Pre-compute all decomposed polynomials (coefficient domain, u32).
    let mut carries = vec![false; poly_len];
    let mut precomputed_decomposed: Vec<Vec<u32>> = Vec::with_capacity(total_components * level);

    for coeff_poly in input_glwe.iter_poly(poly_len) {
        basis.init_carry_slice(coeff_poly.0, &mut carries);
        for decomposer in basis.decompose_iter() {
            let mut digits = vec![0u32; poly_len];
            decomposer.decompose_slice_to(coeff_poly.0, &mut digits, &mut carries);
            precomputed_decomposed.push(digits);
        }
    }

    assert_eq!(precomputed_decomposed.len(), total_components * level);

    let mut decomposed_fourier = vec![0.0f64; blen];

    let name = format!(
        "forward_fft/N={}_k={}_level={}",
        poly_len, glwe_dimension, level
    );

    c.bench_function(&name, |b| {
        b.iter(|| {
            for decomposed_poly in &precomputed_decomposed {
                fft.forward_torus_slice(decomposed_poly, &mut decomposed_fourier);
            }
            black_box(&mut decomposed_fourier);
        })
    });
}

// ---------------------------------------------------------------------------
// Sub-benchmark: Fourier accumulation only
// ---------------------------------------------------------------------------

fn bench_accumulation(c: &mut Criterion, log_n: u32, glwe_dimension: usize, log_basis: u32) {
    let fft = FftTableImpl::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let fourier_len = fft.fourier_length();
    let blen = fft.buffer_len();
    let total_components = glwe_dimension + 1;
    let level = (32 / log_basis) as usize;

    let basis = ApproxSignedBasis::<u32>::new(None, log_basis, Some(level));
    let fourier_key = make_fourier_key(&fft, glwe_dimension, level);
    let input_glwe = make_input_glwe(&fft, glwe_dimension);

    // Pre-compute all decomposed Fourier polynomials.
    let mut ctx = TfheFftContext::<u32>::new(poly_len, fourier_len, glwe_dimension);
    let glwe_fourier_len = total_components * blen;
    let glev_len = level * glwe_fourier_len;

    let mut precomputed: Vec<Vec<f64>> = Vec::with_capacity(total_components * level);

    for (coeff_poly, key_row) in input_glwe
        .iter_poly(poly_len)
        .zip(fourier_key.iter_glev(glev_len))
    {
        basis.init_carry_slice(coeff_poly.0, &mut ctx.carries);
        for (decomposer, _key_glwe) in basis
            .decompose_iter()
            .zip(key_row.iter_glwe(glwe_fourier_len))
        {
            decomposer.decompose_slice_to(coeff_poly.0, &mut ctx.decomposed_poly, &mut ctx.carries);
            fft.forward_torus_slice(&ctx.decomposed_poly, &mut ctx.decomposed_fourier);
            precomputed.push(ctx.decomposed_fourier.clone());
        }
    }

    let mut accumulator = vec![0.0f64; total_components * blen];

    let name = format!(
        "accumulation/N={}_k={}_level={}",
        poly_len, glwe_dimension, level
    );

    c.bench_function(&name, |b| {
        b.iter(|| {
            accumulator.fill(0.0);

            for (input_idx, key_row) in (0..total_components).zip(fourier_key.iter_glev(glev_len)) {
                for (level_idx, key_glwe) in (0..level).zip(key_row.iter_glwe(glwe_fourier_len)) {
                    let decomposed_data = &precomputed[input_idx * level + level_idx];
                    let decomposed = FourierPolynomial::new(decomposed_data.as_slice());

                    for out_idx in 0..total_components {
                        let acc_start = out_idx * blen;
                        let acc_end = acc_start + blen;
                        let key_start = out_idx * blen;
                        let key_end = key_start + blen;

                        let mut acc = FourierPolynomial::new(&mut accumulator[acc_start..acc_end]);
                        let key_poly =
                            FourierPolynomial::new(&key_glwe.as_ref()[key_start..key_end]);

                        acc.add_mul_assign(&decomposed, &key_poly);
                    }
                }
            }

            black_box(&mut accumulator);
        })
    });
}

// ---------------------------------------------------------------------------
// Sub-benchmark: specialized accumulation (k=1 / k=2 fused kernels)
// ---------------------------------------------------------------------------

fn bench_accumulation_specialized_with<Table: FftTable>(
    c: &mut Criterion,
    log_n: u32,
    glwe_dimension: usize,
    log_basis: u32,
    prefix: &str,
) {
    // Only k=1 has a specialized kernel currently enabled in production.
    if glwe_dimension != 1 {
        return;
    }

    let fft = Table::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let fourier_len = fft.fourier_length();
    let blen = fft.buffer_len();
    let total_components = glwe_dimension + 1;
    let level = (32 / log_basis) as usize;

    let basis = ApproxSignedBasis::<u32>::new(None, log_basis, Some(level));
    let fourier_key = make_fourier_key(&fft, glwe_dimension, level);
    let input_glwe = make_input_glwe(&fft, glwe_dimension);

    let mut ctx = TfheFftContext::<u32>::new(poly_len, fourier_len, glwe_dimension);
    let glwe_fourier_len = total_components * blen;
    let glev_len = level * glwe_fourier_len;

    let mut precomputed: Vec<Vec<f64>> = Vec::with_capacity(total_components * level);

    for (coeff_poly, key_row) in input_glwe
        .iter_poly(poly_len)
        .zip(fourier_key.iter_glev(glev_len))
    {
        basis.init_carry_slice(coeff_poly.0, &mut ctx.carries);
        for (decomposer, _key_glwe) in basis
            .decompose_iter()
            .zip(key_row.iter_glwe(glwe_fourier_len))
        {
            decomposer.decompose_slice_to(coeff_poly.0, &mut ctx.decomposed_poly, &mut ctx.carries);
            for (j, &digit) in ctx.decomposed_poly.iter().enumerate() {
                ctx.decomposed_centered_f64[j] = digit.into_f64_centered();
            }
            fft.forward_centered_f64_slice(
                &ctx.decomposed_centered_f64,
                &mut ctx.decomposed_fourier,
            );
            precomputed.push(ctx.decomposed_fourier.clone());
        }
    }

    let mut accumulator = vec![0.0f64; total_components * blen];

    let name = format!(
        "{}accumulation_specialized/N={}_k={}_level={}",
        prefix, poly_len, glwe_dimension, level
    );

    c.bench_function(&name, |b| {
        b.iter(|| {
            accumulator.fill(0.0);

            for (input_idx, key_row) in (0..total_components).zip(fourier_key.iter_glev(glev_len)) {
                for (level_idx, key_glwe) in (0..level).zip(key_row.iter_glwe(glwe_fourier_len)) {
                    let decomposed_data = &precomputed[input_idx * level + level_idx];

                    accumulate_k1(decomposed_data, key_glwe.as_ref(), &mut accumulator);
                }
            }

            black_box(&mut accumulator);
        })
    });
}

// ---------------------------------------------------------------------------
// Sub-benchmark: inverse FFT only
// ---------------------------------------------------------------------------

fn bench_inverse_fft(c: &mut Criterion, log_n: u32, glwe_dimension: usize, log_basis: u32) {
    let fft = FftTableImpl::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let _fourier_len = fft.fourier_length();
    let blen = fft.buffer_len();
    let total_components = glwe_dimension + 1;
    let level = (32 / log_basis) as usize;

    // Pre-fill Fourier accumulator with random data.
    let fourier_accumulator: Vec<f64> = (0..total_components * blen)
        .map(|_| rand::random::<f64>() * 2.0 - 1.0)
        .collect();

    let glwe_len = total_components * poly_len;
    let mut output_glwe = Glwe::<Vec<u32>>::zero(glwe_len);

    let name = format!(
        "inverse_fft/N={}_k={}_level={}",
        poly_len, glwe_dimension, level
    );

    c.bench_function(&name, |b| {
        b.iter(|| {
            for out_idx in 0..total_components {
                let acc_start = out_idx * blen;
                let acc_end = acc_start + blen;
                let out_start = out_idx * poly_len;
                let out_end = out_start + poly_len;
                fft.inverse_torus_slice(
                    &fourier_accumulator[acc_start..acc_end],
                    &mut output_glwe.as_mut()[out_start..out_end],
                );
            }
            black_box(&mut output_glwe);
        })
    });
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn bench_external_product(c: &mut Criterion) {
    // Case 1: N=1024, k=1, level=4 (log_basis=8)
    bench_full(c, 10, 1, 8);
    bench_full_packed(c, 10, 1, 8);
    bench_decomposition(c, 10, 1, 8);
    bench_forward_fft(c, 10, 1, 8);
    bench_decomposition_forward_fft(c, 10, 1, 8);
    bench_accumulation(c, 10, 1, 8);
    bench_accumulation_specialized_with::<FftTableImpl>(c, 10, 1, 8, "");
    bench_accumulation_specialized_with::<PackedFftTable>(c, 10, 1, 8, "packed/");
    bench_inverse_fft(c, 10, 1, 8);

    // Case 2: N=2048, k=1, level=4
    bench_full(c, 11, 1, 8);
    bench_full_packed(c, 11, 1, 8);
    bench_decomposition(c, 11, 1, 8);
    bench_forward_fft(c, 11, 1, 8);
    bench_decomposition_forward_fft(c, 11, 1, 8);
    bench_accumulation(c, 11, 1, 8);
    bench_accumulation_specialized_with::<FftTableImpl>(c, 11, 1, 8, "");
    bench_accumulation_specialized_with::<PackedFftTable>(c, 11, 1, 8, "packed/");
    bench_inverse_fft(c, 11, 1, 8);

    // Case 3: N=1024, k=2, level=4
    bench_full(c, 10, 2, 8);
    bench_full_packed(c, 10, 2, 8);
    bench_decomposition(c, 10, 2, 8);
    bench_forward_fft(c, 10, 2, 8);
    bench_decomposition_forward_fft(c, 10, 2, 8);
    bench_accumulation(c, 10, 2, 8);
    bench_inverse_fft(c, 10, 2, 8);
}

criterion::criterion_group! {
    name = benches;
    config = quick_criterion();
    targets = bench_external_product
}
criterion::criterion_main!(benches);
