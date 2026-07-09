//! TFHE external product in the Fourier domain.
//!
//! The external product multiplies a coefficient GLWE ciphertext by a
//! Fourier-domain GGSW key using signed gadget decomposition, accumulation
//! in the Fourier domain, and inverse FFT back to the coefficient domain.
//!
//! All Fourier buffers use split `[re | im]` f64 layout.

use primus_data::{Data, DataMut, RawData};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, TorusFftValue};
use primus_poly::FourierPolynomial;

use crate::context::tfhe::TfheFftContext;
use crate::ggsw::fourier::FourierGgsw;
use crate::glwe::fourier::FourierGlwe;
use crate::tfhe::TorusGlwe;

// ---------------------------------------------------------------------------
// Specialized accumulation kernels
// ---------------------------------------------------------------------------

/// Fused FMA for `k = 1` (2 GLWE components): processes both mask and body
/// in a single pass over the decomposed Fourier polynomial, reusing its
/// `[re, im]` values in registers.
///
/// All buffers use split `[re | im]` layout with `half = buffer_len() / 2`
/// complex values each.
#[inline]
#[doc(hidden)]
pub fn accumulate_k1(decomposed: &[f64], key_glwe: &[f64], accumulator: &mut [f64]) {
    let half = decomposed.len() / 2;
    let (d_re, d_im) = decomposed.split_at(half);
    let (k0_re, rest) = key_glwe.split_at(half);
    let (k0_im, rest) = rest.split_at(half);
    let (k1_re, k1_im) = rest.split_at(half);
    let (a0_re, rest) = accumulator.split_at_mut(half);
    let (a0_im, rest) = rest.split_at_mut(half);
    let (a1_re, a1_im) = rest.split_at_mut(half);

    #[cfg(target_arch = "x86_64")]
    {
        if *primus_fft::cpu::HAS_AVX2_FMA {
            unsafe {
                accumulate_k1_avx2(
                    d_re, d_im, k0_re, k0_im, k1_re, k1_im, a0_re, a0_im, a1_re, a1_im, half,
                );
                return;
            }
        }
    }
    // Scalar fallback
    accumulate_k1_scalar(
        d_re, d_im, k0_re, k0_im, k1_re, k1_im, a0_re, a0_im, a1_re, a1_im, half,
    );
}

/// Scalar fallback for `accumulate_k1`.
#[inline(always)]
fn accumulate_k1_scalar(
    d_re: &[f64],
    d_im: &[f64],
    k0_re: &[f64],
    k0_im: &[f64],
    k1_re: &[f64],
    k1_im: &[f64],
    a0_re: &mut [f64],
    a0_im: &mut [f64],
    a1_re: &mut [f64],
    a1_im: &mut [f64],
    half: usize,
) {
    for j in 0..half {
        let lr = d_re[j];
        let li = d_im[j];

        // Component 0 (mask)
        a0_re[j] += lr * k0_re[j] - li * k0_im[j];
        a0_im[j] += lr * k0_im[j] + li * k0_re[j];

        // Component 1 (body)
        a1_re[j] += lr * k1_re[j] - li * k1_im[j];
        a1_im[j] += lr * k1_im[j] + li * k1_re[j];
    }
}

/// AVX2+FMA kernel: 4 complex values per iteration, both components fused.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,fma")]
unsafe fn accumulate_k1_avx2(
    d_re: &[f64],
    d_im: &[f64],
    k0_re: &[f64],
    k0_im: &[f64],
    k1_re: &[f64],
    k1_im: &[f64],
    a0_re: &mut [f64],
    a0_im: &mut [f64],
    a1_re: &mut [f64],
    a1_im: &mut [f64],
    half: usize,
) {
    use std::arch::x86_64::*;

    let mut j = 0usize;
    while j + 3 < half {
        unsafe {
            // Load decomposed polynomial (4 complex values).
            let lr = _mm256_loadu_pd(d_re.as_ptr().add(j));
            let li = _mm256_loadu_pd(d_im.as_ptr().add(j));

            // --- Component 0 (mask) ---
            let k0r = _mm256_loadu_pd(k0_re.as_ptr().add(j));
            let k0i = _mm256_loadu_pd(k0_im.as_ptr().add(j));
            let a0r_v = _mm256_loadu_pd(a0_re.as_ptr().add(j));
            let a0i_v = _mm256_loadu_pd(a0_im.as_ptr().add(j));

            // t0_re = l_re * k0_re - l_im * k0_im
            let t0r = _mm256_fnmadd_pd(li, k0i, _mm256_mul_pd(lr, k0r));
            // t0_im = l_re * k0_im + l_im * k0_re
            let t0i = _mm256_fmadd_pd(li, k0r, _mm256_mul_pd(lr, k0i));

            _mm256_storeu_pd(a0_re.as_mut_ptr().add(j), _mm256_add_pd(a0r_v, t0r));
            _mm256_storeu_pd(a0_im.as_mut_ptr().add(j), _mm256_add_pd(a0i_v, t0i));

            // --- Component 1 (body) ---
            let k1r = _mm256_loadu_pd(k1_re.as_ptr().add(j));
            let k1i = _mm256_loadu_pd(k1_im.as_ptr().add(j));
            let a1r_v = _mm256_loadu_pd(a1_re.as_ptr().add(j));
            let a1i_v = _mm256_loadu_pd(a1_im.as_ptr().add(j));

            let t1r = _mm256_fnmadd_pd(li, k1i, _mm256_mul_pd(lr, k1r));
            let t1i = _mm256_fmadd_pd(li, k1r, _mm256_mul_pd(lr, k1i));

            _mm256_storeu_pd(a1_re.as_mut_ptr().add(j), _mm256_add_pd(a1r_v, t1r));
            _mm256_storeu_pd(a1_im.as_mut_ptr().add(j), _mm256_add_pd(a1i_v, t1i));
        }
        j += 4;
    }
    // Scalar tail.
    for j in j..half {
        let lr = d_re[j];
        let li = d_im[j];

        a0_re[j] += lr * k0_re[j] - li * k0_im[j];
        a0_im[j] += lr * k0_im[j] + li * k0_re[j];

        a1_re[j] += lr * k1_re[j] - li * k1_im[j];
        a1_im[j] += lr * k1_im[j] + li * k1_re[j];
    }
}

/// Fused FMA for `k = 2` (3 GLWE components): processes mask a₁, mask a₂,
/// and body b in a single pass.
#[inline]
#[doc(hidden)]
pub fn accumulate_k2(decomposed: &[f64], key_glwe: &[f64], accumulator: &mut [f64]) {
    let half = decomposed.len() / 2;
    let (d_re, d_im) = decomposed.split_at(half);

    let (k0_re, rest) = key_glwe.split_at(half);
    let (k0_im, rest) = rest.split_at(half);
    let (k1_re, rest) = rest.split_at(half);
    let (k1_im, rest) = rest.split_at(half);
    let (k2_re, k2_im) = rest.split_at(half);

    let (a0_re, rest) = accumulator.split_at_mut(half);
    let (a0_im, rest) = rest.split_at_mut(half);
    let (a1_re, rest) = rest.split_at_mut(half);
    let (a1_im, rest) = rest.split_at_mut(half);
    let (a2_re, a2_im) = rest.split_at_mut(half);

    for j in 0..half {
        let lr = d_re[j];
        let li = d_im[j];

        // Component 0 (mask a₁)
        a0_re[j] += lr * k0_re[j] - li * k0_im[j];
        a0_im[j] += lr * k0_im[j] + li * k0_re[j];

        // Component 1 (mask a₂)
        a1_re[j] += lr * k1_re[j] - li * k1_im[j];
        a1_im[j] += lr * k1_im[j] + li * k1_re[j];

        // Component 2 (body)
        a2_re[j] += lr * k2_re[j] - li * k2_im[j];
        a2_im[j] += lr * k2_im[j] + li * k2_re[j];
    }
}

// ---------------------------------------------------------------------------
// External product
// ---------------------------------------------------------------------------

/// TFHE external product: `output = input ⊡ key` in the Fourier domain.
pub fn external_product_to<T, Table, A, B, C>(
    input: &TorusGlwe<A>,
    key: &FourierGgsw<B>,
    output: &mut TorusGlwe<C>,
    basis: &ApproxSignedBasis<T>,
    fft: &Table,
    context: &mut TfheFftContext<T>,
    glwe_dimension: usize,
) where
    T: TorusFftValue,
    Table: FftTable,
    A: RawData<Elem = T> + Data,
    B: RawData<Elem = f64> + Data,
    C: RawData<Elem = T> + DataMut,
{
    let poly_len = fft.poly_length();
    let blen = fft.buffer_len(); // 2 * fourier_length
    let level = basis.decompose_length();
    let total_components = glwe_dimension + 1;

    // Zero the accumulator (split f64).
    context.fourier_accumulator.fill(0.0);

    // Key layout: (k+1) rows × level GLWE × (k+1) polynomials.
    let glwe_fourier_len = total_components * blen;
    let glev_len = level * glwe_fourier_len;

    for (coeff_poly, key_row) in input.iter_poly(poly_len).zip(key.iter_glev(glev_len)) {
        basis.init_carry_slice(coeff_poly.0, &mut context.carries);

        for (decomposer, key_glwe) in basis
            .decompose_iter()
            .zip(key_row.iter_glwe(glwe_fourier_len))
        {
            decomposer.decompose_slice_to(
                coeff_poly.0,
                &mut context.decomposed_poly,
                &mut context.carries,
            );

            // Convert u32 digits → centered f64 (fused: avoids per-element
            // `into_f64_centered` inside the FFT twist loop).
            for (j, &digit) in context.decomposed_poly.iter().enumerate() {
                context.decomposed_centered_f64[j] = digit.into_f64_centered();
            }

            // Forward FFT from centered f64 (directly into decomposed_fourier).
            fft.forward_centered_f64_slice(
                &context.decomposed_centered_f64,
                &mut context.decomposed_fourier,
            );

            // accumulator += decomposed * key_glwe (component-wise).
            // Use specialized scalar fused kernel for k=1; k≥2 uses the
            // generic path which already has AVX2/FMA SIMD dispatch.
            if total_components == 2 {
                accumulate_k1(
                    &context.decomposed_fourier,
                    key_glwe.as_ref(),
                    &mut context.fourier_accumulator,
                );
            } else {
                let mut acc_glwe = FourierGlwe::new(context.fourier_accumulator.as_mut_slice());
                let key_glwe_view = FourierGlwe::new(key_glwe.as_ref());
                acc_glwe.add_mul_fourier_poly_assign(
                    &FourierPolynomial::new(context.decomposed_fourier.as_slice()),
                    &key_glwe_view,
                );
            }
        }
    }

    // Inverse FFT: split f64 accumulator → torus output.
    for out_idx in 0..total_components {
        let acc_start = out_idx * blen;
        let acc_end = acc_start + blen;
        let out_start = out_idx * poly_len;
        let out_end = out_start + poly_len;
        fft.inverse_torus_slice(
            &context.fourier_accumulator[acc_start..acc_end],
            &mut output.as_mut()[out_start..out_end],
        );
    }
}
