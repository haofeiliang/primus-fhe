//! Negacyclic FFT for Z[X]/(X^N+1) — tfhe-rs style.
//!
//! # Background: from cyclic to negacyclic
//!
//! A standard complex FFT of size N computes evaluations at the N-th roots of
//! unity `ω^k = exp(−i·2π·k/N)`.  Pointwise multiplication in this domain
//! gives **cyclic** convolution modulo `X^N − 1`.
//!
//! Homomorphic encryption uses the negacyclic ring `Z[X]/(X^N + 1)`, which
//! requires evaluating polynomials at the primitive 2N-th roots of unity — but
//! only the *odd* powers: `ζ^(2k+1)` where `ζ = exp(i·π/N)` and `k = 0..N/2−1`.
//! (The even powers `ζ^(2k)` are the standard N-th roots.)  Because conjugate
//! symmetry gives `ζ^(2N−(2k+1)) = conj(ζ^(2k+1))`, only N/2 distinct complex
//! values are needed.
//!
//! So the negacyclic FFT maps N real coefficients → N/2 complex values, and
//! we need a size‑N/2 complex FFT as the core engine.
//!
//! # Two ways to feed the N/2 FFT
//!
//! **Old packed approach (even/odd split → 2 FFTs):**
//! Decompose the polynomial into even/odd powers:
//! `P(X) = P_even(X²) + X·P_odd(X²)`.
//! Evaluating at `ζ^(2k+1)` gives:
//! `P(ζ^(2k+1)) = P_even(ζ^(4k+2)) + ζ^(2k+1)·P_odd(ζ^(4k+2))`.
//! Both `P_even` and `P_odd` need their own twist to align with standard FFT
//! points → **2 × N/2 FFT** + a final combine step with `ω_k = ζ^(2k+1)`.
//!
//! **New tfhe-rs approach (first/second-half split → 1 FFT):**
//! Split the polynomial into first and second halves: the first N/2 coefficients
//! become the "real" part, the second N/2 become the "imaginary" part of a
//! complex vector.  Multiply by the 2N‑th roots of unity (twist `exp(i·π·m/N)`),
//! then apply one standard complex FFT of size N/2.  No combine step on the
//! forward path, no conjugate‑symmetry reconstruction on the inverse path —
//! just untwist directly into the two halves of the output polynomial.
//!
//! # Why it's still mod X^N+1
//!
//! The negacyclic convolution property holds: pointwise multiplication in the
//! Fourier domain equals negacyclic convolution modulo X^N+1 in the time domain.
//! Both the even/odd and first/second-half formulations compute the same set of
//! values `P(ζ^(2k+1))` (up to a global conjugation convention). The FFT sign
//! and twist sign are self-consistent: forward + inverse roundtrip is exact.

pub mod stockham;

use std::cell::UnsafeCell;
use std::f64::consts::PI;

use num_complex::Complex64;

use crate::error::FftError;
use crate::table::FftTable;
use crate::torus::TorusFftValue;

use stockham::StockhamFft;

// ---------------------------------------------------------------------------
// Twisties — 2N-th roots of unity
// ---------------------------------------------------------------------------

/// Precomputed twist factors `exp(i·π·m/N)` for `m = 0..N/2`.
struct Twisties {
    poly_length: usize,    // N
    fourier_length: usize, // h = N/2

    /// `cos(π·m/N)` for forward twist.
    twist_re: Vec<f64>,
    /// `sin(π·m/N)` for forward twist.
    twist_im: Vec<f64>,

    /// `cos(π·m/N) / h` for inverse untwist (pre-scaled by 1/h).
    inv_twist_re_scaled: Vec<f64>,
    /// `-sin(π·m/N) / h` for inverse untwist.
    inv_twist_im_scaled: Vec<f64>,
}

impl Twisties {
    fn new(log_n: u32) -> Self {
        let n = 1usize << log_n;
        let h = n / 2;
        let n_f64 = n as f64;
        let h_f64 = h as f64;
        let scale = 1.0 / h_f64;

        let mut twist_re = Vec::with_capacity(h);
        let mut twist_im = Vec::with_capacity(h);
        let mut inv_twist_re_scaled = Vec::with_capacity(h);
        let mut inv_twist_im_scaled = Vec::with_capacity(h);
        for m in 0..h {
            let theta = PI * m as f64 / n_f64;
            let tr = theta.cos();
            let ti = theta.sin();
            twist_re.push(tr);
            twist_im.push(ti);
            // conj(twist_m) / h = (tr - i·ti) / h
            inv_twist_re_scaled.push(tr * scale);
            inv_twist_im_scaled.push(-ti * scale);
        }

        Self {
            poly_length: n,
            fourier_length: h,
            twist_re,
            twist_im,
            inv_twist_re_scaled,
            inv_twist_im_scaled,
        }
    }
}

// ---------------------------------------------------------------------------
// PackedFftTableExperimental
// ---------------------------------------------------------------------------

/// Scratch buffer for the negacyclic transform — single half-size complex array.
struct ExpScratch {
    /// Complex scratch (length h = N/2).
    scratch: Vec<Complex64>,
}

impl ExpScratch {
    fn new(h: usize) -> Self {
        Self {
            scratch: vec![Complex64::new(0.0, 0.0); h],
        }
    }
}

/// Experimental negacyclic FFT table — tfhe-rs style.
///
/// Uses first-half/second-half split + twist + single complex FFT, matching
/// the approach in `tfhe-rs/tfhe/fft_impl/fft64/math/fft`.
pub struct PackedFftTableExperimental {
    log_n: u32,
    tables: Twisties,
    stockham: StockhamFft,
    scratch: UnsafeCell<ExpScratch>,
}

unsafe impl Sync for PackedFftTableExperimental {}

impl PackedFftTableExperimental {
    /// Returns `log2(N)`.
    #[inline]
    pub fn log_n(&self) -> u32 {
        self.log_n
    }
}

impl FftTable for PackedFftTableExperimental {
    fn new(log_n: u32) -> Result<Self, FftError> {
        if log_n < 2 {
            return Err(FftError::InvalidLogN {
                log_n,
                max: usize::BITS - 1,
            });
        }

        let n = 1usize << log_n;
        let h = n / 2;
        let tables = Twisties::new(log_n);
        let stockham = StockhamFft::new(h);
        let scratch = UnsafeCell::new(ExpScratch::new(h));

        Ok(Self {
            log_n,
            tables,
            stockham,
            scratch,
        })
    }

    #[inline]
    fn poly_length(&self) -> usize {
        self.tables.poly_length
    }

    #[inline]
    fn fourier_length(&self) -> usize {
        self.tables.fourier_length
    }

    fn forward_torus_slice<T: TorusFftValue>(&self, input: &[T], output: &mut [f64]) {
        let n = self.tables.poly_length;
        let h = self.tables.fourier_length;
        debug_assert_eq!(input.len(), n);
        debug_assert_eq!(output.len(), 2 * h);

        let exp = unsafe { &mut *self.scratch.get() };

        // Step 1: first-half/second-half split, center, twist → Complex64.
        let (first, second) = input.split_at(h);
        for m in 0..h {
            let re = first[m].into_f64_centered();
            let im = second[m].into_f64_centered();
            let tr = self.tables.twist_re[m];
            let ti = self.tables.twist_im[m];
            // (re + i·im) * (tr + i·ti) = (re·tr - im·ti) + i·(re·ti + im·tr)
            exp.scratch[m] = Complex64::new(
                f64::mul_add(re, tr, -im * ti),
                f64::mul_add(re, ti, im * tr),
            );
        }

        // Step 2: single h-point FFT. Negacyclic convention uses exp(+i).
        self.stockham.inverse(&mut exp.scratch);

        // Step 3: output in split [re|im] layout.
        let (out_re, out_im) = output.split_at_mut(h);
        for m in 0..h {
            out_re[m] = exp.scratch[m].re;
            out_im[m] = exp.scratch[m].im;
        }
    }

    fn forward_centered_f64_slice(&self, input: &[f64], output: &mut [f64]) {
        let n = self.tables.poly_length;
        let h = self.tables.fourier_length;
        debug_assert_eq!(input.len(), n);
        debug_assert_eq!(output.len(), 2 * h);

        let exp = unsafe { &mut *self.scratch.get() };

        // Step 1: first-half/second-half split, twist (no centering).
        let (first, second) = input.split_at(h);
        for m in 0..h {
            let re = first[m];
            let im = second[m];
            let tr = self.tables.twist_re[m];
            let ti = self.tables.twist_im[m];
            exp.scratch[m] = Complex64::new(
                f64::mul_add(re, tr, -im * ti),
                f64::mul_add(re, ti, im * tr),
            );
        }

        // Step 2: single h-point FFT. Negacyclic forward uses exp(+i).
        self.stockham.inverse(&mut exp.scratch);

        // Step 3: output in split [re|im].
        let (out_re, out_im) = output.split_at_mut(h);
        for m in 0..h {
            out_re[m] = exp.scratch[m].re;
            out_im[m] = exp.scratch[m].im;
        }
    }

    fn inverse_torus_slice<T: TorusFftValue>(&self, input: &[f64], output: &mut [T]) {
        let n = self.tables.poly_length;
        let h = self.tables.fourier_length;
        debug_assert_eq!(input.len(), 2 * h);
        debug_assert_eq!(output.len(), n);

        let exp = unsafe { &mut *self.scratch.get() };
        let (p_re, p_im) = input.split_at(h);

        // Step 1: load from split [re|im] → Complex64.
        for m in 0..h {
            exp.scratch[m] = Complex64::new(p_re[m], p_im[m]);
        }

        // Step 2: single h-point FFT. Negacyclic inverse uses exp(-i).
        self.stockham.forward(&mut exp.scratch);

        // Step 3: untwist, round, and interleave.
        for m in 0..h {
            let itr = self.tables.inv_twist_re_scaled[m]; // cos(π·m/N) / h
            let iti = self.tables.inv_twist_im_scaled[m]; // -sin(π·m/N) / h
            let v = exp.scratch[m];
            // v * conj(twist) / h = v * (itr + i·iti)
            // = (v.re·itr - v.im·iti) + i·(v.re·iti + v.im·itr)
            // But iti is already -sin/h, so iti = -sin/h.
            // conj(twist)/h = (cos - i·sin)/h = cos/h + i·(-sin/h) = itr + i·iti
            // v * (itr + i·iti) = (re·itr - im·(-sin/h)) + i·(re·(-sin/h) + im·itr)
            // Hmm, let me re-derive:
            // conj(exp(i·π·m/N)) / h = (cos - i·sin) / h = cos/h + i·(-sin/h)
            // v = re + i·im
            // v * conj / h = (re·cos/h - im·(-sin/h)) + i·(re·(-sin/h) + im·cos/h)
            // = (re·cos/h + im·sin/h) + i·(-re·sin/h + im·cos/h)
            //
            // With itr = cos/h, iti = -sin/h:
            // re' = re·itr - im·iti = re·cos/h - im·(-sin/h) = re·cos/h + im·sin/h ✓
            // im' = re·iti + im·itr = re·(-sin/h) + im·cos/h ✓
            let re_out = f64::mul_add(v.re, itr, -v.im * iti);
            let im_out = f64::mul_add(v.re, iti, v.im * itr);
            output[m] = T::from_f64_wrapping_rounded(re_out);
            output[m + h] = T::from_f64_wrapping_rounded(im_out);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_negacyclic_convolution_property() {
        // Verify the key property for FHE: pointwise multiplication in the
        // Fourier domain corresponds to negacyclic convolution mod X^N+1.
        // I.e., forward(a) · forward(b) ≡ forward(a * b mod X^N+1).
        for log_n in 2..=6 {
            let n = 1usize << log_n;
            let h = n / 2;
            let table = PackedFftTableExperimental::new(log_n).unwrap();

            // Two random polynomials
            let a: Vec<u32> = (0..n)
                .map(|j| match j % 5 {
                    0 => 0,
                    1 => 1,
                    2 => (-1i32) as u32,
                    3 => 2,
                    _ => (-2i32) as u32,
                })
                .collect();
            let b: Vec<u32> = (0..n)
                .map(|j| match j % 3 {
                    0 => 1u32,
                    1 => (-1i32) as u32,
                    _ => 0,
                })
                .collect();

            // Naive negacyclic convolution: c_k = Σ_{i+j=k} a_i·b_j - Σ_{i+j=k+N} a_i·b_j
            let mut c = vec![0i64; n];
            for i in 0..n {
                for j in 0..n {
                    let val = (a[i] as i32 as i64) * (b[j] as i32 as i64);
                    let idx = i + j;
                    if idx < n {
                        c[idx] += val;
                    } else {
                        c[idx - n] -= val;
                    }
                }
            }
            let c_mod: Vec<u32> = c.iter().map(|&v| v as u32).collect();

            // FFT-based convolution
            let mut fa = vec![0.0f64; 2 * h];
            let mut fb = vec![0.0f64; 2 * h];
            table.forward_torus_slice(&a, &mut fa);
            table.forward_torus_slice(&b, &mut fb);

            // Pointwise multiply in Fourier domain
            let (fa_re, fa_im) = fa.split_at(h);
            let (fb_re, fb_im) = fb.split_at(h);
            let mut fc = vec![0.0f64; 2 * h];
            let (fc_re, fc_im) = fc.split_at_mut(h);
            for k in 0..h {
                // (a_re + i·a_im) * (b_re + i·b_im)
                fc_re[k] = fa_re[k] * fb_re[k] - fa_im[k] * fb_im[k];
                fc_im[k] = fa_re[k] * fb_im[k] + fa_im[k] * fb_re[k];
            }

            let mut result = vec![0u32; n];
            table.inverse_torus_slice(&fc, &mut result);

            assert_eq!(
                result, c_mod,
                "convolution property failed for log_n={log_n}"
            );
        }
    }

    #[test]
    fn exp_roundtrip_u32_small() {
        for log_n in 2..=12 {
            let table = PackedFftTableExperimental::new(log_n).unwrap();
            let h = table.fourier_length();
            let n = table.poly_length();

            let input: Vec<u32> = (0..n)
                .map(|i| match i % 5 {
                    0 => 0u32,
                    1 => 1u32,
                    2 => (-1i32) as u32,
                    3 => 2u32,
                    _ => (-2i32) as u32,
                })
                .collect();

            let mut fourier = vec![0.0f64; 2 * h];
            table.forward_torus_slice(&input, &mut fourier);
            let mut output = vec![0u32; n];
            table.inverse_torus_slice(&fourier, &mut output);

            assert_eq!(input, output, "roundtrip failed for log_n={log_n}");
        }
    }

    #[test]
    fn exp_centered_equiv() {
        for log_n in 2..=6 {
            let table = PackedFftTableExperimental::new(log_n).unwrap();
            let h = table.fourier_length();
            let n = table.poly_length();
            let blen = 2 * h;

            let test_values: Vec<u32> = vec![
                0,
                1,
                (-1i32) as u32,
                2,
                (-2i32) as u32,
                100,
                (-100i32) as u32,
            ];
            let input: Vec<u32> = (0..n).map(|i| test_values[i % test_values.len()]).collect();
            let centered: Vec<f64> = input.iter().map(|&v| v.into_f64_centered()).collect();

            let mut out_torus = vec![0.0f64; blen];
            table.forward_torus_slice(&input, &mut out_torus);

            let mut out_centered = vec![0.0f64; blen];
            table.forward_centered_f64_slice(&centered, &mut out_centered);

            for (i, (&a, &b)) in out_torus.iter().zip(&out_centered).enumerate() {
                assert!(
                    (a - b).abs() < 1e-12,
                    "centered equiv mismatch at {i} for log_n={log_n}"
                );
            }
        }
    }

    #[test]
    fn exp_vs_rustfft_roundtrip() {
        // Verify that our transform produces consistent roundtrip results
        // with the packed approach, even though intermediate Fourier domain
        // representations may differ (different mathematical decompositions).
        use crate::packed64::PackedFftTable;
        for log_n in 2..=10 {
            let rustfft_table = PackedFftTable::new(log_n).unwrap();
            let exp_table = PackedFftTableExperimental::new(log_n).unwrap();
            let n = exp_table.poly_length();
            let h = exp_table.fourier_length();
            let blen = 2 * h;

            let test_values: Vec<u32> = vec![
                0,
                1,
                (-1i32) as u32,
                2,
                (-2i32) as u32,
                100,
                (-100i32) as u32,
                i32::MIN as u32,
                i32::MAX as u32,
            ];
            let input: Vec<u32> = (0..n).map(|i| test_values[i % test_values.len()]).collect();

            // Each table does its own forward + inverse roundtrip
            let mut fourier = vec![0.0f64; blen];

            // rustfft-backed roundtrip
            rustfft_table.forward_torus_slice(&input, &mut fourier);
            let mut rustfft_inv = vec![0u32; n];
            rustfft_table.inverse_torus_slice(&fourier, &mut rustfft_inv);
            assert_eq!(
                input, rustfft_inv,
                "rustfft roundtrip failed for log_n={log_n}"
            );

            // our roundtrip
            exp_table.forward_torus_slice(&input, &mut fourier);
            let mut exp_inv = vec![0u32; n];
            exp_table.inverse_torus_slice(&fourier, &mut exp_inv);
            assert_eq!(
                input, exp_inv,
                "experimental roundtrip failed for log_n={log_n}"
            );
        }
    }
}
