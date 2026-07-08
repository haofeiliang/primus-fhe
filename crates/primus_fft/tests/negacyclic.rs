use primus_fft::{FftTable, FftTableImpl};

// ---------------------------------------------------------------------------
// Helper: naive negacyclic convolution (X^N + 1)
// ---------------------------------------------------------------------------

/// Compute `a * b mod (X^N + 1)` using direct O(N^2) convolution with `i64`
/// intermediates to avoid overflow.
///
/// Coefficients are in torus (u32) representation and are interpreted as
/// centered `i32` values for multiplication. The result is wrapped back to
/// u32 with centered semantics.
fn naive_negacyclic_convolve_u32(a: &[u32], b: &[u32]) -> Vec<u32> {
    let n = a.len();
    let mut c = vec![0i64; n];

    for (i, &ai) in a.iter().enumerate() {
        let a_c = ai as i32 as i64;
        for (j, &bj) in b.iter().enumerate() {
            let b_c = bj as i32 as i64;
            let prod = a_c * b_c;
            let idx = i + j;
            if idx < n {
                c[idx] += prod;
            } else {
                c[idx - n] -= prod;
            }
        }
    }

    c.iter().map(|&x| (x as i32) as u32).collect()
}

/// Compute `a * b mod (X^N - 1)` (cyclic convolution) using direct O(N^2).
fn naive_cyclic_convolve_u32(a: &[u32], b: &[u32]) -> Vec<u32> {
    let n = a.len();
    let mut c = vec![0i64; n];

    for (i, &ai) in a.iter().enumerate() {
        let a_c = ai as i32 as i64;
        for (j, &bj) in b.iter().enumerate() {
            let b_c = bj as i32 as i64;
            let prod = a_c * b_c;
            let idx = (i + j) % n;
            c[idx] += prod;
        }
    }

    c.iter().map(|&x| (x as i32) as u32).collect()
}

/// Pointwise complex multiply on split layout: `out = a * b`.
///
/// Layout: `[re_0..re_{m-1}, im_0..im_{m-1}]`.
fn split_mul_to(a: &[f64], b: &[f64], out: &mut [f64]) {
    let m = a.len() / 2;
    debug_assert_eq!(a.len(), 2 * m);
    debug_assert_eq!(b.len(), 2 * m);
    debug_assert_eq!(out.len(), 2 * m);

    let (a_re, a_im) = a.split_at(m);
    let (b_re, b_im) = b.split_at(m);
    let (out_re, out_im) = out.split_at_mut(m);

    for i in 0..m {
        out_re[i] = a_re[i] * b_re[i] - a_im[i] * b_im[i];
        out_im[i] = a_re[i] * b_im[i] + a_im[i] * b_re[i];
    }
}

/// Negacyclic product via FFT: forward → pointwise mul → inverse.
fn fft_negacyclic_product(table: &FftTableImpl, a: &[u32], b: &[u32]) -> Vec<u32> {
    let n = table.poly_length();
    let blen = table.buffer_len();
    assert_eq!(a.len(), n);
    assert_eq!(b.len(), n);

    let mut fa = vec![0.0f64; blen];
    let mut fb = vec![0.0f64; blen];

    table.forward_torus_slice(a, &mut fa);
    table.forward_torus_slice(b, &mut fb);

    let mut fc = vec![0.0f64; blen];
    split_mul_to(&fa, &fb, &mut fc);

    let mut c = vec![0u32; n];
    table.inverse_torus_slice(&fc, &mut c);
    c
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// FFT-based negacyclic product must match the naive O(N^2) X^N+1 convolution.
#[test]
fn negacyclic_mul_matches_naive_u32() {
    for log_n in 1..=6 {
        let table = FftTableImpl::new(log_n).unwrap();
        let n = table.poly_length();

        // Coefficients in [-2, -1, 0, 1, 2] (centered), wrapped to u32
        let a: Vec<u32> = (0..n)
            .map(|i| match i % 5 {
                0 => 0u32,
                1 => 1u32,
                2 => (-1i32) as u32,
                3 => 2u32,
                _ => (-2i32) as u32,
            })
            .collect();

        let b: Vec<u32> = (0..n)
            .map(|i| match (i / 2) % 5 {
                0 => 0u32,
                1 => (-1i32) as u32,
                2 => 1u32,
                3 => (-2i32) as u32,
                _ => 2u32,
            })
            .collect();

        let expected = naive_negacyclic_convolve_u32(&a, &b);
        let actual = fft_negacyclic_product(&table, &a, &b);

        assert_eq!(
            expected, actual,
            "negacyclic_mul_matches_naive_u32 failed for log_n={log_n}"
        );
    }
}

/// The negacyclic twist is essential: a cyclic (X^N-1) product differs from
/// the negacyclic (X^N+1) product for non-trivial inputs.
#[test]
fn raw_cyclic_fft_is_not_used() {
    let log_n = 4;
    let table = FftTableImpl::new(log_n).unwrap();
    let n = table.poly_length();

    // Non-trivial polynomials
    let a: Vec<u32> = (0..n).map(|i| (i as i32) as u32).collect();
    let b: Vec<u32> = (0..n).map(|i| ((i * 3) as i32) as u32).collect();

    let negacyclic = fft_negacyclic_product(&table, &a, &b);
    let cyclic = naive_cyclic_convolve_u32(&a, &b);

    assert_ne!(
        negacyclic, cyclic,
        "negacyclic product must differ from cyclic product for non-trivial inputs"
    );
}

/// Multiplying by `X^d` should rotate coefficients and flip signs on wrap.
#[test]
fn monomial_mul_matches_negacyclic_rotation() {
    let log_n = 4;
    let table = FftTableImpl::new(log_n).unwrap();
    let n = table.poly_length();

    // Polynomial a(x) = 1 + 2*x + 3*x^2 + 4*x^3 + ...
    let mut a = vec![0u32; n];
    for (i, ai) in a.iter_mut().enumerate().take(4.min(n)) {
        *ai = (i + 1) as i32 as u32;
    }

    for d in [0, 1, 3, n - 1] {
        let mut monomial = vec![0u32; n];
        monomial[d] = 1;

        let result = fft_negacyclic_product(&table, &monomial, &a);

        // Expected: X^d * a(x) mod (X^N + 1)
        let mut expected = vec![0u32; n];
        for (i, &ai) in a.iter().enumerate() {
            if ai != 0 {
                let idx = i + d;
                if idx < n {
                    expected[idx] = ai;
                } else {
                    expected[idx - n] = 0u32.wrapping_sub(ai);
                }
            }
        }

        assert_eq!(result, expected, "monomial multiplication failed for d={d}");
    }
}

/// Zero polynomial times anything = zero. Constant-1 = identity. (-1) negates.
#[test]
fn zero_and_one_polynomials() {
    let log_n = 4;
    let table = FftTableImpl::new(log_n).unwrap();
    let n = table.poly_length();

    let a: Vec<u32> = (0..n)
        .map(|i| match i % 5 {
            0 => 2u32,
            1 => (-1i32) as u32,
            2 => 0,
            3 => 1,
            _ => (-2i32) as u32,
        })
        .collect();

    // 0 * a == 0
    let zero = vec![0u32; n];
    let result_zero = fft_negacyclic_product(&table, &zero, &a);
    assert_eq!(result_zero, zero, "zero polynomial times a should be zero");

    // 1 * a == a
    let mut one = vec![0u32; n];
    one[0] = 1;
    let result_one = fft_negacyclic_product(&table, &one, &a);
    assert_eq!(result_one, a, "one polynomial times a should be a");

    // (-1) * a == -a (wrapping negation)
    let mut minus_one = vec![0u32; n];
    minus_one[0] = 0u32.wrapping_sub(1);
    let result_minus_one = fft_negacyclic_product(&table, &minus_one, &a);
    let neg_a: Vec<u32> = a.iter().map(|&x| 0u32.wrapping_sub(x)).collect();
    assert_eq!(
        result_minus_one, neg_a,
        "(-1) polynomial times a should be -a"
    );
}

/// Monomial at degree 0 (X^0 = 1) is the identity element.
#[test]
fn monomial_degree_zero_is_identity() {
    let log_n = 4;
    let table = FftTableImpl::new(log_n).unwrap();
    let n = table.poly_length();

    let a: Vec<u32> = (0..n).map(|i| (i as i32) as u32).collect();

    let mut identity = vec![0u32; n];
    identity[0] = 1;

    let result = fft_negacyclic_product(&table, &identity, &a);
    assert_eq!(result, a, "X^0 * a should equal a");
}
