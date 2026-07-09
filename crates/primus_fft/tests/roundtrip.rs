use primus_fft::{FftTable, FftTableImpl, PackedFftTable, TorusFftValue};

/// Small centered coefficients should roundtrip exactly through
/// forward + inverse transform for all N from 2 to 64.
#[test]
fn roundtrip_u32_small() {
    for log_n in 1..=6 {
        let table = FftTableImpl::new(log_n).unwrap();
        let n = table.poly_length();
        let blen = table.buffer_len();

        let mut fourier = vec![0.0f64; blen];
        let mut output = vec![0u32; n];

        // Test pattern: small centered values [-2, -1, 0, 1, 2] (wrapped to u32)
        let input: Vec<u32> = (0..n)
            .map(|i| match i % 5 {
                0 => 0u32,
                1 => 1u32,
                2 => (-1i32) as u32,
                3 => 2u32,
                _ => (-2i32) as u32,
            })
            .collect();

        table.forward_torus_slice(&input, &mut fourier);
        table.inverse_torus_slice(&fourier, &mut output);
        assert_eq!(
            input, output,
            "roundtrip_u32_small failed for log_n={log_n}"
        );
    }
}

/// A single non-zero coefficient (monomial) should roundtrip exactly.
#[test]
fn roundtrip_u32_monomial() {
    for log_n in 1..=6 {
        let table = FftTableImpl::new(log_n).unwrap();
        let n = table.poly_length();
        let blen = table.buffer_len();

        let mut fourier = vec![0.0f64; blen];
        let mut output = vec![0u32; n];

        for pos in [0, 1, n / 2, n - 1] {
            let mut input = vec![0u32; n];
            input[pos] = 1;

            fourier.fill(0.0);
            output.fill(0);

            table.forward_torus_slice(&input, &mut fourier);
            table.inverse_torus_slice(&fourier, &mut output);
            assert_eq!(
                input, output,
                "roundtrip_u32_monomial failed for log_n={log_n}, pos={pos}"
            );
        }
    }
}

/// All-zeros polynomial roundtrips exactly.
#[test]
fn roundtrip_zero_polynomial() {
    for log_n in 1..=6 {
        let table = FftTableImpl::new(log_n).unwrap();
        let n = table.poly_length();
        let blen = table.buffer_len();

        let input = vec![0u32; n];
        let mut fourier = vec![0.0f64; blen];
        let mut output = vec![1u32; n]; // start with non-zero to catch failures

        table.forward_torus_slice(&input, &mut fourier);
        table.inverse_torus_slice(&fourier, &mut output);
        assert_eq!(
            input, output,
            "roundtrip_zero_polynomial failed for log_n={log_n}"
        );
    }
}

/// Constant-1 polynomial roundtrips exactly (identity element).
#[test]
fn roundtrip_one_polynomial() {
    for log_n in 1..=6 {
        let table = FftTableImpl::new(log_n).unwrap();
        let n = table.poly_length();
        let blen = table.buffer_len();

        let mut input = vec![0u32; n];
        input[0] = 1;

        let mut fourier = vec![0.0f64; blen];
        let mut output = vec![0u32; n];

        table.forward_torus_slice(&input, &mut fourier);
        table.inverse_torus_slice(&fourier, &mut output);
        assert_eq!(
            input, output,
            "roundtrip_one_polynomial failed for log_n={log_n}"
        );
    }
}

/// u64 roundtrip for small values (within f64 exact integer range, |v| <= 2^53).
#[test]
fn roundtrip_u64_small() {
    for log_n in 1..=4 {
        let table = FftTableImpl::new(log_n).unwrap();
        let n = table.poly_length();
        let blen = table.buffer_len();

        let mut fourier = vec![0.0f64; blen];
        let mut output = vec![0u64; n];

        // Small values that fit exactly in f64 (53-bit mantissa)
        let input: Vec<u64> = (0..n)
            .map(|i| match i % 5 {
                0 => 0u64,
                1 => 1u64,
                2 => (-1i64) as u64,
                3 => 2u64,
                _ => (-2i64) as u64,
            })
            .collect();

        table.forward_torus_slice(&input, &mut fourier);
        table.inverse_torus_slice(&fourier, &mut output);
        assert_eq!(
            input, output,
            "roundtrip_u64_small failed for log_n={log_n}"
        );
    }
}

/// u16 roundtrip for small values.
#[test]
fn roundtrip_u16_small() {
    for log_n in 1..=4 {
        let table = FftTableImpl::new(log_n).unwrap();
        let n = table.poly_length();
        let blen = table.buffer_len();

        let mut fourier = vec![0.0f64; blen];
        let mut output = vec![0u16; n];

        let input: Vec<u16> = (0..n)
            .map(|i| match i % 5 {
                0 => 0u16,
                1 => 1u16,
                2 => (-1i16) as u16,
                3 => 2u16,
                _ => (-2i16) as u16,
            })
            .collect();

        table.forward_torus_slice(&input, &mut fourier);
        table.inverse_torus_slice(&fourier, &mut output);
        assert_eq!(
            input, output,
            "roundtrip_u16_small failed for log_n={log_n}"
        );
    }
}

// ---------------------------------------------------------------------------
// Packed backend — shape assertions
// ---------------------------------------------------------------------------

#[test]
fn packed_shape() {
    for log_n in 2..=6 {
        let table = PackedFftTable::new(log_n).unwrap();
        let n = 1 << log_n;
        assert_eq!(table.poly_length(), n, "poly_length should be N");
        assert_eq!(
            table.fourier_length(),
            n / 2,
            "fourier_length should be N/2"
        );
        assert_eq!(table.buffer_len(), n, "buffer_len should be N");
    }
}

// ---------------------------------------------------------------------------
// Packed backend — roundtrip
// ---------------------------------------------------------------------------

#[test]
fn packed_roundtrip_u32_small() {
    for log_n in 2..=6 {
        let table = PackedFftTable::new(log_n).unwrap();
        let n = table.poly_length();
        let blen = table.buffer_len(); // = N

        let mut fourier = vec![0.0f64; blen];
        let mut output = vec![0u32; n];

        let input: Vec<u32> = (0..n)
            .map(|i| match i % 5 {
                0 => 0u32,
                1 => 1u32,
                2 => (-1i32) as u32,
                3 => 2u32,
                _ => (-2i32) as u32,
            })
            .collect();

        table.forward_torus_slice(&input, &mut fourier);
        table.inverse_torus_slice(&fourier, &mut output);
        assert_eq!(
            input, output,
            "packed_roundtrip_u32_small failed for log_n={log_n}"
        );
    }
}

#[test]
fn packed_roundtrip_u64_small() {
    for log_n in 2..=4 {
        let table = PackedFftTable::new(log_n).unwrap();
        let n = table.poly_length();
        let blen = table.buffer_len();

        let mut fourier = vec![0.0f64; blen];
        let mut output = vec![0u64; n];

        let input: Vec<u64> = (0..n)
            .map(|i| match i % 5 {
                0 => 0u64,
                1 => 1u64,
                2 => (-1i64) as u64,
                3 => 2u64,
                _ => (-2i64) as u64,
            })
            .collect();

        table.forward_torus_slice(&input, &mut fourier);
        table.inverse_torus_slice(&fourier, &mut output);
        assert_eq!(
            input, output,
            "packed_roundtrip_u64_small failed for log_n={log_n}"
        );
    }
}

#[test]
fn packed_roundtrip_u16_small() {
    for log_n in 2..=4 {
        let table = PackedFftTable::new(log_n).unwrap();
        let n = table.poly_length();
        let blen = table.buffer_len();

        let mut fourier = vec![0.0f64; blen];
        let mut output = vec![0u16; n];

        let input: Vec<u16> = (0..n)
            .map(|i| match i % 5 {
                0 => 0u16,
                1 => 1u16,
                2 => (-1i16) as u16,
                3 => 2u16,
                _ => (-2i16) as u16,
            })
            .collect();

        table.forward_torus_slice(&input, &mut fourier);
        table.inverse_torus_slice(&fourier, &mut output);
        assert_eq!(
            input, output,
            "packed_roundtrip_u16_small failed for log_n={log_n}"
        );
    }
}

#[test]
fn packed_roundtrip_zero_polynomial() {
    for log_n in 2..=6 {
        let table = PackedFftTable::new(log_n).unwrap();
        let n = table.poly_length();
        let blen = table.buffer_len();

        let input = vec![0u32; n];
        let mut fourier = vec![0.0f64; blen];
        let mut output = vec![1u32; n];

        table.forward_torus_slice(&input, &mut fourier);
        table.inverse_torus_slice(&fourier, &mut output);
        assert_eq!(
            input, output,
            "packed_roundtrip_zero failed for log_n={log_n}"
        );
    }
}

#[test]
fn packed_roundtrip_one_polynomial() {
    for log_n in 2..=6 {
        let table = PackedFftTable::new(log_n).unwrap();
        let n = table.poly_length();
        let blen = table.buffer_len();

        let mut input = vec![0u32; n];
        input[0] = 1;

        let mut fourier = vec![0.0f64; blen];
        let mut output = vec![0u32; n];

        table.forward_torus_slice(&input, &mut fourier);
        table.inverse_torus_slice(&fourier, &mut output);
        assert_eq!(
            input, output,
            "packed_roundtrip_one failed for log_n={log_n}"
        );
    }
}

#[test]
fn packed_roundtrip_u32_monomial() {
    for log_n in 2..=6 {
        let table = PackedFftTable::new(log_n).unwrap();
        let n = table.poly_length();
        let blen = table.buffer_len();

        let mut fourier = vec![0.0f64; blen];
        let mut output = vec![0u32; n];

        for pos in [0, 1, n / 2, n - 1] {
            let mut input = vec![0u32; n];
            input[pos] = 1;

            fourier.fill(0.0);
            output.fill(0);

            table.forward_torus_slice(&input, &mut fourier);
            table.inverse_torus_slice(&fourier, &mut output);
            assert_eq!(
                input, output,
                "packed_roundtrip_u32_monomial failed for log_n={log_n}, pos={pos}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Packed vs full-complex backend — cross-consistency
// ---------------------------------------------------------------------------

/// Forward+inverse through the packed backend must match the same through the
/// full-complex backend (within torus rounding tolerance).
#[test]
fn packed_matches_full_roundtrip() {
    for log_n in 2..=6 {
        let full_table = FftTableImpl::new(log_n).unwrap();
        let packed_table = PackedFftTable::new(log_n).unwrap();
        let n = 1 << log_n;

        let input: Vec<u32> = (0..n)
            .map(|i| match i % 11 {
                0 => 0u32,
                1 => 1u32,
                2 => (-1i32) as u32,
                3 => 2u32,
                4 => (-2i32) as u32,
                5 => 100u32,
                6 => (-100i32) as u32,
                7 => 1u32 << 31,
                8 => (1u32 << 31) | 1,
                9 => u32::MAX,
                _ => u32::MAX / 2,
            })
            .collect();

        // Full roundtrip
        let mut full_fourier = vec![0.0f64; full_table.buffer_len()];
        let mut full_output = vec![0u32; n];
        full_table.forward_torus_slice(&input, &mut full_fourier);
        full_table.inverse_torus_slice(&full_fourier, &mut full_output);

        // Packed roundtrip
        let mut packed_fourier = vec![0.0f64; packed_table.buffer_len()];
        let mut packed_output = vec![0u32; n];
        packed_table.forward_torus_slice(&input, &mut packed_fourier);
        packed_table.inverse_torus_slice(&packed_fourier, &mut packed_output);

        // Packed Fourier storage is half the size.
        assert_eq!(
            packed_table.buffer_len(),
            full_table.buffer_len() / 2,
            "packed buffer_len should be half of full"
        );

        // Both roundtrip to the same result.
        assert_eq!(
            full_output, packed_output,
            "packed and full roundtrip must match for log_n={log_n}"
        );
    }
}

// ---------------------------------------------------------------------------
// Packed backend — naive negacyclic multiplication
// ---------------------------------------------------------------------------

/// Naive O(N²) negacyclic convolution: c = a * b mod (X^N + 1)
/// over i64 with wrapping (simulating torus arithmetic).
fn naive_negacyclic_mul(a: &[u32], b: &[u32]) -> Vec<u32> {
    let n = a.len();
    debug_assert_eq!(n, b.len());
    let mut c = vec![0i64; n];
    for i in 0..n {
        for j in 0..n {
            let prod = (a[i] as i32 as i64) * (b[j] as i32 as i64);
            let k = i + j;
            if k < n {
                c[k] = c[k].wrapping_add(prod);
            } else {
                c[k - n] = c[k - n].wrapping_sub(prod);
            }
        }
    }
    c.into_iter().map(|v| (v as i32) as u32).collect()
}

/// Packed negacyclic multiplication: forward FFT both inputs,
/// pointwise complex multiply, inverse FFT.
fn packed_negacyclic_mul(table: &PackedFftTable, a: &[u32], b: &[u32]) -> Vec<u32> {
    let n = table.poly_length();
    let blen = table.buffer_len();
    debug_assert_eq!(a.len(), n);
    debug_assert_eq!(b.len(), n);

    let mut fa = vec![0.0f64; blen];
    let mut fb = vec![0.0f64; blen];
    table.forward_torus_slice(a, &mut fa);
    table.forward_torus_slice(b, &mut fb);

    // Pointwise complex multiply in split layout:
    // (re_a + i*im_a) * (re_b + i*im_b) = (re_a*re_b - im_a*im_b) + i*(re_a*im_b + im_a*re_b)
    let half_n = table.fourier_length();
    let (re_a, im_a) = fa.split_at(half_n);
    let (re_b, im_b) = fb.split_at(half_n);

    let mut fc = vec![0.0f64; blen];
    let (re_c, im_c) = fc.split_at_mut(half_n);
    for k in 0..half_n {
        re_c[k] = re_a[k] * re_b[k] - im_a[k] * im_b[k];
        im_c[k] = re_a[k] * im_b[k] + im_a[k] * re_b[k];
    }

    let mut c = vec![0u32; n];
    table.inverse_torus_slice(&fc, &mut c);
    c
}

#[test]
fn packed_negacyclic_mul_matches_naive_u32() {
    for log_n in 2..=5 {
        let table = PackedFftTable::new(log_n).unwrap();
        let n = 1 << log_n;

        // Small coefficients so products fit without excessive rounding error.
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
            .map(|i| match i % 7 {
                0 => 0u32,
                1 => 1u32,
                2 => 2u32,
                3 => (-1i32) as u32,
                4 => (-2i32) as u32,
                5 => 3u32,
                _ => (-3i32) as u32,
            })
            .collect();

        let c_naive = naive_negacyclic_mul(&a, &b);
        let c_packed = packed_negacyclic_mul(&table, &a, &b);

        assert_eq!(
            c_naive, c_packed,
            "packed negacyclic mul must match naive for log_n={log_n}"
        );
    }
}

#[test]
fn packed_negacyclic_mul_monomial_is_rotation() {
    for log_n in 2..=5 {
        let table = PackedFftTable::new(log_n).unwrap();
        let n = 1 << log_n;

        // Multiply by X (monomial at position 1)
        let mut x_poly = vec![0u32; n];
        x_poly[1] = 1;

        // Random-ish input
        let input: Vec<u32> = (0..n).map(|i| (i as u32) % 10).collect();

        let result = packed_negacyclic_mul(&table, &input, &x_poly);

        // Multiplication by X in Z[X]/(X^N+1): coefficients shift right,
        // coefficient at N-1 wraps to position 0 with sign flip.
        for j in 0..n {
            let expected = if j == 0 {
                // X * X^{N-1} = X^N = -1, so the N-1 term moves to 0 with negation
                (-(input[n - 1] as i32)) as u32
            } else {
                input[j - 1]
            };
            assert_eq!(
                result[j], expected,
                "X-monomial mul mismatch at index {j} for log_n={log_n}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// forward_centered_f64_slice equivalence tests
// ---------------------------------------------------------------------------

/// Verify `forward_centered_f64_slice(centered(input)) ≈ forward_torus_slice(input)`
/// across backends, sizes, and torus types with boundary values.
fn check_centered_equiv<Table: FftTable>(table: &Table, log_n: u32) {
    let n = table.poly_length();
    let blen = table.buffer_len();

    // Build a rich test pattern: zeros, small positives, wrapping negatives,
    // i32::MIN/MAX representations, and large u32 values.
    let test_values: Vec<u32> = {
        let mut v = Vec::new();
        v.push(0u32);
        v.push(1u32);
        v.push((-1i32) as u32);
        v.push(2u32);
        v.push((-2i32) as u32);
        v.push(100u32);
        v.push((-100i32) as u32);
        v.push(i32::MIN as u32); // 1 << 31
        v.push(i32::MAX as u32); // (1 << 31) - 1
        v.push((i32::MIN as u32) + 1); // edge near wrap
        v.push(u32::MAX);
        v.push(u32::MAX / 2);
        v
    };

    let input: Vec<u32> = (0..n).map(|i| test_values[i % test_values.len()]).collect();

    // Reference: forward_torus_slice
    let mut out_torus = vec![0.0f64; blen];
    table.forward_torus_slice(&input, &mut out_torus);

    // Centered path: center → forward_centered_f64_slice
    let centered: Vec<f64> = input.iter().map(|&v| v.into_f64_centered()).collect();
    let mut out_centered = vec![0.0f64; blen];
    table.forward_centered_f64_slice(&centered, &mut out_centered);

    // Bit-exact equality expected (same math, same FFT, just skipped centering).
    assert_eq!(
        out_torus, out_centered,
        "forward_centered_f64_slice must equal forward_torus_slice for log_n={log_n}"
    );
}

#[test]
fn centered_equiv_full_u32() {
    for log_n in 1..=6 {
        let table = FftTableImpl::new(log_n).unwrap();
        check_centered_equiv::<FftTableImpl>(&table, log_n);
    }
}

#[test]
fn centered_equiv_packed_u32() {
    for log_n in 2..=6 {
        let table = PackedFftTable::new(log_n).unwrap();
        check_centered_equiv::<PackedFftTable>(&table, log_n);
    }
}

#[test]
fn centered_equiv_full_u64() {
    // Build a rich u64 test vector with values near the i64 boundary.
    let test_values: Vec<u64> = {
        let mut v = Vec::new();
        v.push(0u64);
        v.push(1u64);
        v.push((-1i64) as u64);
        v.push(2u64);
        v.push((-2i64) as u64);
        v.push(100u64);
        v.push((-100i64) as u64);
        v.push(i64::MIN as u64);
        v.push(i64::MAX as u64);
        v.push(u64::MAX);
        v.push(u64::MAX / 2);
        v.push(1u64 << 53); // boundary of exact f64 integer representation
        v.push((1u64 << 53) + 1);
        v
    };

    for log_n in 1..=3 {
        let table = FftTableImpl::new(log_n).unwrap();
        let n = table.poly_length();
        let blen = table.buffer_len();

        let input: Vec<u64> = (0..n).map(|i| test_values[i % test_values.len()]).collect();

        let mut out_torus = vec![0.0f64; blen];
        table.forward_torus_slice(&input, &mut out_torus);

        let centered: Vec<f64> = input.iter().map(|&v| v.into_f64_centered()).collect();
        let mut out_centered = vec![0.0f64; blen];
        table.forward_centered_f64_slice(&centered, &mut out_centered);

        assert_eq!(
            out_torus, out_centered,
            "u64: centered_equiv must match for log_n={log_n}"
        );
    }
}

#[test]
fn centered_equiv_full_u16() {
    let test_values: Vec<u16> = {
        let mut v = Vec::new();
        v.push(0u16);
        v.push(1u16);
        v.push((-1i16) as u16);
        v.push(2u16);
        v.push((-2i16) as u16);
        v.push(i16::MIN as u16);
        v.push(i16::MAX as u16);
        v.push(u16::MAX);
        v
    };

    for log_n in 1..=4 {
        let table = FftTableImpl::new(log_n).unwrap();
        let n = table.poly_length();
        let blen = table.buffer_len();

        let input: Vec<u16> = (0..n).map(|i| test_values[i % test_values.len()]).collect();

        let mut out_torus = vec![0.0f64; blen];
        table.forward_torus_slice(&input, &mut out_torus);

        let centered: Vec<f64> = input.iter().map(|&v| v.into_f64_centered()).collect();
        let mut out_centered = vec![0.0f64; blen];
        table.forward_centered_f64_slice(&centered, &mut out_centered);

        assert_eq!(
            out_torus, out_centered,
            "u16: centered_equiv must match for log_n={log_n}"
        );
    }
}
