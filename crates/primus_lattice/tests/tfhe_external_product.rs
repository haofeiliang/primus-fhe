use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, FftTableImpl, PackedFftTable};
use primus_lattice::context::tfhe::TfheFftContext;
use primus_lattice::ggsw::Ggsw;
use primus_lattice::ggsw::fourier::FourierGgswOwned;
use primus_lattice::glwe::Glwe;
use primus_lattice::tfhe::external_product::external_product_to;

// ---------------------------------------------------------------------------
// Naive coefficient-domain external product (reference, u32 only)
// ---------------------------------------------------------------------------

/// Naive coefficient-domain external product for u32: decomposes each input
/// component, multiplies by the coefficient GGSW key, and accumulates.
fn naive_external_product_u32(
    input: &Glwe<Vec<u32>>,
    ggsw_coeff: &Ggsw<Vec<u32>>,
    output: &mut Glwe<Vec<u32>>,
    basis: &ApproxSignedBasis<u32>,
    glwe_dimension: usize,
    poly_len: usize,
) {
    let total_components = glwe_dimension + 1;
    let level = basis.decompose_length();
    let glwe_len = total_components * poly_len;
    let glev_len = level * glwe_len;

    output.set_zero();

    let mut carries = vec![false; poly_len];
    let mut decomposed = vec![0u32; poly_len];

    for input_component in 0..total_components {
        let coeff_offset = input_component * poly_len;
        let coeff_poly = &input.as_ref()[coeff_offset..coeff_offset + poly_len];

        basis.init_carry_slice(coeff_poly, &mut carries);

        for (level_idx, decomposer) in basis.decompose_iter().enumerate() {
            decomposer.decompose_slice_to(coeff_poly, &mut decomposed, &mut carries);

            for output_component in 0..total_components {
                let out_offset = output_component * poly_len;
                let out_poly = &mut output.as_mut()[out_offset..out_offset + poly_len];

                let key_offset =
                    input_component * glev_len + level_idx * glwe_len + output_component * poly_len;
                let key_poly = &ggsw_coeff.as_ref()[key_offset..key_offset + poly_len];

                for j in 0..poly_len {
                    // Interpret each torus value as centered i32, do arithmetic in i64
                    let s = decomposed[j] as i32 as i64;
                    let g = key_poly[j] as i32 as i64;
                    let prod = s.wrapping_mul(g);
                    let old = out_poly[j] as i32 as i64;
                    let sum = old.wrapping_add(prod);
                    out_poly[j] = (sum as i32) as u32;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn external_product_smoke_test() {
    let log_n = 3;
    let fft = FftTableImpl::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let blen = fft.buffer_len(); // 2 * fourier_len (split f64 per polynomial)

    // Parameters: k=1, level=2
    let glwe_dimension = 1; // mask count k
    let total_components = glwe_dimension + 1; // k + 1 = 2
    let level = 2;

    let glwe_len = total_components * poly_len; // 2 * 8 = 16
    let glev_len = level * glwe_len; // 2 * 16 = 32
    let ggsw_len = total_components * glev_len; // 2 * 32 = 64

    // Create basis: modulus=None (power-of-2), log_basis=4 (B=16)
    let basis = ApproxSignedBasis::<u32>::new(None, 4, Some(level));

    // Create coefficient GGSW key with small values
    let ggsw_coeff: Vec<u32> = (0..ggsw_len).map(|i| ((i % 7) as i32 - 3) as u32).collect();
    let ggsw_coeff = Ggsw::new(ggsw_coeff);

    // Convert to Fourier (split f64 layout: blen per polynomial)
    let fourier_glwe_len = total_components * fft.fourier_length(); // 2 * 16 = 32
    let fourier_glev_len = level * fourier_glwe_len; // 2 * 32 = 64
    let fourier_ggsw_len = total_components * fourier_glev_len; // 2 * 64 = 128
    let mut fourier_key = FourierGgswOwned::zero(fourier_ggsw_len);
    ggsw_coeff.write_fourier_form(&mut fourier_key, &fft);

    // Create input GLWE
    let input: Vec<u32> = (0..glwe_len).map(|i| ((i as i32 % 5) - 2) as u32).collect();
    let input_glwe = Glwe::new(input);

    // External product (FFT-based)
    let mut ctx = TfheFftContext::<u32>::new(poly_len, fft.fourier_length(), glwe_dimension);
    let mut output_fft = Glwe::<Vec<u32>>::zero(glwe_len);
    external_product_to(
        &input_glwe,
        &fourier_key,
        &mut output_fft,
        &basis,
        &fft,
        &mut ctx,
        glwe_dimension,
    );

    // Naive coefficient-domain reference
    let mut output_naive = Glwe::<Vec<u32>>::zero(glwe_len);
    naive_external_product_u32(
        &input_glwe,
        &ggsw_coeff,
        &mut output_naive,
        &basis,
        glwe_dimension,
        poly_len,
    );

    assert_eq!(
        output_fft.as_ref(),
        output_naive.as_ref(),
        "FFT-based external product must match naive coefficient reference"
    );
}

#[test]
fn external_product_zero_input() {
    let log_n = 2;
    let fft = FftTableImpl::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let _fourier_len = fft.fourier_length();
    let glwe_dimension = 1; // mask count k = 1
    let total_components = glwe_dimension + 1; // = 2
    let level = 1;
    let glwe_len = total_components * poly_len;
    let fourier_glwe_len = total_components * fft.fourier_length();
    let fourier_glev_len = level * fourier_glwe_len;
    let fourier_ggsw_len = total_components * fourier_glev_len;

    let basis = ApproxSignedBasis::<u32>::new(None, 8, Some(level));

    // Arbitrary Fourier key
    let mut key = FourierGgswOwned::zero(fourier_ggsw_len);
    key.as_mut().fill_with(|| 1.0f64);

    let input = Glwe::<Vec<u32>>::zero(glwe_len);
    let mut output = Glwe::<Vec<u32>>::zero(glwe_len);
    let mut ctx = TfheFftContext::<u32>::new(poly_len, fft.fourier_length(), glwe_dimension);

    external_product_to(
        &input,
        &key,
        &mut output,
        &basis,
        &fft,
        &mut ctx,
        glwe_dimension,
    );

    // Zero input should produce zero output (all zero coefficients → all zero decomposed digits)
    for &v in output.as_ref() {
        assert_eq!(v, 0u32);
    }
}

#[test]
fn context_sizes() {
    let poly_len = 1024;
    let fourier_len = 1024;
    let glwe_dimension = 2; // k = 2, total = 3
    let blen = 2 * fourier_len;

    let ctx = TfheFftContext::<u32>::new(poly_len, fourier_len, glwe_dimension);
    assert_eq!(ctx.carries.len(), poly_len);
    assert_eq!(ctx.decomposed_poly.len(), poly_len);
    assert_eq!(ctx.decomposed_fourier.len(), blen);
    // k + 1 = 3, each polynomial = blen (split f64)
    assert_eq!(ctx.fourier_accumulator.len(), (glwe_dimension + 1) * blen);

    let mut ctx = ctx;
    ctx.resize(512, 256, 3); // k=3, total=4
    let blen2 = 2 * 256;
    assert_eq!(ctx.carries.len(), 512);
    assert_eq!(ctx.decomposed_poly.len(), 512);
    assert_eq!(ctx.decomposed_fourier.len(), blen2);
    assert_eq!(ctx.fourier_accumulator.len(), (3 + 1) * blen2);
}

// ---------------------------------------------------------------------------
// Additional parameter combinations
// ---------------------------------------------------------------------------

#[test]
fn external_product_n32_k2_level2() {
    let log_n = 5; // N = 32
    let fft = FftTableImpl::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let flen = fft.fourier_length();
    let _blen = fft.buffer_len();

    let k = 2; // mask count
    let total_components = k + 1; // = 3
    let level = 2;

    let glwe_len = total_components * poly_len; // 3 * 32 = 96
    let glev_len = level * glwe_len; // 2 * 96 = 192
    let ggsw_len = total_components * glev_len; // 3 * 192 = 576

    let fourier_glwe_len = total_components * flen;
    let fourier_glev_len = level * fourier_glwe_len;
    let fourier_ggsw_len = total_components * fourier_glev_len;

    let basis = ApproxSignedBasis::<u32>::new(None, 4, Some(level));

    // Coefficient GGSW key with small values
    let ggsw_coeff: Vec<u32> = (0..ggsw_len).map(|i| ((i % 7) as i32 - 3) as u32).collect();
    let ggsw_coeff = Ggsw::new(ggsw_coeff);

    // Convert to Fourier
    let mut fourier_key = FourierGgswOwned::zero(fourier_ggsw_len);
    ggsw_coeff.write_fourier_form(&mut fourier_key, &fft);

    // Input GLWE
    let input: Vec<u32> = (0..glwe_len).map(|i| ((i as i32 % 5) - 2) as u32).collect();
    let input_glwe = Glwe::new(input);

    // FFT-based external product
    let mut ctx = TfheFftContext::<u32>::new(poly_len, flen, k);
    let mut output_fft = Glwe::<Vec<u32>>::zero(glwe_len);
    external_product_to(
        &input_glwe,
        &fourier_key,
        &mut output_fft,
        &basis,
        &fft,
        &mut ctx,
        k,
    );

    // Naive coefficient-domain reference
    let mut output_naive = Glwe::<Vec<u32>>::zero(glwe_len);
    naive_external_product_u32(
        &input_glwe,
        &ggsw_coeff,
        &mut output_naive,
        &basis,
        k,
        poly_len,
    );

    assert_eq!(
        output_fft.as_ref(),
        output_naive.as_ref(),
        "FFT external product must match naive reference for N=32,k=2,level=2"
    );
}

#[test]
fn external_product_zero_key() {
    let log_n = 3; // N = 8
    let fft = FftTableImpl::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let flen = fft.fourier_length();

    let k = 1;
    let total_components = k + 1;
    let level = 2;

    let glwe_len = total_components * poly_len;
    let fourier_glwe_len = total_components * flen;
    let fourier_glev_len = level * fourier_glwe_len;
    let fourier_ggsw_len = total_components * fourier_glev_len;

    let basis = ApproxSignedBasis::<u32>::new(None, 4, Some(level));

    // All-zero Fourier key
    let fourier_key = FourierGgswOwned::zero(fourier_ggsw_len);

    // Arbitrary non-zero input
    let input: Vec<u32> = (0..glwe_len).map(|i| ((i as i32 % 7) - 3) as u32).collect();
    let input_glwe = Glwe::new(input);

    let mut ctx = TfheFftContext::<u32>::new(poly_len, flen, k);
    let mut output = Glwe::<Vec<u32>>::zero(glwe_len);
    external_product_to(
        &input_glwe,
        &fourier_key,
        &mut output,
        &basis,
        &fft,
        &mut ctx,
        k,
    );

    // Zero key → all products are zero → output should be all zeros
    for &v in output.as_ref() {
        assert_eq!(v, 0u32, "zero key must produce zero output");
    }
}

// ---------------------------------------------------------------------------
// Fourier key length structure
// ---------------------------------------------------------------------------

/// Verify that the Fourier GGSW key has the correct structure:
/// - Logical complex count = (k+1) × level × (k+1) × fourier_length()
/// - Physical f64 count = 2 × logical count = (k+1) × level × (k+1) × buffer_len()
#[test]
fn fourier_key_length_structure() {
    for log_n in 1..=5 {
        let fft = FftTableImpl::new(log_n).unwrap();
        let flen = fft.fourier_length();
        let blen = fft.buffer_len();

        assert_eq!(blen, 2 * flen);

        for k in 1..=3 {
            for level in 1..=3 {
                let total_components = k + 1;

                // Logical complex count: rows × levels × polynomials-per-row × fourier_length
                let expected_logical = total_components * level * total_components * flen;

                // Physical f64 count (split [re|im]): 2 × logical
                let expected_physical = 2 * expected_logical;

                let key = FourierGgswOwned::zero(expected_logical);

                assert_eq!(
                    key.as_ref().len(),
                    expected_physical,
                    "Fourier GGSW physical f64 length mismatch: \
                     log_n={log_n}, k={k}, level={level}"
                );

                // Also verify directly using buffer_len:
                assert_eq!(
                    key.as_ref().len(),
                    total_components * level * total_components * blen,
                    "Fourier GGSW length = rows×levels×polys×buffer_len: \
                     log_n={log_n}, k={k}, level={level}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Packed backend — external product
// ---------------------------------------------------------------------------

#[test]
fn packed_external_product_smoke_test() {
    let log_n = 3; // N = 8
    let fft = PackedFftTable::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let flen = fft.fourier_length(); // N/2 = 4
    let _blen = fft.buffer_len(); // N = 8

    let k = 1; // mask count
    let total_components = k + 1;
    let level = 2;

    let glwe_len = total_components * poly_len; // 16
    let glev_len = level * glwe_len; // 32
    let ggsw_len = total_components * glev_len; // 64

    let basis = ApproxSignedBasis::<u32>::new(None, 4, Some(level));

    // Coefficient GGSW key
    let ggsw_coeff: Vec<u32> = (0..ggsw_len).map(|i| ((i % 7) as i32 - 3) as u32).collect();
    let ggsw_coeff = Ggsw::new(ggsw_coeff);

    // Convert to packed Fourier (half the size of full).
    let fourier_glwe_len = total_components * flen;
    let fourier_glev_len = level * fourier_glwe_len;
    let fourier_ggsw_len = total_components * fourier_glev_len;
    let mut fourier_key = FourierGgswOwned::zero(fourier_ggsw_len);
    ggsw_coeff.write_fourier_form(&mut fourier_key, &fft);

    // Packed: key is half the size of full.
    let full_blen = 2 * poly_len; // full backend buffer_len
    assert_eq!(
        fourier_key.as_ref().len(),
        total_components * level * total_components * fft.buffer_len()
    );
    assert_eq!(fft.buffer_len(), full_blen / 2);

    // Input GLWE
    let input: Vec<u32> = (0..glwe_len).map(|i| ((i as i32 % 5) - 2) as u32).collect();
    let input_glwe = Glwe::new(input);

    // FFT-based external product with packed backend
    let mut ctx = TfheFftContext::<u32>::new(poly_len, flen, k);
    let mut output_fft = Glwe::<Vec<u32>>::zero(glwe_len);
    external_product_to(
        &input_glwe,
        &fourier_key,
        &mut output_fft,
        &basis,
        &fft,
        &mut ctx,
        k,
    );

    // Naive coefficient-domain reference
    let mut output_naive = Glwe::<Vec<u32>>::zero(glwe_len);
    naive_external_product_u32(
        &input_glwe,
        &ggsw_coeff,
        &mut output_naive,
        &basis,
        k,
        poly_len,
    );

    assert_eq!(
        output_fft.as_ref(),
        output_naive.as_ref(),
        "packed external product must match naive reference"
    );
}

#[test]
fn packed_external_product_n32_k2_level2() {
    let log_n = 5; // N = 32
    let fft = PackedFftTable::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let flen = fft.fourier_length(); // N/2 = 16

    let k = 2;
    let total_components = k + 1;
    let level = 2;

    let glwe_len = total_components * poly_len;
    let glev_len = level * glwe_len;
    let ggsw_len = total_components * glev_len;

    let basis = ApproxSignedBasis::<u32>::new(None, 4, Some(level));

    let ggsw_coeff: Vec<u32> = (0..ggsw_len).map(|i| ((i % 7) as i32 - 3) as u32).collect();
    let ggsw_coeff = Ggsw::new(ggsw_coeff);

    let fourier_glwe_len = total_components * flen;
    let fourier_glev_len = level * fourier_glwe_len;
    let fourier_ggsw_len = total_components * fourier_glev_len;
    let mut fourier_key = FourierGgswOwned::zero(fourier_ggsw_len);
    ggsw_coeff.write_fourier_form(&mut fourier_key, &fft);

    let input: Vec<u32> = (0..glwe_len).map(|i| ((i as i32 % 5) - 2) as u32).collect();
    let input_glwe = Glwe::new(input);

    let mut ctx = TfheFftContext::<u32>::new(poly_len, flen, k);
    let mut output_fft = Glwe::<Vec<u32>>::zero(glwe_len);
    external_product_to(
        &input_glwe,
        &fourier_key,
        &mut output_fft,
        &basis,
        &fft,
        &mut ctx,
        k,
    );

    let mut output_naive = Glwe::<Vec<u32>>::zero(glwe_len);
    naive_external_product_u32(
        &input_glwe,
        &ggsw_coeff,
        &mut output_naive,
        &basis,
        k,
        poly_len,
    );

    assert_eq!(
        output_fft.as_ref(),
        output_naive.as_ref(),
        "packed external product for N=32,k=2,level=2 must match naive"
    );
}

#[test]
fn packed_external_product_zero_key() {
    let log_n = 3;
    let fft = PackedFftTable::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let flen = fft.fourier_length();

    let k = 1;
    let total_components = k + 1;
    let level = 2;

    let glwe_len = total_components * poly_len;
    let fourier_glwe_len = total_components * flen;
    let fourier_glev_len = level * fourier_glwe_len;
    let fourier_ggsw_len = total_components * fourier_glev_len;

    let basis = ApproxSignedBasis::<u32>::new(None, 4, Some(level));

    // All-zero packed Fourier key
    let fourier_key = FourierGgswOwned::zero(fourier_ggsw_len);

    let input: Vec<u32> = (0..glwe_len).map(|i| ((i as i32 % 7) - 3) as u32).collect();
    let input_glwe = Glwe::new(input);

    let mut ctx = TfheFftContext::<u32>::new(poly_len, flen, k);
    let mut output = Glwe::<Vec<u32>>::zero(glwe_len);
    external_product_to(
        &input_glwe,
        &fourier_key,
        &mut output,
        &basis,
        &fft,
        &mut ctx,
        k,
    );

    for &v in output.as_ref() {
        assert_eq!(v, 0u32, "packed: zero key must produce zero output");
    }
}

#[test]
fn packed_external_product_zero_input() {
    let log_n = 2;
    let fft = PackedFftTable::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let flen = fft.fourier_length();

    let k = 1;
    let total_components = k + 1;
    let level = 1;

    let glwe_len = total_components * poly_len;
    let fourier_glwe_len = total_components * flen;
    let fourier_glev_len = level * fourier_glwe_len;
    let fourier_ggsw_len = total_components * fourier_glev_len;

    let basis = ApproxSignedBasis::<u32>::new(None, 8, Some(level));

    let mut key = FourierGgswOwned::zero(fourier_ggsw_len);
    key.as_mut().fill_with(|| 1.0f64);

    let input = Glwe::<Vec<u32>>::zero(glwe_len);
    let mut output = Glwe::<Vec<u32>>::zero(glwe_len);
    let mut ctx = TfheFftContext::<u32>::new(poly_len, flen, k);

    external_product_to(&input, &key, &mut output, &basis, &fft, &mut ctx, k);

    for &v in output.as_ref() {
        assert_eq!(v, 0u32, "packed: zero input must produce zero output");
    }
}

#[test]
fn packed_and_full_produce_same_external_product() {
    for log_n in 2..=4 {
        let full_fft = FftTableImpl::new(log_n).unwrap();
        let packed_fft = PackedFftTable::new(log_n).unwrap();

        let poly_len = full_fft.poly_length();
        let k = 1;
        let total_components = k + 1;
        let level = 2;

        let glwe_len = total_components * poly_len;
        let glev_len = level * glwe_len;
        let ggsw_len = total_components * glev_len;

        let basis = ApproxSignedBasis::<u32>::new(None, 4, Some(level));

        let ggsw_coeff: Vec<u32> = (0..ggsw_len).map(|i| ((i % 7) as i32 - 3) as u32).collect();
        let ggsw_coeff = Ggsw::new(ggsw_coeff);

        // Full backend key
        let full_flen = full_fft.fourier_length();
        let full_fourier_glwe_len = total_components * full_flen;
        let full_fourier_glev_len = level * full_fourier_glwe_len;
        let full_fourier_ggsw_len = total_components * full_fourier_glev_len;
        let mut full_key = FourierGgswOwned::zero(full_fourier_ggsw_len);
        ggsw_coeff.write_fourier_form(&mut full_key, &full_fft);

        // Packed backend key
        let packed_flen = packed_fft.fourier_length();
        let packed_fourier_glwe_len = total_components * packed_flen;
        let packed_fourier_glev_len = level * packed_fourier_glwe_len;
        let packed_fourier_ggsw_len = total_components * packed_fourier_glev_len;
        let mut packed_key = FourierGgswOwned::zero(packed_fourier_ggsw_len);
        ggsw_coeff.write_fourier_form(&mut packed_key, &packed_fft);

        // Verify packed key is half the size
        assert_eq!(full_key.as_ref().len(), 2 * packed_key.as_ref().len());

        let input: Vec<u32> = (0..glwe_len).map(|i| ((i as i32 % 5) - 2) as u32).collect();
        let input_glwe = Glwe::new(input);

        // Full backend external product
        let mut full_ctx = TfheFftContext::<u32>::new(poly_len, full_flen, k);
        let mut full_output = Glwe::<Vec<u32>>::zero(glwe_len);
        external_product_to(
            &input_glwe,
            &full_key,
            &mut full_output,
            &basis,
            &full_fft,
            &mut full_ctx,
            k,
        );

        // Packed backend external product
        let mut packed_ctx = TfheFftContext::<u32>::new(poly_len, packed_flen, k);
        let mut packed_output = Glwe::<Vec<u32>>::zero(glwe_len);
        external_product_to(
            &input_glwe,
            &packed_key,
            &mut packed_output,
            &basis,
            &packed_fft,
            &mut packed_ctx,
            k,
        );

        assert_eq!(
            full_output.as_ref(),
            packed_output.as_ref(),
            "full and packed backends must produce same result for log_n={log_n}"
        );
    }
}
