use primus_fft::{FftTable, FftTableImpl, PackedFftTable};
use primus_lattice::ggsw::Ggsw;
use primus_lattice::ggsw::fourier::FourierGgswOwned;
use primus_lattice::glev::Glev;
use primus_lattice::glev::fourier::FourierGlevOwned;
use primus_lattice::glwe::Glwe;
use primus_lattice::glwe::fourier::FourierGlweOwned;

// ---------------------------------------------------------------------------
// GLWE roundtrip
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_glwe_u32() {
    for log_n in 1..=4 {
        let fft = FftTableImpl::new(log_n).unwrap();
        let poly_len = fft.poly_length();
        let _fourier_len = fft.fourier_length();

        let k = 2;
        let glwe_len = (k + 1) * poly_len;
        let fourier_glwe_len = (k + 1) * fft.fourier_length();

        // Coefficient GLWE with small centered values
        let coeff: Vec<u32> = (0..glwe_len)
            .map(|i| match i % 5 {
                0 => 0u32,
                1 => 1u32,
                2 => (-1i32) as u32,
                3 => 2u32,
                _ => (-2i32) as u32,
            })
            .collect();
        let glwe = Glwe::new(coeff.clone());

        // Forward: coeff → Fourier
        let mut fourier_glwe = FourierGlweOwned::zero(fourier_glwe_len);
        glwe.write_fourier_form(&mut fourier_glwe, &fft);

        // Inverse: Fourier → coeff
        let mut result = Glwe::<Vec<u32>>::zero(glwe_len);
        fourier_glwe.write_torus_form(&mut result, &fft);

        assert_eq!(
            coeff,
            result.as_ref(),
            "GLWE u32 roundtrip failed for log_n={log_n}"
        );
    }
}

#[test]
fn roundtrip_glwe_u64() {
    for log_n in 1..=3 {
        let fft = FftTableImpl::new(log_n).unwrap();
        let poly_len = fft.poly_length();
        let _fourier_len = fft.fourier_length();

        let k = 1;
        let glwe_len = (k + 1) * poly_len;
        let fourier_glwe_len = (k + 1) * fft.fourier_length();

        let coeff: Vec<u64> = (0..glwe_len)
            .map(|i| match i % 5 {
                0 => 0u64,
                1 => 1u64,
                2 => (-1i64) as u64,
                3 => 2u64,
                _ => (-2i64) as u64,
            })
            .collect();
        let glwe = Glwe::new(coeff.clone());

        let mut fourier_glwe = FourierGlweOwned::zero(fourier_glwe_len);
        glwe.write_fourier_form(&mut fourier_glwe, &fft);

        let mut result = Glwe::<Vec<u64>>::zero(glwe_len);
        fourier_glwe.write_torus_form(&mut result, &fft);

        assert_eq!(
            coeff,
            result.as_ref(),
            "GLWE u64 roundtrip failed for log_n={log_n}"
        );
    }
}

// ---------------------------------------------------------------------------
// GLEV roundtrip
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_glev_u32() {
    let log_n = 3;
    let fft = FftTableImpl::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let fourier_len = fft.fourier_length();

    let k = 1;
    let level = 2;
    let glwe_len = (k + 1) * poly_len; // 2 * 8 = 16
    let glev_len = level * glwe_len; // 2 * 16 = 32
    let fourier_glwe_len = (k + 1) * fft.fourier_length();
    let fourier_glev_len = level * fourier_glwe_len;

    let coeff: Vec<u32> = (0..glev_len)
        .map(|i| match i % 5 {
            0 => 0u32,
            1 => 1u32,
            2 => (-1i32) as u32,
            3 => 2u32,
            _ => (-2i32) as u32,
        })
        .collect();
    let glev = Glev::new(coeff.clone());

    let mut fourier_glev = FourierGlevOwned::zero(fourier_glev_len);
    glev.write_fourier_form(&mut fourier_glev, &fft);

    let mut result = Glev::<Vec<u32>>::zero(glev_len);
    fourier_glev.write_torus_form(&mut result, &fft);

    assert_eq!(coeff, result.as_ref(), "GLEV u32 roundtrip failed");
}

// ---------------------------------------------------------------------------
// GGSW roundtrip
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_ggsw_u32() {
    let log_n = 2;
    let fft = FftTableImpl::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let fourier_len = fft.fourier_length();

    let k = 1;
    let level = 1;
    let glwe_len = (k + 1) * poly_len; // 2 * 4 = 8
    let glev_len = level * glwe_len; // 1 * 8 = 8
    let ggsw_len = (k + 1) * glev_len; // 2 * 8 = 16
    let fourier_glwe_len = (k + 1) * fft.fourier_length();
    let fourier_glev_len = level * fourier_glwe_len;
    let fourier_ggsw_len = (k + 1) * fourier_glev_len;

    let coeff: Vec<u32> = (0..ggsw_len)
        .map(|i| match i % 5 {
            0 => 0u32,
            1 => 1u32,
            2 => (-1i32) as u32,
            3 => 2u32,
            _ => (-2i32) as u32,
        })
        .collect();
    let ggsw = Ggsw::new(coeff.clone());

    let mut fourier_ggsw = FourierGgswOwned::zero(fourier_ggsw_len);
    ggsw.write_fourier_form(&mut fourier_ggsw, &fft);

    let mut result = Ggsw::<Vec<u32>>::zero(ggsw_len);
    fourier_ggsw.write_torus_form(&mut result, &fft);

    assert_eq!(coeff, result.as_ref(), "GGSW u32 roundtrip failed");
}

// ---------------------------------------------------------------------------
// Shape boundary tests
// ---------------------------------------------------------------------------

#[test]
fn glwe_shape_matches_fourier_shape() {
    let log_n = 3;
    let fft = FftTableImpl::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let fourier_len = fft.fourier_length();

    for k in 1..=3 {
        let glwe_len = (k + 1) * poly_len;
        let fourier_glwe_len = (k + 1) * fft.fourier_length();

        let glwe = Glwe::<Vec<u32>>::zero(glwe_len);
        let mut fourier = FourierGlweOwned::zero(fourier_glwe_len);
        glwe.write_fourier_form(&mut fourier, &fft);

        assert_eq!(fourier.byte_count(), 2 * fourier_glwe_len * 8);
    }
}

#[test]
fn zero_glwe_roundtrip() {
    let log_n = 3;
    let fft = FftTableImpl::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let fourier_len = fft.fourier_length();

    let k = 2;
    let glwe_len = (k + 1) * poly_len;
    let fourier_glwe_len = (k + 1) * fft.fourier_length();

    let glwe = Glwe::<Vec<u32>>::zero(glwe_len);
    let mut fourier = FourierGlweOwned::zero(fourier_glwe_len);
    glwe.write_fourier_form(&mut fourier, &fft);

    // After forward transform, Fourier should still be close to zero
    // (all-zero input → all-zero Fourier output)
    for &c in fourier.as_ref() {
        assert!(
            c.abs() < 1e-12,
            "zero input should produce zero Fourier output"
        );
    }

    let mut result = Glwe::<Vec<u32>>::zero(glwe_len);
    fourier.write_torus_form(&mut result, &fft);
    for &v in result.as_ref() {
        assert_eq!(v, 0u32, "zero roundtrip should be exact");
    }
}

// ---------------------------------------------------------------------------
// Logical vs physical length tests
// ---------------------------------------------------------------------------

/// For each Fourier container type, verify that `zero(n)` — where `n` is the
/// logical complex count — allocates `2 * n` physical `f64` values, and that
/// the relationship between `fourier_length()` and `buffer_len()` is consistent.
#[test]
fn fourier_container_logical_vs_physical() {
    for log_n in 1..=4 {
        let fft = FftTableImpl::new(log_n).unwrap();
        let flen = fft.fourier_length();
        let blen = fft.buffer_len();

        assert_eq!(blen, 2 * flen, "buffer_len must be 2 * fourier_length");

        for k in 1..=3 {
            let total_polys = k + 1;

            // --- FourierGlweOwned ---
            let glwe_logical = total_polys * flen;
            let glwe = FourierGlweOwned::zero(glwe_logical);
            assert_eq!(
                glwe.as_ref().len(),
                2 * glwe_logical,
                "GLWE: physical f64 = 2 × logical, log_n={log_n} k={k}"
            );
            assert_eq!(
                glwe.as_ref().len(),
                total_polys * blen,
                "GLWE: physical f64 = (k+1) × buffer_len, log_n={log_n} k={k}"
            );
            assert_eq!(
                glwe.byte_count(),
                8 * glwe.as_ref().len(),
                "GLWE: byte_count = 8 × physical f64, log_n={log_n} k={k}"
            );

            let level = 2;

            // --- FourierGlevOwned ---
            let glwe_logical = total_polys * flen;
            let glev_logical = level * glwe_logical;
            let glev = FourierGlevOwned::zero(glev_logical);
            assert_eq!(
                glev.as_ref().len(),
                2 * glev_logical,
                "GLEV: physical f64 = 2 × logical, log_n={log_n} k={k}"
            );
            assert_eq!(
                glev.as_ref().len(),
                level * total_polys * blen,
                "GLEV: physical f64 = level × (k+1) × buffer_len, log_n={log_n} k={k}"
            );
            assert_eq!(
                glev.byte_count(),
                8 * glev.as_ref().len(),
                "GLEV: byte_count = 8 × physical f64, log_n={log_n} k={k}"
            );

            // --- FourierGgswOwned ---
            let ggsw_logical = total_polys * glev_logical;
            let ggsw = FourierGgswOwned::zero(ggsw_logical);
            assert_eq!(
                ggsw.as_ref().len(),
                2 * ggsw_logical,
                "GGSW: physical f64 = 2 × logical, log_n={log_n} k={k}"
            );
            assert_eq!(
                ggsw.as_ref().len(),
                total_polys * level * total_polys * blen,
                "GGSW: physical f64 = (k+1)×level×(k+1)×buffer_len, log_n={log_n} k={k}"
            );
            assert_eq!(
                ggsw.byte_count(),
                8 * ggsw.as_ref().len(),
                "GGSW: byte_count = 8 × physical f64, log_n={log_n} k={k}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Chunking with buffer_len
// ---------------------------------------------------------------------------

/// Verify that `fft.buffer_len()` is the correct chunk size for splitting raw
/// `f64` Fourier storage into per-polynomial slices, and that
/// `fft.fourier_length()` gives the logical complex count for each polynomial.
#[test]
fn chunking_with_buffer_len() {
    for log_n in 1..=4 {
        let fft = FftTableImpl::new(log_n).unwrap();
        let flen = fft.fourier_length();
        let blen = fft.buffer_len();

        assert_eq!(blen, 2 * flen);

        let k = 2;
        let total_polys = k + 1;

        // Build a GLWE with known values so we can verify chunking.
        let glwe_logical = total_polys * flen;
        let mut glwe = FourierGlweOwned::zero(glwe_logical);
        // Write a pattern: polynomial i gets value i+1 in all its elements.
        for (poly_idx, poly_slice) in glwe.as_mut().chunks_exact_mut(blen).enumerate() {
            for v in poly_slice.iter_mut() {
                *v = (poly_idx + 1) as f64;
            }
        }

        // Chunk using buffer_len(): each chunk = one polynomial's f64 buffer.
        let chunks: Vec<&[f64]> = glwe.as_ref().chunks_exact(blen).collect();
        assert_eq!(
            chunks.len(),
            total_polys,
            "buffer_len-based chunking must yield one chunk per polynomial"
        );
        for (i, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk.len(), blen);
            let expected = (i + 1) as f64;
            assert!(
                chunk.iter().all(|&x| x == expected),
                "polynomial {i} should have all elements == {expected}"
            );
        }

        // Each FourierPolynomial view via iter_fourier_poly reports correct lengths.
        for poly in glwe.iter_fourier_poly(flen) {
            assert_eq!(poly.fourier_length(), flen);
            assert_eq!(poly.as_ref().len(), blen);
        }

        // Chunking with fourier_length() (wrong!) would under-count.
        // buffer_len() = 2 * fourier_length, so using fourier_length as
        // chunk size would split each polynomial in half.
        let wrong_chunks: Vec<&[f64]> = glwe.as_ref().chunks_exact(flen).collect();
        assert_eq!(wrong_chunks.len(), 2 * total_polys);
    }
}

// ---------------------------------------------------------------------------
// Packed backend — shape and roundtrip
// ---------------------------------------------------------------------------

#[test]
fn packed_glwe_roundtrip_u32() {
    for log_n in 2..=4 {
        let fft = PackedFftTable::new(log_n).unwrap();
        let poly_len = fft.poly_length();
        let fourier_len = fft.fourier_length();

        assert_eq!(fourier_len, poly_len / 2, "packed fourier_length = N/2");
        assert_eq!(fft.buffer_len(), poly_len, "packed buffer_len = N");

        let k = 2;
        let glwe_len = (k + 1) * poly_len;
        let fourier_glwe_len = (k + 1) * fourier_len;

        let coeff: Vec<u32> = (0..glwe_len)
            .map(|i| match i % 5 {
                0 => 0u32,
                1 => 1u32,
                2 => (-1i32) as u32,
                3 => 2u32,
                _ => (-2i32) as u32,
            })
            .collect();
        let glwe = Glwe::new(coeff.clone());

        let mut fourier_glwe = FourierGlweOwned::zero(fourier_glwe_len);
        glwe.write_fourier_form(&mut fourier_glwe, &fft);

        // Packed Fourier storage is half the size of full.
        let expected_physical = (k + 1) * fft.buffer_len();
        assert_eq!(fourier_glwe.as_ref().len(), expected_physical);

        let mut result = Glwe::<Vec<u32>>::zero(glwe_len);
        fourier_glwe.write_torus_form(&mut result, &fft);

        assert_eq!(
            coeff,
            result.as_ref(),
            "packed GLWE u32 roundtrip failed for log_n={log_n}"
        );
    }
}

#[test]
fn packed_glev_roundtrip_u32() {
    let log_n = 3; // N = 8
    let fft = PackedFftTable::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let fourier_len = fft.fourier_length(); // N/2 = 4
    let blen = fft.buffer_len(); // N = 8

    let k = 1;
    let level = 2;
    let glwe_len = (k + 1) * poly_len;
    let glev_len = level * glwe_len;
    let fourier_glwe_len = (k + 1) * fourier_len;
    let fourier_glev_len = level * fourier_glwe_len;

    let coeff: Vec<u32> = (0..glev_len)
        .map(|i| match i % 5 {
            0 => 0u32,
            1 => 1u32,
            2 => (-1i32) as u32,
            3 => 2u32,
            _ => (-2i32) as u32,
        })
        .collect();
    let glev = Glev::new(coeff.clone());

    let mut fourier_glev = FourierGlevOwned::zero(fourier_glev_len);
    glev.write_fourier_form(&mut fourier_glev, &fft);

    // Packed: physical = level * (k+1) * buffer_len = 2 * 2 * 8 = 32
    assert_eq!(fourier_glev.as_ref().len(), level * (k + 1) * blen);

    let mut result = Glev::<Vec<u32>>::zero(glev_len);
    fourier_glev.write_torus_form(&mut result, &fft);

    assert_eq!(coeff, result.as_ref(), "packed GLEV u32 roundtrip failed");
}

#[test]
fn packed_ggsw_roundtrip_u32() {
    let log_n = 2; // N = 4
    let fft = PackedFftTable::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let fourier_len = fft.fourier_length(); // N/2 = 2
    let blen = fft.buffer_len(); // N = 4

    let k = 1;
    let level = 1;
    let glwe_len = (k + 1) * poly_len;
    let glev_len = level * glwe_len;
    let ggsw_len = (k + 1) * glev_len;
    let fourier_glwe_len = (k + 1) * fourier_len;
    let fourier_glev_len = level * fourier_glwe_len;
    let fourier_ggsw_len = (k + 1) * fourier_glev_len;

    let coeff: Vec<u32> = (0..ggsw_len)
        .map(|i| match i % 5 {
            0 => 0u32,
            1 => 1u32,
            2 => (-1i32) as u32,
            3 => 2u32,
            _ => (-2i32) as u32,
        })
        .collect();
    let ggsw = Ggsw::new(coeff.clone());

    let mut fourier_ggsw = FourierGgswOwned::zero(fourier_ggsw_len);
    ggsw.write_fourier_form(&mut fourier_ggsw, &fft);

    // Packed: physical = (k+1) * level * (k+1) * buffer_len = 2 * 1 * 2 * 4 = 16
    assert_eq!(
        fourier_ggsw.as_ref().len(),
        (k + 1) * level * (k + 1) * blen
    );

    let mut result = Ggsw::<Vec<u32>>::zero(ggsw_len);
    fourier_ggsw.write_torus_form(&mut result, &fft);

    assert_eq!(coeff, result.as_ref(), "packed GGSW u32 roundtrip failed");
}

#[test]
fn packed_fourier_container_sizes() {
    for log_n in 2..=4 {
        let fft = PackedFftTable::new(log_n).unwrap();
        let flen = fft.fourier_length(); // N/2
        let blen = fft.buffer_len(); // N

        assert_eq!(blen, 2 * flen);
        assert_eq!(flen, fft.poly_length() / 2);

        for k in 1..=2 {
            let total_polys = k + 1;
            let level = 2;

            // GLWE: logical = (k+1) * N/2, physical = (k+1) * N
            let glwe_logical = total_polys * flen;
            let glwe = FourierGlweOwned::zero(glwe_logical);
            assert_eq!(glwe.as_ref().len(), total_polys * blen);

            // GLEV: logical = level * (k+1) * N/2, physical = level * (k+1) * N
            let glev_logical = level * glwe_logical;
            let glev = FourierGlevOwned::zero(glev_logical);
            assert_eq!(glev.as_ref().len(), level * total_polys * blen);

            // GGSW: logical = (k+1) * level * (k+1) * N/2
            //        physical = (k+1) * level * (k+1) * N
            let ggsw_logical = total_polys * glev_logical;
            let ggsw = FourierGgswOwned::zero(ggsw_logical);
            assert_eq!(
                ggsw.as_ref().len(),
                total_polys * level * total_polys * blen
            );
        }
    }
}
