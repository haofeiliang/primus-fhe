use primus_lattice::ggsw::fourier::{FourierGgsw, FourierGgswIter, FourierGgswOwned};
use primus_lattice::glev::fourier::{FourierGlev, FourierGlevIter, FourierGlevOwned};
use primus_lattice::glwe::fourier::{FourierGlwe, FourierGlweIter, FourierGlweOwned};

// `zero(n)` takes the logical complex count; the buffer holds 2*n f64 values.

// ---------------------------------------------------------------------------
// FourierGlwe tests
// ---------------------------------------------------------------------------

#[test]
fn fourier_glwe_new_and_zero() {
    let glwe = FourierGlweOwned::zero(3); // 6 f64
    assert_eq!(glwe.byte_count(), 6 * 8);
}

#[test]
fn fourier_glwe_set_zero() {
    let data = vec![1.0f64; 12];
    let mut glwe = FourierGlwe::new(data);
    glwe.set_zero();
    assert!(glwe.as_ref().iter().all(|&x| x == 0.0f64));
}

#[test]
fn fourier_glwe_a_b_slices() {
    // k=2 mask + 1 body = 3 polys, each logical length 3
    let flen = 3;
    let k = 2;
    let logical_glwe = (k + 1) * flen; // 9 logical → 18 f64
    let mid = k * flen; // 6 logical → 12 f64
    let data = vec![0.0f64; 2 * logical_glwe];
    let glwe = FourierGlwe::new(data);
    let (a, b) = glwe.a_b_slices(2 * mid);
    assert_eq!(a.len(), 2 * mid);
    assert_eq!(b.len(), 2 * flen);
}

#[test]
fn fourier_glwe_a_b_mut_slices() {
    let flen = 2;
    let k = 1;
    let logical_glwe = (k + 1) * flen; // 4 logical → 8 f64
    let mid = k * flen; // 2 logical → 4 f64
    let mut glwe = FourierGlweOwned::zero(logical_glwe);
    {
        let (a, b) = glwe.a_b_mut_slices(2 * mid);
        a[0] = 1.0;
        b[0] = 2.0;
    }
    assert_eq!(glwe.as_ref()[0], 1.0);
    assert_eq!(glwe.as_ref()[2 * mid], 2.0);
}

#[test]
fn fourier_glwe_iter_fourier_poly() {
    // 2 polys, each logical length 2 → 4 f64 each → 8 total
    let flen = 2;
    let data = vec![1.0f64; 4 * flen];
    let glwe = FourierGlwe::new(data);
    let polys: Vec<_> = glwe.iter_fourier_poly(flen).collect();
    assert_eq!(polys.len(), 2);
    assert_eq!(polys[0].fourier_length(), 2);
    assert_eq!(polys[1].fourier_length(), 2);
}

#[test]
fn fourier_glwe_iterator() {
    // 2 GLWEs, each logical complex count 4 → 8 f64 → 16 total
    let glwe_len = 4; // logical complex count per GLWE
    let data = vec![0.0f64; 2 * 2 * glwe_len]; // 2 GLWEs × 8 f64 = 16
    let iter = FourierGlweIter::new(&data, 2 * glwe_len);
    assert_eq!(iter.count(), 2);
}

// ---------------------------------------------------------------------------
// FourierGlev tests
// ---------------------------------------------------------------------------

#[test]
fn fourier_glev_new_and_zero() {
    let glev = FourierGlevOwned::zero(18); // 36 f64
    assert_eq!(glev.byte_count(), 36 * 8);
}

#[test]
fn fourier_glev_set_zero() {
    let data = vec![1.0f64; 18];
    let mut glev = FourierGlev::new(data);
    glev.set_zero();
    assert!(glev.as_ref().iter().all(|&x| x == 0.0f64));
}

#[test]
fn fourier_glev_iter_glwe() {
    // 3 GLWEs, each logical complex count 8 → 16 f64
    let glwe_len = 8; // logical complex count per GLWE
    let glev_len = 3 * 2 * glwe_len; // 3 × 16 f64 = 48
    let data = vec![0.0f64; glev_len];
    let glev = FourierGlev::new(data);
    let glwes: Vec<_> = glev.iter_glwe(2 * glwe_len).collect();
    assert_eq!(glwes.len(), 3);
}

#[test]
fn fourier_glev_iterator() {
    let glev_len = 12; // f64 count per GLev
    let data = vec![0.0f64; 24];
    let iter = FourierGlevIter::new(&data, glev_len);
    assert_eq!(iter.count(), 2);
}

// ---------------------------------------------------------------------------
// FourierGgsw tests
// ---------------------------------------------------------------------------

#[test]
fn fourier_ggsw_new_and_zero() {
    let ggsw = FourierGgswOwned::zero(36); // 72 f64
    assert_eq!(ggsw.byte_count(), 72 * 8);
}

#[test]
fn fourier_ggsw_set_zero() {
    let data = vec![1.0f64; 72];
    let mut ggsw = FourierGgsw::new(data);
    ggsw.set_zero();
    assert!(ggsw.as_ref().iter().all(|&x| x == 0.0f64));
}

#[test]
fn fourier_ggsw_iter_glev() {
    let glev_len = 16; // f64 count per GLev
    let ggsw_len = 32; // 2 rows × 16
    let data = vec![0.0f64; ggsw_len];
    let ggsw = FourierGgsw::new(data);
    let glevs: Vec<_> = ggsw.iter_glev(glev_len).collect();
    assert_eq!(glevs.len(), 2);
}

#[test]
fn fourier_ggsw_iterator() {
    let ggsw_len = 16;
    let data = vec![0.0f64; 32];
    let iter = FourierGgswIter::new(&data, ggsw_len);
    assert_eq!(iter.count(), 2);
}
