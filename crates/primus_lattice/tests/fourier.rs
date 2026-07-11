use primus_fft::Complex64;
use primus_lattice::{ggsw::FourierGgswOwned, glev::FourierGlevOwned, glwe::FourierGlweOwned};

#[test]
fn fourier_ciphertexts_store_complex_values() {
    let glwe = FourierGlweOwned::zero(16);
    let glev = FourierGlevOwned::zero(32);
    let ggsw = FourierGgswOwned::zero(64);
    assert_eq!(glwe.as_ref(), vec![Complex64::default(); 16]);
    assert_eq!(glev.as_ref().len(), 32);
    assert_eq!(ggsw.as_ref().len(), 64);
    assert_eq!(glwe.byte_count(), 16 * core::mem::size_of::<Complex64>());
}

#[test]
fn nested_iterators_use_complex_element_lengths() {
    let glev = FourierGlevOwned::zero(24);
    let mut glwes = glev.iter_glwe(8);
    assert_eq!(glwes.len(), 3);
    assert_eq!(glwes.next_back().unwrap().as_ref().len(), 8);
    assert_eq!(glwes.len(), 2);
    let ggsw = FourierGgswOwned::zero(48);
    assert_eq!(ggsw.iter_glev(24).count(), 2);
}

#[test]
#[should_panic(expected = "Fourier data length must be divisible")]
fn fourier_iterator_rejects_a_partial_trailing_component() {
    let glev = FourierGlevOwned::zero(25);
    let _ = glev.iter_glwe(8);
}

#[test]
#[should_panic(expected = "Fourier chunk length must be non-zero")]
fn fourier_iterator_rejects_zero_component_length() {
    let glev = FourierGlevOwned::zero(24);
    let _ = glev.iter_glwe(0);
}
