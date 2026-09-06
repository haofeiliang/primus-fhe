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
fn fourier_arithmetic_covers_all_components_and_matches_in_place() {
    use primus_lattice::{
        ggsw::FourierGgsw, glev::FourierGlev, glwe::FourierGlwe, ngsw::FourierNgsw,
        nlev::FourierNlev, ntru::FourierNtru,
    };

    let lhs = [
        Complex64::new(1.0, 2.0),
        Complex64::new(-3.0, 4.0),
        Complex64::new(5.0, -6.0),
        Complex64::new(-7.0, -8.0),
    ];
    let rhs = [Complex64::new(2.0, -1.0); 4];
    macro_rules! check {
        ($cipher:ident) => {{
            let input = $cipher::new(lhs.as_slice());
            let rhs = $cipher::new(rhs.as_slice());
            let mut storage = [Complex64::new(42.0, 42.0); 4];
            let mut output = $cipher::new(storage.as_mut_slice());
            input.add_to(&rhs, &mut output);
            assert_eq!(output.as_ref(), &lhs.map(|x| x + Complex64::new(2.0, -1.0)));
            output.sub_assign(&rhs);
            assert_eq!(output.as_ref(), &lhs);
            input.sub_to(&rhs, &mut output);
            assert_eq!(output.as_ref(), &lhs.map(|x| x - Complex64::new(2.0, -1.0)));
            output.add_assign(&rhs);
            assert_eq!(output.as_ref(), &lhs);
            input.neg_to(&mut output);
            assert_eq!(output.as_ref(), &lhs.map(|x| -x));
            output.neg_assign();
            assert_eq!(output.as_ref(), &lhs);
            input.mul_scalar_to(-2.0, &mut output);
            assert_eq!(output.as_ref(), &lhs.map(|x| x * -2.0));
            output.mul_scalar_assign(-0.5);
            assert_eq!(output.as_ref(), &lhs);
        }};
    }
    check!(FourierGlwe);
    check!(FourierNtru);
    check!(FourierGlev);
    check!(FourierGgsw);
    check!(FourierNlev);
    check!(FourierNgsw);
}
