use primus_lattice::{
    ggsw::NttGgsw, glev::NttGlev, glwe::NttGlwe, ngsw::NttNgsw, nlev::NttNlev, ntru::NttNtru,
    rgsw::NttRgsw, rlev::NttRlev, rlwe::NttRlwe,
};
use primus_modulus::BarrettModulus;
use primus_poly::NttPolynomial;

#[test]
fn ntt_products_overwrite_or_accumulate_each_component() {
    let modulus = BarrettModulus::new(97u32);
    let poly = NttPolynomial([0, 3, 96, 5]);
    macro_rules! check {
        ($cipher:ident, $components:expr) => {{
            let values: Vec<u32> = (0..4 * $components).map(|i| 96 - i as u32).collect();
            let product: Vec<_> = values
                .iter()
                .enumerate()
                .map(|(i, &x)| x * poly.as_ref()[i % 4] % 97)
                .collect();
            let input = $cipher::new(values.as_slice());
            let mut output = $cipher::new(vec![11; values.len()]);
            input.mul_ntt_polynomial_to(&poly, &mut output, modulus);
            assert_eq!(output.as_ref(), product);
            output.as_mut().copy_from_slice(&values);
            output.mul_ntt_polynomial_assign(&poly, modulus);
            assert_eq!(output.as_ref(), product);
            output.as_mut().fill(11);
            output.add_mul_ntt_polynomial_assign(&input, &poly, modulus);
            let accumulated: Vec<_> = product.iter().map(|x| (x + 11) % 97).collect();
            assert_eq!(output.as_ref(), accumulated);
        }};
    }
    check!(NttGlwe, 3);
    check!(NttRlwe, 2);
    check!(NttNtru, 1);
    check!(NttGlev, 2 * 3);
    check!(NttGgsw, 3 * 2 * 3);
    check!(NttRlev, 2 * 2);
    check!(NttRgsw, 2 * 2 * 2);
    check!(NttNlev, 2);
    check!(NttNgsw, 2);
}

#[cfg(feature = "rns")]
#[test]
fn dcrt_products_preserve_component_and_modulus_order() {
    use primus_lattice::{
        ggsw::DcrtGgsw, glev::DcrtGlev, glwe::DcrtGlwe, rgsw::DcrtRgsw, rlev::DcrtRlev,
        rlwe::DcrtRlwe,
    };
    use primus_poly::DcrtPolynomial;
    const N: usize = 2;
    let qs = [17u32, 97];
    let moduli = qs.map(BarrettModulus::new);
    let poly = DcrtPolynomial([0, 16, 96, 5]);
    macro_rules! check {
        ($cipher:ident, $components:expr) => {{
            let values: Vec<u32> = (0..4 * $components)
                .map(|i| qs[i / N % 2] - 1 - i as u32 % qs[i / N % 2])
                .collect();
            let product: Vec<_> = values
                .iter()
                .enumerate()
                .map(|(i, &x)| x * poly.as_ref()[i % 4] % qs[i / N % 2])
                .collect();
            let input = $cipher::new(values.as_slice());
            let mut output = $cipher::new(vec![11; values.len()]);
            input.mul_dcrt_polynomial_to(&poly, &mut output, N, &moduli);
            assert_eq!(output.as_ref(), product);
            output.as_mut().copy_from_slice(&values);
            output.mul_dcrt_polynomial_assign(&poly, N, &moduli);
            assert_eq!(output.as_ref(), product);
            output.as_mut().fill(11);
            output.add_mul_dcrt_polynomial_assign(&input, &poly, N, &moduli);
            let accumulated: Vec<_> = product
                .iter()
                .enumerate()
                .map(|(i, x)| (x + 11) % qs[i / N % 2])
                .collect();
            assert_eq!(output.as_ref(), accumulated);
        }};
    }
    check!(DcrtGlwe, 3);
    check!(DcrtRlwe, 2);
    // Two gadget levels, three GLWE polynomials, and three GGSW rows.
    check!(DcrtGlev, 2 * 3);
    check!(DcrtGgsw, 3 * 2 * 3);
    check!(DcrtRlev, 2 * 2);
    check!(DcrtRgsw, 2 * 2 * 2);
}
