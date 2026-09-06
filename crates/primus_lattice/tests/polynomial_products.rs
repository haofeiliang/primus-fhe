//! Negacyclic monomials and component-wise NTT/DCRT polynomial products.

use primus_lattice::{
    ggsw::{Ggsw, NttGgsw},
    glev::{Glev, NttGlev},
    glwe::{Glwe, NttGlwe},
    ngsw::{Ngsw, NttNgsw},
    nlev::{Nlev, NttNlev},
    ntru::{Ntru, NttNtru},
    rgsw::{NttRgsw, Rgsw},
    rlev::{NttRlev, Rlev},
    rlwe::{NttRlwe, Rlwe},
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::NttPolynomial;

// Independent coefficient oracle, including sign changes after one or two wraps.
fn expected(acc: &[u32], rhs: &[u32], exponent: usize, n: usize, qs: &[u32]) -> Vec<u32> {
    let mut result = acc.to_vec();
    for (i, &value) in rhs.iter().enumerate() {
        let component = i / n;
        let q = qs[component % qs.len()];
        let degree = i % n + exponent;
        let destination = component * n + degree % n;
        let term = if (degree / n).is_multiple_of(2) {
            value
        } else {
            (q - value) % q
        };
        result[destination] = (result[destination] + term) % q;
    }
    result
}

#[test]
fn coefficient_monomial_accumulation_matches_oracle_and_ntt_product() {
    const N: usize = 32;
    const Q: u32 = 193;
    let modulus = BarrettModulus::new(Q);
    let table = UintNttTable::<u32>::new(5, modulus).unwrap();
    macro_rules! check {
        ($coeff:ident, $ntt:ident, $components:expr $(, $length:expr)?) => {{
            let rhs: Vec<_> = (0..N * $components).map(|i| (i as u32 * 31 + 7) % Q).collect();
            let acc: Vec<_> = (0..rhs.len()).map(|i| (i as u32 * 13 + 11) % Q).collect();
            let input = $coeff::new(rhs.as_slice());
            let mut transformed_rhs = rhs.clone();
            let mut transformed_acc = acc.clone();
            for p in transformed_rhs.chunks_exact_mut(N) { table.transform_slice(p); }
            for p in transformed_acc.chunks_exact_mut(N) { table.transform_slice(p); }
            let ntt_rhs = $ntt::new(transformed_rhs.as_slice());
            for exponent in 0..2 * N {
                let oracle = expected(&acc, &rhs, exponent, N, &[Q]);
                let mut storage = acc.clone();
                let mut output = $coeff::new(storage.as_mut_slice());
                output.add_mul_monomial_assign(&input, exponent, $($length,)? modulus);
                assert_eq!(output.as_ref(), oracle, "{} exponent {exponent}", stringify!($coeff));
                let product = expected(&vec![0; rhs.len()], &rhs, exponent, N, &[Q]);
                input.mul_monomial_to(exponent, &mut output, $($length,)? modulus);
                assert_eq!(output.as_ref(), product);
                output.as_mut().copy_from_slice(&rhs);
                output.mul_monomial_assign(exponent, $($length,)? modulus);
                assert_eq!(output.as_ref(), product);
                let mut monomial = vec![0; N];
                monomial[exponent % N] = if exponent < N { 1 } else { Q - 1 };
                table.transform_slice(&mut monomial);
                let mut ntt_output = $ntt::new(transformed_acc.clone());
                ntt_output.add_mul_ntt_polynomial_assign(&ntt_rhs, &NttPolynomial(monomial), modulus);
                for p in ntt_output.as_mut().chunks_exact_mut(N) { table.inverse_transform_slice(p); }
                assert_eq!(ntt_output.as_ref(), oracle, "{} exponent {exponent}", stringify!($ntt));
            }
        }};
    }
    check!(Glwe, NttGlwe, 3, N);
    check!(Rlwe, NttRlwe, 2, N);
    check!(Ntru, NttNtru, 1);
    check!(Glev, NttGlev, 2 * 3, N);
    check!(Ggsw, NttGgsw, 3 * 2 * 3, N);
    check!(Rlev, NttRlev, 2 * 2, N);
    check!(Rgsw, NttRgsw, 2 * 2 * 2, N);
    check!(Nlev, NttNlev, 2, N);
    check!(Ngsw, NttNgsw, 2, N);
}

#[cfg(feature = "rns")]
#[test]
fn crt_monomial_accumulation_preserves_modulus_and_gadget_order() {
    use primus_lattice::{
        ggsw::CrtGgsw, glev::CrtGlev, glwe::CrtGlwe, rgsw::CrtRgsw, rlev::CrtRlev, rlwe::CrtRlwe,
    };
    const N: usize = 32;
    let qs = [193u32, 257];
    let moduli = qs.map(BarrettModulus::new);
    let rns_poly_len = N * qs.len();
    macro_rules! check {
        ($cipher:ident, $components:expr) => {{
            let rhs: Vec<_> = (0..rns_poly_len * $components)
                .map(|i| (i as u32 * 31 + 7) % qs[i / N % 2])
                .collect();
            let acc: Vec<_> = (0..rhs.len())
                .map(|i| (i as u32 * 13 + 11) % qs[i / N % 2])
                .collect();
            let input = $cipher::new(rhs.as_slice());
            for exponent in 0..2 * N {
                let mut storage = acc.clone();
                let mut output = $cipher::new(storage.as_mut_slice());
                output.add_mul_monomial_assign(&input, exponent, N, rns_poly_len, &moduli);
                assert_eq!(output.as_ref(), expected(&acc, &rhs, exponent, N, &qs));
                let product = expected(&vec![0; rhs.len()], &rhs, exponent, N, &qs);
                input.mul_monomial_to(exponent, &mut output, N, rns_poly_len, &moduli);
                assert_eq!(output.as_ref(), product);
                output.as_mut().copy_from_slice(&rhs);
                output.mul_monomial_assign(exponent, N, rns_poly_len, &moduli);
                assert_eq!(output.as_ref(), product);
            }
        }};
    }
    check!(CrtGlwe, 3);
    check!(CrtRlwe, 2);
    check!(CrtGlev, 2 * 3);
    check!(CrtGgsw, 3 * 2 * 3);
    check!(CrtRlev, 2 * 2);
    check!(CrtRgsw, 2 * 2 * 2);
}

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
