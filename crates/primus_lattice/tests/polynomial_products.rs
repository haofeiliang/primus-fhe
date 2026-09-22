//! Negacyclic monomials and component-wise NTT/DCRT polynomial products.

use primus_lattice::{
    ggsw::{Ggsw, NttGgsw},
    ntru::{Ntru, NttNtru},
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, UintNttTable};

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
fn coefficient_and_ntt_monomials_match_negacyclic_oracle() {
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
            let ntt_acc = $ntt::new(transformed_acc.as_slice());
            let mut scratch = vec![Q - 1; N];
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
                let mut ntt_output = $ntt::new(transformed_acc.clone());
                ntt_output.add_mul_monomial_assign(&ntt_rhs, exponent, modulus, &table, &mut scratch);
                ntt_output.write_coeff_form(&mut output, &table);
                assert_eq!(output.as_ref(), oracle, "{} exponent {exponent}", stringify!($ntt));
                ntt_rhs.mul_monomial_to(exponent, &mut ntt_output, modulus, &table, &mut scratch);
                ntt_output.write_coeff_form(&mut output, &table);
                assert_eq!(output.as_ref(), product);
                ntt_output.as_mut().copy_from_slice(&transformed_rhs);
                ntt_output.mul_monomial_assign(exponent, modulus, &table, &mut scratch);
                ntt_output.write_coeff_form(&mut output, &table);
                assert_eq!(output.as_ref(), product);
                ntt_acc.sub_mul_monomial_to(&ntt_rhs, exponent, &mut ntt_output, modulus, &table, &mut scratch);
                ntt_output.write_coeff_form(&mut output, &table);
                // -X^e = X^(e+N), with the exponent reduced modulo 2N.
                let difference = expected(&acc, &rhs, (exponent + N) % (2 * N), N, &[Q]);
                assert_eq!(output.as_ref(), difference);
            }
        }};
    }
    // NTRU has a single-polynomial implementation; GGSW covers the shared
    // multi-polynomial kernels across rows, levels and mask/body components.
    check!(Ntru, NttNtru, 1);
    check!(Ggsw, NttGgsw, 3 * 2 * 3, N);
}

#[cfg(feature = "rns")]
#[test]
fn crt_monomial_accumulation_preserves_modulus_and_gadget_order() {
    use primus_lattice::ggsw::CrtGgsw;
    const N: usize = 32;
    let qs = [193u32, 257];
    let moduli = qs.map(BarrettModulus::new);
    let rns_poly_len = N * qs.len();
    let rhs: Vec<_> = (0..rns_poly_len * (3 * 2 * 3))
        .map(|i| (i as u32 * 31 + 7) % qs[i / N % 2])
        .collect();
    let acc: Vec<_> = (0..rhs.len())
        .map(|i| (i as u32 * 13 + 11) % qs[i / N % 2])
        .collect();
    let input = CrtGgsw::new(rhs.as_slice());
    for exponent in 0..2 * N {
        let mut storage = acc.clone();
        let mut output = CrtGgsw::new(storage.as_mut_slice());
        output.add_mul_monomial_assign(&input, exponent, N, rns_poly_len, &moduli);
        assert_eq!(output.as_ref(), expected(&acc, &rhs, exponent, N, &qs));
        let product = expected(&vec![0; rhs.len()], &rhs, exponent, N, &qs);
        input.mul_monomial_to(exponent, &mut output, N, rns_poly_len, &moduli);
        assert_eq!(output.as_ref(), product);
        output.as_mut().copy_from_slice(&rhs);
        output.mul_monomial_assign(exponent, N, rns_poly_len, &moduli);
        assert_eq!(output.as_ref(), product);
    }
}

#[cfg(feature = "rns")]
#[test]
fn dcrt_products_preserve_component_and_modulus_order() {
    use primus_lattice::ggsw::DcrtGgsw;
    use primus_poly::DcrtPolynomial;
    const N: usize = 2;
    let qs = [17u32, 97];
    let moduli = qs.map(BarrettModulus::new);
    let poly = DcrtPolynomial([0, 16, 96, 5]);
    let values: Vec<u32> = (0..4 * (3 * 2 * 3))
        .map(|i| qs[i / N % 2] - 1 - i as u32 % qs[i / N % 2])
        .collect();
    let product: Vec<_> = values
        .iter()
        .enumerate()
        .map(|(i, &x)| x * poly.as_ref()[i % 4] % qs[i / N % 2])
        .collect();
    let input = DcrtGgsw::new(values.as_slice());
    let mut output = DcrtGgsw::new(vec![11; values.len()]);
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
}
