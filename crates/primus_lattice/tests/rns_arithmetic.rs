#![cfg(feature = "rns")]

use primus_factor::ShoupFactor;
use primus_lattice::{
    glwe::{CrtGlwe, DcrtGlwe},
    rlwe::{CrtRlwe, DcrtRlwe},
};
use primus_modulus::BarrettModulus;

#[test]
fn rns_arithmetic_preserves_component_and_modulus_order() {
    const N: usize = 2;
    let qs = [17u32, 97];
    let moduli = qs.map(BarrettModulus::new);
    let scalars = [3, 5];
    let factors = [
        ShoupFactor::new(scalars[0], qs[0]),
        ShoupFactor::new(scalars[1], qs[1]),
    ];
    let rns_poly_len = N * qs.len();

    macro_rules! check {
        ($cipher:ident, $components:expr) => {{
            let len = rns_poly_len * $components;
            let lhs: Vec<u32> = (0..len)
                .map(|i| {
                    let q = qs[i / N % qs.len()];
                    if i % 2 == 0 { (i as u32) % q } else { q - 1 }
                })
                .collect();
            let rhs: Vec<u32> = (0..len)
                .map(|i| (i as u32 + 2) % qs[i / N % qs.len()])
                .collect();
            let expected = |op: fn(u32, u32, u32, u32) -> u32| -> Vec<u32> {
                lhs.iter()
                    .zip(&rhs)
                    .enumerate()
                    .map(|(i, (&a, &b))| {
                        let limb = i / N % qs.len();
                        op(a, b, qs[limb], scalars[limb])
                    })
                    .collect()
            };
            let input = $cipher::new(lhs.as_slice());
            let rhs = $cipher::new(rhs.as_slice());
            let mut storage = vec![11; len];
            let mut output = $cipher::new(storage.as_mut_slice());
            input.add_to(&rhs, &mut output, N, rns_poly_len, &moduli);
            assert_eq!(output.as_ref(), expected(|a, b, q, _| (a + b) % q));
            output.sub_assign(&rhs, N, rns_poly_len, &moduli);
            assert_eq!(output.as_ref(), lhs);
            input.sub_to(&rhs, &mut output, N, rns_poly_len, &moduli);
            assert_eq!(output.as_ref(), expected(|a, b, q, _| (a + q - b) % q));
            output.add_assign(&rhs, N, rns_poly_len, &moduli);
            assert_eq!(output.as_ref(), lhs);
            input.neg_to(&mut output, N, rns_poly_len, &moduli);
            assert_eq!(output.as_ref(), expected(|a, _, q, _| (q - a) % q));
            output.neg_assign(N, rns_poly_len, &moduli);
            assert_eq!(output.as_ref(), lhs);
            let product = expected(|a, _, q, s| (a * s) % q);
            input.mul_scalar_to(&scalars, &mut output, N, rns_poly_len, &moduli);
            assert_eq!(output.as_ref(), product);
            output.as_mut().copy_from_slice(&lhs);
            output.mul_scalar_assign(&scalars, N, rns_poly_len, &moduli);
            assert_eq!(output.as_ref(), product);
            input.mul_factor_to(&factors, &mut output, N, rns_poly_len, &qs);
            assert_eq!(output.as_ref(), product);
            output.as_mut().copy_from_slice(&lhs);
            output.mul_factor_assign(&factors, N, rns_poly_len, &qs);
            assert_eq!(output.as_ref(), product);
        }};
    }
    check!(CrtGlwe, 3);
    check!(DcrtGlwe, 3);
    check!(CrtRlwe, 2);
    check!(DcrtRlwe, 2);
}
