use primus_factor::ShoupFactor;
use primus_lattice::{
    ggsw::{Ggsw, NttGgsw},
    glev::{Glev, NttGlev},
    glwe::{Glwe, NttGlwe, TruncatedGlwe},
    lwe::{Lwe, MultiMsgLwe},
    ngsw::{Ngsw, NttNgsw},
    nlev::{Nlev, NttNlev},
    ntru::{Ntru, NttNtru},
    rgsw::{NttRgsw, Rgsw},
    rlev::{NttRlev, Rlev},
    rlwe::{NttRlwe, Rlwe},
};

#[test]
fn scalar_and_factor_products_preserve_overwrite_and_accumulation_semantics() {
    const Q: u32 = 97;
    macro_rules! check {
        ($cipher:ident, $len:expr) => {{
            let values: Vec<u32> = (0..$len).map(|i| i as u32 * 31 % Q).collect();
            let input = $cipher::new(values.as_slice());
            let mut storage = vec![11; values.len()];
            let mut output = $cipher::new(storage.as_mut_slice());
            for scalar in [0, 3, Q - 1] {
                let factor = ShoupFactor::new(scalar, Q);
                let expected: Vec<_> = values.iter().map(|x| x * scalar % Q).collect();
                output.as_mut().fill(11);
                input.mul_factor_to(factor, &mut output, Q);
                assert_eq!(output.as_ref(), expected);
                output.as_mut().copy_from_slice(&values);
                output.mul_factor_assign(factor, Q);
                assert_eq!(output.as_ref(), expected);
                let acc: Vec<_> = (0..values.len()).map(|i| (i as u32 * 7 + 11) % Q).collect();
                output.as_mut().copy_from_slice(&acc);
                output.add_mul_factor_assign(&input, factor, Q);
                let sum: Vec<_> = acc
                    .iter()
                    .zip(&expected)
                    .map(|(a, p)| (a + p) % Q)
                    .collect();
                assert_eq!(output.as_ref(), sum);
                output.as_mut().copy_from_slice(&acc);
                output.sub_mul_factor_assign(&input, factor, Q);
                let difference: Vec<_> = acc
                    .iter()
                    .zip(&expected)
                    .map(|(a, p)| (a + Q - p) % Q)
                    .collect();
                assert_eq!(output.as_ref(), difference);
                let modulus = primus_modulus::BarrettModulus::new(Q);
                output.as_mut().fill(11);
                input.mul_scalar_to(scalar, &mut output, modulus);
                assert_eq!(output.as_ref(), expected);
                output.as_mut().copy_from_slice(&values);
                output.mul_scalar_assign(scalar, modulus);
                assert_eq!(output.as_ref(), expected);
                output.as_mut().copy_from_slice(&acc);
                output.add_mul_scalar_assign(&input, scalar, modulus);
                assert_eq!(output.as_ref(), sum);
                output.as_mut().copy_from_slice(&acc);
                output.sub_mul_scalar_assign(&input, scalar, modulus);
                assert_eq!(output.as_ref(), difference);
            }
        }};
    }
    // N = 32; GLWE dimension 2, gadget length 2. Packed/truncated bodies
    // also exercise storage that is not a whole number of polynomials.
    check!(Lwe, 65);
    check!(MultiMsgLwe, 36);
    check!(TruncatedGlwe, 67);
    check!(Glwe, 96);
    check!(NttGlwe, 96);
    check!(Rlwe, 64);
    check!(NttRlwe, 64);
    check!(Ntru, 32);
    check!(NttNtru, 32);
    check!(Glev, 192);
    check!(NttGlev, 192);
    check!(Ggsw, 576);
    check!(NttGgsw, 576);
    check!(Rlev, 128);
    check!(NttRlev, 128);
    check!(Rgsw, 256);
    check!(NttRgsw, 256);
    check!(Nlev, 64);
    check!(NttNlev, 64);
    check!(Ngsw, 64);
    check!(NttNgsw, 64);
}

#[cfg(feature = "rns")]
#[test]
fn ring_gadget_factors_preserve_level_and_modulus_order() {
    use primus_lattice::{
        rgsw::{CrtRgsw, DcrtRgsw},
        rlev::{CrtRlev, DcrtRlev},
    };
    const N: usize = 32;
    let qs = [17u32, 97];
    let scalars = [3, 5];
    let factors = [ShoupFactor::new(3, 17), ShoupFactor::new(5, 97)];
    let rns_poly_len = N * qs.len();
    macro_rules! check {
        ($cipher:ident, $components:expr) => {{
            let values: Vec<u32> = (0..rns_poly_len * $components)
                .map(|i| i as u32 * 31 % qs[i / N % 2])
                .collect();
            let expected: Vec<_> = values
                .iter()
                .enumerate()
                .map(|(i, x)| x * scalars[i / N % 2] % qs[i / N % 2])
                .collect();
            let input = $cipher::new(values.as_slice());
            let mut storage = vec![11; values.len()];
            let mut output = $cipher::new(storage.as_mut_slice());
            input.mul_factor_to(&factors, &mut output, N, rns_poly_len, &qs);
            assert_eq!(output.as_ref(), expected);
            output.as_mut().copy_from_slice(&values);
            output.mul_factor_assign(&factors, N, rns_poly_len, &qs);
            assert_eq!(output.as_ref(), expected);
        }};
    }
    check!(CrtRlev, 2 * 2);
    check!(DcrtRlev, 2 * 2);
    check!(CrtRgsw, 2 * 2 * 2);
    check!(DcrtRgsw, 2 * 2 * 2);
}
