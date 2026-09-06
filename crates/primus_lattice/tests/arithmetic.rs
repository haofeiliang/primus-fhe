//! Single-modulus arithmetic: borrowed outputs, allocation reuse, and fused products.

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
use primus_modulus::BarrettModulus;

#[test]
fn borrowed_lwe_arithmetic_overwrites_output_across_modulus_boundary() {
    let modulus = BarrettModulus::new(97u32);
    let lhs = [0, 96, 45, 80];
    let rhs = [1, 2, 45, 30];

    macro_rules! check {
        ($cipher:ident) => {{
            let lhs = $cipher::new(lhs.as_slice());
            let rhs = $cipher::new(rhs.as_slice());
            let mut storage = [42; 4];
            let mut output = $cipher::new(storage.as_mut_slice());
            lhs.add_to(&rhs, &mut output, modulus);
            assert_eq!(output.as_ref(), &[1, 1, 90, 13]);
            output.as_mut().fill(42);
            lhs.sub_to(&rhs, &mut output, modulus);
            assert_eq!(output.as_ref(), &[96, 94, 0, 50]);
            lhs.neg_to(&mut output, modulus);
            assert_eq!(output.as_ref(), &[0, 1, 52, 17]);
        }};
    }

    check!(Lwe);
    check!(MultiMsgLwe);
}

#[test]
fn consuming_negation_reuses_owned_and_borrowed_storage() {
    let modulus = BarrettModulus::new(97u32);
    let ciphertext = Lwe::new(vec![0, 96, 45]);
    let original_pointer = ciphertext.as_ref().as_ptr();
    let ciphertext = ciphertext.neg(modulus);
    assert_eq!(ciphertext.as_ref().as_ptr(), original_pointer);
    assert_eq!(ciphertext.as_ref(), &[0, 1, 52]);

    let mut storage = [0, 96, 45];
    let ciphertext = Lwe::new(storage.as_mut_slice()).neg(modulus);
    assert_eq!(ciphertext.as_ref(), &[0, 1, 52]);
    assert_eq!(storage, [0, 1, 52]);
}

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
                let modulus = BarrettModulus::new(Q);
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
