use primus_lattice::lwe::{Lwe, MultiMsgLwe};
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
            lhs.mul_scalar_to(3, &mut output, modulus);
            assert_eq!(output.as_ref(), &[0, 94, 38, 46]);
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
