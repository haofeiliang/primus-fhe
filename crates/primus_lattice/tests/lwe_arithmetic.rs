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
        }};
    }

    check!(Lwe);
    check!(MultiMsgLwe);
}
