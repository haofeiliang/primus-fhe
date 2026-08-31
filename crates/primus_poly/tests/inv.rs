use primus_modulus::BarrettModulus;
use primus_poly::{DcrtPolynomial, NttPolynomial};
use primus_reduce::ReduceError;

#[test]
fn ntt_inverse_to_writes_output() {
    let modulus = BarrettModulus::new(17u32);
    let input = NttPolynomial::new(vec![1, 2, 3, 4]);
    let mut output = NttPolynomial::new(vec![0; 4]);

    input.inv_to(&mut output, modulus);

    assert_eq!(output.as_slice(), &[1, 9, 6, 13]);
}

#[test]
fn ntt_try_inverse_to_reports_noninvertible_value() {
    let modulus = BarrettModulus::new(17u32);
    let input = NttPolynomial::new(vec![1, 0, 3, 4]);
    let mut output = NttPolynomial::new(vec![0; 4]);

    assert_eq!(
        input.try_inv_to(&mut output, modulus),
        Err(ReduceError::NoInverse {
            value: 0,
            modulus: 17,
        })
    );
}

#[test]
fn dcrt_inverse_to_respects_component_layout() {
    let moduli = [BarrettModulus::new(17u32), BarrettModulus::new(19u32)];
    let input = DcrtPolynomial::new(vec![1, 2, 3, 4, 5, 6]);
    let mut output = DcrtPolynomial::new(vec![0; 6]);

    input.inv_to(&mut output, 3, &moduli);

    assert_eq!(output.as_slice(), &[1, 9, 6, 5, 4, 16]);
}

#[test]
fn dcrt_try_inverse_to_reports_noninvertible_component() {
    let moduli = [BarrettModulus::new(17u32), BarrettModulus::new(19u32)];
    let input = DcrtPolynomial::new(vec![1, 2, 3, 4, 0, 6]);
    let mut output = DcrtPolynomial::new(vec![0; 6]);

    assert_eq!(
        input.try_inv_to(&mut output, 3, &moduli),
        Err(ReduceError::NoInverse {
            value: 0,
            modulus: 19,
        })
    );
}
