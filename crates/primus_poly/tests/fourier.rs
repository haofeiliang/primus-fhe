//! Pointwise arithmetic has no transform normalization. Dyadic inputs and
//! hand-computed results make these checks exact in f64.

use num_complex::Complex64;
use primus_poly::FourierPolynomial;

#[test]
fn pointwise_arithmetic_matches_complex_oracle() {
    let lhs = FourierPolynomial::new([Complex64::new(1.0, 2.0), Complex64::new(-3.0, 1.0)]);
    let rhs = FourierPolynomial::new([Complex64::new(2.0, -1.0), Complex64::new(0.5, 2.0)]);
    let sum = [Complex64::new(3.0, 1.0), Complex64::new(-2.5, 3.0)];
    let difference = [Complex64::new(-1.0, 3.0), Complex64::new(-3.5, -1.0)];
    let product = [Complex64::new(4.0, 3.0), Complex64::new(-3.5, -5.5)];
    let scaled = [Complex64::new(-2.5, -5.0), Complex64::new(7.5, -2.5)];
    let negative = [Complex64::new(-1.0, -2.0), Complex64::new(3.0, -1.0)];

    // Assign and out-of-place kernels have separate write/aliasing contracts;
    // consuming wrappers that just call assign need no duplicate checks.
    let mut inplace = lhs.clone();
    inplace.as_mut_view().add_assign(&rhs.as_view());
    assert_eq!(inplace.as_slice(), sum);
    inplace.copy_from(&lhs);
    inplace.as_mut_view().sub_assign(&rhs);
    assert_eq!(inplace.as_slice(), difference);
    inplace.copy_from(&lhs);
    inplace.mul_assign(&rhs);
    assert_eq!(inplace.as_slice(), product);

    // A nonzero accumulator distinguishes += lhs*rhs from an overwrite.
    inplace.copy_from(&lhs);
    inplace.add_mul_assign(&lhs.as_view(), &rhs.as_view());
    assert_eq!(
        inplace.as_slice(),
        [Complex64::new(5.0, 5.0), Complex64::new(-6.5, -4.5)]
    );
    inplace.copy_from(&lhs);
    inplace.mul_scalar_assign(-2.5);
    assert_eq!(inplace.as_slice(), scaled);
    inplace.copy_from(&lhs);
    inplace.neg_assign();
    assert_eq!(inplace.as_slice(), negative);

    let mut output = lhs.clone();
    // Mutable views write the owner's storage; shared views retain the representation.
    let rhs_view: FourierPolynomial<&[Complex64]> = (&rhs).into();
    lhs.as_view().add_to(&rhs_view, &mut output.as_mut_view());
    assert_eq!(output.as_slice(), sum);
    lhs.sub_to(&rhs_view, &mut output.as_mut_view());
    assert_eq!(output.as_slice(), difference);
    lhs.sub_rev_assign(&mut output);
    assert_eq!(output, rhs);
    lhs.as_view().mul_to(&rhs, &mut output.as_mut_view());
    assert_eq!(output.as_slice(), product);
    lhs.mul_scalar_to(-2.5, &mut output);
    assert_eq!(output.as_slice(), scaled);
    lhs.neg_to(&mut output);
    assert_eq!(output.as_slice(), negative);
}
