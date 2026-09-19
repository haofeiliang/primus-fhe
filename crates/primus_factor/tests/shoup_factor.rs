#[cfg(feature = "simd")]
use primus_factor::SimdFactorMul;
use primus_factor::{
    Factor, FactorMul, FactorSliceOps, LazyFactorMul, LazyFactorSliceOps, ShoupFactor,
};
use primus_integer::FheUint;
#[cfg(feature = "simd")]
use primus_integer::{LaneArray, SimdArray, SimdInteger};
use primus_modulus::BarrettModulus;
use primus_reduce::prelude::*;
use rand::{distr::Uniform, prelude::*};

type ValueT = u32;

const MODULUS: ValueT = 536_813_569;
const SECOND_MODULUS: ValueT = 998_244_353;

fn ensure_trait<T: FheUint, F: Factor<T>>(_factor: F) {}

#[test]
fn test_trait_bound() {
    ensure_trait(ShoupFactor::new(1, MODULUS));
}

#[test]
fn scalar_mul_against_barrett() {
    let modulus = BarrettModulus::<ValueT>::new(MODULUS);
    let distr = Uniform::new(0, MODULUS).unwrap();
    let mut rng = rand::rng();

    for _ in 0..256 {
        let factor_value = distr.sample(&mut rng);
        let rhs = distr.sample(&mut rng);
        let factor = ShoupFactor::new(factor_value, MODULUS);

        let expected = modulus.reduce_mul(factor_value, rhs);
        assert_eq!(factor.factor_mul_modulo(rhs, MODULUS), expected);

        let lazy = factor.lazy_factor_mul_modulo(rhs, MODULUS);
        assert!(lazy < MODULUS * 2);
        assert_eq!(modulus.reduce_once(lazy), expected);
    }
}

#[test]
fn reset_against_barrett() {
    let modulus = BarrettModulus::<ValueT>::new(MODULUS);
    let second_modulus = BarrettModulus::<ValueT>::new(SECOND_MODULUS);
    let mut factor = ShoupFactor::new(1, MODULUS);
    let distr = Uniform::new(0, MODULUS).unwrap();
    let mut rng = rand::rng();

    for _ in 0..64 {
        let factor_value = distr.sample(&mut rng);
        let rhs = distr.sample(&mut rng);

        factor.set(factor_value, MODULUS);
        assert_eq!(
            factor.factor_mul_modulo(rhs, MODULUS),
            modulus.reduce_mul(factor_value, rhs)
        );

        factor.set_modulus(SECOND_MODULUS);
        assert_eq!(
            factor.factor_mul_modulo(rhs, SECOND_MODULUS),
            second_modulus.reduce_mul(factor_value, rhs)
        );
    }
}

#[cfg(feature = "simd")]
#[test]
fn per_lane_simd_factors_match_scalar_multiplication() {
    type SimdValueT = u64;
    type SimdT = <SimdValueT as SimdInteger>::SimdT;

    const SIMD_MODULUS: SimdValueT = 1_152_921_504_606_830_593;

    let factors: Vec<_> = (0..<SimdValueT as SimdInteger>::LANE_COUNT)
        .map(|lane| ShoupFactor::new(17 * lane as SimdValueT + 3, SIMD_MODULUS))
        .collect();
    let rhs_array =
        <SimdValueT as SimdInteger>::Array::from_fn(|lane| 31 * lane as SimdValueT + 11);

    let simd_factor =
        <ShoupFactor<SimdValueT> as SimdFactorMul<SimdValueT>>::simd_from_factor_slice(&factors);
    let rhs = <SimdT as SimdArray<SimdValueT>>::from_array(rhs_array);
    let modulus = <SimdT as SimdArray<SimdValueT>>::splat(SIMD_MODULUS);
    let actual =
        <SimdT as SimdArray<SimdValueT>>::to_array(simd_factor.factor_mul_modulo(rhs, modulus));
    let expected: Vec<_> = factors
        .iter()
        .zip(rhs_array)
        .map(|(&factor, rhs)| factor.factor_mul_modulo(rhs, SIMD_MODULUS))
        .collect();

    assert_eq!(actual.as_ref(), expected);
}

#[test]
fn slice_mul_against_wide_product() {
    fn check<T: FheUint + TryFrom<u64> + Into<u128>>(q: u64) {
        let convert = |value| T::try_from(value).ok().unwrap();
        let modulus = convert(q);
        let mut state = 0x1234_5678_9abc_def0u64;
        for len in [0, 1, 7, 8, 15, 16, 17, 31, 32, 33, 64, 65, 1024, 1025] {
            let input: Vec<T> = (0..len)
                .map(|i| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    convert(match i % 4 {
                        0 => 0,
                        1 => q - 1,
                        _ => state % q,
                    })
                })
                .collect();
            for factor_value in [0, 1, 17, q - 1] {
                let factor = ShoupFactor::new(convert(factor_value), modulus);
                let expected: Vec<T> = input
                    .iter()
                    .map(|&value| {
                        convert((u128::from(factor_value) * value.into() % u128::from(q)) as u64)
                    })
                    .collect();
                // Offset the in-place slice and guard both ends, including empty input.
                let mut assign = vec![T::MAX; len + 2];
                assign[1..len + 1].copy_from_slice(&input);
                factor.factor_mul_slice_assign(&mut assign[1..len + 1], modulus);
                assert_eq!(&assign[1..len + 1], expected);
                assert_eq!(assign[0], T::MAX);
                assert_eq!(assign[len + 1], T::MAX);

                let mut output = vec![T::ZERO; len];
                factor.factor_mul_slice_to(&input, &mut output, modulus);
                assert_eq!(output, expected);

                let mut lazy_assign = input.clone();
                factor.lazy_factor_mul_slice_assign(&mut lazy_assign, modulus);
                factor.lazy_factor_mul_slice_to(&input, &mut output, modulus);
                for values in [&lazy_assign, &output] {
                    for (&actual, &expected) in values.iter().zip(&expected) {
                        let actual: u128 = actual.into();
                        assert!(actual < 2 * u128::from(q));
                        assert_eq!(actual % u128::from(q), expected.into());
                    }
                }
            }
        }
    }

    for q in [536_813_569, (1 << 31) - 1] {
        check::<u32>(q);
    }
    for q in [1_125_899_906_826_241, (1 << 63) - 1] {
        check::<u64>(q);
    }
}

#[test]
fn fused_slice_ops_against_barrett() {
    let modulus = BarrettModulus::<ValueT>::new(MODULUS);
    let distr = Uniform::new(0, MODULUS).unwrap();
    let mut rng = rand::rng();

    for &len in &[0usize, 1, 3, 7, 8, 15, 16, 17, 31, 33, 64, 65] {
        let factor_value = distr.sample(&mut rng);
        let factor = ShoupFactor::new(factor_value, MODULUS);
        let rhs: Vec<ValueT> = (0..len).map(|_| distr.sample(&mut rng)).collect();
        let acc: Vec<ValueT> = (0..len).map(|_| distr.sample(&mut rng)).collect();
        let addend: Vec<ValueT> = (0..len).map(|_| distr.sample(&mut rng)).collect();

        let products: Vec<ValueT> = rhs
            .iter()
            .map(|&value| modulus.reduce_mul(factor_value, value))
            .collect();

        let expected_add: Vec<ValueT> = acc
            .iter()
            .zip(&products)
            .map(|(&acc, &product)| modulus.reduce_add(acc, product))
            .collect();
        let mut add_assign = acc.clone();
        factor.add_factor_mul_slice_assign(&mut add_assign, &rhs, MODULUS);
        assert_eq!(
            add_assign, expected_add,
            "add_factor_mul_slice_assign len={len}"
        );

        let expected_sub: Vec<ValueT> = acc
            .iter()
            .zip(&products)
            .map(|(&acc, &product)| modulus.reduce_sub(acc, product))
            .collect();
        let mut sub_assign = acc.clone();
        factor.sub_factor_mul_slice_assign(&mut sub_assign, &rhs, MODULUS);
        assert_eq!(
            sub_assign, expected_sub,
            "sub_factor_mul_slice_assign len={len}"
        );

        let expected_to: Vec<ValueT> = products
            .iter()
            .zip(&addend)
            .map(|(&product, &addend)| modulus.reduce_add(product, addend))
            .collect();
        let mut output = vec![0; len];
        factor.factor_mul_add_slice_to(&rhs, &addend, &mut output, MODULUS);
        assert_eq!(output, expected_to, "factor_mul_add_slice_to len={len}");
    }
}
