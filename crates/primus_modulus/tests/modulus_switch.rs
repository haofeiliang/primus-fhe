//! Fixed-pair switching checked with independent u128 integer arithmetic.
use primus_modulus::integer::FheUint;
use primus_modulus::reduce::{Modulus, PrepareModulusSwitch, PreparedModulusSwitch};
use primus_modulus::{BarrettModulus, CompactModulus, NativeModulus, PowOf2Modulus, UintModulus};

fn value<T: TryFrom<u128>>(x: u128) -> T {
    T::try_from(x).ok().unwrap()
}
fn points(end: u128) -> Vec<u128> {
    if end <= 256 {
        (0..end).collect()
    } else {
        vec![0, 1, end / 2 - 1, end / 2, end / 2 + 1, end - 2, end - 1]
    }
}
fn check_pair<T, S, D>(source: S, target: D)
where
    T: FheUint + Into<u128> + TryFrom<u128>,
    S: PrepareModulusSwitch<ValueT = T>,
    D: Modulus<ValueT = T>,
{
    let native = 1u128 << T::BITS;
    let q = source.explicit_value().map(Into::into).unwrap_or(native);
    let r = target.explicit_value().map(Into::into).unwrap_or(native);
    let conversion = source.prepare_switch_to(target);
    let mut inputs = points(q);
    for m in [0, r / 2, r - 1] {
        // Equivalent to ceil(((m+1)*q-floor(q/2))/r), avoiding 2^128.
        let boundary = (m * q + q.div_ceil(2)).div_ceil(r);
        if boundary > 0 && boundary < q {
            inputs.extend([boundary - 1, boundary]);
        }
    }
    let expected: Vec<T> = inputs
        .iter()
        .map(|&x| value(((x * r + q / 2) / q) % r))
        .collect();
    for (&x, &expected) in inputs.iter().zip(&expected) {
        assert_eq!(
            conversion.switch(value(x)),
            expected,
            "source={q}, target={r}, value={x}"
        );
    }
    // The batch path must preserve payloads while using the same rounding.
    let mut actual = vec![T::ZERO; inputs.len()];
    conversion.switch_map(
        inputs.into_iter().enumerate().map(|(i, x)| (value(x), i)),
        |x, i| actual[i] = x,
    );
    assert_eq!(actual, expected);
}
fn check_source<T, S>(source: S)
where
    T: FheUint + Into<u128> + TryFrom<u128>,
    S: PrepareModulusSwitch<ValueT = T>,
{
    check_pair(source, NativeModulus::<T>::new());
    let native = 1u128 << T::BITS;
    let root = 1u128 << (T::BITS / 2);
    for q in [
        2,
        3,
        7,
        9,
        18,
        45,
        97,
        128,
        131,
        257,
        root + 1,
        native / 2 + 1,
        native - 1,
    ] {
        check_pair(source, UintModulus::<T>::new(value(q)));
        if q.is_power_of_two() {
            check_pair(source, PowOf2Modulus::<T>::new(value(q)));
        }
        if q < native / 4 {
            check_pair(source, CompactModulus::<T>::new(value(q)));
            check_pair(source, BarrettModulus::<T>::new(value(q)));
        }
    }
}
#[test]
fn fixed_pairs_match_integer_oracle() {
    fn cases<T: FheUint + Into<u128> + TryFrom<u128>>() {
        check_source(NativeModulus::<T>::new());
        let native = 1u128 << T::BITS;
        let root = 1u128 << (T::BITS / 2);
        for q in [
            2,
            3,
            7,
            9,
            18,
            45,
            97,
            128,
            131,
            257,
            root + 1,
            native / 2,
            native / 2 + 1,
            native - 1,
        ] {
            check_source(UintModulus::<T>::new(value(q)));
            if q.is_power_of_two() {
                check_source(PowOf2Modulus::<T>::new(value(q)));
            }
            if q < native / 4 {
                check_source(CompactModulus::<T>::new(value(q)));
                check_source(BarrettModulus::<T>::new(value(q)));
            }
        }
    }
    cases::<u16>();
    cases::<u32>();
    cases::<u64>();
}
#[cfg(feature = "derive")]
#[test]
fn derived_modulus_supports_both_directions() {
    #[derive(primus_modulus::Barrett)]
    #[modulus(ty = u32, value = 97)]
    struct Q;
    check_source::<u32, _>(Q);
    check_pair(NativeModulus::<u32>::new(), Q);
    check_pair(UintModulus::new(128u32), Q);
}
