//! Cross-validates `BarrettModulus` against `UintModulus` and wide arithmetic.

use primus_modulus::{BarrettModulus, UintModulus};
use primus_reduce::{FieldContext, prelude::*};
use rand::{
    RngExt, SeedableRng,
    distr::{Distribution, Uniform},
    rngs::StdRng,
};

type ValueT = u32;

const MODULUS: ValueT = 536_813_569;
const SEED: u64 = 0x4241_5252_4554_5431;

#[test]
fn constructor_bounds() {
    assert!(std::panic::catch_unwind(|| BarrettModulus::<ValueT>::new(0)).is_err());
    assert!(std::panic::catch_unwind(|| BarrettModulus::<ValueT>::new(1)).is_err());

    let u32_limit = 1u32 << (u32::BITS - 2);
    assert!(std::panic::catch_unwind(|| BarrettModulus::<u32>::new(u32_limit)).is_err());
    assert!(BarrettModulus::<u32>::try_new(u32_limit - 1).is_some());
    assert!(BarrettModulus::<u32>::try_new(u32_limit).is_none());

    let u64_limit = 1u64 << (u64::BITS - 2);
    assert!(BarrettModulus::<u64>::try_new(u64_limit - 1).is_some());
    assert!(BarrettModulus::<u64>::try_new(u64_limit).is_none());
}

fn field_trait<M: FieldContext<ValueT>>(_modulus: M) {}

#[test]
fn scalar_ops_against_uint() {
    let b = BarrettModulus::<u32>::new(MODULUS);
    let u = UintModulus(MODULUS);
    let distr = Uniform::new(0, MODULUS).unwrap();

    field_trait(b);

    let mut rng = StdRng::seed_from_u64(SEED);

    for _ in 0..20 {
        let a: u32 = distr.sample(&mut rng);
        let c: u32 = distr.sample(&mut rng);

        assert_eq!(b.reduce_add(a, c), u.reduce_add(a, c));
        assert_eq!(b.reduce_sub(a, c), u.reduce_sub(a, c));
        assert_eq!(b.reduce_double(a), u.reduce_double(a));
        assert_eq!(b.reduce_neg(a), u.reduce_neg(a));

        let v = if rng.random_bool(0.5) {
            a
        } else {
            a.wrapping_add(MODULUS)
        };
        assert_eq!(b.reduce_once(v), u.reduce_once(v));

        let product = (a as u64) * (c as u64);
        let expected = (product % MODULUS as u64) as u32;
        assert_eq!(b.reduce((product as u32, (product >> 32) as u32)), expected);
    }
}

#[test]
fn slice_ops_against_uint() {
    let b = BarrettModulus::<u32>::new(MODULUS);
    let u = UintModulus(MODULUS);
    let distr = Uniform::new(0, MODULUS).unwrap();
    let mut rng = StdRng::seed_from_u64(SEED);

    for &len in &[0usize, 1, 3, 7, 8, 15, 16, 17, 31, 33, 64, 65] {
        let a: Vec<u32> = (0..len).map(|_| distr.sample(&mut rng)).collect();
        let c: Vec<u32> = (0..len).map(|_| distr.sample(&mut rng)).collect();

        for op in &["add", "sub", "neg", "once"] {
            let a_in = match *op {
                "once" => a.iter().map(|&x| x.wrapping_add(MODULUS)).collect(),
                _ => a.clone(),
            };
            let mut b_res = a_in.clone();
            let mut u_res = a_in;

            match *op {
                "add" => {
                    b.reduce_add_slice_assign(&mut b_res, &c);
                    u.reduce_add_slice_assign(&mut u_res, &c);
                }
                "sub" => {
                    b.reduce_sub_slice_assign(&mut b_res, &c);
                    u.reduce_sub_slice_assign(&mut u_res, &c);
                }
                "neg" => {
                    b.reduce_neg_slice_assign(&mut b_res);
                    u.reduce_neg_slice_assign(&mut u_res);
                }
                "once" => {
                    b.reduce_once_slice_assign(&mut b_res);
                    u.reduce_once_slice_assign(&mut u_res);
                }
                _ => {}
            }
            assert_eq!(b_res, u_res, "{op} len={len}");
        }
    }
}

#[test]
fn inverse_slice_ops_against_uint() {
    let b = BarrettModulus::<u32>::new(MODULUS);
    let u = UintModulus(MODULUS);

    for input in [&[][..], &[1][..], &[1, 2, 3, 17, 257][..]] {
        let mut expected = vec![0; input.len()];
        u.reduce_inv_slice_to(input, &mut expected);

        let mut output = vec![u32::MAX; input.len()];
        b.reduce_inv_slice_to(input, &mut output);
        assert_eq!(output, expected);

        output.fill(u32::MAX);
        b.try_reduce_inv_slice_to(input, &mut output).unwrap();
        assert_eq!(output, expected);
    }
}

#[test]
fn try_inverse_slice_reports_noninvertible_input() {
    let modulus = BarrettModulus::<u32>::new(15);
    let input = [2, 3, 4];
    let mut output = [u32::MAX; 3];

    assert!(
        modulus
            .try_reduce_inv_slice_to(&input, &mut output)
            .is_err()
    );
    assert_eq!(input, [2, 3, 4]);
}

fn mul_mod(a: u32, b: u32) -> u32 {
    ((a as u64 * b as u64) % MODULUS as u64) as u32
}

#[test]
fn mul_ops() {
    let m = BarrettModulus::<u32>::new(MODULUS);
    let distr = Uniform::new(0, MODULUS).unwrap();
    let mut rng = StdRng::seed_from_u64(SEED);

    for _ in 0..20 {
        let a: u32 = distr.sample(&mut rng);
        let b: u32 = distr.sample(&mut rng);
        let d: u32 = distr.sample(&mut rng);

        assert_eq!(m.reduce_mul(a, b), mul_mod(a, b));
        assert_eq!(m.reduce_square(a), mul_mod(a, a));

        let expected_fma = ((a as u64 * b as u64 + d as u64) % MODULUS as u64) as u32;
        assert_eq!(m.reduce_mul_add(a, b, d), expected_fma);

        // A lazy product becomes canonical after one correction.
        let lazy = m.lazy_reduce_mul(a, b);
        assert!(lazy < MODULUS * 2);
        assert_eq!(m.reduce_once(lazy), mul_mod(a, b));
    }
}

#[test]
fn dot_product() {
    let m = BarrettModulus::<u32>::new(MODULUS);
    let distr = Uniform::new(0, MODULUS).unwrap();
    let mut rng = StdRng::seed_from_u64(SEED);

    for &len in &[0usize, 1, 7, 15, 16, 17, 31, 32, 33, 127, 128, 129] {
        let a: Vec<u32> = (0..len).map(|_| distr.sample(&mut rng)).collect();
        let b: Vec<u32> = (0..len).map(|_| distr.sample(&mut rng)).collect();

        let expected = a.iter().zip(&b).fold(0u64, |acc, (&x, &y)| {
            (acc + x as u64 * y as u64) % MODULUS as u64
        }) as u32;
        assert_eq!(
            m.reduce_dot_product(&a, &b),
            expected,
            "dot_product len={len}"
        );
        assert_eq!(
            m.reduce_dot_product_iter(a.iter().copied(), b.iter().copied()),
            expected,
            "dot_product_iter len={len}"
        );
    }
}

#[test]
fn dot_product_accumulator_boundary() {
    let modulus = (1u64 << (u64::BITS - 2)) - 1;
    let operand = modulus - 1;
    let values = [operand; 16];

    // Each product is one modulo `modulus`; this also exercises the largest
    // supported unreduced 16-term accumulator.
    assert_eq!(
        BarrettModulus::new(modulus).reduce_dot_product(&values, &values),
        16
    );
}

#[cfg(feature = "simd")]
#[test]
fn simd_dot_product_accumulator_boundary() {
    use primus_modulus::integer::SimdInteger;

    let modulus = (1u64 << (u64::BITS - 2)) - 1;
    let operand = modulus - 1;
    let len = 16 * <u64 as SimdInteger>::LANE_COUNT;
    let values = vec![operand; len];

    assert_eq!(
        BarrettModulus::new(modulus).reduce_dot_product(&values, &values),
        len as u64
    );
}

#[test]
fn mul_slice_ops() {
    let m = BarrettModulus::<u32>::new(MODULUS);
    let distr = Uniform::new(0, MODULUS).unwrap();
    let mut rng = StdRng::seed_from_u64(SEED);

    for &len in &[0usize, 1, 3, 7, 8, 15, 16, 17, 31, 33, 64, 65] {
        let a: Vec<u32> = (0..len).map(|_| distr.sample(&mut rng)).collect();
        let b: Vec<u32> = (0..len).map(|_| distr.sample(&mut rng)).collect();
        let c: Vec<u32> = (0..len).map(|_| distr.sample(&mut rng)).collect();
        let scalar: u32 = distr.sample(&mut rng);
        let expected_mul: Vec<u32> = a.iter().zip(&b).map(|(&x, &y)| mul_mod(x, y)).collect();

        let mut assign = a.clone();
        m.reduce_mul_slice_assign(&mut assign, &b);
        assert_eq!(assign, expected_mul, "mul_slice_assign len={len}");
        let mut to = vec![0; len];
        m.reduce_mul_slice_to(&a, &b, &mut to);
        assert_eq!(to, expected_mul, "mul_slice_to len={len}");

        let expected_scalar: Vec<u32> = a.iter().map(|&x| mul_mod(x, scalar)).collect();
        let mut assign = a.clone();
        m.reduce_mul_scalar_slice_assign(&mut assign, scalar);
        assert_eq!(assign, expected_scalar, "scalar_mul_slice_assign len={len}");
        let mut to = vec![0; len];
        m.reduce_mul_scalar_slice_to(&a, scalar, &mut to);
        assert_eq!(to, expected_scalar, "scalar_mul_slice_to len={len}");

        let mut lazy_assign = a.clone();
        m.lazy_reduce_mul_slice_assign(&mut lazy_assign, &b);
        for v in lazy_assign.iter() {
            assert!(*v < MODULUS * 2, "lazy >= 2M");
        }
        for (v, &exp) in lazy_assign.iter_mut().zip(&expected_mul) {
            *v = m.reduce_once(*v);
            assert_eq!(*v, exp, "lazy_mul_slice_assign len={len}");
        }
        let mut lazy_to = vec![0; len];
        m.lazy_reduce_mul_slice_to(&a, &b, &mut lazy_to);
        for v in lazy_to.iter_mut() {
            assert!(*v < MODULUS * 2);
            *v = m.reduce_once(*v);
        }
        assert_eq!(lazy_to, expected_mul, "lazy_mul_slice_to len={len}");

        let expected_acc: Vec<u32> = c
            .iter()
            .zip(&a)
            .zip(&b)
            .map(|((&acc, &x), &y)| ((acc as u64 + x as u64 * y as u64) % MODULUS as u64) as u32)
            .collect();
        let mut acc = c.clone();
        m.reduce_add_mul_slice_assign(&mut acc, &a, &b);
        assert_eq!(acc, expected_acc, "add_mul_slice_assign len={len}");

        let expected_sub: Vec<u32> = c
            .iter()
            .zip(&a)
            .zip(&b)
            .map(|((&acc, &x), &y)| {
                let prod = mul_mod(x, y);
                if acc >= prod {
                    acc - prod
                } else {
                    acc + MODULUS - prod
                }
            })
            .collect();
        let mut acc = c.clone();
        m.reduce_sub_mul_slice_assign(&mut acc, &a, &b);
        assert_eq!(acc, expected_sub, "sub_mul_slice_assign len={len}");

        let mut lazy_acc = c.clone();
        m.lazy_reduce_sub_mul_slice_assign(&mut lazy_acc, &a, &b);
        for value in &mut lazy_acc {
            assert!(*value < MODULUS * 2);
            *value = m.reduce_once(*value);
        }
        assert_eq!(
            lazy_acc, expected_sub,
            "lazy_sub_mul_slice_assign len={len}"
        );

        let expected_abc: Vec<u32> = a
            .iter()
            .zip(&b)
            .zip(&c)
            .map(|((&x, &y), &z)| ((x as u64 * y as u64 + z as u64) % MODULUS as u64) as u32)
            .collect();
        let mut out = vec![0; len];
        m.reduce_mul_add_slice_to(&a, &b, &c, &mut out);
        assert_eq!(out, expected_abc, "mul_add_slice_to len={len}");

        let expected_sbc: Vec<u32> = b
            .iter()
            .zip(&c)
            .map(|(&y, &z)| ((scalar as u64 * y as u64 + z as u64) % MODULUS as u64) as u32)
            .collect();
        let mut out = vec![0; len];
        m.reduce_mul_scalar_add_slice_to(&b, scalar, &c, &mut out);
        assert_eq!(out, expected_sbc, "scalar_mul_add_slice_to len={len}");

        let expected_asc: Vec<u32> = c
            .iter()
            .zip(&b)
            .map(|(&acc, &y)| ((acc as u64 + scalar as u64 * y as u64) % MODULUS as u64) as u32)
            .collect();
        let mut acc = c.clone();
        m.reduce_add_mul_scalar_slice_assign(&mut acc, &b, scalar);
        assert_eq!(acc, expected_asc, "add_scalar_mul_slice_assign len={len}");
    }
}

#[cfg(feature = "simd")]
#[test]
fn simd_slice_ops_against_uint() {
    let b = BarrettModulus::<u32>::new(MODULUS);
    let u = UintModulus(MODULUS);
    let distr = Uniform::new(0, MODULUS).unwrap();
    let mut rng = StdRng::seed_from_u64(SEED);

    for &len in &[
        0usize, 1, 3, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129,
    ] {
        let a: Vec<u32> = (0..len).map(|_| distr.sample(&mut rng)).collect();
        let c: Vec<u32> = (0..len).map(|_| distr.sample(&mut rng)).collect();

        for op in &["add", "sub", "neg"] {
            let mut b_res = a.clone();
            let mut u_res = a.clone();
            match *op {
                "add" => {
                    b.reduce_add_slice_assign(&mut b_res, &c);
                    u.reduce_add_slice_assign(&mut u_res, &c);
                }
                "sub" => {
                    b.reduce_sub_slice_assign(&mut b_res, &c);
                    u.reduce_sub_slice_assign(&mut u_res, &c);
                }
                "neg" => {
                    b.reduce_neg_slice_assign(&mut b_res);
                    u.reduce_neg_slice_assign(&mut u_res);
                }
                _ => {}
            }
            assert_eq!(b_res, u_res, "simd {op} len={len}");
        }
    }
}
