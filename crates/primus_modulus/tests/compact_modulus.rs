//! Cross-validates `CompactModulus` against `UintModulus`.

use primus_modulus::{CompactModulus, UintModulus};
use primus_reduce::prelude::*;
use rand::{SeedableRng, distr::Uniform, prelude::*, rngs::StdRng};

const MODULUS: u32 = 536_813_569;
const SEED: u64 = 0x434f_4d50_4143_5431;

#[test]
fn constructor_bounds() {
    assert!(std::panic::catch_unwind(|| CompactModulus::<u32>::new(0)).is_err());
    let limit = (1u32) << (u32::BITS - 2);
    assert_eq!(CompactModulus::new(limit - 1).0, limit - 1);
    assert!(std::panic::catch_unwind(|| CompactModulus::new(limit)).is_err());
}

#[test]
fn scalar_ops_against_uint() {
    let cm = CompactModulus::new(MODULUS);
    let u = UintModulus(MODULUS);
    let distr = Uniform::new(0, MODULUS).unwrap();
    let mut rng = StdRng::seed_from_u64(SEED);

    for _ in 0..20 {
        let a: u32 = distr.sample(&mut rng);
        let b: u32 = distr.sample(&mut rng);

        assert_eq!(cm.reduce_add(a, b), u.reduce_add(a, b));
        assert_eq!(cm.reduce_double(a), u.reduce_double(a));
        assert_eq!(cm.reduce_sub(a, b), u.reduce_sub(a, b));
    }
}

#[test]
fn slice_ops_against_uint() {
    let cm = CompactModulus::new(MODULUS);
    let u = UintModulus(MODULUS);
    let distr = Uniform::new(0, MODULUS).unwrap();
    let mut rng = StdRng::seed_from_u64(SEED ^ 1);

    for &len in &[0usize, 1, 7, 8, 9, 15, 16, 17] {
        let a: Vec<u32> = (0..len).map(|_| distr.sample(&mut rng)).collect();
        let b: Vec<u32> = (0..len).map(|_| distr.sample(&mut rng)).collect();

        let mut cm_res = a.clone();
        let mut u_res = a.clone();
        cm.reduce_add_slice_assign(&mut cm_res, &b);
        u.reduce_add_slice_assign(&mut u_res, &b);
        assert_eq!(cm_res, u_res, "add len={len}");

        let mut cm_res = a.clone();
        let mut u_res = a.clone();
        cm.reduce_sub_slice_assign(&mut cm_res, &b);
        u.reduce_sub_slice_assign(&mut u_res, &b);
        assert_eq!(cm_res, u_res, "sub len={len}");
    }
}
