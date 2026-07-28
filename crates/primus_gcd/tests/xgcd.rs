use primus_gcd::Xgcd;
use rand::{RngExt, SeedableRng, rngs::StdRng};

const RANDOM_CASES: usize = 128;

fn seeded_rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

/// Verifies the complete `u8` input space for GCD, coprimality, and the
/// extended-GCD Bézout identity.
#[test]
fn u8_gcd_and_xgcd_are_exhaustive() {
    for x in u8::MIN..=u8::MAX {
        for y in u8::MIN..=x {
            let expected_gcd = x.gcd(y);
            let (a, b, gcd) = u8::xgcd(x, y);

            assert_eq!(expected_gcd, y.gcd(x), "x={x}, y={y}");
            assert_eq!(gcd, expected_gcd, "x={x}, y={y}, a={a}, b={b}");
            assert_eq!(x.is_coprime(y), gcd == 1, "x={x}, y={y}");
            assert_eq!(
                a as u16 * x as u16 - b as u16 * y as u16,
                gcd as u16,
                "x={x}, y={y}, a={a}, b={b}, gcd={gcd}",
            );
        }
    }
}

/// Verifies the complete valid `u8` input space for the `gcdinv` range and
/// modular identity contracts.
#[test]
fn u8_gcdinv_is_exhaustive() {
    for modulus in 1..=u8::MAX {
        for value in u8::MIN..modulus {
            let (inverse, gcd) = u8::gcdinv(value, modulus);

            assert_eq!(gcd, value.gcd(modulus), "value={value}, modulus={modulus}");
            assert!(inverse < modulus, "inverse={inverse}, modulus={modulus}");
            assert_eq!(
                (inverse as u16 * value as u16) % modulus as u16,
                gcd as u16 % modulus as u16,
                "value={value}, modulus={modulus}, inverse={inverse}, gcd={gcd}",
            );
        }
    }
}

/// Verifies every odd `u8` for every supported power-of-two mask and for the
/// native-word inverse operation.
#[test]
fn u8_power_of_two_inverses_are_exhaustive() {
    for value in (1..=u8::MAX).step_by(2) {
        for bits in 1..=u8::BITS {
            let mask = if bits == u8::BITS {
                u8::MAX
            } else {
                (1u8 << bits) - 1
            };
            let inverse = u8::gcdinv_pow_of_2(value, mask).unwrap();
            assert_eq!(
                inverse.wrapping_mul(value) & mask,
                1,
                "value={value}, bits={bits}, inverse={inverse}",
            );
        }

        let inverse = u8::gcdinv_native(value).unwrap();
        assert_eq!(inverse.wrapping_mul(value), 1, "value={value}");
    }
}

/// Verifies the public panic preconditions and the non-invertible even-input
/// behavior without repeating them for every macro-generated integer type.
#[test]
fn public_preconditions_and_noninvertible_inputs() {
    assert!(std::panic::catch_unwind(|| u64::xgcd(1, 2)).is_err());
    assert!(std::panic::catch_unwind(|| u64::gcdinv(2, 2)).is_err());

    for (value, mask) in [(3u64, 0), (3, 5), (2, 10)] {
        assert!(
            std::panic::catch_unwind(|| u64::gcdinv_pow_of_2(value, mask)).is_err(),
            "value={value}, mask={mask}",
        );
    }

    assert_eq!(u64::gcdinv_pow_of_2(2, u64::MAX), None);
    assert_eq!(u64::gcdinv_native(2), None);
}

macro_rules! check_widened_identities {
    ($rng:ident, $ty:ty, $wide:ty) => {
        for _ in 0..RANDOM_CASES {
            let x: $ty = $rng.random::<$wide>() as $ty;
            let y: $ty = $rng.random_range(0..=x);
            let (a, b, gcd) = <$ty>::xgcd(x, y);

            assert_eq!(gcd, x.gcd(y), "type={}, x={x}, y={y}", stringify!($ty));
            assert_eq!(
                a as $wide * x as $wide - b as $wide * y as $wide,
                gcd as $wide,
                "type={}, x={x}, y={y}, a={a}, b={b}, gcd={gcd}",
                stringify!($ty),
            );

            let modulus: $ty = $rng.random_range(1..=<$ty>::MAX);
            let value: $ty = $rng.random_range(0..modulus);
            let (inverse, gcd) = <$ty>::gcdinv(value, modulus);

            assert_eq!(
                gcd,
                value.gcd(modulus),
                "type={}, value={value}, modulus={modulus}",
                stringify!($ty),
            );
            assert!(inverse < modulus);
            assert_eq!(
                (inverse as $wide * value as $wide) % modulus as $wide,
                gcd as $wide % modulus as $wide,
                "type={}, value={value}, modulus={modulus}, inverse={inverse}, gcd={gcd}",
                stringify!($ty),
            );
        }
    };
}

/// Verifies the returned coefficients for every non-`u128` integer width
/// against a wider primitive-integer oracle.
#[test]
fn wider_integer_identities_match_widened_oracles() {
    let mut rng = seeded_rng(0x7769_6465_5f69_6465);

    check_widened_identities!(rng, u16, u32);
    check_widened_identities!(rng, u32, u64);
    check_widened_identities!(rng, u64, u128);

    #[cfg(target_pointer_width = "32")]
    check_widened_identities!(rng, usize, u64);
    #[cfg(target_pointer_width = "64")]
    check_widened_identities!(rng, usize, u128);
}

macro_rules! check_power_of_two_inverse {
    ($rng:ident, $ty:ty) => {
        for _ in 0..RANDOM_CASES {
            let value: $ty = ($rng.random::<u128>() as $ty) | 1;
            let bits = $rng.random_range(1..=<$ty>::BITS);
            let mask = if bits == <$ty>::BITS {
                <$ty>::MAX
            } else {
                ((1 as $ty) << bits) - 1
            };

            let inverse = <$ty>::gcdinv_pow_of_2(value, mask).unwrap();
            assert_eq!(
                inverse.wrapping_mul(value) & mask,
                1,
                "type={}, value={value}, bits={bits}",
                stringify!($ty),
            );

            let native_inverse = <$ty>::gcdinv_native(value).unwrap();
            assert_eq!(
                native_inverse.wrapping_mul(value),
                1,
                "type={}, value={value}",
                stringify!($ty),
            );
        }
    };
}

/// Verifies Newton lifting and mask truncation at every primitive word width;
/// `u8` is covered separately by its exhaustive test.
#[test]
fn power_of_two_inverses_cover_wider_integer_widths() {
    let mut rng = seeded_rng(0x706f_7732_5f77_6964);

    check_power_of_two_inverse!(rng, u16);
    check_power_of_two_inverse!(rng, u32);
    check_power_of_two_inverse!(rng, u64);
    check_power_of_two_inverse!(rng, u128);
    check_power_of_two_inverse!(rng, usize);
}

/// Verifies the explicitly optimized high-MSB and high-quotient `u64` paths
/// against exact `u128` identities.
#[test]
fn u64_high_bit_paths_match_widened_oracles() {
    let mut rng = seeded_rng(0x7536_345f_6d73_625f);
    let low = (u64::MAX >> 2) + 1;
    let high = u64::MAX >> 1;

    for _ in 0..RANDOM_CASES {
        let x = rng.random_range(low..=high);
        let y = rng.random_range(low..=x);
        let (a, b, gcd) = u64::xgcd(x, y);
        assert_eq!(a as u128 * x as u128 - b as u128 * y as u128, gcd as u128);

        let modulus = rng.random_range((low + 1)..=high);
        let value = rng.random_range(low..modulus);
        let (inverse, gcd) = u64::gcdinv(value, modulus);
        assert_eq!(
            (inverse as u128 * value as u128) % modulus as u128,
            gcd as u128 % modulus as u128,
        );
    }

    let high_quotient = (u64::MAX >> 1) + 1;
    assert_eq!(u64::xgcd(high_quotient, 1), (1, high_quotient - 1, 1));
    assert_eq!(u64::gcdinv(1, high_quotient), (1, 1));
}

fn wide_mul_u128(lhs: u128, rhs: u128) -> [u64; 4] {
    let lhs = [lhs as u64, (lhs >> 64) as u64];
    let rhs = [rhs as u64, (rhs >> 64) as u64];
    let mut result = [0u64; 4];

    for (lhs_index, &lhs_limb) in lhs.iter().enumerate() {
        let mut carry = 0u128;
        for (rhs_index, &rhs_limb) in rhs.iter().enumerate() {
            let output_index = lhs_index + rhs_index;
            let value = lhs_limb as u128 * rhs_limb as u128 + result[output_index] as u128 + carry;
            result[output_index] = value as u64;
            carry = value >> 64;
        }

        let mut output_index = lhs_index + rhs.len();
        while carry != 0 {
            assert!(
                output_index < result.len(),
                "wide multiplication overflowed"
            );
            let value = result[output_index] as u128 + carry;
            result[output_index] = value as u64;
            carry = value >> 64;
            output_index += 1;
        }
    }

    result
}

fn wide_add_u128(mut lhs: [u64; 4], rhs: u128) -> [u64; 4] {
    let rhs = [rhs as u64, (rhs >> 64) as u64, 0, 0];
    let mut carry = 0u128;

    for (lhs_limb, rhs_limb) in lhs.iter_mut().zip(rhs) {
        let value = *lhs_limb as u128 + rhs_limb as u128 + carry;
        *lhs_limb = value as u64;
        carry = value >> 64;
    }

    assert_eq!(carry, 0, "wide addition overflowed");
    lhs
}

fn add_mod_u128(lhs: u128, rhs: u128, modulus: u128) -> u128 {
    debug_assert!(lhs < modulus);
    debug_assert!(rhs < modulus);

    if lhs >= modulus - rhs {
        lhs - (modulus - rhs)
    } else {
        lhs + rhs
    }
}

fn mul_mod_u128(mut lhs: u128, mut rhs: u128, modulus: u128) -> u128 {
    lhs %= modulus;
    let mut result = 0;

    while rhs != 0 {
        if rhs & 1 == 1 {
            result = add_mod_u128(result, lhs, modulus);
        }
        rhs >>= 1;
        if rhs != 0 {
            lhs = add_mod_u128(lhs, lhs, modulus);
        }
    }

    result
}

fn assert_u128_xgcd_identity(x: u128, y: u128) {
    let (a, b, gcd) = u128::xgcd(x, y);
    assert_eq!(gcd, x.gcd(y), "x={x}, y={y}");
    assert_eq!(
        wide_mul_u128(a, x),
        wide_add_u128(wide_mul_u128(b, y), gcd),
        "x={x}, y={y}, a={a}, b={b}, gcd={gcd}",
    );
}

fn assert_u128_gcdinv_identity(value: u128, modulus: u128) {
    let (inverse, gcd) = u128::gcdinv(value, modulus);
    assert_eq!(gcd, value.gcd(modulus), "value={value}, modulus={modulus}");
    assert!(inverse < modulus);
    assert_eq!(
        mul_mod_u128(inverse, value, modulus),
        gcd % modulus,
        "value={value}, modulus={modulus}, inverse={inverse}, gcd={gcd}",
    );
}

/// Verifies full-width `u128` coefficients with independent two-limb wide
/// multiplication and overflow-free modular multiplication oracles.
#[test]
fn u128_full_width_identities_match_independent_oracles() {
    const TOP_BIT: u128 = 1 << 127;

    for (x, y) in [
        (0, 0),
        (1, 0),
        (u128::MAX, u128::MAX),
        (u128::MAX, u128::MAX - 1),
        (u128::MAX, TOP_BIT + 1),
        (TOP_BIT, 1),
        (TOP_BIT + 123, TOP_BIT),
    ] {
        assert_u128_xgcd_identity(x, y);
    }

    for (value, modulus) in [
        (0, 1),
        (1, 2),
        (1, TOP_BIT),
        (TOP_BIT - 1, TOP_BIT),
        (TOP_BIT, u128::MAX),
        (u128::MAX - 1, u128::MAX),
    ] {
        assert_u128_gcdinv_identity(value, modulus);
    }

    let mut rng = seeded_rng(0x7531_3238_5f66_756c);
    for _ in 0..RANDOM_CASES {
        let x = rng.random::<u128>();
        let y = rng.random_range(0..=x);
        assert_u128_xgcd_identity(x, y);

        let modulus = rng.random_range(1..=u128::MAX);
        let value = rng.random_range(0..modulus);
        assert_u128_gcdinv_identity(value, modulus);
    }
}
