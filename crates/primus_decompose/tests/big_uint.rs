use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_integer::{AsFrom, BigUint, FheUint};
use rand::{RngExt, SeedableRng, rngs::StdRng};

// Test products fit in u128, so the oracle does not depend on BigUint arithmetic.
fn to_u128<T: FheUint + Into<u128>>(limbs: &[T]) -> u128 {
    limbs
        .iter()
        .rev()
        .fold(0, |value, &limb| (value << T::BITS) | limb.into())
}

fn limbs<T: FheUint + AsFrom<u128>>(value: u128, len: usize) -> Vec<T> {
    (0..len)
        .map(|index| T::as_from(value >> (index as u32 * T::BITS)))
        .collect()
}

fn inputs(q: u128, log_basis: u32, levels: usize, drop_bits: u32) -> Vec<u128> {
    let radix = 1u128 << log_basis;
    let step = 1u128 << drop_bits;
    let threshold = (0..levels)
        .map(|level| (radix / 2 - 1) << (drop_bits + level as u32 * log_basis))
        .sum::<u128>()
        + if drop_bits == 0 { 1 } else { step / 2 };
    let mut values = vec![0, 1, q / 2, q - 1];
    for boundary in [step / 2, step, threshold, 1 << 32, 1 << 64] {
        for value in [boundary.saturating_sub(1), boundary, boundary + 1] {
            if value < q {
                values.push(value);
            }
        }
    }
    let mut rng = StdRng::seed_from_u64(0x4445_434f_4d50);
    values.extend((0..64).map(|_| rng.random_range(0..q)));
    values.sort_unstable();
    values.dedup();
    values
}

fn assert_contract<T>(moduli: &[T], log_basis: u32, retained: Option<usize>)
where
    T: FheUint + Into<u128> + AsFrom<u128>,
{
    let q: u128 = moduli.iter().map(|&m| m.into()).product();
    let modulus = BigUint(limbs::<T>(q, (q.ilog2() + 1).div_ceil(T::BITS) as usize));
    let basis = BigUintApproxSignedBasis::try_new(modulus.view(), log_basis, retained).unwrap();
    let levels = retained.unwrap_or((q.ilog2() + 1) as usize / log_basis as usize);
    let drop_bits = q.ilog2() + 1 - levels as u32 * log_basis;
    let bound = if drop_bits == 0 {
        0
    } else {
        1 << (drop_bits - 1)
    };
    let radix = 1i128 << log_basis;
    let len = basis.big_uint_value_len();
    assert_eq!(to_u128(basis.modulus()), q);
    assert_eq!(basis.drop_bits(), drop_bits);
    assert_eq!(basis.decompose_length(), levels);
    assert_eq!(basis.decomposer_iter().len(), levels);
    assert_eq!(basis.scalar_iter().len(), levels);
    assert_eq!(to_u128(basis.approximate_error_bound().digits()), bound);

    for (level, scalar) in basis.scalar_iter().enumerate() {
        let expected = 1u128 << (drop_bits + level as u32 * log_basis);
        assert_eq!(to_u128(scalar), expected);
    }

    for input in inputs(q, log_basis, levels, drop_bits) {
        let (adjusted, mut carry) = basis.init_value_carry(&BigUint(limbs::<T>(input, len)));
        let mut sum = 0i128;
        for (level, decomposer) in basis.decomposer_iter().enumerate() {
            let (digit, next_carry) = decomposer.decompose(&adjusted, carry);
            let (unsigned, unsigned_carry) = decomposer.unsigned_decompose(&adjusted, carry);
            assert_eq!(next_carry, unsigned_carry);
            let unsigned = unsigned.into() as i128;
            assert!((0..radix).contains(&unsigned));
            let centered = if unsigned >= radix / 2 {
                unsigned - radix
            } else {
                unsigned
            };
            assert_eq!(to_u128(&digit), centered.rem_euclid(q as i128) as u128);
            sum += centered * (1i128 << (drop_bits + level as u32 * log_basis));
            carry = next_carry;
        }
        let output = sum.rem_euclid(q as i128) as u128;
        let distance = input.abs_diff(output);
        let error = distance.min(q - distance);
        assert!(
            error <= bound,
            "q={q}, logB={log_basis}, levels={levels}, input={input}, output={output}, error={error}, bound={bound}"
        );
    }
}

#[test]
fn retained_levels_match_modular_oracle() {
    let moduli = [134_215_681u32, 134_176_769];
    for log_basis in [3, 5, 7] {
        assert_contract(&moduli, log_basis, None);
    }
    // 49-bit product: start the retained levels before, at, and beyond bit 32.
    let moduli = [65_537u32, 65_539, 65_543];
    for (log_basis, retained) in [(3, 6), (17, 1), (4, 4), (4, 1)] {
        assert_contract(&moduli, log_basis, Some(retained));
    }
    // 100-bit product exercises the same boundaries for 64-bit limbs.
    let moduli = [1_125_899_906_826_241u64, 1_125_899_906_629_633];
    for (log_basis, retained) in [(4, 10), (3, 12), (4, 8)] {
        assert_contract(&moduli, log_basis, Some(retained));
    }
}

#[test]
fn batch_matches_scalar_decomposition() {
    let moduli = [134_215_681u32, 134_176_769];
    let q: u128 = moduli.iter().map(|&m| u128::from(m)).product();
    let modulus = BigUint(limbs(q, (q.ilog2() + 1).div_ceil(u32::BITS) as usize));
    for log_basis in [3, 5] {
        let basis = BigUintApproxSignedBasis::<u32>::new(modulus.view(), log_basis, None);
        let len = basis.big_uint_value_len();
        let values: Vec<u32> = inputs(q, log_basis, basis.decompose_length(), basis.drop_bits())
            .into_iter()
            .flat_map(|value| limbs(value, len))
            .collect();
        let count = values.len() / len;
        let mut adjusted = vec![u32::MAX; values.len()];
        let mut carries = vec![true; count];
        basis.init_value_carry_slice_to(&values, &mut adjusted, &mut carries);
        let mut in_place = values.clone();
        let mut in_place_carries = vec![true; count];
        basis.init_value_carry_slice_assign(&mut in_place, &mut in_place_carries);
        assert_eq!(adjusted, in_place);
        assert_eq!(carries, in_place_carries);
        for ((input, actual), &carry) in values
            .chunks_exact(len)
            .zip(adjusted.chunks_exact(len))
            .zip(&carries)
        {
            let (expected, expected_carry) = basis.init_value_carry(&BigUint(input));
            assert_eq!(actual, expected);
            assert_eq!(carry, expected_carry);
        }

        let mut signed_digits = vec![u32::MAX; values.len()];
        let mut unsigned_digits = vec![u32::MAX; count];
        for decomposer in basis.decomposer_iter() {
            let previous_carries = carries.clone();
            let mut unsigned_carries = carries.clone();
            decomposer.decompose_slice_to(&adjusted, &mut signed_digits, &mut carries);
            decomposer.unsigned_decompose_slice_to(
                &adjusted,
                &mut unsigned_digits,
                &mut unsigned_carries,
            );
            assert_eq!(carries, unsigned_carries);
            for (index, value) in adjusted.chunks_exact(len).enumerate() {
                let (digit, carry) = decomposer.decompose(value, previous_carries[index]);
                assert_eq!(&signed_digits[index * len..(index + 1) * len], digit);
                assert_eq!(carries[index], carry);
                let mut digit_to = vec![u32::MAX; len];
                let mut carry_to = previous_carries[index];
                decomposer.decompose_to(value, &mut digit_to, &mut carry_to);
                assert_eq!(digit_to, digit);
                assert_eq!(carry_to, carry);
                let (unsigned, carry) =
                    decomposer.unsigned_decompose(value, previous_carries[index]);
                let mut unsigned_to = u32::MAX;
                let mut carry_to = previous_carries[index];
                decomposer.unsigned_decompose_to(value, &mut unsigned_to, &mut carry_to);
                assert_eq!(unsigned_to, unsigned);
                assert_eq!(unsigned_digits[index], unsigned);
                assert_eq!(carry_to, carry);
            }
        }
    }
}
