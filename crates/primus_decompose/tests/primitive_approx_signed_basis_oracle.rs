use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;

fn assert_decomposition_contract<T>(
    basis: &ApproxSignedBasis<T>,
    value: T,
    modulus: Option<T>,
) -> u128
where
    T: FheUint + Into<u128>,
{
    let q = modulus.map(Into::into).unwrap_or(1u128 << T::BITS);
    let input = value.into();
    let radix = 1u128 << basis.log_basis();
    let half_radix = radix / 2;

    let scalars: Vec<_> = basis.scalar_iter().map(Into::into).collect();
    assert_eq!(scalars.len(), basis.decompose_length());

    let mut expected_scalar = 1u128 << basis.drop_bits();
    for (level, &scalar) in scalars.iter().enumerate() {
        assert_eq!(
            scalar, expected_scalar,
            "level {level} is not ordered from low to high"
        );
        expected_scalar *= radix;
    }

    let (adjusted, mut carry) = basis.init_value_carry(value);
    let mut recomposed = 0u128;
    for (level, (decomposer, scalar)) in basis.decompose_iter().zip(scalars).enumerate() {
        let (raw_digit, next_carry) = decomposer.decompose(adjusted, carry);
        carry = next_carry;

        let raw_digit = raw_digit.into();
        assert!(raw_digit < q);
        let centered_digit = if raw_digit >= q - half_radix {
            raw_digit as i128 - q as i128
        } else {
            raw_digit as i128
        };
        assert!(
            (-((half_radix) as i128)..(half_radix as i128)).contains(&centered_digit),
            "level {level}: digit {centered_digit} is outside [-B/2, B/2)"
        );

        recomposed = (recomposed + scalar * raw_digit) % q;
    }

    let clockwise = (recomposed + q - input) % q;
    let counterclockwise = (input + q - recomposed) % q;
    let error = clockwise.min(counterclockwise);
    assert!(
        error <= basis.approximate_error_bound().into(),
        "q={q}, input={input}, output={recomposed}, error={error}, bound={}",
        Into::<u128>::into(basis.approximate_error_bound())
    );

    recomposed
}

#[test]
fn exhaustive_explicit_moduli_match_contract() {
    for q in 4u16..=255 {
        for log_basis in 2..u16::BITS {
            if (1u32 << log_basis) > u32::from(q) {
                break;
            }

            let value_bits = if q.is_power_of_two() {
                q.trailing_zeros()
            } else {
                u16::BITS - q.leading_zeros()
            };
            let full_length = value_bits / log_basis;
            for length in 1..=full_length as usize {
                let basis = ApproxSignedBasis::new(Some(q), log_basis, Some(length));
                for value in 0..q {
                    assert_decomposition_contract(&basis, value, Some(q));
                }
            }
        }
    }
}

#[test]
fn native_dropped_bits_use_round_half_up() {
    let basis = ApproxSignedBasis::<u16>::new(None, 4, Some(3));
    let q = 1u128 << u16::BITS;
    let step = 1u128 << basis.drop_bits();
    let half_step = step / 2;

    for value in u16::MIN..=u16::MAX {
        let actual = assert_decomposition_contract(&basis, value, None);
        let expected = ((u128::from(value) + half_step) / step * step) % q;
        assert_eq!(actual, expected, "input={value}");
    }
}

#[test]
fn representative_u32_u64_and_ntt_prime_cases_match_contract() {
    let native_u32 = ApproxSignedBasis::<u32>::new(None, 8, Some(3));
    for value in [0, 1, (1 << 7) - 1, 1 << 7, (1 << 24) - 1, 1 << 24, u32::MAX] {
        assert_decomposition_contract(&native_u32, value, None);
    }

    let native_u64 = ApproxSignedBasis::<u64>::new(None, 8, Some(4));
    for value in [
        0,
        1,
        (1 << 31) - 1,
        1 << 31,
        (1 << 32) - 1,
        1 << 32,
        u64::MAX,
    ] {
        assert_decomposition_contract(&native_u64, value, None);
    }

    const NTT_PRIME: u32 = 1_073_692_673;
    let explicit = ApproxSignedBasis::new(Some(NTT_PRIME), 8, Some(3));
    for value in [
        0,
        1,
        NTT_PRIME / 2,
        NTT_PRIME / 2 + 1,
        NTT_PRIME - 2,
        NTT_PRIME - 1,
    ] {
        assert_decomposition_contract(&explicit, value, Some(NTT_PRIME));
    }
}

#[test]
fn invalid_parameters_are_rejected() {
    assert!(std::panic::catch_unwind(|| ApproxSignedBasis::<u32>::new(None, 1, None)).is_err());
    assert!(
        std::panic::catch_unwind(|| ApproxSignedBasis::<u32>::new(None, u32::BITS, None)).is_err()
    );
    assert!(std::panic::catch_unwind(|| ApproxSignedBasis::<u32>::new(Some(13), 4, None)).is_err());
    assert!(std::panic::catch_unwind(|| ApproxSignedBasis::<u32>::new(None, 4, Some(0))).is_err());
}

#[test]
fn slice_length_mismatches_are_rejected() {
    let basis = ApproxSignedBasis::<u32>::new(None, 4, Some(2));

    assert!(
        std::panic::catch_unwind(|| basis.init_value_carry_slice_to(
            &[0, 1],
            &mut [0],
            &mut [false; 2]
        ))
        .is_err()
    );

    let decomposer = basis.decompose_iter().next().unwrap();
    assert!(
        std::panic::catch_unwind(|| {
            decomposer.decompose_slice_to(&[0, 1], &mut [0; 2], &mut [false])
        })
        .is_err()
    );
}

#[test]
fn serde_roundtrip_rebuilds_derived_state() {
    for basis in [
        ApproxSignedBasis::<u64>::new(None, 8, Some(4)),
        ApproxSignedBasis::new(Some(1_073_692_673), 8, Some(3)),
    ] {
        let serialized = serde_json::to_value(&basis).unwrap();
        let fields = serialized.as_object().unwrap();
        assert_eq!(fields.len(), 3);
        assert!(fields.contains_key("modulus"));
        assert!(fields.contains_key("log_basis"));
        assert!(fields.contains_key("reverse_length"));
        assert!(!fields.contains_key("scalars"));
        assert!(!fields.contains_key("value_masks"));

        let rebuilt: ApproxSignedBasis<u64> = serde_json::from_value(serialized).unwrap();
        assert_eq!(rebuilt, basis);
        assert_eq!(
            rebuilt.scalar_iter().collect::<Vec<_>>(),
            basis.scalar_iter().collect::<Vec<_>>()
        );
    }
}

#[test]
fn serde_rejects_invalid_parameters_without_panicking() {
    for serialized in [
        r#"{"modulus":null,"log_basis":1,"reverse_length":null}"#,
        r#"{"modulus":13,"log_basis":4,"reverse_length":null}"#,
        r#"{"modulus":null,"log_basis":4,"reverse_length":0}"#,
    ] {
        assert!(serde_json::from_str::<ApproxSignedBasis<u32>>(serialized).is_err());
    }
}
