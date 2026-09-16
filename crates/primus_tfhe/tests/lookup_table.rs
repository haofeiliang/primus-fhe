//! Shared LUT compiler boundaries, raw scales, and rotation layout.
use std::{cell::Cell, cmp::Reverse, fmt::Debug};

#[path = "support/allocations.rs"]
mod allocations;

use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus, UintModulus};
use primus_reduce::RingContext;

use primus_tfhe::{
    BivariateLookupTable, InterleavedLookupTable, LookupTable, LookupTableError, LweCiphertext,
};

macro_rules! with_modulus {
    ($q:expr, $modulus:ident, $body:block) => {
        match $q {
            None => {
                let $modulus = NativeModulus::new();
                $body
            }
            Some(q) if q.is_power_of_two() => {
                let $modulus = PowOf2Modulus::new(q);
                $body
            }
            Some(q) if q.leading_zeros() > 1 => {
                let $modulus = BarrettModulus::new(q);
                $body
            }
            Some(q) => {
                let $modulus = UintModulus::new(q);
                $body
            }
        }
    };
}

fn compile_single<T: FheUint, M: RingContext<T>, F: Fn(usize) -> Result<T, LookupTableError>>(
    d: usize,
    n: usize,
    t: T,
    q: Option<T>,
    acc: M,
    output: F,
) -> Result<LookupTable<T>, LookupTableError> {
    with_modulus!(q, modulus, {
        LookupTable::try_new(d, n, t, modulus, acc, output)
    })
}
fn compile_interleaved<
    T: FheUint,
    M: RingContext<T>,
    F: Fn(usize, usize) -> Result<T, LookupTableError>,
>(
    d: usize,
    n: usize,
    k: usize,
    t: T,
    q: Option<T>,
    acc: M,
    output: F,
) -> Result<InterleavedLookupTable<T>, LookupTableError> {
    with_modulus!(q, modulus, {
        InterleavedLookupTable::try_new(d, n, k, t, modulus, acc, output)
    })
}
fn modulus_switch<T: FheUint>(value: T, q: Option<T>, n: usize) -> usize {
    with_modulus!(q, modulus, {
        primus_tfhe::backend_support::modulus_switch(value, modulus, n)
    })
}
fn modulus_switch_with_step<T: FheUint>(
    value: T,
    q: Option<T>,
    n: usize,
    rotation_step: usize,
) -> usize {
    with_modulus!(q, modulus, {
        primus_tfhe::backend_support::modulus_switch_with_step(value, modulus, n, rotation_step)
    })
}

#[test]
fn raw_compilation_validates_layout_encoding_and_canonical_outputs() {
    let modulus = BarrettModulus::new(97u32);
    for (domain, n, t, q, expected) in [
        (
            0,
            64,
            4,
            Some(97),
            LookupTableError::InvalidInputDomain {
                domain_len: 0,
                max_domain_len: 2,
            },
        ),
        (
            3,
            64,
            4,
            Some(97),
            LookupTableError::InvalidInputDomain {
                domain_len: 3,
                max_domain_len: 2,
            },
        ),
        (2, 0, 4, Some(97), LookupTableError::InvalidPolynomialLength),
        (2, 3, 4, Some(97), LookupTableError::InvalidPolynomialLength),
        (
            2,
            usize::MAX / 2 + 1,
            4,
            Some(97),
            LookupTableError::InvalidPolynomialLength,
        ),
        (2, 64, 1, Some(97), LookupTableError::InvalidInputEncoding),
        (2, 64, 4, Some(4), LookupTableError::InvalidInputEncoding),
    ] {
        let error = compile_single(domain, n, t, q, modulus, |_| {
            panic!("invalid compilation arguments must precede output generation")
        })
        .unwrap_err();
        assert_eq!(error, expected);
    }
    assert_eq!(
        compile_single(2, 64, 4, Some(97), modulus, |input| Ok(if input == 0 {
            1
        } else {
            97
        }))
        .unwrap_err(),
        LookupTableError::EncodedOutputOutOfRange { input: 1 },
    );
    for (count, expected) in [
        (0, LookupTableError::EmptyOutputs),
        (
            usize::MAX,
            LookupTableError::OutputCountTooLarge {
                output_count: usize::MAX,
                poly_length: 64,
            },
        ),
        (
            64,
            LookupTableError::PlaintextDomainTooLarge {
                domain_len: 2,
                coefficients_per_output: 1,
            },
        ),
    ] {
        assert_eq!(
            compile_interleaved(2, 64, count, 4, Some(97), modulus, |_, _| Ok(0)).unwrap_err(),
            expected
        );
    }
}

#[test]
fn compilation_allocates_only_the_result() {
    fn check<M: RingContext<u32>>(modulus: M) {
        const N: usize = 1024;
        let q = modulus.explicit_value();
        let (_, single) = allocations::measure(|| {
            compile_single(8, N, 16, q, modulus, |input| Ok(input as u32)).unwrap()
        });
        assert_eq!(
            (single.count, single.allocated_bytes),
            (1, N * size_of::<u32>())
        );
        let (_, full) = allocations::measure(|| {
            LookupTable::try_new_odd_full_domain(N, 15, modulus, modulus, |input| Ok(input as u32))
                .unwrap()
        });
        assert_eq!(
            (full.count, full.allocated_bytes),
            (1, N * size_of::<u32>())
        );
        for count in [1, 3, 4, 16] {
            let (_, many) = allocations::measure(|| {
                compile_interleaved(8, N, count, 16, q, modulus, |input, output| {
                    Ok((input + output) as u32)
                })
                .unwrap()
            });
            assert_eq!(
                (many.count, many.allocated_bytes),
                (1, N * size_of::<u32>())
            );
        }
    }
    check(NativeModulus::new());
    check(BarrettModulus::new(132_120_577));
}

#[test]
fn many_outputs_are_evaluated_once_in_input_order_and_stop_on_error() {
    for expected in [
        None,
        Some(LookupTableError::OutputOutOfRange { input: 1 }),
        Some(LookupTableError::EncodedOutputOutOfRange { input: 1 }),
    ] {
        let calls = Cell::new(0);
        let result = compile_interleaved(
            3,
            32,
            4,
            8u32,
            Some(97),
            BarrettModulus::new(97),
            |input, output| {
                assert_eq!(calls.replace(calls.get() + 1), input * 4 + output);
                if (input, output) == (1, 2) {
                    match &expected {
                        Some(error @ LookupTableError::OutputOutOfRange { .. }) => {
                            return Err(error.clone());
                        }
                        Some(LookupTableError::EncodedOutputOutOfRange { .. }) => return Ok(97),
                        _ => {}
                    }
                }
                Ok((input + output) as u32)
            },
        );
        assert_eq!(result.err(), expected);
        assert_eq!(calls.get(), if expected.is_some() { 7 } else { 12 });
    }
}

// Independent arithmetic uses u128 even for native u64; all test domains are
// small enough that the products fit. No RoundedCodec or production rotation
// helper participates in the expected LUT geometry.
fn round_ratio(numerator: u128, denominator: u128) -> u128 {
    (numerator + denominator / 2) / denominator
}

fn rotate<T>(input: &[T], exponent: usize, q: u128) -> Vec<T>
where
    T: FheUint + Into<u128> + TryFrom<u128, Error: Debug>,
{
    let n = input.len();
    let mut output = vec![T::ZERO; n];
    for (index, &value) in input.iter().enumerate() {
        let degree = (index + exponent) % (2 * n);
        let value = value.into();
        let value = if degree < n { value } else { (q - value) % q };
        output[degree % n] = T::try_from(value).unwrap();
    }
    output
}

fn raw_output(input: usize, output: usize, q: u128) -> u128 {
    // Independent raw scales include zero and residues near q, as used by
    // Boolean and gadget-scaled LUTs.
    match output % 4 {
        0 => input as u128,
        1 => q - 1 - input as u128,
        2 => q / 8 + 3 * input as u128,
        _ => q / 3 - input as u128,
    }
}

fn check_layout<T, M>(
    n: usize,
    t: usize,
    domain: usize,
    count: usize,
    input_q: Option<T>,
    modulus: M,
) where
    T: FheUint + Into<u128> + TryFrom<u128, Error: Debug>,
    M: RingContext<T>,
{
    let q = input_q.map_or(1u128 << T::BITS, Into::into);
    let output_q = modulus
        .explicit_value()
        .map_or(1u128 << T::BITS, Into::into);
    let padded_output_count = count.next_power_of_two();
    let coefficients_per_output = n / padded_output_count;
    let centers: Vec<_> = (0..=domain)
        .map(|input| {
            let encoded = round_ratio(input as u128 * q, t as u128);
            (round_ratio(encoded * (2 * coefficients_per_output) as u128, q) as usize)
                .min(coefficients_per_output)
        })
        .collect();
    assert!(centers.windows(2).all(|pair| pair[0] < pair[1]));

    let check = |polynomial: &[T]| {
        for output_group in polynomial.chunks_exact(padded_output_count) {
            assert!(output_group[count..].iter().all(|&value| value == T::ZERO));
        }
        for position in 0..2 * coefficients_per_output {
            // Nearest-center search, with ties going to the higher center,
            // is independent of the compiler's midpoint/fill implementation.
            let nearest = (0..=domain)
                .min_by_key(|&input| {
                    (
                        centers[input].abs_diff(position % coefficients_per_output),
                        Reverse(input),
                    )
                })
                .unwrap();
            let rotated = rotate(
                polynomial,
                (2 * n - position * padded_output_count) % (2 * n),
                output_q,
            );
            for (output, &actual) in rotated.iter().take(count).enumerate() {
                // The extra center terminates the programmed prefix with
                // -f(0); that tail is not another valid message.
                let value = raw_output(
                    if nearest == domain { 0 } else { nearest },
                    output,
                    output_q,
                );
                let negate = (nearest == domain) ^ (position >= coefficients_per_output);
                let expected = if negate {
                    (output_q - value) % output_q
                } else {
                    value
                };
                assert_eq!(
                    actual.into(),
                    expected,
                    "bits={}, q={q}, output_q={output_q}, N={n}, t={t}, D={domain}, k={count}, position={position}, output={output}",
                    T::BITS,
                );
            }
        }
    };
    let value = |input, output| {
        assert!(output < count, "padding slots must not invoke the callback");
        Ok(T::try_from(raw_output(input, output, output_q)).unwrap())
    };
    let t = T::try_from(t as u128).unwrap();
    let many = compile_interleaved(domain, n, count, t, input_q, modulus, value).unwrap();
    assert_eq!(many.input_domain_len(), domain);
    assert_eq!(many.output_count(), count);
    assert_eq!(many.padded_output_count(), padded_output_count);
    assert!(many.is_compatible(n, t, input_q, modulus.explicit_value()));
    check(many.polynomial().as_ref());
    if count == 1 {
        let single =
            compile_single(domain, n, t, input_q, modulus, |input| value(input, 0)).unwrap();
        assert_eq!(single.input_domain_len(), domain);
        assert!(single.is_compatible(n, t, input_q, modulus.explicit_value()));
        check(single.polynomial().as_ref());
    }
}

fn check_word_layouts<T>()
where
    T: FheUint + Into<u128> + TryFrom<u128, Error: Debug>,
{
    let word_max = T::try_from((1u128 << T::BITS) - 1).unwrap();
    for q in [
        None,
        Some(T::try_from(97u128).unwrap()),
        Some(T::try_from(128u128).unwrap()),
        Some(word_max),
    ] {
        for t in [3usize, 4, 5, 6] {
            for domain in [1, t.div_ceil(2)] {
                for count in [1, 2, 3, 4, 5] {
                    check_layout(32, t, domain, count, q, NativeModulus::new());
                    check_layout(
                        32,
                        t,
                        domain,
                        count,
                        q,
                        BarrettModulus::new(T::try_from(97u128).unwrap()),
                    );
                }
            }
        }
    }
}

#[test]
fn compiled_luts_match_independent_negacyclic_oracle() {
    check_word_layouts::<u16>();
    check_word_layouts::<u32>();
    check_word_layouts::<u64>();
    // A layout with one coefficient per output has no stored terminating plateau.
    for count in [1, 4] {
        check_layout(count, 2, 1, count, None::<u32>, NativeModulus::new());
    }
    // Double rounding gives center 13, whereas round(32/3) would give 11.
    // Here that difference moves the actual plateau boundaries as well.
    check_layout(16, 3, 2, 1, Some(5u32), BarrettModulus::new(97));
}

#[test]
fn rotation_center_collisions_are_rejected() {
    for (n, t, q, expected) in [
        (
            4,
            6u32,
            10,
            LookupTableError::RotationCenterCollision {
                first_input: 1,
                second_input: 2,
                center_position: 2,
            },
        ),
        (
            2,
            3,
            5,
            LookupTableError::RotationCenterCollision {
                first_input: 1,
                second_input: 2,
                center_position: 2,
            },
        ),
    ] {
        assert_eq!(
            compile_single(
                t.div_ceil(2) as usize,
                n,
                t,
                Some(q),
                BarrettModulus::new(97u32),
                |_| Ok(1)
            )
            .unwrap_err(),
            expected,
        );
        // Interleaving preserves these centers in per-output coordinates.
        assert_eq!(
            compile_interleaved(
                t.div_ceil(2) as usize,
                n * 2,
                2,
                t,
                Some(q),
                BarrettModulus::new(97u32),
                |_, _| Ok(1)
            )
            .unwrap_err(),
            expected,
        );
    }
}

fn check_quantization<T>()
where
    T: FheUint + Into<u128> + TryFrom<u128, Error: Debug>,
{
    let native_q = 1u128 << T::BITS;
    let check = |q: u128, native: bool, length: usize, value: u128| {
        let modulus = (!native).then(|| T::try_from(q).unwrap());
        let input = T::try_from(value).unwrap();
        let expected = round_ratio(value * length as u128, q) as usize % length;
        assert_eq!(modulus_switch(input, modulus, length), expected);
        for rotation_step in [1, length / 2] {
            let expected = round_ratio(value * (length / rotation_step) as u128, q) as usize
                % (length / rotation_step)
                * rotation_step;
            assert_eq!(
                modulus_switch_with_step(input, modulus, length, rotation_step),
                expected
            );
        }
    };
    for length in [2, 8, 64] {
        for q in 2..=33u128 {
            for value in 0..q {
                check(q, false, length, value);
            }
        }
        for (q, native) in [(native_q, true), (native_q - 1, false)] {
            for value in [0, 1, q - 1] {
                check(q, native, length, value);
            }
            for index in 0..length {
                let threshold = ((2 * index + 1) as u128 * q).div_ceil(2 * length as u128);
                for value in [threshold - 1, threshold, threshold + 1] {
                    check(q, native, length, value);
                }
            }
        }
    }
    let length = 1usize << (usize::BITS.min(T::BITS) - 1);
    for value in [0, native_q / 2, native_q - 1] {
        check(native_q, true, length, value);
    }
}

#[test]
fn quantizer_and_lut_reject_unrepresentable_rotation_domains() {
    let modulus = NativeModulus::<u16>::new();
    for two_n in [1 << 16, 1 << 17] {
        // A smaller quantization target must not bypass the 2N boundary.
        for rotation_step in [1, 2] {
            assert!(
                std::panic::catch_unwind(|| {
                    primus_tfhe::backend_support::RotationQuantizer::new(
                        modulus,
                        two_n,
                        rotation_step,
                    )
                })
                .is_err()
            );
            assert_eq!(
                InterleavedLookupTable::try_new(
                    1,
                    two_n / 2,
                    rotation_step,
                    2,
                    modulus,
                    modulus,
                    |_, _| panic!("invalid rotation domain must precede output generation"),
                )
                .unwrap_err(),
                LookupTableError::InvalidPolynomialLength,
            );
        }
    }
}

#[test]
fn coefficient_quantization_matches_wide_integer_oracle() {
    check_quantization::<u16>();
    check_quantization::<u32>();
    check_quantization::<u64>();
    // Rounding in the smaller domain differs from clearing low bits afterward.
    assert_eq!(modulus_switch_with_step(2u32, Some(16), 16, 4), 4);
    assert_eq!(modulus_switch(2u32, Some(16), 16) & !3, 0);
}

#[test]
fn bivariate_packing_and_lut_match_integer_oracles() {
    fn check<M: RingContext<u32>>(modulus: M) {
        const N: usize = 32;
        let q = modulus.explicit_value().map_or(1u128 << 32, u128::from);
        let input_codec = RoundedCodec::new(16, modulus);
        let output_codec = RoundedCodec::new(8, modulus);
        let mut saw_rounding_discrepancy = false;
        for (base, rhs_len) in [(1, 3), (3, 2), (4, 2)] {
            let calls = Cell::new(0);
            let lut = BivariateLookupTable::try_new(
                base,
                rhs_len,
                N,
                &input_codec,
                &output_codec,
                |x, y| {
                    assert!(x < base && y < rhs_len);
                    assert_eq!(calls.replace(calls.get() + 1), x + base * y);
                    ((x * x + y) % 8) as u32
                },
            )
            .unwrap();
            assert_eq!(calls.get(), base * rhs_len);
            assert_eq!(
                (lut.lhs_domain_len(), lut.rhs_domain_len()),
                (base, rhs_len)
            );
            assert_eq!(lut.lookup_table().input_domain_len(), base * rhs_len);

            // Deterministic masks and a binary secret; 33 coefficients include a SIMD tail.
            let mut lhs =
                LweCiphertext::new((0..33).map(|i| (q - 1 - i) as u32).collect::<Vec<_>>());
            let mut rhs = LweCiphertext::new(
                (0..33)
                    .map(|i| ((q / 3 + 17 * i) % q) as u32)
                    .collect::<Vec<_>>(),
            );
            let dot = |ciphertext: &LweCiphertext<u32>| -> u128 {
                ciphertext
                    .a()
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| i % 2 == 0)
                    .map(|(_, &a)| u128::from(a))
                    .sum()
            };
            let mut packed = LweCiphertext::zero(32);
            for y in 0..rhs_len {
                for x in 0..base {
                    let ex = round_ratio(x as u128 * q, 16);
                    let ey = round_ratio(y as u128 * q, 16);
                    let ez = round_ratio((x + base * y) as u128 * q, 16);
                    let rho = (ex + base as u128 * ey) as i128 - ez as i128;
                    saw_rounding_discrepancy |= rho != 0;
                    assert!(2 * rho.abs() <= (base + 2) as i128);
                    // Known errors e_x=-2 and e_y=1 exercise amplification and modular wrap.
                    *lhs.b_mut() = ((dot(&lhs) + ex + q - 2) % q) as u32;
                    *rhs.b_mut() = ((dot(&rhs) + ey + 1) % q) as u32;
                    let (_, allocation) =
                        allocations::measure(|| lut.pack_to(&lhs, &rhs, &mut packed));
                    assert_eq!(allocation.count, 0);
                    for ((&a, &b), &actual) in
                        lhs.as_ref().iter().zip(rhs.as_ref()).zip(packed.as_ref())
                    {
                        assert_eq!(
                            u128::from(actual),
                            (u128::from(a) + base as u128 * u128::from(b)) % q
                        );
                    }
                    let phase = (u128::from(packed.b()) + q - dot(&packed) % q) % q;
                    assert_eq!(phase, (ex + base as u128 * ey + q - 2 + base as u128) % q);
                    // Inspect the LUT at the actual packed encoding, not an ideal E(x+B*y).
                    let rotation = round_ratio((ex + base as u128 * ey) % q * (2 * N) as u128, q)
                        as usize
                        % (2 * N);
                    let rotated = rotate(
                        lut.lookup_table().polynomial().as_ref(),
                        (2 * N - rotation) % (2 * N),
                        q,
                    );
                    let expected = round_ratio(((x * x + y) % 8) as u128 * q, 8);
                    assert_eq!(u128::from(rotated[0]), expected);
                }
            }
        }
        assert_eq!(saw_rounding_discrepancy, !q.is_multiple_of(16));
    }
    check(NativeModulus::new());
    check(BarrettModulus::new(131));
}

#[test]
fn bivariate_boundaries_reject_before_callbacks_or_output_writes() {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    let input_codec = RoundedCodec::new(16u32, NativeModulus::new());
    let output_codec = RoundedCodec::new(8u32, NativeModulus::new());
    for (lhs, rhs, expected) in [
        (
            0,
            2,
            LookupTableError::InvalidBivariateDomain {
                lhs_domain_len: 0,
                rhs_domain_len: 2,
            },
        ),
        (
            2,
            0,
            LookupTableError::InvalidBivariateDomain {
                lhs_domain_len: 2,
                rhs_domain_len: 0,
            },
        ),
        (
            usize::MAX,
            2,
            LookupTableError::InvalidBivariateDomain {
                lhs_domain_len: usize::MAX,
                rhs_domain_len: 2,
            },
        ),
        (
            3,
            3,
            LookupTableError::InvalidInputDomain {
                domain_len: 9,
                max_domain_len: 8,
            },
        ),
    ] {
        assert_eq!(
            BivariateLookupTable::try_new(
                lhs,
                rhs,
                16,
                &input_codec,
                &output_codec,
                |_, _| panic!("invalid domain must precede callback")
            )
            .unwrap_err(),
            expected
        );
    }
    let wrong_codec = RoundedCodec::new(8, BarrettModulus::new(131));
    assert_eq!(
        BivariateLookupTable::try_new(3, 2, 16, &input_codec, &wrong_codec, |_, _| panic!(
            "wrong modulus must precede callback"
        ))
        .unwrap_err(),
        LookupTableError::OutputModulusMismatch
    );
    assert_eq!(
        BivariateLookupTable::try_new(3, 2, 16, &input_codec, &output_codec, |_, _| 8).unwrap_err(),
        LookupTableError::OutputOutOfRange { input: 0 }
    );
    let lut =
        BivariateLookupTable::try_new(3, 2, 16, &input_codec, &output_codec, |x, y| (x + y) as u32)
            .unwrap();
    let input = LweCiphertext::zero(4);
    let short = LweCiphertext::zero(3);
    let empty = LweCiphertext::new(Vec::new());
    for (lhs, rhs, initial) in [
        (&input, &short, &input),
        (&input, &input, &short),
        (&empty, &empty, &empty),
    ] {
        let mut output = initial.clone();
        assert!(catch_unwind(AssertUnwindSafe(|| lut.pack_to(lhs, rhs, &mut output))).is_err());
        assert_eq!(&output, initial);
    }
}

fn check_odd_full_domain<T, M>(n: usize, t: usize, input_q: Option<T>, modulus: M)
where
    T: FheUint + Into<u128> + TryFrom<u128, Error: Debug>,
    M: RingContext<T>,
{
    let q = input_q.map_or(1u128 << T::BITS, Into::into);
    let output_q = modulus
        .explicit_value()
        .map_or(1u128 << T::BITS, Into::into);
    let centers: Vec<_> = (0..t)
        .map(|m| {
            (round_ratio(round_ratio(m as u128 * q, t as u128) * (2 * n) as u128, q)
                % (2 * n) as u128) as usize
        })
        .collect();
    let calls: Vec<_> = (0..t).map(|_| Cell::new(0)).collect();
    let value = |m| ((m + 1) % t) as u128;
    let result = with_modulus!(input_q, input_modulus, {
        LookupTable::try_new_odd_full_domain(n, T::as_from(t), input_modulus, modulus, |m| {
            calls[m].set(calls[m].get() + 1);
            Ok(T::try_from(value(m)).unwrap())
        })
    });
    let mut folded: Vec<_> = centers.iter().map(|c| c % n).collect();
    folded.sort_unstable();
    if folded.windows(2).any(|pair| pair[0] == pair[1]) {
        assert!(matches!(
            result,
            Err(LookupTableError::RotationCenterCollision { .. })
        ));
        return;
    }
    let lut = result.unwrap();
    assert_eq!(lut.input_domain_len(), t);
    assert!(lut.is_compatible(n, T::as_from(t), input_q, modulus.explicit_value()));
    assert!(calls.iter().all(|count| count.get() == 1));

    // Search signed copies of every *unfolded* center independently of the
    // compiler's input ordering. Every rotation checks a plateau or its boundary,
    // including midpoint ties and both sides of the seams at 0, N and 2N.
    let mut candidates = Vec::new();
    for (m, &center) in centers.iter().enumerate() {
        for copy in -2i64..=2 {
            let output = if copy % 2 == 0 {
                value(m)
            } else {
                (output_q - value(m)) % output_q
            };
            candidates.push((center as i64 + copy * n as i64, output));
        }
        assert_eq!(
            rotate(
                lut.polynomial().as_ref(),
                (2 * n - center) % (2 * n),
                output_q
            )[0]
            .into(),
            value(m),
        );
    }
    for position in 0..2 * n {
        let &(_, expected) = candidates
            .iter()
            .min_by_key(|&&(center, _)| (center.abs_diff(position as i64), Reverse(center)))
            .unwrap();
        let actual = rotate(
            lut.polynomial().as_ref(),
            (2 * n - position) % (2 * n),
            output_q,
        )[0];
        assert_eq!(
            actual.into(),
            expected,
            "q={q}, t={t}, N={n}, position={position}"
        );
    }
}

#[test]
fn odd_full_domain_matches_signed_integer_oracle() {
    fn check<T: FheUint + Into<u128> + TryFrom<u128, Error: Debug>>() {
        for t in [3usize, 5, 9, 15] {
            for q in [
                None,
                Some(t as u128 + 1),
                Some(t as u128 + 2),
                Some(97),
                Some(128),
                Some((1u128 << T::BITS) - 1),
            ] {
                let q = q.map(|q| T::try_from(q).unwrap());
                check_odd_full_domain(16, t, q, NativeModulus::new());
                check_odd_full_domain(16, t, q, BarrettModulus::new(T::try_from(97u128).unwrap()));
            }
        }
    }
    check::<u16>();
    check::<u32>();
    check::<u64>();
}

#[test]
fn odd_full_domain_rejects_invalid_domains_and_outputs() {
    for (n, t, q, expected) in [
        (0, 3, 97, LookupTableError::InvalidPolynomialLength),
        (8, 1, 97, LookupTableError::InvalidInputEncoding),
        (8, 3, 3, LookupTableError::InvalidInputEncoding),
        (8, 4, 97, LookupTableError::EvenPlaintextModulus),
        (
            8,
            9,
            97,
            LookupTableError::PlaintextDomainTooLarge {
                domain_len: 9,
                coefficients_per_output: 8,
            },
        ),
    ] {
        assert_eq!(
            LookupTable::try_new_odd_full_domain(
                n,
                t,
                BarrettModulus::new(q),
                BarrettModulus::new(97u32),
                |_| panic!("invalid parameters must precede callbacks"),
            )
            .unwrap_err(),
            expected
        );
    }
    let modulus = BarrettModulus::new(97u32);
    for error in [
        LookupTableError::EncodedOutputOutOfRange { input: 3 },
        LookupTableError::OutputOutOfRange { input: 3 },
    ] {
        let calls = Cell::new(0);
        let result = LookupTable::try_new_odd_full_domain(16, 5, modulus, modulus, |m| {
            calls.set(calls.get() + 1);
            match m {
                0 => Ok(1),
                3 if matches!(error, LookupTableError::EncodedOutputOutOfRange { .. }) => Ok(97),
                3 => Err(error.clone()),
                _ => panic!("callback must stop at the first invalid output"),
            }
        });
        assert_eq!(result.unwrap_err(), error);
        assert_eq!(calls.get(), 2);
    }
}
