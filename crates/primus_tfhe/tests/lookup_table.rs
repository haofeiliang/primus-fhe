//! Shared LUT compiler boundaries, raw scales, and rotation layout.
use std::{cell::Cell, cmp::Reverse, fmt::Debug};

#[path = "support/allocations.rs"]
mod allocations;

use primus_integer::FheUint;
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus, UintModulus};
use primus_reduce::RingContext;

use primus_tfhe::{InterleavedLookupTable, LookupTable, LookupTableError};

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
fn windowed_modulus_switch<T: FheUint>(value: T, q: Option<T>, n: usize, w: usize) -> usize {
    with_modulus!(q, modulus, {
        primus_tfhe::backend_support::windowed_modulus_switch(value, modulus, n, w)
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
                rotation_domain_len: 1,
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
    let stride = count.next_power_of_two();
    let virtual_n = n / stride;
    let centers: Vec<_> = (0..=domain)
        .map(|input| {
            let encoded = round_ratio(input as u128 * q, t as u128);
            (round_ratio(encoded * (2 * virtual_n) as u128, q) as usize).min(virtual_n)
        })
        .collect();
    assert!(centers.windows(2).all(|pair| pair[0] < pair[1]));

    let check = |polynomial: &[T]| {
        for row in polynomial.chunks_exact(stride) {
            assert!(row[count..].iter().all(|&value| value == T::ZERO));
        }
        for position in 0..2 * virtual_n {
            // Nearest-center search, with ties going to the higher center,
            // is independent of the compiler's midpoint/fill implementation.
            let nearest = (0..=domain)
                .min_by_key(|&input| {
                    (
                        centers[input].abs_diff(position % virtual_n),
                        Reverse(input),
                    )
                })
                .unwrap();
            let rotated = rotate(polynomial, (2 * n - position * stride) % (2 * n), output_q);
            for (output, &actual) in rotated.iter().take(count).enumerate() {
                // The extra center terminates the programmed prefix with
                // -f(0); that tail is not another valid message.
                let value = raw_output(
                    if nearest == domain { 0 } else { nearest },
                    output,
                    output_q,
                );
                let negate = (nearest == domain) ^ (position >= virtual_n);
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
    assert_eq!(many.stride(), stride);
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
    // A one-coefficient virtual ring has no stored terminating plateau.
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
                exponent: 2,
            },
        ),
        (
            2,
            3,
            5,
            LookupTableError::RotationCenterCollision {
                first_input: 1,
                second_input: 2,
                exponent: 2,
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
        // The same virtual layout is used by the interleaved compiler.
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
        for window in [1, length / 2] {
            let expected = round_ratio(value * (length / window) as u128, q) as usize
                % (length / window)
                * window;
            assert_eq!(
                windowed_modulus_switch(input, modulus, length, window),
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
        // A smaller virtual target must not bypass the physical-domain boundary.
        for window in [1, 2] {
            assert!(
                std::panic::catch_unwind(|| {
                    primus_tfhe::backend_support::RotationQuantizer::new(modulus, two_n, window)
                })
                .is_err()
            );
            assert_eq!(
                InterleavedLookupTable::try_new(
                    1,
                    two_n / 2,
                    window,
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
    // Rounding in the virtual ring differs from clearing low bits afterward.
    assert_eq!(windowed_modulus_switch(2u32, Some(16), 16, 4), 4);
    assert_eq!(modulus_switch(2u32, Some(16), 16) & !3, 0);
}
