use std::{cell::Cell, cmp::Reverse};

use primus_encoding::{RoundedCodec, ScaledCodec};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_reduce::RingContext;
use primus_test_allocations as allocations;
use primus_tfhe::{FactorizedLookupTable, LookupTableError};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

fn round_ratio(numerator: i64, denominator: i64) -> i64 {
    (numerator + denominator / 2) / denominator
}

// Independent signed negacyclic arithmetic; no production LUT, rotation or NTT helper.
fn multiply(lhs: &[i64], rhs: &[i64], q: i64) -> Vec<i64> {
    let n = lhs.len();
    let mut result = vec![0; n];
    for (i, &a) in lhs.iter().enumerate() {
        for (j, &b) in rhs.iter().enumerate() {
            result[(i + j) % n] += if i + j < n { a * b } else { -a * b };
        }
    }
    result.into_iter().map(|x| x.rem_euclid(q)).collect()
}

fn rotate_negative(poly: &[i64], rotation: usize, q: i64) -> Vec<i64> {
    let n = poly.len();
    (0..n)
        .map(|i| {
            let position = i + rotation;
            let sign = if (position / n).is_multiple_of(2) {
                1
            } else {
                -1
            };
            (sign * poly[position % n]).rem_euclid(q)
        })
        .collect()
}

#[test]
fn factorization_and_all_rotations_match_integer_geometry() {
    fn check<M: RingContext<u32>>(n: usize, t: u32, domain: usize, input_modulus: M) {
        let input_q = input_modulus.explicit_value().map_or(1i64 << 32, i64::from);
        let input_codec = RoundedCodec::new(t, input_modulus);
        let centers: Vec<_> = (0..=domain)
            .map(|m| {
                round_ratio(
                    round_ratio(m as i64 * input_q, t.into()) * 2 * n as i64,
                    input_q,
                )
                .min(n as i64)
            })
            .collect();
        for output_t in [2, 8] {
            const Q: i64 = 97;
            let output_codec = ScaledCodec::new(output_t, BarrettModulus::new(Q as u32));
            let value = |m: usize, i: usize| match i {
                0 => 0,
                1 => output_t - 1,
                _ => ((m * 3 + 1) % output_t as usize) as u32,
            };
            let calls = Cell::new(0);
            let (lut, allocation) = allocations::measure(|| {
                FactorizedLookupTable::try_new(domain, n, 3, &input_codec, &output_codec, |m, i| {
                    assert_eq!(calls.replace(calls.get() + 1), i * domain + m);
                    value(m, i)
                })
                .unwrap()
            });
            assert_eq!(
                allocation.count, 2,
                "one allocation for V and one for all factors"
            );
            assert_eq!(calls.get(), 3 * domain);
            assert_eq!(lut.output_count(), 3); // Even N=1 supports more than N outputs.
            assert_eq!(lut.input_domain_len(), domain);
            assert_eq!(lut.output_plaintext_modulus(), output_t);
            assert!(lut.is_compatible(n, t, input_modulus.explicit_value(), Some(Q as u32)));
            let common: Vec<_> = lut
                .common_polynomial()
                .as_ref()
                .iter()
                .map(|&x| i64::from(x))
                .collect();
            let delta = round_ratio(Q, output_t.into());
            for (i, factor) in lut.factors().enumerate() {
                // Nearest-center search, with ties choosing the higher center,
                // supplies p independently of the compiler's interval scan.
                let p: Vec<_> = (0..n)
                    .map(|position| {
                        let nearest = (0..=domain)
                            .min_by_key(|&m| {
                                ((centers[m] - position as i64).abs(), Reverse(centers[m]))
                            })
                            .unwrap();
                        if nearest == domain {
                            -i64::from(value(0, i))
                        } else {
                            i64::from(value(nearest, i))
                        }
                    })
                    .collect();
                let factor: Vec<_> = factor.as_ref().iter().map(|&x| i64::from(x)).collect();
                let signed_differences: Vec<_> = (0..n)
                    .map(|j| {
                        if j == 0 {
                            p[0] + p[n - 1]
                        } else {
                            p[j] - p[j - 1]
                        }
                    })
                    .collect();
                assert_eq!(
                    factor,
                    signed_differences
                        .iter()
                        .map(|x| x.rem_euclid(Q))
                        .collect::<Vec<_>>()
                );
                let scaled: Vec<_> = p.iter().map(|x| (delta * x).rem_euclid(Q)).collect();
                for rotation in 0..2 * n {
                    assert_eq!(
                        multiply(&rotate_negative(&common, rotation, Q), &factor, Q),
                        rotate_negative(&scaled, rotation, Q)
                    );
                }
                for (m, &center) in centers[..domain].iter().enumerate() {
                    let phase = rotate_negative(&scaled, center as usize, Q)[0];
                    assert_eq!(output_codec.decode_value(phase as u32), value(m, i));
                }
            }
        }
    }
    // Empty negative tail, ordinary/short domains, nonbinary t, and double rounding.
    for (n, t, domain, q) in [(1, 2, 1, 97), (8, 8, 4, 97), (16, 15, 4, 97), (16, 3, 2, 5)] {
        check(n, t, domain, BarrettModulus::new(q));
    }
    check(16, 5, 3, NativeModulus::new());
}

#[test]
fn factorized_compilation_rejects_invalid_domains_moduli_and_values() {
    let modulus = BarrettModulus::new(97u32);
    let input = RoundedCodec::new(8, modulus);
    let output = ScaledCodec::new(8, modulus);
    for (domain, n, count, expected) in [
        (4, 8, 0, LookupTableError::EmptyOutputs),
        (4, 0, 3, LookupTableError::InvalidPolynomialLength),
        (
            4,
            8,
            usize::MAX / 8 + 1,
            LookupTableError::TableLengthOverflow,
        ),
        (
            0,
            8,
            3,
            LookupTableError::InvalidInputDomain {
                domain_len: 0,
                max_domain_len: 4,
            },
        ),
        (
            5,
            8,
            3,
            LookupTableError::InvalidInputDomain {
                domain_len: 5,
                max_domain_len: 4,
            },
        ),
    ] {
        assert_eq!(
            FactorizedLookupTable::try_new(domain, n, count, &input, &output, |_, _| panic!(
                "invalid arguments must precede callback"
            ))
            .unwrap_err(),
            expected
        );
    }
    fn reject_modulus<M: RingContext<u32>>(modulus: M) {
        let input = RoundedCodec::new(8, modulus);
        let output = ScaledCodec::new(8, modulus);
        assert_eq!(
            FactorizedLookupTable::try_new(4, 8, 1, &input, &output, |_, _| 0).unwrap_err(),
            LookupTableError::UnsupportedFactorizationModulus
        );
    }
    reject_modulus(NativeModulus::new());
    reject_modulus(BarrettModulus::new(98));
    assert_eq!(
        FactorizedLookupTable::try_new(4, 8, 3, &input, &output, |m, i| if i == 1 && m == 2 {
            8
        } else {
            0
        })
        .unwrap_err(),
        LookupTableError::OutputOutOfRange { input: 2 }
    );
    assert!(matches!(
        FactorizedLookupTable::try_new(
            3,
            4,
            1,
            &RoundedCodec::new(6, BarrettModulus::new(10)),
            &output,
            |_, _| 0
        ),
        Err(LookupTableError::RotationCenterCollision { .. })
    ));
}
