use primus_integer::FheUint;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_poly::Polynomial;
use primus_reduce::{ReduceAdd, ReduceSub};

// Scatter each source independently in Z_q[X]/(X^N+1); the implementation
// instead partitions both rotations into shared contiguous intervals.
fn check<T: FheUint + Into<u64>, M: Copy + ReduceAdd<T, Output = T> + ReduceSub<T, Output = T>>(
    modulus: M,
    q: u128,
) {
    // Empty batches have no coefficients or rotation intervals to verify.
    primus_poly::add_mul_monomial_pair_assign(&mut [], &[], 0, &[], 0, 8, modulus);

    // Exhaust short rotations, then exercise longer intervals and component
    // boundaries. There is no size-dependent kernel requiring a PBS-sized N.
    for (n, components) in [(1, 1), (2, 3), (8, 1), (64, 3)] {
        let len = n * components;
        let values: Vec<T> = (0..3 * len)
            .map(|i| {
                T::as_from(match i % 5 {
                    0 => 0,
                    1 => (q - 1) as u64,
                    _ => ((i as u128 * 0x9e37_79b9_7f4a_7c15) % q) as u64,
                })
            })
            .collect();
        let first = Polynomial(&values[..len]);
        let second = Polynomial(&values[len..2 * len]);
        let exponents: Vec<_> = if n <= 8 {
            (0..2 * n).collect()
        } else {
            vec![0, 1, n / 2, n - 1, n, n + 1, n + n / 2, 2 * n - 1]
        };
        for &ra in &exponents {
            for &rb in &exponents {
                let mut output = values[2 * len..].to_vec();
                // Repeat on the initialized accumulator to exercise scratch reuse.
                for _ in 0..2 {
                    let mut expected = output.clone();
                    for (source, r) in [(first.as_ref(), ra), (second.as_ref(), rb)] {
                        for (i, &value) in source.iter().enumerate() {
                            let power = i % n + r;
                            let index = i / n * n + power % n;
                            let old = u128::from(expected[index].into());
                            let value = u128::from(value.into());
                            let result = if (power / n).is_multiple_of(2) {
                                (old + value) % q
                            } else {
                                (old + q - value) % q
                            };
                            expected[index] = T::as_from(result as u64);
                        }
                    }
                    if components == 1 {
                        Polynomial(output.as_mut_slice())
                            .add_mul_monomial_pair_assign(&first, ra, &second, rb, modulus);
                    } else {
                        primus_poly::add_mul_monomial_pair_assign(
                            &mut output,
                            first.as_ref(),
                            ra,
                            second.as_ref(),
                            rb,
                            n,
                            modulus,
                        );
                    }
                    assert_eq!(
                        output, expected,
                        "N={n}, components={components}, ra={ra}, rb={rb}"
                    );
                }
            }
        }
    }
}

#[test]
fn paired_monomials_match_independent_ring_arithmetic() {
    check::<u32, _>(NativeModulus::new(), 1u128 << 32);
    check::<u64, _>(NativeModulus::new(), 1u128 << 64);
    check::<u32, _>(BarrettModulus::new(132_120_577u32), 132_120_577);
    const Q64: u64 = 1_152_921_504_606_830_593;
    check::<u64, _>(BarrettModulus::new(Q64), Q64.into());
}
