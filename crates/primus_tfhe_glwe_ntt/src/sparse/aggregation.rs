//! Bounded unreduced bucket accumulation for the u64 NTT path.

use primus_integer::FheUint;
use primus_lattice::GadgetSize;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_poly::Polynomial;
use primus_reduce::Reduce;

/// Largest group satisfying (2m+1)q <= T::MAX. Other word widths retain their
/// existing kernels. The caller falls back to pair reduction when a complete
/// bucket does not fit, avoiding repeated full reductions for short groups.
#[inline]
pub(super) fn max_group_len<T: FheUint>(q: T) -> usize {
    if T::BITS != 64 {
        return 0;
    }
    let count: u128 = ((T::MAX / q - T::ONE) / T::TWO).as_into();
    count.min(usize::MAX as u128) as usize
}

/// Adds one complete bucket's rotated selectors into an initialized canonical
/// tile, then restores canonical residues. The key/workspace own control layout,
/// polynomial-aligned tile bounds and exponent validity; the caller establishes
/// indices.len() <= max_group_len(q). With m sources, an initial m*q bias keeps
/// every intermediate in [0,(2m+1)q), so even negative terms cannot wrap.
#[inline]
pub(super) fn add_rotated_group_assign<T: FheUint>(
    indices: &[usize],
    selections: &[T],
    exponents: &[usize],
    acc: &mut [T],
    tile_start: usize,
    size: GadgetSize,
    modulus: BarrettModulus<T>,
) {
    debug_assert!(indices.len() <= max_group_len(modulus.value()));
    let n = size.glwe_size().poly_length().get();
    let control_len = size.ggsw_len();
    let tile_end = tile_start + acc.len();
    let bias = T::as_from(indices.len()) * modulus.value();
    for value in acc.iter_mut() {
        *value += bias;
    }

    // Native kernels provide word addition/subtraction with no q correction.
    // The proven bound prevents actual wrapping; final reduction is modulo q.
    let (pairs, tail) = indices.as_chunks::<2>();
    let mut selection_pairs = selections.chunks_exact(2 * control_len);
    for (indices, pair) in pairs.iter().zip(selection_pairs.by_ref()) {
        let (a, b) = pair.split_at(control_len);
        primus_poly::add_mul_monomial_pair_assign(
            acc,
            &a[tile_start..tile_end],
            exponents[indices[0]],
            &b[tile_start..tile_end],
            exponents[indices[1]],
            n,
            NativeModulus::new(),
        );
    }
    if let Some(&index) = tail.first() {
        let source = &selection_pairs.remainder()[tile_start..tile_end];
        for (acc, source) in acc.chunks_exact_mut(n).zip(source.chunks_exact(n)) {
            Polynomial(acc).add_mul_monomial_assign(
                &Polynomial(source),
                exponents[index],
                NativeModulus::new(),
            );
        }
    }
    reduce_group_assign(acc, modulus);
}

/// Canonicalizes the bounded u64 group before the ordinary NTT entry. Keep the
/// scalar fallback on machines without the measured vector instruction set.
#[inline]
fn reduce_group_assign<T: FheUint>(values: &mut [T], modulus: BarrettModulus<T>) {
    #[cfg(target_arch = "x86_64")]
    if T::BITS == 64
        && std::is_x86_feature_detected!("avx512f")
        && std::is_x86_feature_detected!("avx512dq")
    {
        // SAFETY: the required CPU features were checked. The kernel uses safe
        // slice iteration; the caller established a 64-bit coefficient type.
        unsafe { reduce_group_u64_assign(values, modulus) };
        return;
    }
    for value in values {
        *value = modulus.reduce(*value);
    }
}

/// For B=2^64, ratio[1]=floor(B/q). Its high product estimates floor(x/q)
/// from below with error at most one. Omitting the low-low 32-bit product loses
/// at most one more, so x-estimate*q is in [0,3q). Two corrections suffice.
/// The partial-product sum fits u64, and Barrett's q<B/4 keeps 3q below B.
/// Expressing the three 32-bit products directly lets LLVM vectorize the loop.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512dq")]
unsafe fn reduce_group_u64_assign<T: FheUint>(values: &mut [T], modulus: BarrettModulus<T>) {
    debug_assert_eq!(T::BITS, 64);
    let q: u64 = modulus.value().as_into();
    let reciprocal: u64 = modulus.ratio()[1].as_into();
    for value in values {
        let x: u64 = (*value).as_into();
        let low_high = (x & 0xffff_ffff) * (reciprocal >> 32);
        let high_low = (x >> 32) * (reciprocal & 0xffff_ffff);
        let high_high = (x >> 32) * (reciprocal >> 32);
        let quotient = high_high + (low_high >> 32) + (((low_high & 0xffff_ffff) + high_low) >> 32);
        let remainder = x - quotient * q;
        let remainder = remainder.min(remainder.wrapping_sub(2 * q));
        *value = T::as_from(remainder.min(remainder.wrapping_sub(q)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use primus_lattice::ggsw::GgswIter;

    // Check reciprocal/correction boundaries independently of the rotation
    // oracle, including full-word inputs and the last incomplete vector.
    #[test]
    fn group_reduction_matches_full_word_remainders() {
        for q in [
            3,
            17,
            268_369_921,
            (1u64 << 50) - 1,
            (1u64 << 50) + 1,
            18_014_398_509_404_161,
            (1u64 << 62) - 1,
        ] {
            let mut values = vec![0, 1, q - 1, q, q + 1, 2 * q - 1, 2 * q, u64::MAX];
            values.extend((0..129u64).map(|i| i.wrapping_mul(0x9e37_79b9_7f4a_7c15)));
            let expected: Vec<_> = values.iter().map(|&x| x % q).collect();
            reduce_group_assign(&mut values, BarrettModulus::new(q));
            assert_eq!(values, expected, "q={q}");
        }
    }

    // Scatter coefficients directly in Z_q, independently of split intervals.
    // Moduli around the four/six-term bounds exercise the last safe group
    // length and odd tails without large CI fixtures.
    #[test]
    fn bounded_bucket_tiles_match_direct_ring_sum() {
        const N: usize = 32;
        const CONTROL_LEN: usize = 8 * N;
        let size = GadgetSize::new(
            primus_lattice::GlweSize::new(
                primus_lattice::GlweDimension::new(1),
                primus_poly::PolyLength::new(N),
            ),
            primus_decompose::DecompositionLevelCount::new(2),
        );
        assert_eq!(max_group_len(132_120_577u32), 0);
        for q in [
            3,
            1_125_899_906_826_241,
            u64::MAX / 9,
            u64::MAX / 9 + 1,
            u64::MAX / 13,
            (1u64 << 62) - 57,
        ] {
            let modulus = BarrettModulus::new(q);
            let capacity = max_group_len(q);
            assert!((2 * capacity as u128 + 1) * q as u128 <= u64::MAX as u128);
            if capacity < usize::MAX {
                assert!((2 * (capacity as u128 + 1) + 1) * q as u128 > u64::MAX as u128);
            }
            for count in [0, 1, 2, 3, 4, 5, 6, 7, 12, 13, 24, 25]
                .into_iter()
                .filter(|&count| count <= capacity)
            {
                let indices: Vec<_> = (0..count).map(|i| 2 * i + 1).collect();
                let data: Vec<u64> = (0..(count + 1) * CONTROL_LEN)
                    .map(|i| {
                        if i % 5 == 0 {
                            0
                        } else {
                            q - 1 - (i as u64 % 13).min(q - 1)
                        }
                    })
                    .collect();
                let (selections, dummy) = data.split_at(count * CONTROL_LEN);
                for first in [0, N - 1, N, N + 1, 2 * N - 1] {
                    for second in [0, N - 1, N, N + 1, 2 * N - 1] {
                        let exponents: Vec<_> = (0..2 * count + 1)
                            .map(|i| if i % 4 < 2 { first } else { second })
                            .collect();
                        let mut expected: Vec<u128> = dummy.iter().map(|&v| v as u128).collect();
                        for (control, &index) in
                            GgswIter::new(selections, size.ggsw_len()).zip(&indices)
                        {
                            for (i, &value) in control.as_ref().iter().enumerate() {
                                let power = i % N + exponents[index];
                                let target = i / N * N + power % N;
                                let signed = if (power / N).is_multiple_of(2) {
                                    value as u128
                                } else {
                                    (q as u128 - value as u128) % q as u128
                                };
                                expected[target] = (expected[target] + signed) % q as u128;
                            }
                        }
                        let mut actual = vec![u64::MAX; CONTROL_LEN];
                        for tile_len in [N, 3 * N, CONTROL_LEN] {
                            actual.copy_from_slice(dummy);
                            for (tile, acc) in actual.chunks_mut(tile_len).enumerate() {
                                let start = tile * tile_len;
                                add_rotated_group_assign(
                                    &indices, selections, &exponents, acc, start, size, modulus,
                                );
                            }
                            assert!(
                                actual.iter().zip(&expected).all(|(&a, &b)| a as u128 == b),
                                "q={q}, capacity={capacity}, count={count}, first={first}, second={second}, tile={tile_len}"
                            );
                        }
                    }
                }
            }
        }
    }
}
