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

/// For `B=2^64`, `ratio[1]=floor(B/q)`. Its high product estimates `floor(x/q)`
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
