//! NTT-domain automorphism implementation (SEAL / CKKS / BGV style).
//!
//! Automorphism σ_k: x → x^k in the NTT (evaluation) domain corresponds to
//! a permutation of evaluation points rather than coefficient manipulation.
//!
//! Compared to the coefficient-domain approach in the parent module, this saves
//! two NTT transforms for the `b` polynomial:
//! - Coefficient path for b: INTT → coeff permutation → NTT  (2 transforms + O(N))
//! - NTT path for b:         NTT permutation                 (O(N) only)
//!
//! For the `a` polynomials, the cost is equivalent either way because key-switch
//! decomposition requires coefficient-domain data.
//!
//! # NTT storage order
//!
//! This codebase uses **bit-reversed** NTT output. In natural order, index `i`
//! corresponds to evaluation point ω^(2i+1). In bit-reversed storage, index
//! `br(i)` stores the evaluation at ω^(2i+1). The permutation table accounts
//! for this: `out[br(i)] = in[br(i')]` where `i' = ((k·(2i+1)) mod 2N − 1) / 2`.

use std::sync::Arc;

use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_lattice::glev::{DcrtGlevIter, DcrtGlevIterMut};
use primus_modulus::PowOf2Modulus;
use primus_ntt::{DcrtTable, ReverseLsbs};
use primus_poly::DcrtPolynomial;
use primus_reduce::{FieldContext, ReduceMul};
use primus_rns::RNSBase;

use crate::{
    CrtGlevParameters, DcrtGlweCiphertext, DcrtGlweSecretKey, glwe::crt::CrtGlweAutoContext,
};

// ---------------------------------------------------------------------------
// NTT-domain permutation generation
// ---------------------------------------------------------------------------

/// Generate the NTT-domain permutation table for automorphism x → x^degree
/// in **bit-reversed** storage order.
///
/// Returns `perm` where `perm[dst] = src`, meaning `out[dst] = in[perm[dst]]`.
fn generate_ntt_permutation(degree: usize, poly_length: usize) -> Vec<u32> {
    let twice_n = poly_length << 1;
    let log_n = poly_length.trailing_zeros();
    let modulus = <PowOf2Modulus<usize>>::new(twice_n);
    let mut perm = vec![0u32; poly_length];

    for i in 0..poly_length {
        // Natural NTT index i → evaluation point ω^(2i+1).
        // NTT(σ_k(f))[i] = f(ω^(k·(2i+1) mod 2N)) = NTT(f)[target].
        let j = modulus.reduce_mul(degree, 2 * i + 1);
        let target = (j - 1) / 2;

        // In bit-reversed storage: out[br(i)] = in[br(target)].
        let out_br = i.reverse_lsbs(log_n);
        let in_br = target.reverse_lsbs(log_n);

        perm[out_br] = in_br as u32;
    }

    perm
}

// ---------------------------------------------------------------------------
// NTT-domain AutoHelper
// ---------------------------------------------------------------------------

/// NTT-domain automorphism helper.
///
/// Stores a precomputed permutation table that maps evaluation-point indices
/// in bit-reversed NTT storage order.
#[derive(Clone)]
pub enum NttAutoHelper {
    /// Permutation table: `out[i] = in[perm[i]]` in bit-reversed storage.
    Permutation(Vec<u32>),
    /// Identity mapping (degree = 1).
    Identity,
}

impl NttAutoHelper {
    pub fn new(degree: usize, poly_length: usize) -> Self {
        if degree == 1 {
            NttAutoHelper::Identity
        } else {
            NttAutoHelper::Permutation(generate_ntt_permutation(degree, poly_length))
        }
    }
}

// ---------------------------------------------------------------------------
// Permutation application
// ---------------------------------------------------------------------------

/// Apply NTT-domain automorphism permutation to a single polynomial.
#[inline]
fn ntt_poly_auto_inplace<T: FheUint>(poly: &[T], result: &mut [T], auto_helper: &NttAutoHelper) {
    match auto_helper {
        NttAutoHelper::Permutation(perm) => {
            debug_assert_eq!(poly.len(), perm.len());
            debug_assert_eq!(result.len(), perm.len());
            for (dst, &src) in result.iter_mut().zip(perm.iter()) {
                *dst = unsafe { *poly.get_unchecked(src as usize) };
            }
        }
        NttAutoHelper::Identity => {
            result.copy_from_slice(poly);
        }
    }
}

/// Apply NTT-domain automorphism to a DCRT polynomial (all RNS moduli).
///
/// The same permutation is applied independently to each modulus component.
#[inline]
pub fn dcrt_poly_ntt_auto_inplace<T: FheUint>(
    dcrt_poly: &[T],
    result: &mut [T],
    auto_helper: &NttAutoHelper,
    poly_length: usize,
) {
    dcrt_poly
        .chunks_exact(poly_length)
        .zip(result.chunks_exact_mut(poly_length))
        .for_each(|(poly, auto_poly)| {
            ntt_poly_auto_inplace(poly, auto_poly, auto_helper);
        });
}

// ---------------------------------------------------------------------------
// NTT-domain auto key generation
// ---------------------------------------------------------------------------

/// Generate automorphism key data entirely in the NTT domain.
///
/// For each secret-key polynomial s_i (in NTT domain), apply NTT-domain
/// permutation σ_k(s_i) and encrypt under a GLEV ciphertext.
///
/// Unlike `super::crt::generate_auto_key_data` which requires a coefficient-domain
/// secret key, this only needs the NTT-domain secret key.
fn generate_ntt_auto_key_data<T, M, Table, R>(
    params: &CrtGlevParameters<T, M>,
    ntt_auto_helper: &NttAutoHelper,
    dcrt_sk: &DcrtGlweSecretKey<T>,
    table: &Table,
    rng: &mut R,
) -> Vec<T>
where
    T: FheUint,
    Table: DcrtTable<ValueT = T>,
    R: rand::Rng + rand::CryptoRng,
    M: FieldContext<T>,
{
    let poly_length = params.poly_length();
    let rns_poly_len = params.rns_poly_len();
    let dcrt_glev_len = params.rns_glev_len();

    let mut key = vec![T::ZERO; params.dimension() * dcrt_glev_len];
    let mut auto_si: DcrtPolynomial<Vec<T>> = DcrtPolynomial::zero(rns_poly_len);

    let key_iter = DcrtGlevIterMut::new(key.as_mut_slice(), dcrt_glev_len);

    dcrt_sk
        .iter_dcrt_poly()
        .zip(key_iter)
        .for_each(|(si, mut dcrt_glev)| {
            dcrt_poly_ntt_auto_inplace(si.0, auto_si.as_mut(), ntt_auto_helper, poly_length);

            dcrt_sk.encrypt_dcrt_msg_to_dcrt_glev_inplace(
                &auto_si,
                &mut dcrt_glev,
                params,
                table,
                rng,
            );
        });

    key
}

// ---------------------------------------------------------------------------
// DcrtGlweAutoKey (NTT-domain)
// ---------------------------------------------------------------------------

/// Automorphism key for NTT-domain automorphism.
///
/// # Data flow (per automorphism evaluation)
///
/// For each `a_i` polynomial:
/// 1. NTT-domain permutation — O(N)
/// 2. INTT to coefficient domain — O(N log N), required for key-switch decomposition
/// 3. Key switch via external product
///
/// For the `b` polynomial:
/// 1. NTT-domain permutation — O(N), stays in NTT domain
#[derive(Clone)]
pub struct DcrtGlweAutoKey<T, Table>
where
    T: FheUint,
    Table: DcrtTable<ValueT = T>,
{
    key: Vec<T>,
    degree: usize,
    rns_glev_len: usize,
    auto_helper: NttAutoHelper,
    table: Arc<Table>,
}

impl<T, Table> DcrtGlweAutoKey<T, Table>
where
    T: FheUint,
    Table: DcrtTable<ValueT = T>,
{
    /// Create a new NTT-domain automorphism key for the mapping x → x^degree.
    ///
    /// Key generation applies the NTT-domain permutation to each secret key
    /// polynomial and encrypts the result under a GLEV ciphertext. Only the
    /// NTT-domain secret key is needed.
    pub fn new<M, R>(
        params: &CrtGlevParameters<T, M>,
        degree: usize,
        dcrt_sk: &DcrtGlweSecretKey<T>,
        table: Arc<Table>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
    {
        let poly_length = params.poly_length();
        let dcrt_glev_len = params.rns_glev_len();

        let auto_helper = NttAutoHelper::new(degree, poly_length);

        let key = generate_ntt_auto_key_data(params, &auto_helper, dcrt_sk, table.as_ref(), rng);

        Self {
            key,
            degree,
            rns_glev_len: dcrt_glev_len,
            auto_helper,
            table: Arc::clone(&table),
        }
    }

    pub fn degree(&self) -> usize {
        self.degree
    }

    pub fn auto_helper(&self) -> &NttAutoHelper {
        &self.auto_helper
    }

    pub fn table(&self) -> &Table {
        &self.table
    }

    pub fn iter_dcrt_glev(&self) -> DcrtGlevIter<'_, T> {
        DcrtGlevIter::new(self.key.as_slice(), self.rns_glev_len)
    }

    /// Perform NTT-domain automorphism on a DCRT GLWE ciphertext.
    ///
    /// Both input `ciphertext` and output `result` are in NTT (evaluation) domain.
    pub fn automorphism_inplace<M, A, B>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        result: &mut DcrtGlweCiphertext<B>,
        params: &CrtGlevParameters<T, M>,
        rns_base: &RNSBase<T, M>,
        context: &mut CrtGlweAutoContext<T>,
    ) where
        M: FieldContext<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = params.poly_length();
        let rns_glwe_mid = params.rns_glwe_mid();
        let moduli = params.cipher_moduli();

        debug_assert_eq!(ciphertext.as_ref().len(), params.rns_glwe_len());

        let (auto_dcrt_poly, glev_context) = context.as_mut();

        result.set_zero();

        let (a_in, b_in) = ciphertext.a_b(rns_glwe_mid);

        // ----- Process a polynomials: NTT permutation → INTT → key switch -----
        self.iter_dcrt_glev()
            .zip(a_in)
            .for_each(|(auto_key_i, in_dcrt_poly)| {
                // 1. NTT-domain permutation (evaluation-point reordering)
                dcrt_poly_ntt_auto_inplace(
                    in_dcrt_poly.0,
                    auto_dcrt_poly.as_mut(),
                    &self.auto_helper,
                    poly_length,
                );

                // 2. INTT → coefficient domain (required for key-switch decomposition)
                self.table.inverse_transform_slice(auto_dcrt_poly.as_mut());

                // 3. Key switch via external product
                result.add_dcrt_glev_mul_crt_poly_assign(
                    &auto_key_i,
                    auto_dcrt_poly,
                    params.basis(),
                    self.table(),
                    rns_base,
                    glev_context,
                );
            });

        // ----- Process b polynomial: NTT permutation only (no transform needed) -----
        dcrt_poly_ntt_auto_inplace(
            b_in.0,
            auto_dcrt_poly.as_mut(),
            &self.auto_helper,
            poly_length,
        );

        // ----- Combine: result = (−a', σ(b) − b') -----
        let (a_out, mut b_out) = result.a_b_mut(rns_glwe_mid);

        a_out.for_each(|mut ai| ai.neg_assign(poly_length, moduli));

        DcrtPolynomial(auto_dcrt_poly.as_ref()).sub_rev_assign(&mut b_out, poly_length, moduli);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CoeffAutoHelper;

    #[test]
    fn test_ntt_permutation_identity() {
        for log_n in 2..12 {
            let n = 1 << log_n;
            let perm = generate_ntt_permutation(1, n);

            for (i, &item) in perm.iter().enumerate() {
                assert_eq!(item, i as u32, "identity failed at index {i} for N={n}");
            }
        }
    }

    #[test]
    fn test_ntt_permutation_is_valid() {
        let test_cases: &[(usize, usize)] = &[
            (3, 8),
            (5, 8),
            (7, 8),
            (3, 16),
            (5, 16),
            (3, 1024),
            (5, 4096),
        ];

        for &(degree, n) in test_cases {
            let perm = generate_ntt_permutation(degree, n);
            assert_eq!(perm.len(), n);

            // Every source index must appear exactly once (valid permutation).
            let mut seen = vec![false; n];
            for &src in &perm {
                let src = src as usize;
                assert!(
                    src < n,
                    "out-of-range index {src} for degree={degree}, N={n}"
                );
                assert!(
                    !seen[src],
                    "duplicate source index {src} for degree={degree}, N={n}"
                );
                seen[src] = true;
            }
            assert!(seen.iter().all(|&s| s));
        }
    }

    /// Verify NTT-domain automorphism against coefficient-domain automorphism
    /// using a real NTT round-trip.
    ///
    /// For a random CRT polynomial f the two paths must produce identical results:
    ///   Path A: coeff_auto(f) → NTT
    ///   Path B: NTT(f)        → ntt_auto
    #[test]
    fn test_ntt_auto_equivalence_with_coefficient_auto() {
        use primus_modulus::BarrettModulus;
        use primus_ntt::{DcrtTable, UintDcrtTable};
        use rand::RngExt;

        type V = u64;

        let poly_length: usize = 512;
        let log_n = poly_length.trailing_zeros();

        let moduli_values: [V; 2] = [1125899906826241, 1125899906629633];
        let moduli = moduli_values.map(BarrettModulus::new);
        let table = UintDcrtTable::new(log_n, &moduli).unwrap();

        let crt_poly_len = moduli.len() * poly_length;

        let mut rng = rand::rng();

        // Random CRT polynomial with coefficients well below every modulus.
        let input: Vec<V> = (0..crt_poly_len)
            .map(|_| rng.random::<u32>() as V)
            .collect();

        for degree in [3, 5, 7, poly_length + 1, 2 * poly_length - 1] {
            // Coefficient-domain helper
            let coeff_helper = CoeffAutoHelper::new(degree, poly_length);

            // NTT-domain helper
            let ntt_helper = if degree == 1 {
                NttAutoHelper::Identity
            } else {
                NttAutoHelper::Permutation(generate_ntt_permutation(degree, poly_length))
            };

            // Path A: coeff_auto → NTT
            let mut path_a = vec![V::default(); crt_poly_len];
            crate::crt_poly_auto_inplace(&input, &mut path_a, &coeff_helper, poly_length, &moduli);
            table.transform_slice(&mut path_a);

            // Path B: NTT → ntt_auto
            let mut ntt_input = input.clone();
            table.transform_slice(&mut ntt_input);
            let mut path_b = vec![V::default(); crt_poly_len];
            dcrt_poly_ntt_auto_inplace(&ntt_input, &mut path_b, &ntt_helper, poly_length);

            assert_eq!(path_a, path_b, "paths diverge for degree={degree}");
        }
    }
}
