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

use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_lattice::{
    RnsGadgetSize,
    glev::{DcrtGlevIter, DcrtGlevIterMut},
};
use primus_modulus::PowOf2Modulus;
use primus_ntt::{DcrtTable, ReverseLsbs};
use primus_poly::DcrtPolynomial;
use primus_reduce::{FieldContext, ReduceMul};

use crate::{
    DcrtGadgetDomain, DcrtGlweCiphertext, DcrtGlweSecretKey, glwe::crt::CrtGlweAutoContext,
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
enum NttAutoOperation {
    /// Permutation table: `out[i] = in[perm[i]]` in bit-reversed storage.
    Permutation(Vec<u32>),
    /// Identity mapping (degree = 1).
    Identity,
}

#[derive(Clone)]
struct NttAutoHelper {
    poly_length: usize,
    operation: NttAutoOperation,
}

impl NttAutoHelper {
    fn new(degree: usize, poly_length: usize) -> Self {
        let operation = if degree == 1 {
            NttAutoOperation::Identity
        } else {
            NttAutoOperation::Permutation(generate_ntt_permutation(degree, poly_length))
        };

        Self {
            poly_length,
            operation,
        }
    }

    #[inline]
    fn poly_length(&self) -> usize {
        self.poly_length
    }
}

// ---------------------------------------------------------------------------
// Permutation application
// ---------------------------------------------------------------------------

/// Apply NTT-domain automorphism permutation to a single polynomial.
#[inline]
fn ntt_poly_auto_inplace<T: FheUint>(poly: &[T], result: &mut [T], operation: &NttAutoOperation) {
    match operation {
        NttAutoOperation::Permutation(perm) => {
            for (dst, &src) in result.iter_mut().zip(perm.iter()) {
                // SAFETY: for a validated odd degree modulo `2N`, the generated
                // target lies in `0..N`; reversing its `log2(N)` low bits keeps
                // it in that range. The DCRT wrapper passes exact-length chunks.
                *dst = unsafe { *poly.get_unchecked(src as usize) };
            }
        }
        NttAutoOperation::Identity => {
            result.copy_from_slice(poly);
        }
    }
}

/// Apply NTT-domain automorphism to a DCRT polynomial (all RNS moduli).
///
/// The same permutation is applied independently to each modulus component.
#[inline]
fn dcrt_poly_ntt_auto_to<T: FheUint>(
    dcrt_poly: &[T],
    result: &mut [T],
    auto_helper: &NttAutoHelper,
) {
    let poly_length = auto_helper.poly_length();

    dcrt_poly
        .chunks_exact(poly_length)
        .zip(result.chunks_exact_mut(poly_length))
        .for_each(|(poly, auto_poly)| {
            ntt_poly_auto_inplace(poly, auto_poly, &auto_helper.operation);
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
    domain: &DcrtGadgetDomain<'_, T, M, Table>,
    ntt_auto_helper: &NttAutoHelper,
    dcrt_sk: &DcrtGlweSecretKey<T>,
    rng: &mut R,
) -> Vec<T>
where
    T: FheUint,
    Table: DcrtTable<ValueT = T>,
    R: rand::Rng + rand::CryptoRng,
    M: FieldContext<T>,
{
    let params = domain.parameters();
    let rns_poly_len = params.rns_poly_len();
    let dcrt_glev_len = params.rns_glev_len();

    let mut key = vec![T::ZERO; params.dimension() * dcrt_glev_len];
    let mut auto_si: DcrtPolynomial<Vec<T>> = DcrtPolynomial::zero(rns_poly_len);

    let key_iter = DcrtGlevIterMut::new(key.as_mut_slice(), dcrt_glev_len);

    dcrt_sk
        .iter_dcrt_poly()
        .zip(key_iter)
        .for_each(|(si, mut dcrt_glev)| {
            dcrt_poly_ntt_auto_to(si.0, auto_si.as_mut(), ntt_auto_helper);

            dcrt_sk.encrypt_dcrt_msg_to_dcrt_glev_inplace(&auto_si, &mut dcrt_glev, domain, rng);
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
pub struct DcrtGlweAutoKey<T: FheUint> {
    key: Vec<T>,
    auto_helper: NttAutoHelper,
    size: RnsGadgetSize,
}

impl<T: FheUint> DcrtGlweAutoKey<T> {
    /// Create a new NTT-domain automorphism key for the mapping x → x^degree.
    ///
    /// Key generation applies the NTT-domain permutation to each secret key
    /// polynomial and encrypts the result under a GLEV ciphertext. Only the
    /// NTT-domain secret key is needed.
    ///
    /// # Panics
    ///
    /// Panics if `degree` is not odd and less than twice the polynomial length.
    pub fn new<M, Table, R>(
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        degree: usize,
        dcrt_sk: &DcrtGlweSecretKey<T>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
    {
        let params = domain.parameters();
        assert_eq!(dcrt_sk.rns_glwe_size(), params.size().rns_glwe_size());

        let poly_length = params.poly_length();
        assert!(
            degree < poly_length * 2 && degree % 2 == 1,
            "automorphism degree must be odd and less than twice the polynomial length"
        );

        let auto_helper = NttAutoHelper::new(degree, poly_length);

        let key = generate_ntt_auto_key_data(domain, &auto_helper, dcrt_sk, rng);

        Self {
            key,
            auto_helper,
            size: domain.size(),
        }
    }

    pub(crate) fn iter_dcrt_glev(&self) -> DcrtGlevIter<'_, T> {
        DcrtGlevIter::new(self.key.as_slice(), self.size.rns_glev_len())
    }

    /// Perform NTT-domain automorphism on a DCRT GLWE ciphertext.
    ///
    /// Both input `ciphertext` and output `result` are in NTT (evaluation) domain.
    pub fn automorphism_to<M, Table, A, B>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        result: &mut DcrtGlweCiphertext<B>,
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        context: &mut CrtGlweAutoContext<T>,
    ) where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        self.automorphism_kernel(ciphertext, result, domain, context);
    }

    /// Internal kernel used by composed operations.
    pub(crate) fn automorphism_kernel<M, Table, A, B>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        result: &mut DcrtGlweCiphertext<B>,
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        context: &mut CrtGlweAutoContext<T>,
    ) where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let params = domain.parameters();
        let table = domain.table();
        let rns_base = domain.rns_base();
        let poly_length = params.poly_length();
        let rns_poly_len = params.rns_poly_len();
        let moduli = params.cipher_moduli();

        let (auto_dcrt_poly, glev_context) = context.as_mut();

        result.set_zero();

        let (a_in, b_in) = ciphertext.a_b(rns_poly_len);

        // ----- Process a polynomials: NTT permutation → INTT → key switch -----
        self.iter_dcrt_glev()
            .zip(a_in)
            .for_each(|(auto_key_i, in_dcrt_poly)| {
                // 1. NTT-domain permutation (evaluation-point reordering)
                dcrt_poly_ntt_auto_to(in_dcrt_poly.0, auto_dcrt_poly.as_mut(), &self.auto_helper);

                // 2. INTT → coefficient domain (required for key-switch decomposition)
                table.inverse_transform_slice(auto_dcrt_poly.as_mut());

                // 3. Key switch via external product
                result.add_dcrt_glev_mul_crt_poly_assign(
                    &auto_key_i,
                    auto_dcrt_poly,
                    params.basis(),
                    table,
                    rns_base,
                    glev_context,
                );
            });

        // ----- Process b polynomial: NTT permutation only (no transform needed) -----
        dcrt_poly_ntt_auto_to(b_in.0, auto_dcrt_poly.as_mut(), &self.auto_helper);

        // ----- Combine: result = (−a', σ(b) − b') -----
        let (a_out, mut b_out) = result.a_b_mut(rns_poly_len);

        a_out.for_each(|mut ai| ai.neg_assign(poly_length, moduli));

        DcrtPolynomial(auto_dcrt_poly.as_ref()).sub_rev_assign(&mut b_out, poly_length, moduli);
    }
}
