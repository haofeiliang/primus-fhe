use std::sync::Mutex;

use primus_data::{Data, DataMut, RawData};
use primus_factor::ShoupFactor;
use primus_integer::{AsInto, BigUint, FheUint};
use primus_ntt::DcrtTable;
use primus_reduce::FieldContext;
use primus_rns::RNSBase;
use rayon::prelude::*;

use crate::{
    CrtGlevParameters, CrtGlweAutoContext, CrtGlweAutoKey, CrtGlweCiphertext, CrtGlweTraceContext,
    DcrtGadgetDomain, DcrtGlweSecretKey, GlweKeySwitchingError, GlweSecretKey,
};

pub type CrtGlweExpandCoeffContext<T> = CrtGlweTraceContext<T>;

/// Thread-safe context pool for parallel coefficient expansion.
///
/// Contexts are lazily allocated and returned internally after each worker
/// finishes. The pool grows up to the number of concurrent worker threads.
pub struct CrtGlweExpandCoeffSyncPool<T: FheUint, M: FieldContext<T>> {
    contexts: Mutex<Vec<CrtGlweExpandCoeffContext<T>>>,
    parameters: CrtGlevParameters<T, M>,
}

impl<T: FheUint, M: FieldContext<T>> CrtGlweExpandCoeffSyncPool<T, M> {
    /// Creates an empty pool. Contexts are allocated lazily on first [`Self::acquire`].
    pub fn new<Table>(domain: &DcrtGadgetDomain<'_, T, M, Table>) -> Self
    where
        Table: DcrtTable<ValueT = T>,
    {
        let parameters = domain.parameters();
        Self {
            contexts: Mutex::new(Vec::new()),
            parameters: parameters.clone(),
        }
    }

    /// Creates a pre-warmed pool with `capacity` contexts already allocated.
    ///
    /// Use `rayon::current_num_threads()` as `capacity` to avoid any allocation
    /// during parallel computation.
    pub fn with_capacity<Table>(capacity: usize, domain: &DcrtGadgetDomain<'_, T, M, Table>) -> Self
    where
        Table: DcrtTable<ValueT = T>,
    {
        let parameters = domain.parameters();
        let contexts = (0..capacity)
            .map(|_| CrtGlweExpandCoeffContext::from_parameters(parameters))
            .collect();
        Self {
            contexts: Mutex::new(contexts),
            parameters: parameters.clone(),
        }
    }

    fn acquire(&self) -> CrtGlweExpandCoeffContext<T> {
        self.contexts
            .lock()
            .unwrap()
            .pop()
            .unwrap_or_else(|| CrtGlweExpandCoeffContext::from_parameters(&self.parameters))
    }

    fn release(&self, ctx: CrtGlweExpandCoeffContext<T>) {
        self.contexts.lock().unwrap().push(ctx);
    }

    fn is_compatible<Table>(&self, domain: &DcrtGadgetDomain<'_, T, M, Table>) -> bool
    where
        Table: DcrtTable<ValueT = T>,
    {
        self.parameters.size().rns_glwe_size() == domain.size().rns_glwe_size()
            && self.parameters.big_uint_value_len() == domain.parameters().big_uint_value_len()
    }

    /// Acquire a context wrapped in a guard that auto-releases on drop.
    fn acquire_guard(&self) -> PoolGuard<'_, T, M> {
        PoolGuard {
            ctx: Some(self.acquire()),
            pool: self,
        }
    }
}

/// RAII guard that automatically releases a context back to the pool on drop.
///
/// Each rayon worker thread holds one guard (via `for_each_init`), so the total
/// number of mutex lock operations per level is O(threads) instead of O(pairs).
struct PoolGuard<'a, T: FheUint, M: FieldContext<T>> {
    ctx: Option<CrtGlweExpandCoeffContext<T>>,
    pool: &'a CrtGlweExpandCoeffSyncPool<T, M>,
}

impl<T: FheUint, M: FieldContext<T>> PoolGuard<'_, T, M> {
    fn as_mut(
        &mut self,
    ) -> (
        &mut primus_lattice::glwe::CrtGlwe<Vec<T>>,
        &mut CrtGlweAutoContext<T>,
    ) {
        self.ctx.as_mut().unwrap().as_mut()
    }
}

impl<T: FheUint, M: FieldContext<T>> Drop for PoolGuard<'_, T, M> {
    fn drop(&mut self) {
        if let Some(ctx) = self.ctx.take() {
            self.pool.release(ctx);
        }
    }
}

#[derive(Clone)]
pub struct CrtGlweExpandCoeffKey<T: FheUint> {
    auto_keys: Vec<CrtGlweAutoKey<T>>,
    inv_count_residues_by_level: Vec<Vec<ShoupFactor<T>>>,
}

impl<T: FheUint> CrtGlweExpandCoeffKey<T> {
    pub fn new<M, Table, R>(
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        sk: &GlweSecretKey<T>,
        dcrt_sk: &DcrtGlweSecretKey<T>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
    {
        let params = domain.parameters();
        let log_n = params.poly_length().trailing_zeros();
        let auto_keys: Vec<CrtGlweAutoKey<T>> = (1..=log_n)
            .rev()
            .map(|x| (1usize << x) + 1)
            .map(|degree| CrtGlweAutoKey::new(domain, degree, sk, dcrt_sk, rng))
            .collect();

        let inv_count_residues_by_level =
            Self::precompute_inv_count_residues(params, domain.rns_base());

        Self {
            auto_keys,
            inv_count_residues_by_level,
        }
    }

    fn precompute_inv_count_residues<M>(
        params: &CrtGlevParameters<T, M>,
        rns_base: &RNSBase<T, M>,
    ) -> Vec<Vec<ShoupFactor<T>>>
    where
        M: FieldContext<T>,
    {
        let log_n = params.poly_length().trailing_zeros() as usize;

        (0..=log_n)
            .map(|log_count| {
                let count = 1usize << log_count;
                let n = count.as_into();
                let n_residue = rns_base.decompose(BigUint(&[n]));

                n_residue
                    .iter()
                    .zip(rns_base.moduli())
                    .map(|(&n, m)| ShoupFactor::new(m.reduce_inv(n), m.value()))
                    .collect()
            })
            .collect()
    }

    /// Coefficient Expansion Algorithm.
    ///
    /// Expands all `poly_length` coefficients.
    /// (Alg. 1)<https://eprint.iacr.org/2024/266.pdf>
    pub fn expand_coefficients_inplace<M, Table, A, B>(
        &self,
        ciphertext: &CrtGlweCiphertext<A>,
        result: &mut [CrtGlweCiphertext<B>],
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        context: &mut CrtGlweExpandCoeffContext<T>,
    ) -> Result<(), GlweKeySwitchingError>
    where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let expected = domain.parameters().poly_length();
        if result.len() != expected {
            return Err(GlweKeySwitchingError::OutputCountMismatch {
                expected,
                actual: result.len(),
            });
        }
        self.expand_partial_coefficients_inplace(ciphertext, result, domain, context)
    }

    /// Coefficient Expansion Algorithm.
    ///
    /// (Alg. 1)<https://eprint.iacr.org/2024/266.pdf>
    pub fn expand_partial_coefficients_inplace<M, Table, A, B>(
        &self,
        ciphertext: &CrtGlweCiphertext<A>,
        result: &mut [CrtGlweCiphertext<B>],
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        context: &mut CrtGlweExpandCoeffContext<T>,
    ) -> Result<(), GlweKeySwitchingError>
    where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let params = domain.parameters();
        let poly_length = params.poly_length();
        let count = result.len();
        if !count.is_power_of_two() || count > poly_length {
            return Err(GlweKeySwitchingError::InvalidExpansionCount {
                maximum: poly_length,
                actual: count,
            });
        }

        let (crt_glwe, auto_context) = context.as_mut();

        let rns_poly_len = params.rns_poly_len();
        let moduli = params.cipher_moduli();
        let moduli_value = params.cipher_moduli_value();
        let twice_poly_length = poly_length * 2;

        let log_d = count.trailing_zeros() as usize;
        debug_assert!(log_d < self.inv_count_residues_by_level.len());

        ciphertext.mul_factor_to(
            &self.inv_count_residues_by_level[log_d],
            &mut result[0],
            poly_length,
            rns_poly_len,
            moduli_value,
        );

        for (i, auto_key) in self.auto_keys.iter().enumerate().take(log_d) {
            let two_pow_i = 1 << i;

            // SAFETY: `i < log_d` guarantees `two_pow_i * 2 <= count == result.len()`,
            // and `two_pow_i <= two_pow_i * 2`, so the split point is within bounds.
            let (x, y) = unsafe { result[..two_pow_i * 2].split_at_mut_unchecked(two_pow_i) };

            x.iter_mut().zip(y.iter_mut()).for_each(|(a_0, b_0)| {
                auto_key.automorphism_kernel(a_0, crt_glwe, domain, auto_context);

                a_0.sub_element_wise_to(crt_glwe, b_0, poly_length, rns_poly_len, moduli);
                b_0.mul_monic_monomial_assign(
                    twice_poly_length - two_pow_i,
                    poly_length,
                    rns_poly_len,
                    moduli,
                );
                a_0.add_element_wise_assign(crt_glwe, poly_length, rns_poly_len, moduli);
            });
        }
        Ok(())
    }

    /// Parallel Coefficient Expansion Algorithm.
    ///
    /// Expands all `poly_length` coefficients using rayon parallelism.
    /// (Alg. 1)<https://eprint.iacr.org/2024/266.pdf>
    pub fn expand_coefficients_inplace_parallel<M, Table, A, B>(
        &self,
        ciphertext: &CrtGlweCiphertext<A>,
        result: &mut [CrtGlweCiphertext<B>],
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        context_pool: &CrtGlweExpandCoeffSyncPool<T, M>,
    ) -> Result<(), GlweKeySwitchingError>
    where
        M: FieldContext<T> + Sync,
        A: RawData<Elem = T> + Data + Sync,
        B: RawData<Elem = T> + DataMut + Send,
        Table: DcrtTable<ValueT = T> + Send + Sync,
    {
        let expected = domain.parameters().poly_length();
        if result.len() != expected {
            return Err(GlweKeySwitchingError::OutputCountMismatch {
                expected,
                actual: result.len(),
            });
        }
        self.expand_partial_coefficients_inplace_parallel(ciphertext, result, domain, context_pool)
    }

    /// Parallel Coefficient Expansion Algorithm.
    ///
    /// (Alg. 1)<https://eprint.iacr.org/2024/266.pdf>
    pub fn expand_partial_coefficients_inplace_parallel<M, Table, A, B>(
        &self,
        ciphertext: &CrtGlweCiphertext<A>,
        result: &mut [CrtGlweCiphertext<B>],
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        context_pool: &CrtGlweExpandCoeffSyncPool<T, M>,
    ) -> Result<(), GlweKeySwitchingError>
    where
        M: FieldContext<T> + Sync,
        A: RawData<Elem = T> + Data + Sync,
        B: RawData<Elem = T> + DataMut + Send,
        Table: DcrtTable<ValueT = T> + Send + Sync,
    {
        let params = domain.parameters();
        let poly_length = params.poly_length();
        let count = result.len();
        if !count.is_power_of_two() || count > poly_length {
            return Err(GlweKeySwitchingError::InvalidExpansionCount {
                maximum: poly_length,
                actual: count,
            });
        }
        if !context_pool.is_compatible(domain) {
            return Err(GlweKeySwitchingError::ContextMismatch);
        }

        let rns_poly_len = params.rns_poly_len();
        let moduli = params.cipher_moduli();
        let moduli_value = params.cipher_moduli_value();
        let twice_poly_length = poly_length * 2;

        let log_d = count.trailing_zeros() as usize;
        debug_assert!(log_d < self.inv_count_residues_by_level.len());

        ciphertext.mul_factor_to(
            &self.inv_count_residues_by_level[log_d],
            &mut result[0],
            poly_length,
            rns_poly_len,
            moduli_value,
        );

        for (i, auto_key) in self.auto_keys.iter().enumerate().take(log_d) {
            let two_pow_i = 1 << i;

            // SAFETY: `i < log_d` guarantees `two_pow_i * 2 <= count == result.len()`,
            // and `two_pow_i <= two_pow_i * 2`, so the split point is within bounds.
            let (x, y) = unsafe { result[..two_pow_i * 2].split_at_mut_unchecked(two_pow_i) };

            x.par_iter_mut().zip(y.par_iter_mut()).for_each_init(
                || context_pool.acquire_guard(),
                |guard, (a_0, b_0)| {
                    let (crt_glwe, auto_context) = guard.as_mut();

                    auto_key.automorphism_kernel(a_0, crt_glwe, domain, auto_context);

                    a_0.sub_element_wise_to(crt_glwe, b_0, poly_length, rns_poly_len, moduli);
                    b_0.mul_monic_monomial_assign(
                        twice_poly_length - two_pow_i,
                        poly_length,
                        rns_poly_len,
                        moduli,
                    );
                    a_0.add_element_wise_assign(crt_glwe, poly_length, rns_poly_len, moduli);
                },
            );
        }
        Ok(())
    }
}
