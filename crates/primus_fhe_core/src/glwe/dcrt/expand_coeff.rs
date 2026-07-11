use std::sync::{Arc, Mutex};

use primus_data::{Data, DataMut, RawData};
use primus_factor::{FactorBase, ShoupFactor};
use primus_integer::{AsInto, BigUint, FheUint};
use primus_ntt::DcrtTable;
use primus_reduce::FieldContext;
use primus_rns::RNSBase;
use rayon::prelude::*;

use crate::{
    CrtGlevParameters, DcrtGlweAutoKey, DcrtGlweCiphertext, DcrtGlweSecretKey, DcrtGlweTraceContext,
};

pub type DcrtGlweExpandCoeffContext<T> = DcrtGlweTraceContext<T>;

/// Thread-safe context pool for parallel coefficient expansion.
///
/// Contexts are lazily allocated on demand and reused via `acquire`/`release`.
/// The pool grows up to the number of concurrent worker threads.
pub struct DcrtGlweExpandCoeffSyncPool<T: FheUint> {
    contexts: Mutex<Vec<DcrtGlweExpandCoeffContext<T>>>,
    dimension: usize,
    poly_length: usize,
    moduli_count: usize,
    crt_poly_len: usize,
    big_uint_poly_len: usize,
}

impl<T: FheUint> DcrtGlweExpandCoeffSyncPool<T> {
    /// Creates an empty pool. Contexts are allocated lazily on first [`Self::acquire`].
    pub fn new(
        dimension: usize,
        poly_length: usize,
        crt_poly_len: usize,
        big_uint_poly_len: usize,
        moduli_count: usize,
    ) -> Self {
        Self {
            contexts: Mutex::new(Vec::new()),
            dimension,
            poly_length,
            moduli_count,
            crt_poly_len,
            big_uint_poly_len,
        }
    }

    /// Creates a pre-warmed pool with `capacity` contexts already allocated.
    ///
    /// Use `rayon::current_num_threads()` as `capacity` to avoid any allocation
    /// during parallel computation.
    pub fn with_capacity(
        capacity: usize,
        dimension: usize,
        poly_length: usize,
        crt_poly_len: usize,
        big_uint_poly_len: usize,
        moduli_count: usize,
    ) -> Self {
        let contexts = (0..capacity)
            .map(|_| {
                DcrtGlweExpandCoeffContext::new(
                    dimension,
                    poly_length,
                    crt_poly_len,
                    big_uint_poly_len,
                    moduli_count,
                )
            })
            .collect();
        Self {
            contexts: Mutex::new(contexts),
            dimension,
            poly_length,
            moduli_count,
            crt_poly_len,
            big_uint_poly_len,
        }
    }

    /// Pop a context from the pool, or create a new one if empty.
    pub fn acquire(&self) -> DcrtGlweExpandCoeffContext<T> {
        self.contexts.lock().unwrap().pop().unwrap_or_else(|| {
            DcrtGlweExpandCoeffContext::new(
                self.dimension,
                self.poly_length,
                self.crt_poly_len,
                self.big_uint_poly_len,
                self.moduli_count,
            )
        })
    }

    /// Return a context to the pool for reuse.
    pub fn release(&self, ctx: DcrtGlweExpandCoeffContext<T>) {
        self.contexts.lock().unwrap().push(ctx);
    }

    /// Acquire a context wrapped in a guard that auto-releases on drop.
    fn acquire_guard(&self) -> PoolGuard<'_, T> {
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
struct PoolGuard<'a, T: FheUint> {
    ctx: Option<DcrtGlweExpandCoeffContext<T>>,
    pool: &'a DcrtGlweExpandCoeffSyncPool<T>,
}

impl<T: FheUint> PoolGuard<'_, T> {
    fn as_mut(
        &mut self,
    ) -> (
        &mut primus_lattice::glwe::DcrtGlwe<Vec<T>>,
        &mut crate::CrtGlweAutoContext<T>,
    ) {
        self.ctx.as_mut().unwrap().as_mut()
    }
}

impl<T: FheUint> Drop for PoolGuard<'_, T> {
    fn drop(&mut self) {
        if let Some(ctx) = self.ctx.take() {
            self.pool.release(ctx);
        }
    }
}

#[derive(Clone)]
pub struct DcrtGlweExpandCoeffKey<T: FheUint, Table>
where
    Table: DcrtTable<ValueT = T>,
{
    auto_keys: Vec<DcrtGlweAutoKey<T, Table>>,
    ntt_monomial_factors: Vec<Vec<ShoupFactor<T>>>,
    inv_count_residues_by_level: Vec<Vec<ShoupFactor<T>>>,
    table: Arc<Table>,
}

impl<T: FheUint, Table> DcrtGlweExpandCoeffKey<T, Table>
where
    Table: DcrtTable<ValueT = T>,
{
    pub fn new<M, R>(
        params: &CrtGlevParameters<T, M>,
        rns_base: &RNSBase<T, M>,
        dcrt_sk: &DcrtGlweSecretKey<T>,
        table: Arc<Table>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
    {
        let log_n = params.poly_length().trailing_zeros();
        let auto_keys: Vec<DcrtGlweAutoKey<T, Table>> = (1..=log_n)
            .rev()
            .map(|x| (1usize << x) + 1)
            .map(|degree| DcrtGlweAutoKey::new(params, degree, dcrt_sk, Arc::clone(&table), rng))
            .collect();

        let ntt_monomial_factors = Self::precompute_monomial_factors(params, table.as_ref());
        let inv_count_residues_by_level = Self::precompute_inv_count_residues(params, rns_base);

        Self {
            auto_keys,
            ntt_monomial_factors,
            inv_count_residues_by_level,
            table,
        }
    }

    pub fn table(&self) -> &Table {
        &self.table
    }

    fn precompute_monomial_factors<M>(
        params: &CrtGlevParameters<T, M>,
        table: &Table,
    ) -> Vec<Vec<ShoupFactor<T>>>
    where
        M: FieldContext<T>,
    {
        let poly_length = params.poly_length();
        let rns_poly_len = params.rns_poly_len();
        let moduli = params.cipher_moduli_value();
        let twice_poly_length = poly_length * 2;
        let log_n = poly_length.trailing_zeros() as usize;

        (0..log_n)
            .map(|i| {
                let degree = twice_poly_length - (1 << i);
                let mut monomial_ntt = vec![T::ZERO; rns_poly_len];
                table.transform_coeff_one_monomial(degree, &mut monomial_ntt);
                monomial_ntt
                    .chunks_exact(poly_length)
                    .zip(moduli)
                    .flat_map(|(poly, &modulus)| {
                        poly.iter()
                            .map(move |&value| ShoupFactor::new(value, modulus))
                    })
                    .collect()
            })
            .collect()
    }

    fn precompute_inv_count_residues<M>(
        params: &CrtGlevParameters<T, M>,
        rns_base: &RNSBase<T, M>,
    ) -> Vec<Vec<ShoupFactor<T>>>
    where
        M: FieldContext<T>,
    {
        let big_uint_value_len = params.big_uint_value_len();
        let log_n = params.poly_length().trailing_zeros() as usize;

        (0..=log_n)
            .map(|log_count| {
                let count = 1usize << log_count;
                let mut n = vec![T::ZERO; big_uint_value_len];
                n[0] = count.as_into();
                let n_residue = rns_base.decompose(BigUint(&n));

                n_residue
                    .iter()
                    .zip(rns_base.moduli())
                    .map(|(&n, m)| {
                        ShoupFactor::new(m.reduce_inv(n), unsafe { m.value_unchecked() })
                    })
                    .collect()
            })
            .collect()
    }

    /// Coefficient Expansion Algorithm.
    ///
    /// Expands all `poly_length` coefficients.
    /// (Alg. 1)<https://eprint.iacr.org/2024/266.pdf>
    pub fn expand_coefficients_inplace<M, A, B>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        result: &mut [DcrtGlweCiphertext<B>],
        params: &CrtGlevParameters<T, M>,
        rns_base: &RNSBase<T, M>,
        context: &mut DcrtGlweExpandCoeffContext<T>,
    ) where
        M: FieldContext<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        debug_assert_eq!(result.len(), params.poly_length());
        self.expand_partial_coefficients_inplace(ciphertext, result, params, rns_base, context);
    }

    /// Coefficient Expansion Algorithm.
    ///
    /// (Alg. 1)<https://eprint.iacr.org/2024/266.pdf>
    pub fn expand_partial_coefficients_inplace<M, A, B>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        result: &mut [DcrtGlweCiphertext<B>],
        params: &CrtGlevParameters<T, M>,
        rns_base: &RNSBase<T, M>,
        context: &mut DcrtGlweExpandCoeffContext<T>,
    ) where
        M: FieldContext<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = params.poly_length();
        let count = result.len();
        assert!(count.is_power_of_two() && count <= poly_length);

        let rns_poly_len = params.rns_poly_len();
        let moduli_value = params.cipher_moduli_value();

        let log_d = count.trailing_zeros() as usize;
        debug_assert!(log_d <= self.ntt_monomial_factors.len());
        debug_assert!(log_d < self.inv_count_residues_by_level.len());

        ciphertext.mul_factor_to(
            &self.inv_count_residues_by_level[log_d],
            &mut result[0],
            poly_length,
            rns_poly_len,
            moduli_value,
        );

        let (dcrt_glwe, auto_context) = context.as_mut();

        for (i, (auto_key, ntt_monomial_factors)) in self
            .auto_keys
            .iter()
            .zip(self.ntt_monomial_factors.iter())
            .enumerate()
            .take(log_d)
        {
            let two_pow_i = 1 << i;

            // SAFETY: `i < log_d` guarantees `two_pow_i * 2 <= count == result.len()`,
            // and `two_pow_i <= two_pow_i * 2`, so the split point is within bounds.
            let (x, y) = unsafe { result[..two_pow_i * 2].split_at_mut_unchecked(two_pow_i) };

            x.iter_mut().zip(y.iter_mut()).for_each(|(a_0, b_0)| {
                auto_key.automorphism_inplace(a_0, dcrt_glwe, params, rns_base, auto_context);

                a_0.butterfly_mul_factor_to(
                    dcrt_glwe,
                    ntt_monomial_factors,
                    b_0,
                    poly_length,
                    moduli_value,
                );
            });
        }
    }

    /// Parallel Coefficient Expansion Algorithm.
    ///
    /// Expands all `poly_length` coefficients using rayon parallelism.
    /// (Alg. 1)<https://eprint.iacr.org/2024/266.pdf>
    pub fn expand_coefficients_inplace_parallel<M, A, B>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        result: &mut [DcrtGlweCiphertext<B>],
        params: &CrtGlevParameters<T, M>,
        rns_base: &RNSBase<T, M>,
        context_pool: &DcrtGlweExpandCoeffSyncPool<T>,
    ) where
        M: FieldContext<T> + Sync,
        A: RawData<Elem = T> + Data + Sync,
        B: RawData<Elem = T> + DataMut + Send,
        Table: Send + Sync,
    {
        debug_assert_eq!(result.len(), params.poly_length());
        self.expand_partial_coefficients_inplace_parallel(
            ciphertext,
            result,
            params,
            rns_base,
            context_pool,
        );
    }

    /// Parallel Coefficient Expansion Algorithm.
    ///
    /// (Alg. 1)<https://eprint.iacr.org/2024/266.pdf>
    pub fn expand_partial_coefficients_inplace_parallel<M, A, B>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        result: &mut [DcrtGlweCiphertext<B>],
        params: &CrtGlevParameters<T, M>,
        rns_base: &RNSBase<T, M>,
        context_pool: &DcrtGlweExpandCoeffSyncPool<T>,
    ) where
        M: FieldContext<T> + Sync,
        A: RawData<Elem = T> + Data + Sync,
        B: RawData<Elem = T> + DataMut + Send,
        Table: Send + Sync,
    {
        let poly_length = params.poly_length();
        let count = result.len();
        assert!(count.is_power_of_two() && count <= poly_length);

        let rns_poly_len = params.rns_poly_len();
        let moduli_value = params.cipher_moduli_value();

        let log_d = count.trailing_zeros() as usize;
        debug_assert!(log_d <= self.ntt_monomial_factors.len());
        debug_assert!(log_d < self.inv_count_residues_by_level.len());

        ciphertext.mul_factor_to(
            &self.inv_count_residues_by_level[log_d],
            &mut result[0],
            poly_length,
            rns_poly_len,
            moduli_value,
        );

        for (i, (auto_key, ntt_monomial_factors)) in self
            .auto_keys
            .iter()
            .zip(self.ntt_monomial_factors.iter())
            .enumerate()
            .take(log_d)
        {
            let two_pow_i = 1 << i;

            // SAFETY: `i < log_d` guarantees `two_pow_i * 2 <= count == result.len()`,
            // and `two_pow_i <= two_pow_i * 2`, so the split point is within bounds.
            let (x, y) = unsafe { result[..two_pow_i * 2].split_at_mut_unchecked(two_pow_i) };

            x.par_iter_mut().zip(y.par_iter_mut()).for_each_init(
                || context_pool.acquire_guard(),
                |guard, (a_0, b_0)| {
                    let (dcrt_glwe, auto_context) = guard.as_mut();

                    auto_key.automorphism_inplace(a_0, dcrt_glwe, params, rns_base, auto_context);

                    a_0.butterfly_mul_factor_to(
                        dcrt_glwe,
                        ntt_monomial_factors,
                        b_0,
                        poly_length,
                        moduli_value,
                    );
                },
            );
        }
    }
}
