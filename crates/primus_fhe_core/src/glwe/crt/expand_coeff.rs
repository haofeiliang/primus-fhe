use primus_data::{Data, DataMut, RawData};
use primus_factor::ShoupFactor;
use primus_integer::{AsInto, BigUint, FheUint};
use primus_ntt::DcrtTable;
use primus_reduce::FieldContext;
use rayon::prelude::*;

use crate::{
    CrtGlweAutoKey, CrtGlweCiphertext, DcrtGadgetDomain, DcrtGlweSecretKey, GlweSecretKey,
};

use super::{CrtGlweExpandCoeffContext, CrtGlweExpandCoeffSyncPool};

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

        let base_q = params.base_q();

        let inv_count_residues_by_level = (0..=log_n)
            .map(|log_count| {
                let count = 1usize << log_count;
                let n = count.as_into();
                let n_residue = base_q.decompose(BigUint(&[n]));

                n_residue
                    .iter()
                    .zip(base_q.moduli())
                    .map(|(&n, m)| ShoupFactor::new(m.reduce_inv(n), m.value()))
                    .collect()
            })
            .collect();

        Self {
            auto_keys,
            inv_count_residues_by_level,
        }
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
    ) where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        assert_eq!(result.len(), domain.parameters().poly_length());
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
    ) where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let params = domain.parameters();
        let poly_length = params.poly_length();
        let count = result.len();
        assert!(count.is_power_of_two() && count <= poly_length);

        let log_d = count.trailing_zeros() as usize;
        let rns_poly_len = params.rns_poly_len();
        let moduli = params.cipher_moduli();

        ciphertext.mul_factor_to(
            &self.inv_count_residues_by_level[log_d],
            &mut result[0],
            poly_length,
            rns_poly_len,
            params.cipher_moduli_value(),
        );

        let (crt_glwe, auto_context) = context.as_mut();
        for (i, auto_key) in self.auto_keys.iter().enumerate().take(log_d) {
            let level_len = 1 << i;
            let (x, y) = result[..level_len * 2].split_at_mut(level_len);
            let monomial_degree = poly_length * 2 - level_len;

            x.iter_mut().zip(y).for_each(|(a_0, b_0)| {
                auto_key.automorphism_kernel(a_0, crt_glwe, domain, auto_context);
                a_0.sub_element_wise_to(crt_glwe, b_0, poly_length, rns_poly_len, moduli);
                b_0.mul_monic_monomial_assign(monomial_degree, poly_length, rns_poly_len, moduli);
                a_0.add_element_wise_assign(crt_glwe, poly_length, rns_poly_len, moduli);
            });
        }
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
        context_pool: &CrtGlweExpandCoeffSyncPool<T>,
    ) where
        M: FieldContext<T> + Sync,
        A: RawData<Elem = T> + Data + Sync,
        B: RawData<Elem = T> + DataMut + Send,
        Table: DcrtTable<ValueT = T> + Send + Sync,
    {
        assert_eq!(result.len(), domain.parameters().poly_length());
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
        context_pool: &CrtGlweExpandCoeffSyncPool<T>,
    ) where
        M: FieldContext<T> + Sync,
        A: RawData<Elem = T> + Data + Sync,
        B: RawData<Elem = T> + DataMut + Send,
        Table: DcrtTable<ValueT = T> + Send + Sync,
    {
        let params = domain.parameters();
        let poly_length = params.poly_length();
        let count = result.len();
        assert!(count.is_power_of_two() && count <= poly_length);

        let log_d = count.trailing_zeros() as usize;
        let rns_poly_len = params.rns_poly_len();
        let moduli = params.cipher_moduli();

        ciphertext.mul_factor_to(
            &self.inv_count_residues_by_level[log_d],
            &mut result[0],
            poly_length,
            rns_poly_len,
            params.cipher_moduli_value(),
        );

        for (i, auto_key) in self.auto_keys.iter().enumerate().take(log_d) {
            let level_len = 1 << i;
            let (x, y) = result[..level_len * 2].split_at_mut(level_len);
            let monomial_degree = poly_length * 2 - level_len;

            x.par_iter_mut().zip(y.par_iter_mut()).for_each_init(
                || context_pool.acquire_guard(),
                |guard, (a_0, b_0)| {
                    let (crt_glwe, auto_context) = guard.as_mut();
                    auto_key.automorphism_kernel(a_0, crt_glwe, domain, auto_context);
                    a_0.sub_element_wise_to(crt_glwe, b_0, poly_length, rns_poly_len, moduli);
                    b_0.mul_monic_monomial_assign(
                        monomial_degree,
                        poly_length,
                        rns_poly_len,
                        moduli,
                    );
                    a_0.add_element_wise_assign(crt_glwe, poly_length, rns_poly_len, moduli);
                },
            );
        }
    }
}
