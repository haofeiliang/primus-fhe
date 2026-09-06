use primus_data::{Data, DataMut};
use primus_factor::ShoupFactor;
use primus_integer::{AsInto, BigUint, FheUint};
use primus_ntt::{DcrtTable, MonomialNttTable, NttTable};
use primus_reduce::FieldContext;
use primus_rns::{RNSBase, ResidueFactors};
use rayon::prelude::*;

use crate::{
    CrtGlevParameters, DcrtGadgetDomain, DcrtGlweAutoKey, DcrtGlweCiphertext, DcrtGlweSecretKey,
};

use super::{DcrtGlweExpandCoeffContext, DcrtGlweExpandCoeffSyncPool};

#[derive(Clone)]
/// Automorphism keys used to expand DCRT GLWE coefficients into ciphertexts.
pub struct DcrtGlweExpandCoeffKey<T: FheUint> {
    auto_keys: Vec<DcrtGlweAutoKey<T>>,
    ntt_monomial_factors: Vec<Vec<ShoupFactor<T>>>,
    inv_count_residues_by_level: Vec<ResidueFactors<Vec<ShoupFactor<T>>>>,
}

impl<T: FheUint> DcrtGlweExpandCoeffKey<T> {
    /// Generates the automorphism keys required for coefficient expansion.
    pub fn new<M, Table, R>(
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        dcrt_sk: &DcrtGlweSecretKey<T>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: MonomialNttTable<ValueT = T>,
    {
        let params = domain.parameters();
        let log_n = params.poly_length().trailing_zeros();
        let auto_keys: Vec<DcrtGlweAutoKey<T>> = (1..=log_n)
            .rev()
            .map(|x| (1usize << x) + 1)
            .map(|degree| DcrtGlweAutoKey::new(domain, degree, dcrt_sk, rng))
            .collect();

        let ntt_monomial_factors = Self::precompute_monomial_factors(params, domain.table());
        let inv_count_residues_by_level =
            Self::precompute_inv_count_residues(params, domain.rns_base());

        Self {
            auto_keys,
            ntt_monomial_factors,
            inv_count_residues_by_level,
        }
    }

    fn precompute_monomial_factors<M, Table>(
        params: &CrtGlevParameters<T, M>,
        table: &DcrtTable<Table>,
    ) -> Vec<Vec<ShoupFactor<T>>>
    where
        M: FieldContext<T>,
        Table: MonomialNttTable<ValueT = T>,
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
    ) -> Vec<ResidueFactors<Vec<ShoupFactor<T>>>>
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

                ResidueFactors(
                    n_residue
                        .iter()
                        .zip(rns_base.moduli())
                        .map(|(&n, m)| ShoupFactor::new(m.reduce_inv(n), m.value()))
                        .collect(),
                )
            })
            .collect()
    }

    /// Coefficient Expansion Algorithm.
    ///
    /// Expands all `poly_length` coefficients.
    /// (Alg. 1)<https://eprint.iacr.org/2024/266.pdf>
    pub fn expand_coefficients_inplace<M, Table, A, B>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        result: &mut [DcrtGlweCiphertext<B>],
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        context: &mut DcrtGlweExpandCoeffContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(result.len(), domain.parameters().poly_length());
        self.expand_partial_coefficients_inplace(ciphertext, result, domain, context)
    }

    /// Coefficient Expansion Algorithm.
    ///
    /// (Alg. 1)<https://eprint.iacr.org/2024/266.pdf>
    pub fn expand_partial_coefficients_inplace<M, Table, A, B>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        result: &mut [DcrtGlweCiphertext<B>],
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        context: &mut DcrtGlweExpandCoeffContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let params = domain.parameters();
        let poly_length = params.poly_length();
        let count = result.len();
        assert!(count.is_power_of_two() && count <= poly_length);

        let log_d = count.trailing_zeros() as usize;
        let moduli_value = params.cipher_moduli_value();

        ciphertext.mul_factor_to(
            &self.inv_count_residues_by_level[log_d],
            &mut result[0],
            poly_length,
            params.rns_poly_len(),
            moduli_value,
        );

        let (dcrt_glwe, auto_context) = context.as_mut();
        for (i, (auto_key, factors)) in self
            .auto_keys
            .iter()
            .zip(&self.ntt_monomial_factors)
            .enumerate()
            .take(log_d)
        {
            let level_len = 1 << i;
            let (x, y) = result[..level_len * 2].split_at_mut(level_len);

            x.iter_mut().zip(y).for_each(|(a_0, b_0)| {
                auto_key.automorphism_kernel(a_0, dcrt_glwe, domain, auto_context);
                a_0.butterfly_mul_factor_to(dcrt_glwe, factors, b_0, poly_length, moduli_value);
            });
        }
    }

    /// Parallel Coefficient Expansion Algorithm.
    ///
    /// Expands all `poly_length` coefficients using rayon parallelism.
    /// (Alg. 1)<https://eprint.iacr.org/2024/266.pdf>
    pub fn expand_coefficients_inplace_parallel<M, Table, A, B>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        result: &mut [DcrtGlweCiphertext<B>],
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        context_pool: &DcrtGlweExpandCoeffSyncPool<T>,
    ) where
        M: FieldContext<T> + Sync,
        A: Data<Elem = T> + Sync,
        B: DataMut<Elem = T> + Send,
        Table: NttTable<ValueT = T>,
    {
        assert_eq!(result.len(), domain.parameters().poly_length());
        self.expand_partial_coefficients_inplace_parallel(ciphertext, result, domain, context_pool)
    }

    /// Parallel Coefficient Expansion Algorithm.
    ///
    /// (Alg. 1)<https://eprint.iacr.org/2024/266.pdf>
    pub fn expand_partial_coefficients_inplace_parallel<M, Table, A, B>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        result: &mut [DcrtGlweCiphertext<B>],
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        context_pool: &DcrtGlweExpandCoeffSyncPool<T>,
    ) where
        M: FieldContext<T> + Sync,
        A: Data<Elem = T> + Sync,
        B: DataMut<Elem = T> + Send,
        Table: NttTable<ValueT = T>,
    {
        let params = domain.parameters();
        let poly_length = params.poly_length();
        let count = result.len();
        assert!(count.is_power_of_two() && count <= poly_length);

        let log_d = count.trailing_zeros() as usize;
        let moduli_value = params.cipher_moduli_value();

        ciphertext.mul_factor_to(
            &self.inv_count_residues_by_level[log_d],
            &mut result[0],
            poly_length,
            params.rns_poly_len(),
            moduli_value,
        );

        for (i, (auto_key, factors)) in self
            .auto_keys
            .iter()
            .zip(&self.ntt_monomial_factors)
            .enumerate()
            .take(log_d)
        {
            let level_len = 1 << i;
            let (x, y) = result[..level_len * 2].split_at_mut(level_len);

            x.par_iter_mut().zip(y.par_iter_mut()).for_each_init(
                || context_pool.acquire_guard(),
                |guard, (a_0, b_0)| {
                    let (dcrt_glwe, auto_context) = guard.as_mut();
                    auto_key.automorphism_kernel(a_0, dcrt_glwe, domain, auto_context);
                    a_0.butterfly_mul_factor_to(dcrt_glwe, factors, b_0, poly_length, moduli_value);
                },
            );
        }
    }
}
