use primus_data::{Data, DataMut};
use primus_factor::ShoupFactor;
use primus_integer::{AsInto, BigUint, FheUint};
use primus_ntt::NttTable;
use primus_reduce::FieldContext;
use primus_rns::ResidueFactors;
use rayon::prelude::*;

use crate::{
    CrtGlweAutoKey, CrtGlweAutomorphismWorkspace, CrtGlweCiphertext, DcrtGadgetDomain,
    DcrtGlweSecretKey, GlweSecretKey,
};

use super::{CrtGlweExpandCoeffSyncPool, CrtGlweExpandCoeffWorkspace};

#[derive(Clone)]
/// Automorphism keys used to expand CRT GLWE coefficients into ciphertexts.
pub struct CrtGlweExpandCoeffKey<T: FheUint> {
    auto_keys: Vec<CrtGlweAutoKey<T>>,
    inv_count_residues_by_level: Vec<ResidueFactors<Vec<ShoupFactor<T>>>>,
}

impl<T: FheUint> CrtGlweExpandCoeffKey<T> {
    /// Generates the automorphism keys required for coefficient expansion.
    pub fn new<M, Table, R>(
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        sk: &GlweSecretKey<T>,
        dcrt_sk: &DcrtGlweSecretKey<T>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let params = domain.parameters();
        let log_n = params.poly_length().log_n();
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

                ResidueFactors(
                    n_residue
                        .iter()
                        .zip(base_q.moduli())
                        .map(|(&n, m)| ShoupFactor::new(m.reduce_inv(n), m.value()))
                        .collect(),
                )
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
    pub fn expand_coefficients_to<M, Table, A, B>(
        &self,
        ciphertext: &CrtGlweCiphertext<A>,
        result: &mut [CrtGlweCiphertext<B>],
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        workspace: &mut CrtGlweExpandCoeffWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(result.len(), domain.parameters().poly_length().get());
        self.expand_partial_coefficients_to(ciphertext, result, domain, workspace)
    }

    /// Coefficient Expansion Algorithm.
    ///
    /// (Alg. 1)<https://eprint.iacr.org/2024/266.pdf>
    pub fn expand_partial_coefficients_to<M, Table, A, B>(
        &self,
        ciphertext: &CrtGlweCiphertext<A>,
        result: &mut [CrtGlweCiphertext<B>],
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        workspace: &mut CrtGlweExpandCoeffWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let params = domain.parameters();
        let poly_length = params.poly_length().get();
        let count = result.len();
        assert!(count.is_power_of_two() && count <= poly_length);
        let ciphertext = ciphertext.as_view();

        let log_d = count.trailing_zeros() as usize;
        let rns_poly_len = params.rns_poly_len();

        ciphertext.mul_factor_to(
            &self.inv_count_residues_by_level[log_d],
            &mut result[0],
            poly_length,
            rns_poly_len,
            params.cipher_moduli_value(),
        );

        let (crt_glwe, auto_workspace) = workspace.as_mut();
        for (i, auto_key) in self.auto_keys.iter().enumerate().take(log_d) {
            let level_len = 1 << i;
            let (x, y) = result[..level_len * 2].split_at_mut(level_len);
            let monomial_degree = poly_length * 2 - level_len;

            x.iter_mut().zip(y).for_each(|(a_0, b_0)| {
                Self::expand_pair_kernel(
                    a_0.as_mut_view(),
                    b_0.as_mut_view(),
                    auto_key,
                    monomial_degree,
                    domain,
                    crt_glwe.as_mut_view(),
                    auto_workspace,
                );
            });
        }
    }

    /// Parallel Coefficient Expansion Algorithm.
    ///
    /// Expands all `poly_length` coefficients using rayon parallelism.
    /// (Alg. 1)<https://eprint.iacr.org/2024/266.pdf>
    pub fn expand_coefficients_parallel_to<M, Table, A, B>(
        &self,
        ciphertext: &CrtGlweCiphertext<A>,
        result: &mut [CrtGlweCiphertext<B>],
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        workspace_pool: &CrtGlweExpandCoeffSyncPool<T>,
    ) where
        M: FieldContext<T> + Sync,
        A: Data<Elem = T> + Sync,
        B: DataMut<Elem = T> + Send,
        Table: NttTable<ValueT = T>,
    {
        assert_eq!(result.len(), domain.parameters().poly_length().get());
        self.expand_partial_coefficients_parallel_to(ciphertext, result, domain, workspace_pool)
    }

    /// Parallel Coefficient Expansion Algorithm.
    ///
    /// (Alg. 1)<https://eprint.iacr.org/2024/266.pdf>
    pub fn expand_partial_coefficients_parallel_to<M, Table, A, B>(
        &self,
        ciphertext: &CrtGlweCiphertext<A>,
        result: &mut [CrtGlweCiphertext<B>],
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        workspace_pool: &CrtGlweExpandCoeffSyncPool<T>,
    ) where
        M: FieldContext<T> + Sync,
        A: Data<Elem = T> + Sync,
        B: DataMut<Elem = T> + Send,
        Table: NttTable<ValueT = T>,
    {
        let params = domain.parameters();
        let poly_length = params.poly_length().get();
        let count = result.len();
        assert!(count.is_power_of_two() && count <= poly_length);
        let ciphertext = ciphertext.as_view();

        let log_d = count.trailing_zeros() as usize;
        let rns_poly_len = params.rns_poly_len();

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
                || workspace_pool.acquire_guard(),
                |guard, (a_0, b_0)| {
                    let (crt_glwe, auto_workspace) = guard.workspace_mut().as_mut();
                    Self::expand_pair_kernel(
                        a_0.as_mut_view(),
                        b_0.as_mut_view(),
                        auto_key,
                        monomial_degree,
                        domain,
                        crt_glwe.as_mut_view(),
                        auto_workspace,
                    );
                },
            );
        }
    }

    /// Splits the original node `c` into `lhs = c + auto(c)` and
    /// `rhs = X^degree * (c - auto(c))`.
    /// Serial and parallel traversal borrow each output separately, avoiding an
    /// allocated collection of views. Operands and scratch must have the complete
    /// domain layout; `scratch` and the automorphism workspace are overwritten.
    fn expand_pair_kernel<M, Table>(
        mut lhs: CrtGlweCiphertext<&mut [T]>,
        mut rhs: CrtGlweCiphertext<&mut [T]>,
        auto_key: &CrtGlweAutoKey<T>,
        monomial_degree: usize,
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        mut scratch: CrtGlweCiphertext<&mut [T]>,
        auto_workspace: &mut CrtGlweAutomorphismWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let params = domain.parameters();
        let poly_length = params.poly_length().get();
        let rns_poly_len = params.rns_poly_len();
        let moduli = params.cipher_moduli();

        auto_key.automorphism_kernel(lhs.as_view(), scratch.as_mut_view(), domain, auto_workspace);
        lhs.sub_to(&scratch, &mut rhs, poly_length, rns_poly_len, moduli);
        rhs.mul_monomial_assign(monomial_degree, poly_length, rns_poly_len, moduli);
        lhs.add_assign(&scratch, poly_length, rns_poly_len, moduli);
    }
}
