use std::sync::Arc;

use primus_data::{Data, DataMut, RawData};
use primus_factor::{FactorBase, ShoupFactor};
use primus_integer::FheUint;
use primus_ntt::DcrtTable;
use primus_reduce::FieldContext;
use primus_rns::RNSBase;

use crate::{
    CrtGlevParameters, DcrtGlweAutoKey, DcrtGlweCiphertext, DcrtGlweSecretKey, DcrtGlweTraceContext,
};

pub type DcrtGlweRevTraceContext<T> = DcrtGlweTraceContext<T>;

#[derive(Clone)]
pub struct DcrtGlweRevTraceKey<T: FheUint, Table>
where
    Table: DcrtTable<ValueT = T>,
{
    auto_keys: Vec<DcrtGlweAutoKey<T, Table>>,
    inv_2_residues: Vec<ShoupFactor<T>>,
    table: Arc<Table>,
}

impl<T: FheUint, Table> DcrtGlweRevTraceKey<T, Table>
where
    Table: DcrtTable<ValueT = T>,
{
    pub fn new<M, R>(
        params: &CrtGlevParameters<T, M>,
        dcrt_sk: &DcrtGlweSecretKey<T>,
        table: Arc<Table>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
    {
        let log_n = params.poly_length().trailing_zeros();

        // Reversed order: degrees 3, 5, 9, ..., 2^logN + 1
        let auto_keys: Vec<DcrtGlweAutoKey<T, Table>> = (1..=log_n)
            .map(|x| (1usize << x) + 1)
            .map(|degree| DcrtGlweAutoKey::new(params, degree, dcrt_sk, Arc::clone(&table), rng))
            .collect();

        // Precompute 2^{-1} mod q_i for each RNS modulus.
        // For odd prime q_i, inv(2) = (q_i + 1) / 2.
        let inv_2_residues: Vec<ShoupFactor<T>> = params
            .cipher_moduli_value()
            .iter()
            .map(|&m| ShoupFactor::new((m + T::ONE) >> 1u32, m))
            .collect();

        Self {
            auto_keys,
            inv_2_residues,
            table,
        }
    }

    pub fn table(&self) -> &Table {
        &self.table
    }

    /// RevHomTrace: Amplification-Removing Reverse Homomorphic Trace.
    ///
    /// Evaluates the field trace with reversed automorphism order and
    /// per-iteration exact division by 2, naturally removing the factor N.
    ///
    /// Output encrypts Tr_{K/Q}(M(X)) / N = M_0 (the constant coefficient).
    ///
    /// Noise variance (Theorem 4): Var(C') <= Var(C) + 4*logN*V_MS + logN*V_Auto,
    /// improving over the standard O(N^3) bound.
    /// With exact arithmetic over odd RNS moduli, V_MS = 0, so
    /// Var(C') <= Var(C) + logN*V_Auto (still O(N log N) when V_Auto = O(N)).
    ///
    /// (Alg. 5) <https://eprint.iacr.org/2025/1088>
    pub fn trace_inplace<M, A, B>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        result: &mut DcrtGlweCiphertext<B>,
        params: &CrtGlevParameters<T, M>,
        rns_base: &RNSBase<T, M>,
        context: &mut DcrtGlweRevTraceContext<T>,
    ) where
        M: FieldContext<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = params.poly_length();
        let rns_poly_len = params.rns_poly_len();
        let moduli = params.cipher_moduli();
        let moduli_value = params.cipher_moduli_value();

        let (dcrt_glwe, auto_context) = context.as_mut();

        result.as_mut().copy_from_slice(ciphertext.as_ref());

        for auto_key in self.auto_keys.iter() {
            // Exact ModSwitch: multiply by 2^{-1} mod q_i (replaces q→q/2 rounding)
            result.mul_factor_assign(
                &self.inv_2_residues,
                poly_length,
                rns_poly_len,
                moduli_value,
            );

            // Automorphism on the halved ciphertext
            auto_key.automorphism_to(result, dcrt_glwe, params, rns_base, auto_context);

            // result = result + auto(result)  [both already halved]
            result.add_element_wise_assign(dcrt_glwe, poly_length, rns_poly_len, moduli);
        }
    }
}
