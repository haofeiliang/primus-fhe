use primus_data::{Data, DataMut};
use primus_factor::ShoupFactor;
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_reduce::FieldContext;
use primus_rns::ResidueFactors;

use super::automorphism::DcrtGlweAutoKeyData;
use super::trace::DcrtGlweTraceWorkspace;
use crate::RnsDomainError;
use crate::automorphism::AutomorphismKeyMetadata;
use crate::{DcrtGadgetDomain, DcrtGlweCiphertext, DcrtGlweSecretKey};

#[derive(Clone)]
/// Automorphism keys for reverse tracing a DCRT GLWE ciphertext.
pub struct DcrtGlweRevTraceKey<T: FheUint> {
    metadata: AutomorphismKeyMetadata<T>,
    auto_keys: Vec<DcrtGlweAutoKeyData<T>>,
    inv_2_residues: ResidueFactors<Vec<ShoupFactor<T>>>,
}

impl<T: FheUint> DcrtGlweRevTraceKey<T> {
    /// Generates the automorphism keys required by the reverse trace.
    ///
    /// # Panics
    /// Panics if secret layouts or ordered moduli do not match the domain.
    ///
    /// # Correctness
    /// The secret must use the domain table's NTT representation.
    #[must_use]
    pub fn new<M, Table, R>(
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
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

        // Reversed order: degrees 3, 5, 9, ..., 2^logN + 1
        let auto_keys: Vec<DcrtGlweAutoKeyData<T>> = (1..=log_n)
            .map(|x| (1usize << x) + 1)
            .map(|degree| DcrtGlweAutoKeyData::new(domain, degree, dcrt_sk, rng))
            .collect();

        // Precompute 2^{-1} mod q_i for each RNS modulus.
        // For odd prime q_i, inv(2) = (q_i + 1) / 2.
        let inv_2_residues: ResidueFactors<Vec<ShoupFactor<T>>> = ResidueFactors(
            params
                .cipher_moduli_value()
                .iter()
                .map(|&m| ShoupFactor::new((m + T::ONE) >> 1u32, m))
                .collect(),
        );

        Self {
            metadata: AutomorphismKeyMetadata::new(domain),
            auto_keys,
            inv_2_residues,
        }
    }

    /// Applies the reversed automorphism order, halving modulo each q_i before
    /// computing both operands of each sum. The caller maintains matching complete
    /// key/domain/workspace resources; scratch is overwritten and reborrowed.
    fn trace_kernel_to<M, Table>(
        &self,
        ciphertext: DcrtGlweCiphertext<&[T]>,
        mut result: DcrtGlweCiphertext<&mut [T]>,
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        workspace: &mut DcrtGlweTraceWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let params = domain.parameters();
        let poly_length = params.poly_length().get();
        let rns_poly_len = params.rns_poly_len();
        let moduli = params.cipher_moduli();
        let moduli_value = params.cipher_moduli_value();

        let (dcrt_glwe, auto_workspace) = workspace.as_mut();

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
            auto_key.automorphism_kernel(
                result.as_view(),
                dcrt_glwe.as_mut_view(),
                domain,
                auto_workspace,
            );

            // result = result + auto(result)  [both already halved]
            result.add_assign(dcrt_glwe, poly_length, rns_poly_len, moduli);
        }
    }
}

/// DCRT normalized reverse trace, bound to one key, numerical domain and owned scratch.
///
/// Construct once and reuse. Numerical checks do not establish secret identity
/// or agreement on the table's NTT representation; callers maintain both.
/// Ciphertexts must contain canonical residues in the bound ordered Q basis.
pub struct DcrtGlweRevTraceEvaluator<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    key: &'a DcrtGlweRevTraceKey<T>,
    domain: &'a DcrtGadgetDomain<'a, T, M, Table>,
    workspace: DcrtGlweTraceWorkspace<T>,
}

impl<'a, T, M, Table> DcrtGlweRevTraceEvaluator<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    /// Creates a new [`DcrtGlweRevTraceEvaluator`] for a compatible key and domain.
    ///
    /// # Panics
    /// Panics if [`Self::try_new`] rejects the binding.
    #[must_use]
    pub fn new(
        key: &'a DcrtGlweRevTraceKey<T>,
        domain: &'a DcrtGadgetDomain<'a, T, M, Table>,
    ) -> Self {
        Self::try_new(key, domain)
            .unwrap_or_else(|error| panic!("invalid DCRT reverse trace binding: {error}"))
    }

    /// Checks layout, ordered Q, radix and retained levels before allocating scratch.
    ///
    /// # Errors
    /// Returns [`RnsDomainError`] if the key and domain are numerically incompatible.
    pub fn try_new(
        key: &'a DcrtGlweRevTraceKey<T>,
        domain: &'a DcrtGadgetDomain<'a, T, M, Table>,
    ) -> Result<Self, RnsDomainError<T>> {
        key.metadata.validate(domain)?;
        let workspace = DcrtGlweTraceWorkspace::from_parameters(domain.parameters());
        Ok(Self {
            key,
            domain,
            workspace,
        })
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
    ///
    /// The output and reusable internal scratch are overwritten.
    ///
    /// # Correctness
    /// Both ciphertexts must match the domain's complete RNS GLWE layout,
    /// NTT representation and the key's secret.
    pub fn trace_to<A: Data<Elem = T>, B: DataMut<Elem = T>>(
        &mut self,
        input: &DcrtGlweCiphertext<A>,
        output: &mut DcrtGlweCiphertext<B>,
    ) {
        let len = self.domain.parameters().rns_glwe_len();
        debug_assert_eq!(input.as_ref().len(), len);
        debug_assert_eq!(output.as_ref().len(), len);
        self.key.trace_kernel_to(
            input.as_view(),
            output.as_mut_view(),
            self.domain,
            &mut self.workspace,
        );
    }
}
