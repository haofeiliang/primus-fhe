//! One blind rotation followed by reverse-trace projection and scheme switching.

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_ntru::NtruCiphertext;
use primus_ntru::{NlevCiphertext, NttNgswCiphertext};
use primus_ntt::MonomialNttTable;
use primus_reduce::ReduceMul;
use primus_tfhe::{InterleavedLookupTable, LookupTableError, LweCiphertext};

use crate::{
    CircuitBootstrapKey, Evaluator, ServerKey, TfheContext, TfheEvaluationError,
    blind_rotation::blind_rotate_lookup_table_to,
};

/// Allocation-free online NTRU circuit bootstrapping with optional evaluation keys.
/// Output is NGSW under f_acc, unlike ordinary PBS's LWE output under f_client.
pub struct CircuitBootstrapEvaluator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    pbs: Evaluator<'a, T, Table>,
    circuit_key: &'a CircuitBootstrapKey<T>,
    lookup_table: InterleavedLookupTable<T>,
    trace_scratch: Vec<T>,
    projected: NlevCiphertext<Vec<T>>,
}

impl<'a, T, Table> CircuitBootstrapEvaluator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Binds the CBS parameters and material carried by one server key.
    /// Rejects sparse keys or absent CBS material.
    ///
    /// # Correctness
    /// Inherits [`Self::try_from_parts`]'s secret and transform requirements.
    /// Bundled generation pairs secrets; layout checks do not establish identity
    /// for externally assembled material or another transform representation.
    pub fn try_new(
        context: &'a TfheContext<T, Table>,
        server_key: &'a ServerKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        if server_key.sparse_bootstrapping_key().is_some() {
            return Err(TfheEvaluationError::UnsupportedSparseBootstrapping);
        }
        let key = server_key
            .circuit_bootstrap_key()
            .ok_or(TfheEvaluationError::MissingCircuitBootstrapKey)?;
        Self::try_from_parts(context, server_key, key)
    }

    /// Binds resources and compiles gadget-scaled identity outputs once.
    /// Uses the circuit key's complete output basis and key parameters.
    /// Rejects sparse server keys.
    ///
    /// # Correctness
    /// The server and circuit keys were generated from the same accumulator
    /// secret and NTT representation. Layout/basis checks do not prove identity.
    pub fn try_from_parts(
        context: &'a TfheContext<T, Table>,
        server_key: &'a ServerKey<T>,
        circuit_key: &'a CircuitBootstrapKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        if server_key.sparse_bootstrapping_key().is_some() {
            return Err(TfheEvaluationError::UnsupportedSparseBootstrapping);
        }
        Self::from_bootstrapper_and_key(Evaluator::try_new(context, server_key)?, circuit_key)
    }

    /// Consumes ordinary PBS workspace and allocates only the additional CBS buffers.
    /// Rejects sparse keys or absent CBS material.
    pub fn try_from_bootstrapper(
        pbs: Evaluator<'a, T, Table>,
    ) -> Result<Self, TfheEvaluationError> {
        if pbs.server_key.sparse_bootstrapping_key().is_some() {
            return Err(TfheEvaluationError::UnsupportedSparseBootstrapping);
        }
        let key = pbs
            .server_key
            .circuit_bootstrap_key()
            .ok_or(TfheEvaluationError::MissingCircuitBootstrapKey)?;
        Self::from_bootstrapper_and_key(pbs, key)
    }

    /// Borrows ordinary PBS operations without allocation or changing the bound resources.
    #[must_use]
    pub fn bootstrapper_mut(
        &mut self,
    ) -> impl primus_tfhe::ProgrammableBootstrap<T>
    + primus_tfhe::ProgrammableBootstrapInterleaved<T>
    + use<'_, 'a, T, Table> {
        &mut self.pbs
    }

    /// Releases CBS buffers and recovers ordinary PBS workspace without allocation.
    #[must_use]
    pub fn into_bootstrapper(self) -> Evaluator<'a, T, Table> {
        self.pbs
    }

    fn from_bootstrapper_and_key(
        pbs: Evaluator<'a, T, Table>,
        circuit_key: &'a CircuitBootstrapKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        let context = pbs.context;
        let parameters = circuit_key.parameters();
        let tfhe = context.parameters();
        if !parameters.is_compatible(tfhe) {
            return Err(TfheEvaluationError::IncompatibleCircuitBootstrapParameters);
        }
        let n = tfhe.poly_length();
        let modulus = tfhe.accumulator_ntru().cipher_modulus();
        let domain_len = primus_tfhe::front_half_domain_len(tfhe.plain_modulus_value(), n)?;
        let scalars: Vec<T> = parameters.output_basis().scalar_iter().collect();
        let lookup_table = InterleavedLookupTable::try_new(
            domain_len,
            n,
            parameters.output_basis().decompose_length(),
            tfhe.plain_modulus_value(),
            tfhe.external_lwe().cipher_modulus(),
            modulus,
            |input, index| {
                let scalar = scalars[index];
                let input =
                    T::try_from(input).map_err(|_| LookupTableError::PlaintextModulusTooLarge)?;
                Ok(modulus.reduce_mul(scalar, input))
            },
        )?;
        Ok(Self {
            pbs,
            circuit_key,
            lookup_table,
            trace_scratch: vec![T::ZERO; 2 * n],
            projected: NlevCiphertext::zero(parameters.output_nlev_len()),
        })
    }

    /// Allocates a zeroed NTT NGSW with this evaluator's output layout.
    /// Allocate once and reuse it with [`Self::circuit_bootstrap_to`].
    #[must_use]
    pub fn allocate_output(&self) -> NttNgswCiphertext<Vec<T>> {
        NttNgswCiphertext::zero(self.circuit_key.parameters().output_nlev_len())
    }

    /// Selects `lhs` for an encrypted zero and `rhs` for an encrypted one.
    /// Overwrites the coefficient-domain output without allocating or resetting scratch.
    ///
    /// # Correctness
    /// `control` must encrypt a bit with this evaluator's output basis, accumulator
    /// secret and transform representation. Both candidates must use that secret,
    /// modulus and the same encoding; their noise must permit the external product.
    /// All coefficient-domain inputs must be canonical residues.
    /// See [`NttNgswCiphertext::cmux_to`] for the underlying numerical contract.
    ///
    /// # Panics
    /// Panics before output writes if any ciphertext has the wrong length.
    pub fn cmux_to<A, B, C, D>(
        &mut self,
        control: &NttNgswCiphertext<A>,
        lhs: &NtruCiphertext<B>,
        rhs: &NtruCiphertext<C>,
        output: &mut NtruCiphertext<D>,
    ) where
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: Data<Elem = T>,
        D: DataMut<Elem = T>,
    {
        let ring_len = self.pbs.context.parameters().poly_length();
        assert_eq!(
            (
                control.as_ref().len(),
                lhs.as_ref().len(),
                rhs.as_ref().len(),
                output.as_ref().len()
            ),
            (
                self.circuit_key.parameters().output_nlev_len(),
                ring_len,
                ring_len,
                ring_len
            ),
            "CMUX ciphertext layout mismatch"
        );
        control.cmux_to(
            lhs,
            rhs,
            output,
            self.circuit_key.parameters().output_basis(),
            self.pbs
                .context
                .parameters()
                .accumulator_ntru()
                .cipher_modulus(),
            self.pbs.context.table(),
            self.pbs.blind_rotation.rotation.external_product(),
        );
    }

    /// Multiplies a coefficient-domain accumulator ciphertext by a gadget control.
    /// Overwrites output without allocating. The control need not encrypt a bit.
    ///
    /// # Correctness
    /// Inherits [`Self::cmux_to`]'s basis, secret, encoding, transform and residue
    /// requirements, with the noise budget appropriate to this multiplication.
    /// See [`NttNgswCiphertext::external_product_to`].
    ///
    /// # Panics
    /// Panics before output writes if any ciphertext has the wrong length.
    pub fn external_product_to<A, B, C>(
        &mut self,
        control: &NttNgswCiphertext<A>,
        input: &NtruCiphertext<B>,
        output: &mut NtruCiphertext<C>,
    ) where
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let ring_len = self.pbs.context.parameters().poly_length();
        assert_eq!(
            (
                control.as_ref().len(),
                input.as_ref().len(),
                output.as_ref().len()
            ),
            (
                self.circuit_key.parameters().output_nlev_len(),
                ring_len,
                ring_len
            ),
            "external-product ciphertext layout mismatch"
        );
        control.external_product_to(
            input,
            output,
            self.circuit_key.parameters().output_basis(),
            self.pbs
                .context
                .parameters()
                .accumulator_ntru()
                .cipher_modulus(),
            self.pbs.context.table(),
            self.pbs.blind_rotation.rotation.external_product(),
        );
    }

    /// Allocates the output NGSW. Inherits [`Self::circuit_bootstrap_to`]'s contracts.
    #[must_use]
    pub fn circuit_bootstrap(&mut self, input: &LweCiphertext<T>) -> NttNgswCiphertext<Vec<T>> {
        let mut output = self.allocate_output();
        self.circuit_bootstrap_to(input, &mut output);
        output
    }

    /// Writes `NGSW_f_acc[m]` with the configured output gadget scalars.
    /// Reuses one BR, trace workspace and coefficient NLev allocation.
    ///
    /// # Correctness
    /// Input uses this context's external client secret, modulus and unsigned
    /// rounded LWE encoding, with m in `0..ceil(t/2)`. Canonical residues and a
    /// noise margin for the coarser ManyLUT windows are required. Trace and
    /// scheme-switch errors must fit the independent CBS budget, including f/f²
    /// amplification; see [`crate::CircuitBootstrapParameters`]. CMUX use requires m=0/1.
    /// The output uses gadget scales, not ordinary plaintext or Boolean encoding.
    ///
    /// # Panics
    /// Panics before output writes if input dimension or output NGSW length is
    /// wrong. Fixed LUT/resource compatibility was checked during construction.
    pub fn circuit_bootstrap_to<S: DataMut<Elem = T>>(
        &mut self,
        input: &LweCiphertext<T>,
        output: &mut NttNgswCiphertext<S>,
    ) {
        let tfhe = self.pbs.context.parameters();
        assert_eq!(
            input.dimension(),
            tfhe.external_lwe_dimension(),
            "circuit-bootstrap input dimension mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            self.circuit_key.parameters().output_nlev_len(),
            "circuit-bootstrap NGSW output length mismatch"
        );
        blind_rotate_lookup_table_to(
            self.pbs.server_key,
            input,
            self.lookup_table.polynomial(),
            self.lookup_table.padded_output_count(),
            &mut self.pbs.blind_rotation,
            tfhe,
            self.pbs.context.table(),
        );
        // A general ManyLUT accumulator does not have a zero message tail.
        // Reverse-trace projection is valid here; prefix expansion is not.
        self.circuit_key
            .trace_key()
            .project_prefix_coefficients_with_scratch_to(
                &self.pbs.blind_rotation.current,
                self.circuit_key
                    .parameters()
                    .output_basis()
                    .decompose_length(),
                self.projected.as_mut(),
                tfhe.accumulator_ntru().cipher_modulus(),
                self.pbs.context.table(),
                &mut self.trace_scratch,
                self.pbs.blind_rotation.rotation.external_product(),
            );
        self.circuit_key.scheme_switch_key().apply_to(
            &self.projected,
            output,
            tfhe.accumulator_ntru().cipher_modulus(),
            self.pbs.context.table(),
            self.pbs.blind_rotation.rotation.external_product(),
        );
    }
}
