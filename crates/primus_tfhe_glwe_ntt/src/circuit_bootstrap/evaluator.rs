//! Patched NTT circuit bootstrapping using PBSManyLUT, reverse-trace projection, and scheme
//! switching.

use primus_data::{Data, DataMut};
use primus_glwe::{GlevCiphertext, GlweCiphertext, NttGlweTraceContext};
use primus_integer::FheUint;
use primus_lattice::ggsw::NttGgsw;
use primus_lwe::LweCiphertext;
use primus_ntt::MonomialNttTable;
use primus_reduce::ReduceMul;
use primus_tfhe::{InterleavedLookupTable, LookupTableError};

use crate::{
    CircuitBootstrapKey, CircuitBootstrapParameters, Evaluator, ServerKey, TfheContext,
    TfheEvaluationError,
};

/// Classic binary/ternary or sparse binary CBS producing NTT GGSW controls.
///
/// Both key variants share trace projection and scheme switching. Workspace
/// contains only the selected blind-rotation algorithm's scratch.
///
/// After construction, [`Self::circuit_bootstrap_to`] reuses all scratch
/// buffers and performs no heap allocation.
pub struct CircuitBootstrapEvaluator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    context: &'a TfheContext<T, Table>,
    pbs: Evaluator<'a, T, Table>,
    parameters: &'a CircuitBootstrapParameters<T>,
    circuit_key: &'a CircuitBootstrapKey<T>,
    lookup_table: InterleavedLookupTable<T>,
    trace: NttGlweTraceContext<T>,
    traced: GlevCiphertext<Vec<T>>,
}

impl<'a, T, Table> CircuitBootstrapEvaluator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Binds the CBS parameters and material carried by one server key.
    /// Returns an error if CBS was not requested during key generation.
    ///
    /// # Correctness
    /// Inherits [`Self::try_from_parts`]'s secret and transform requirements.
    /// Bundled generation pairs secrets; layout checks do not establish identity
    /// for externally assembled material or another transform representation.
    pub fn try_new(
        context: &'a TfheContext<T, Table>,
        server_key: &'a ServerKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        let key = server_key
            .circuit_bootstrap_key()
            .ok_or(TfheEvaluationError::MissingCircuitBootstrapKey)?;
        Self::try_from_parts(context, server_key, key.parameters(), key)
    }

    /// Creates an evaluator and compiles the gadget-scaled identity
    /// PBSManyLUT used by circuit bootstrapping.
    ///
    /// Checks parameter, layout and decomposition-basis compatibility and binds
    /// the server key's classic or sparse blind rotation. These checks do not
    /// establish a noise margin for the selected output gadget scales.
    ///
    /// # Correctness
    ///
    /// `server_key` and `circuit_key` must be generated from the same paired
    /// client secrets, so blind rotation, trace projection and scheme switching
    /// use the same accumulator GLWE secret. Both keys must use the NTT
    /// representation of `context.table()`. Compatibility checks do not verify
    /// secret or transform identity; see the underlying
    /// [`primus_glwe::NttGlweSchemeSwitchKey::apply_to`] contract.
    pub fn try_from_parts(
        context: &'a TfheContext<T, Table>,
        server_key: &'a ServerKey<T>,
        parameters: &'a CircuitBootstrapParameters<T>,
        circuit_key: &'a CircuitBootstrapKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        Self::from_bootstrapper_and_parts(
            Evaluator::try_for_circuit_bootstrap(context, server_key)?,
            parameters,
            circuit_key,
        )
    }

    /// Consumes complete PBS workspace and preserves it for ordinary operations and recovery.
    /// Allocates only the additional CBS buffers; requires bundled CBS key material.
    pub fn try_from_bootstrapper(
        pbs: Evaluator<'a, T, Table>,
    ) -> Result<Self, TfheEvaluationError> {
        let key = pbs
            .server_key
            .circuit_bootstrap_key()
            .ok_or(TfheEvaluationError::MissingCircuitBootstrapKey)?;
        Self::from_bootstrapper_and_parts(pbs, key.parameters(), key)
    }

    /// Borrows ordinary PBS without allocation, while preventing replacement of the bound evaluator.
    /// Returns `None` only for standalone BootstrapKeyswitch CBS, which omits return-KS storage.
    /// Use [`Self::try_from_bootstrapper`] when alternating ordinary PBS and CBS.
    #[must_use]
    pub fn bootstrapper_mut(
        &mut self,
    ) -> Option<
        impl primus_tfhe::ProgrammableBootstrap<T>
        + primus_tfhe::ProgrammableBootstrapInterleaved<T>
        + use<'_, 'a, T, Table>,
    > {
        self.pbs.has_key_switching().then_some(&mut self.pbs)
    }

    /// Recovers ordinary PBS workspace and releases CBS-only buffers.
    /// Reuses all allocations when constructed from an ordinary bootstrapper or with KS→BR order.
    /// Standalone BR→KS CBS explicitly allocates its missing return-KS workspace here.
    #[must_use]
    pub fn into_bootstrapper(mut self) -> Evaluator<'a, T, Table> {
        self.pbs.complete_workspace();
        self.pbs
    }

    fn from_bootstrapper_and_parts(
        pbs: Evaluator<'a, T, Table>,
        parameters: &'a CircuitBootstrapParameters<T>,
        circuit_key: &'a CircuitBootstrapKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        let context = pbs.context;
        let tfhe = context.parameters();
        if !parameters.is_compatible(tfhe) {
            return Err(TfheEvaluationError::IncompatibleCircuitBootstrapParameters);
        }
        if !circuit_key.is_compatible(parameters) {
            return Err(TfheEvaluationError::IncompatibleCircuitBootstrapKey);
        }

        let glwe = tfhe.accumulator_glwe();
        let modulus = glwe.cipher_modulus();
        let poly_length = glwe.poly_length();
        let domain_len =
            primus_tfhe::front_half_domain_len(tfhe.plain_modulus_value(), poly_length)?;
        let gadget_scalars: Vec<T> = parameters.output_basis().scalar_iter().collect();
        let lookup_table = InterleavedLookupTable::try_new(
            domain_len,
            poly_length,
            parameters.output_basis().decompose_length(),
            tfhe.plain_modulus_value(),
            tfhe.small_lwe().cipher_modulus(),
            modulus,
            |input, output_index| {
                let scalar = gadget_scalars[output_index];
                let input =
                    T::try_from(input).map_err(|_| LookupTableError::PlaintextModulusTooLarge)?;
                Ok(modulus.reduce_mul(scalar, input))
            },
        )?;

        let glwe_size = glwe.size();

        Ok(Self {
            context,
            pbs,
            parameters,
            circuit_key,
            lookup_table,
            trace: NttGlweTraceContext::new(glwe_size),
            traced: GlevCiphertext::zero(parameters.output_size().glev_len()),
        })
    }

    /// Allocates a zeroed NTT GGSW with this evaluator's output layout.
    /// Allocate once and reuse it with [`Self::circuit_bootstrap_to`].
    #[must_use]
    pub fn allocate_output(&self) -> NttGgsw<Vec<T>> {
        NttGgsw::zero(self.parameters.output_size().ggsw_len())
    }

    /// Selects `lhs` for an encrypted zero and `rhs` for an encrypted one.
    /// Overwrites the coefficient-domain output without allocating or resetting scratch.
    ///
    /// # Correctness
    /// `control` must encrypt a bit with this evaluator's output basis, accumulator
    /// secret and transform representation. Both candidates must use that secret,
    /// modulus and the same encoding; their noise must permit the external product.
    /// All coefficient-domain inputs must be canonical residues.
    /// See [`NttGgsw::cmux_to`] for the underlying numerical contract.
    ///
    /// # Panics
    /// Panics before output writes if any ciphertext has the wrong length.
    pub fn cmux_to<A, B, C, D>(
        &mut self,
        control: &NttGgsw<A>,
        lhs: &GlweCiphertext<B>,
        rhs: &GlweCiphertext<C>,
        output: &mut GlweCiphertext<D>,
    ) where
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: Data<Elem = T>,
        D: DataMut<Elem = T>,
    {
        let ring_len = self.parameters.output_size().glwe_size().glwe_len();
        assert_eq!(
            (
                control.as_ref().len(),
                lhs.as_ref().len(),
                rhs.as_ref().len(),
                output.as_ref().len()
            ),
            (
                self.parameters.output_size().ggsw_len(),
                ring_len,
                ring_len,
                ring_len
            ),
            "CMUX ciphertext layout mismatch"
        );
        self.pbs
            .with_external_product(self.parameters.output_size(), |scratch| {
                control.cmux_to(
                    lhs,
                    rhs,
                    output,
                    self.parameters.output_basis(),
                    self.context
                        .parameters()
                        .accumulator_glwe()
                        .cipher_modulus(),
                    self.context.table(),
                    scratch,
                );
            });
    }

    /// Multiplies a coefficient-domain accumulator ciphertext by a gadget control.
    /// Overwrites output without allocating. The control need not encrypt a bit.
    ///
    /// # Correctness
    /// Inherits [`Self::cmux_to`]'s basis, secret, encoding, transform and residue
    /// requirements, with the noise budget appropriate to this multiplication.
    /// See [`NttGgsw::external_product_to`].
    ///
    /// # Panics
    /// Panics before output writes if any ciphertext has the wrong length.
    pub fn external_product_to<A, B, C>(
        &mut self,
        control: &NttGgsw<A>,
        input: &GlweCiphertext<B>,
        output: &mut GlweCiphertext<C>,
    ) where
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let ring_len = self.parameters.output_size().glwe_size().glwe_len();
        assert_eq!(
            (
                control.as_ref().len(),
                input.as_ref().len(),
                output.as_ref().len()
            ),
            (self.parameters.output_size().ggsw_len(), ring_len, ring_len),
            "external-product ciphertext layout mismatch"
        );
        self.pbs
            .with_external_product(self.parameters.output_size(), |scratch| {
                control.external_product_to(
                    input,
                    output,
                    self.parameters.output_basis(),
                    self.context
                        .parameters()
                        .accumulator_glwe()
                        .cipher_modulus(),
                    self.context.table(),
                    scratch,
                );
            });
    }

    /// Circuit-bootstraps into a newly allocated NTT GGSW ciphertext.
    ///
    /// The output uses the gadget scalars described by [`Self::circuit_bootstrap_to`].
    ///
    /// # Correctness
    ///
    /// Inherits [`Self::circuit_bootstrap_to`]'s input encoding, plaintext domain,
    /// canonical-residue, noise and key/NTT representation requirements.
    ///
    /// # Panics
    ///
    /// Panics if the input dimension differs from the configured external LWE
    /// dimension. The output is allocated with the configured GGSW length.
    #[must_use]
    pub fn circuit_bootstrap(&mut self, input: &LweCiphertext<T>) -> NttGgsw<Vec<T>> {
        let mut output = self.allocate_output();
        self.circuit_bootstrap_to(input, &mut output);
        output
    }

    /// Converts an external LWE ciphertext into an NTT GGSW under the main
    /// GLWE key. Output levels preserve the gadget scalars compiled by this
    /// evaluator; they do not use the ordinary LWE plaintext scale.
    ///
    /// # Correctness
    ///
    /// The key/NTT representation requirements of [`Self::try_new`] must hold.
    /// Input must use the external client secret paired with `server_key`, this
    /// context's external LWE modulus and unsigned rounded encoding, with a
    /// plaintext in `0..ceil(t/2)` and canonical residues, where `t` is the TFHE
    /// plaintext modulus. Noise must fit the coarser ManyLUT rotation intervals;
    /// trace and scheme-switching errors must also fit the independent CBS
    /// budget described by [`CircuitBootstrapParameters`]. For sparse keys, include
    /// aggregation noise from every bucket, including zero selections and dummies.
    /// CMUX consumption requires plaintext 0 or 1. The output remains under the accumulator GLWE
    /// secret and uses gadget scales, not ordinary LWE or Boolean encoding.
    ///
    /// # Panics
    ///
    /// Panics before output writes if the input dimension differs from the
    /// configured external LWE dimension or the output length differs from the
    /// configured GGSW length. LUT parameters are fixed during construction.
    pub fn circuit_bootstrap_to<S>(&mut self, input: &LweCiphertext<T>, output: &mut NttGgsw<S>)
    where
        S: DataMut<Elem = T>,
    {
        let tfhe = self.context.parameters();
        assert_eq!(
            input.dimension(),
            tfhe.external_lwe_dimension(),
            "circuit-bootstrap input dimension mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            self.parameters.output_size().ggsw_len(),
            "circuit-bootstrap output GGSW layout mismatch"
        );

        let accumulator = self.pbs.blind_rotate(
            input,
            self.lookup_table.polynomial(),
            self.lookup_table.padded_output_count(),
        );

        self.circuit_key.trace_key().project_prefix_coefficients_to(
            accumulator,
            self.parameters.output_basis().decompose_length(),
            self.traced.as_mut(),
            self.context
                .parameters()
                .accumulator_glwe()
                .cipher_modulus(),
            self.context.table(),
            &mut self.trace,
        );
        // CMUX can bind the same buffers to a different output decomposition.
        self.pbs
            .with_external_product(self.parameters.scheme_switch().size(), |scratch| {
                self.circuit_key.scheme_switch_key().apply_to(
                    &self.traced,
                    output,
                    self.context
                        .parameters()
                        .accumulator_glwe()
                        .cipher_modulus(),
                    self.context.table(),
                    scratch,
                );
            });
    }
}
