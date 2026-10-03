//! Patched NTT circuit bootstrapping using PBSManyLUT, reverse-trace projection, and scheme
//! switching.

use primus_data::{Data, DataMut};
use primus_encoding::RoundedCodec;
use primus_glwe::{GlevCiphertext, GlweCiphertext, NttGlweKeySwitchingKey, NttGlweTraceWorkspace};
use primus_integer::FheUint;
use primus_lattice::ggsw::NttGgsw;
use primus_modulus::BarrettModulus;
use primus_ntt::MonomialNttTable;
use primus_tfhe::InterleavedLookupTable;

use super::key::CircuitBootstrapBinding;

use crate::{
    BootstrappingKey, CircuitBootstrapKey, CircuitBootstrapParameters, Evaluator, Lwe, ServerKey,
    TfheContext, TfheEvaluationError, bootstrap::CircuitBootstrapResources,
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
    resources: CircuitBootstrapResources<'a, T, Table>,
    circuit: CircuitBootstrapBinding<'a, T>,
    lookup_table: InterleavedLookupTable<T>,
    trace: NttGlweTraceWorkspace<T>,
    traced: GlevCiphertext<Vec<T>>,
}

impl<'a, T, Table> CircuitBootstrapEvaluator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Binds the CBS parameters and material carried by one server key.
    /// Rejects missing CBS material, an incompatible input codec modulus,
    /// or an input domain that does not fit the gadget identity ManyLUT.
    ///
    /// # Correctness
    /// Inherits [`Self::try_from_parts`]'s secret and transform requirements.
    /// Bundled generation pairs secrets; layout checks do not establish identity
    /// for externally assembled material or another transform representation.
    pub fn try_new(
        context: &'a TfheContext<T, Table>,
        server_key: &'a ServerKey<T>,
        input_codec: &RoundedCodec<T, BarrettModulus<T>>,
    ) -> Result<Self, TfheEvaluationError> {
        let key = server_key
            .circuit_bootstrap_key()
            .ok_or(TfheEvaluationError::MissingCircuitBootstrapKey)?;
        Self::try_from_parts(
            context,
            server_key.bootstrapping_key(),
            (context.parameters().pbs_order() == crate::PbsOrder::KeyswitchBootstrap)
                .then_some(server_key.glwe_key_switching_key()),
            key.parameters(),
            key,
            input_codec,
        )
    }

    /// Creates an evaluator and compiles the gadget-scaled identity
    /// PBSManyLUT used by circuit bootstrapping.
    ///
    /// Checks parameter, layout, decomposition-basis and input-codec compatibility,
    /// validates ManyLUT capacity for that encoding, and binds
    /// classic or sparse blind rotation. These checks do not
    /// establish a noise margin for the selected output gadget scales.
    ///
    /// `input_key_switching_key` is required for KS→BR and may be `None` for
    /// BR→KS. Any supplied KS key is validated; BR→KS does not retain it or
    /// allocate return scratch. Missing KS→BR material is reported before evaluation.
    ///
    /// # Correctness
    ///
    /// BR, optional KS, and `circuit_key` must be generated from the same paired
    /// client secrets, so blind rotation, trace projection and scheme switching
    /// use the same accumulator GLWE secret. All transformed keys must use the NTT
    /// representation of `context.table()`. Compatibility checks do not verify
    /// secret or transform identity; see the underlying
    /// [`primus_glwe::NttGlweSchemeSwitchKey::apply_to`] contract.
    pub fn try_from_parts(
        context: &'a TfheContext<T, Table>,
        bootstrapping_key: &'a BootstrappingKey<T>,
        input_key_switching_key: Option<&'a NttGlweKeySwitchingKey<T>>,
        parameters: &'a CircuitBootstrapParameters<T>,
        circuit_key: &'a CircuitBootstrapKey<T>,
        input_codec: &RoundedCodec<T, BarrettModulus<T>>,
    ) -> Result<Self, TfheEvaluationError> {
        Self::from_resources_and_parts(
            CircuitBootstrapResources::try_new(
                context,
                bootstrapping_key,
                input_key_switching_key,
            )?,
            parameters,
            circuit_key,
            input_codec,
        )
    }

    /// Consumes complete PBS workspace and preserves it for ordinary operations and recovery.
    /// Compiles the selected input encoding and allocates only additional CBS buffers;
    /// checks the supplied CBS key and ManyLUT capacity.
    ///
    /// # Correctness
    /// `circuit_key` must use the bootstrapper's accumulator secret and transform;
    /// see [`Self::try_from_parts`].
    pub fn try_from_bootstrapper(
        pbs: Evaluator<'a, T, Table>,
        circuit_key: &'a CircuitBootstrapKey<T>,
        input_codec: &RoundedCodec<T, BarrettModulus<T>>,
    ) -> Result<Self, TfheEvaluationError> {
        Self::from_resources_and_parts(
            CircuitBootstrapResources::Bootstrapper(pbs),
            circuit_key.parameters(),
            circuit_key,
            input_codec,
        )
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
        self.resources.bootstrapper_mut()
    }

    /// Recovers ordinary PBS workspace and releases CBS-only buffers.
    /// Reuses all allocations when constructed from an ordinary bootstrapper or with KS→BR order.
    /// Standalone BR→KS CBS explicitly allocates its missing return-KS workspace here.
    ///
    /// # Correctness
    /// The supplied KS key must use the original paired secrets and transform.
    /// A compatible replacement reuses the active KS stage's buffers.
    pub fn try_into_bootstrapper(
        self,
        key_switching_key: &'a NttGlweKeySwitchingKey<T>,
    ) -> Result<Evaluator<'a, T, Table>, TfheEvaluationError> {
        self.resources.try_into_bootstrapper(key_switching_key)
    }

    /// Bind the circuit parameters once and compile the gadget-scaled identity LUT.
    fn from_resources_and_parts(
        resources: CircuitBootstrapResources<'a, T, Table>,
        parameters: &'a CircuitBootstrapParameters<T>,
        circuit_key: &'a CircuitBootstrapKey<T>,
        input_codec: &RoundedCodec<T, BarrettModulus<T>>,
    ) -> Result<Self, TfheEvaluationError> {
        let context = resources.engine().context;
        let tfhe = context.parameters();
        let circuit = CircuitBootstrapBinding::try_new(tfhe, parameters, circuit_key)?;

        let glwe = tfhe.blind_rotation_ggsw();
        let lookup_table = parameters.compile_lookup_table(input_codec)?;

        let glwe_size = glwe.glwe_size();

        Ok(Self {
            resources,
            circuit,
            lookup_table,
            trace: NttGlweTraceWorkspace::new(glwe_size),
            traced: GlevCiphertext::zero(parameters.output_size().glev_len()),
        })
    }

    /// Allocates a zeroed NTT GGSW with this evaluator's output layout.
    /// Allocate once and reuse it with [`Self::circuit_bootstrap_to`].
    #[must_use]
    pub fn allocate_output(&self) -> NttGgsw<Vec<T>> {
        NttGgsw::zero(self.circuit.parameters.output_size().ggsw_len())
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
        let engine = self.resources.engine_mut();
        let parameters = self.circuit.parameters;
        let context = engine.context;
        let ring_len = parameters.output_size().glwe_size().glwe_len();
        assert_eq!(
            (
                control.as_ref().len(),
                lhs.as_ref().len(),
                rhs.as_ref().len(),
                output.as_ref().len()
            ),
            (
                parameters.output_size().ggsw_len(),
                ring_len,
                ring_len,
                ring_len
            ),
            "CMUX ciphertext layout mismatch"
        );
        engine.with_external_product(parameters.output_size(), |scratch| {
            control.cmux_to(
                lhs,
                rhs,
                output,
                parameters.output_basis(),
                context.parameters().blind_rotation_ggsw().cipher_modulus(),
                context.table(),
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
        let engine = self.resources.engine_mut();
        let parameters = self.circuit.parameters;
        let context = engine.context;
        let ring_len = parameters.output_size().glwe_size().glwe_len();
        assert_eq!(
            (
                control.as_ref().len(),
                input.as_ref().len(),
                output.as_ref().len()
            ),
            (parameters.output_size().ggsw_len(), ring_len, ring_len),
            "external-product ciphertext layout mismatch"
        );
        engine.with_external_product(parameters.output_size(), |scratch| {
            control.external_product_to(
                input,
                output,
                parameters.output_basis(),
                context.parameters().blind_rotation_ggsw().cipher_modulus(),
                context.table(),
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
    pub fn circuit_bootstrap(&mut self, input: Lwe<&[T]>) -> NttGgsw<Vec<T>> {
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
    /// Input must use the external secret paired with the bound BR/KS material,
    /// this context's external LWE modulus and unsigned rounded encoding, with a
    /// plaintext in `0..ceil(t/2)` and canonical residues, where `t` is the selected
    /// input codec's plaintext modulus. Noise must fit the coarser ManyLUT rotation intervals;
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
    pub fn circuit_bootstrap_to<S>(&mut self, input: Lwe<&[T]>, output: &mut NttGgsw<S>)
    where
        S: DataMut<Elem = T>,
    {
        let engine = self.resources.engine_mut();
        let parameters = self.circuit.parameters;
        let circuit_key = self.circuit.key;
        let context = engine.context;
        let tfhe = context.parameters();
        assert_eq!(
            input.dimension(),
            tfhe.external_lwe_dimension().get(),
            "circuit-bootstrap input dimension mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            parameters.output_size().ggsw_len(),
            "circuit-bootstrap output GGSW layout mismatch"
        );

        let accumulator = engine.blind_rotate(
            input,
            self.lookup_table.polynomial(),
            self.lookup_table.padded_output_count(),
        );

        circuit_key.trace_key().project_prefix_coefficients_to(
            accumulator,
            parameters.output_basis().decompose_length().get(),
            self.traced.as_mut(),
            context.parameters().blind_rotation_ggsw().cipher_modulus(),
            context.table(),
            &mut self.trace,
        );
        // CMUX can bind the same buffers to a different output decomposition.
        engine.with_external_product(parameters.scheme_switch().size(), |scratch| {
            circuit_key.scheme_switch_key().apply_to(
                &self.traced,
                output,
                context.parameters().blind_rotation_ggsw().cipher_modulus(),
                context.table(),
                scratch,
            );
        });
    }
}

impl<T, Table> TfheContext<T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Binds the server key's optional CBS material to reusable workspace.
    /// Returns an error if the capability is absent or incompatible.
    ///
    /// # Correctness
    /// Inherits [`CircuitBootstrapEvaluator::try_new`]'s transform requirements.
    pub fn circuit_bootstrap_evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
        input_codec: &RoundedCodec<T, BarrettModulus<T>>,
    ) -> Result<CircuitBootstrapEvaluator<'a, T, Table>, TfheEvaluationError> {
        CircuitBootstrapEvaluator::try_new(self, server_key, input_codec)
    }
}
