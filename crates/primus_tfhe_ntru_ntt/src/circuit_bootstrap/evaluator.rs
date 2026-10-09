//! One blind rotation followed by reverse-trace projection and scheme switching.

use primus_data::{Data, DataMut};
use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_ntru::NtruCiphertext;
use primus_ntru::{NlevCiphertext, NttNgswCiphertext};
use primus_ntt::MonomialNttTable;
use primus_tfhe::{CircuitBootstrapLookupTable, LookupTableError};

use crate::{BootstrapResources, CircuitBootstrapKey, Lwe, TfheContext, TfheEvaluationError};

/// Prepared NTRU circuit-bootstrapping LUT and projection buffers.
/// Common BR/EP resources are borrowed per operation; no return buffers are owned.
/// Output is NGSW under f_acc, unlike ordinary PBS's LWE output under independent s at q.
pub struct CircuitBootstrapEvaluator<'a, T, Table, LM = primus_modulus::BarrettModulus<T>>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    context: &'a TfheContext<T, Table, LM>,
    circuit_key: &'a CircuitBootstrapKey<T>,
    lookup_table: CircuitBootstrapLookupTable<T>,
    trace_scratch: Vec<T>,
    projected: NlevCiphertext<Vec<T>>,
}

impl<'a, T, Table, LM> CircuitBootstrapEvaluator<'a, T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Binds the circuit key, compiles the gadget-scaled identity LUT, and allocates
    /// projection scratch. Does not retain a borrow of the resource owner itself.
    /// Online calls accept resources made from the same context.
    ///
    /// # Correctness
    /// The circuit key must share the resources' actual accumulator secret and
    /// NTT representation; compatibility checks do not establish these identities.
    /// Switching between classic and sparse resources must preserve both secrets.
    pub fn try_new(
        resources: &BootstrapResources<'a, T, Table, LM>,
        circuit_key: &'a CircuitBootstrapKey<T>,
        input_codec: &RoundedCodec<T, LM>,
    ) -> Result<Self, TfheEvaluationError> {
        let context = resources.context;
        let tfhe = context.parameters();
        circuit_key.check_parameters(tfhe)?;
        if input_codec.ciphertext_modulus().explicit_value()
            != tfhe.external_lwe().cipher_modulus_value()
        {
            return Err(LookupTableError::InputModulusMismatch.into());
        }
        let lookup_table = circuit_key.parameters().compile_lookup_table(input_codec)?;
        Ok(Self::from_lookup_table(context, circuit_key, lookup_table))
    }

    /// Binds a precompiled integer CBS program without cloning or recompilation.
    /// Checks its N, external q, accumulator Q and exact output gadget basis
    /// against the circuit key before allocating projection storage.
    /// Both classic and sparse BR use this same path.
    ///
    /// # Correctness
    /// Inherits [`Self::try_new`]'s secret and representation requirements. Noise
    /// must satisfy [`Self::circuit_bootstrap_to`] and the consuming operation.
    /// Inputs must use the encoding selected at program compilation. CMux requires
    /// the function to return a bit throughout the programmed input domain.
    pub fn try_with_lookup_table(
        resources: &BootstrapResources<'a, T, Table, LM>,
        circuit_key: &'a CircuitBootstrapKey<T>,
        lookup_table: CircuitBootstrapLookupTable<T>,
    ) -> Result<Self, TfheEvaluationError> {
        let context = resources.context;
        let tfhe = context.parameters();
        circuit_key.check_parameters(tfhe)?;
        if !lookup_table.is_compatible(
            tfhe.poly_length(),
            tfhe.external_lwe().cipher_modulus_value(),
            circuit_key.parameters().output_basis(),
        ) {
            return Err(TfheEvaluationError::IncompatibleCircuitBootstrapLookupTable);
        }
        Ok(Self::from_lookup_table(context, circuit_key, lookup_table))
    }

    /// Allocates projection storage after compilation or external program binding
    /// establishes the program/key/context pairing. No checks are repeated here.
    pub(super) fn from_lookup_table(
        context: &'a TfheContext<T, Table, LM>,
        circuit_key: &'a CircuitBootstrapKey<T>,
        lookup_table: CircuitBootstrapLookupTable<T>,
    ) -> Self {
        let n = context.parameters().poly_length().get();
        Self {
            context,
            circuit_key,
            lookup_table,
            trace_scratch: vec![T::ZERO; 2 * n],
            projected: NlevCiphertext::zero(circuit_key.parameters().output_nlev_len()),
        }
    }

    /// Allocates a zeroed NTT NGSW with this evaluator's output layout.
    /// Allocate once and reuse it with [`Self::circuit_bootstrap_to`].
    #[must_use]
    pub fn allocate_output(&self) -> NttNgswCiphertext<Vec<T>> {
        NttNgswCiphertext::zero(self.circuit_key.parameters().output_nlev_len())
    }

    /// Allocates the output NGSW. Inherits [`Self::circuit_bootstrap_to`]'s contracts.
    #[must_use]
    pub fn circuit_bootstrap(
        &mut self,
        input: Lwe<&[T]>,
        resources: &mut BootstrapResources<'a, T, Table, LM>,
    ) -> NttNgswCiphertext<Vec<T>> {
        let mut output = self.allocate_output();
        self.circuit_bootstrap_to(input, &mut output, resources);
        output
    }

    /// Writes `NGSW_f_acc[F(m)]` with the configured output gadget scalars.
    /// Reuses one BR, trace workspace and coefficient NLev allocation.
    ///
    /// # Correctness
    /// Input uses this context's external client secret, modulus and unsigned
    /// rounded LWE encoding, with m in `0..ceil(t/2)`. Canonical residues and a
    /// noise margin for the coarser ManyLUT windows are required. Trace and
    /// scheme-switch errors must fit the independent CBS budget, including f/f²
    /// amplification; see [`crate::CbsGadgetParameters`]. CMux requires
    /// `F(m)` in `{0, 1}` throughout the programmed domain.
    /// The default identity program uses `F(m)=m`. The output uses gadget scales,
    /// not ordinary plaintext or Boolean encoding.
    ///
    /// # Panics
    /// Panics before output writes if input dimension or output NGSW length is
    /// wrong, or resources use a different context binding. Fixed LUT
    /// geometry was checked during construction.
    pub fn circuit_bootstrap_to<S: DataMut<Elem = T>>(
        &mut self,
        input: Lwe<&[T]>,
        output: &mut NttNgswCiphertext<S>,
        resources: &mut BootstrapResources<'a, T, Table, LM>,
    ) {
        resources.check_context(self.context);
        let parameters = self.circuit_key.parameters();
        let circuit_key = self.circuit_key;
        let tfhe = resources.context.parameters();
        assert_eq!(
            input.dimension(),
            tfhe.external_lwe_dimension().get(),
            "circuit-bootstrap input dimension mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            parameters.output_nlev_len(),
            "circuit-bootstrap NGSW output length mismatch"
        );
        resources.blind_rotate(
            input,
            self.lookup_table.polynomial(),
            self.lookup_table.padded_output_count(),
        ); // A general ManyLUT accumulator does not have a zero message tail.
        // Reverse-trace projection is valid here; prefix expansion is not.
        circuit_key
            .trace_key()
            .project_prefix_coefficients_with_scratch_to(
                &resources.blind_rotation.current,
                parameters.output_basis().decompose_length().get(),
                self.projected.as_mut(),
                tfhe.accumulator_ntru().cipher_modulus(),
                resources.context.table(),
                &mut self.trace_scratch,
                resources.blind_rotation.rotation.external_product(),
            );
        circuit_key.scheme_switch_key().apply_to(
            &self.projected,
            output,
            tfhe.accumulator_ntru().cipher_modulus(),
            resources.context.table(),
            resources.blind_rotation.rotation.external_product(),
        );
    }
}

// Operations that consume a CBS control using the shared product scratch.
impl<'a, T, Table, LM> CircuitBootstrapEvaluator<'a, T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
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
    /// Panics before output writes on a different context binding or a
    /// wrong ciphertext length.
    pub fn cmux_to<A, B, C, D>(
        &self,
        control: &NttNgswCiphertext<A>,
        lhs: &NtruCiphertext<B>,
        rhs: &NtruCiphertext<C>,
        output: &mut NtruCiphertext<D>,
        resources: &mut BootstrapResources<'a, T, Table, LM>,
    ) where
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: Data<Elem = T>,
        D: DataMut<Elem = T>,
    {
        resources.check_context(self.context);
        super::control::cmux_to(
            self.circuit_key.parameters(),
            control.as_view(),
            lhs.as_view(),
            rhs.as_view(),
            output.as_mut_view(),
            resources,
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
    /// Panics before output writes on a different context binding or a
    /// wrong ciphertext length.
    pub fn external_product_to<A, B, C>(
        &self,
        control: &NttNgswCiphertext<A>,
        input: &NtruCiphertext<B>,
        output: &mut NtruCiphertext<C>,
        resources: &mut BootstrapResources<'a, T, Table, LM>,
    ) where
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        resources.check_context(self.context);
        super::control::external_product_to(
            self.circuit_key.parameters(),
            control.as_view(),
            input.as_view(),
            output.as_mut_view(),
            resources,
        );
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Prepares the configured gadget identity CBS using shared resources and an independent key.
    /// Uses this context's input encoding and gadgets; no return scratch is allocated.
    /// Resources must belong to this exact context. Advanced constructors on
    /// [`CircuitBootstrapEvaluator`] permit explicit programs and encoding overrides.
    ///
    /// # Correctness
    /// Inherits [`CircuitBootstrapEvaluator::try_new`]'s secret, representation and noise contracts.
    pub fn circuit_bootstrap_evaluator_with_resources<'a>(
        &'a self,
        resources: &BootstrapResources<'a, T, Table, LM>,
        circuit_key: &'a CircuitBootstrapKey<T>,
    ) -> Result<CircuitBootstrapEvaluator<'a, T, Table, LM>, TfheEvaluationError> {
        let parameters = self.check_circuit_bootstrap_binding(resources, circuit_key)?;
        CircuitBootstrapEvaluator::try_new(resources, circuit_key, parameters.input_codec())
    }
}
