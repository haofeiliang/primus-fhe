//! One blind rotation followed by reverse-trace projection and scheme switching.

use primus_data::{Data, DataMut};
use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_ntru::NtruCiphertext;
use primus_ntru::{NlevCiphertext, NttNgswCiphertext};
use primus_ntt::MonomialNttTable;
use primus_tfhe::{InterleavedLookupTable, LookupTableError};

use super::key::CircuitBootstrapBinding;

use crate::{
    CircuitBootstrapKey, Lwe, TfheEvaluationError,
    bootstrap::{BootstrapBinding, BootstrapResources},
};

/// Prepared NTRU circuit-bootstrapping LUT and projection buffers.
/// Common BR/EP resources are borrowed per operation; no return buffers are owned.
/// Output is NGSW under f_acc, unlike ordinary PBS's LWE output under independent s at q.
pub struct CircuitBootstrapEvaluator<'a, T, Table, LM = primus_modulus::BarrettModulus<T>>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    binding: BootstrapBinding<'a, T, Table, LM>,
    circuit: CircuitBootstrapBinding<'a, T>,
    lookup_table: InterleavedLookupTable<T>,
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
        let circuit = CircuitBootstrapBinding::try_new(tfhe, circuit_key)?;
        let parameters = circuit.parameters;
        let poly_length = tfhe.poly_length();
        let n = poly_length.get();
        if input_codec.ciphertext_modulus().explicit_value()
            != tfhe.external_lwe().cipher_modulus_value()
        {
            return Err(LookupTableError::InputModulusMismatch.into());
        }
        let lookup_table = parameters.compile_lookup_table(input_codec)?;
        Ok(Self {
            binding: resources.binding(),
            circuit,
            lookup_table,
            trace_scratch: vec![T::ZERO; 2 * n],
            projected: NlevCiphertext::zero(parameters.output_nlev_len()),
        })
    }

    /// Allocates a zeroed NTT NGSW with this evaluator's output layout.
    /// Allocate once and reuse it with [`Self::circuit_bootstrap_to`].
    #[must_use]
    pub fn allocate_output(&self) -> NttNgswCiphertext<Vec<T>> {
        NttNgswCiphertext::zero(self.circuit.parameters.output_nlev_len())
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
    /// Panics before output writes on a different context binding or a
    /// wrong ciphertext length.
    pub fn cmux_to<A, B, C, D>(
        &mut self,
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
        self.binding.check(resources);
        let parameters = self.circuit.parameters;
        let ring_len = resources.context.parameters().poly_length().get();
        assert_eq!(
            (
                control.as_ref().len(),
                lhs.as_ref().len(),
                rhs.as_ref().len(),
                output.as_ref().len()
            ),
            (parameters.output_nlev_len(), ring_len, ring_len, ring_len),
            "CMUX ciphertext layout mismatch"
        );
        control.cmux_to(
            lhs,
            rhs,
            output,
            parameters.output_basis(),
            resources
                .context
                .parameters()
                .accumulator_ntru()
                .cipher_modulus(),
            resources.context.table(),
            resources.workspace.rotation.external_product(),
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
        &mut self,
        control: &NttNgswCiphertext<A>,
        input: &NtruCiphertext<B>,
        output: &mut NtruCiphertext<C>,
        resources: &mut BootstrapResources<'a, T, Table, LM>,
    ) where
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        self.binding.check(resources);
        let parameters = self.circuit.parameters;
        let ring_len = resources.context.parameters().poly_length().get();
        assert_eq!(
            (
                control.as_ref().len(),
                input.as_ref().len(),
                output.as_ref().len()
            ),
            (parameters.output_nlev_len(), ring_len, ring_len),
            "external-product ciphertext layout mismatch"
        );
        control.external_product_to(
            input,
            output,
            parameters.output_basis(),
            resources
                .context
                .parameters()
                .accumulator_ntru()
                .cipher_modulus(),
            resources.context.table(),
            resources.workspace.rotation.external_product(),
        );
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
    /// wrong, or resources use a different context binding. Fixed LUT
    /// geometry was checked during construction.
    pub fn circuit_bootstrap_to<S: DataMut<Elem = T>>(
        &mut self,
        input: Lwe<&[T]>,
        output: &mut NttNgswCiphertext<S>,
        resources: &mut BootstrapResources<'a, T, Table, LM>,
    ) {
        self.binding.check(resources);
        let parameters = self.circuit.parameters;
        let circuit_key = self.circuit.key;
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
                &resources.workspace.current,
                parameters.output_basis().decompose_length().get(),
                self.projected.as_mut(),
                tfhe.accumulator_ntru().cipher_modulus(),
                resources.context.table(),
                &mut self.trace_scratch,
                resources.workspace.rotation.external_product(),
            );
        circuit_key.scheme_switch_key().apply_to(
            &self.projected,
            output,
            tfhe.accumulator_ntru().cipher_modulus(),
            resources.context.table(),
            resources.workspace.rotation.external_product(),
        );
    }
}
