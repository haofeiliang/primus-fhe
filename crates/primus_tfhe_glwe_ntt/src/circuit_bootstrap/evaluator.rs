//! Patched NTT circuit bootstrapping using PBSManyLUT, reverse-trace projection, and scheme
//! switching.

use primus_data::DataMut;
use primus_glwe::{
    GlevCiphertext, GlweCiphertext, NttGlweKeySwitchingContext, NttGlweSchemeSwitchContext,
    NttGlweTraceContext,
};
use primus_integer::FheUint;
use primus_lattice::ggsw::NttGgsw;
use primus_lwe::LweCiphertext;
use primus_ntt::NttTable;
use primus_reduce::ReduceMul;
use primus_tfhe::{LookupTableError, ManyLookupTable};
use primus_tfhe_glwe::GlwePbsOrder as PbsOrder;

use crate::{
    CircuitBootstrapKey, CircuitBootstrapParameters, NttGlweBlindRotationContext, ServerKey,
    TfheContext, evaluator::prepare_small_lwe,
};

/// An error produced while constructing a circuit-bootstrap evaluator.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CircuitBootstrapEvaluationError {
    /// The ordinary PBS server key does not match the TFHE context.
    #[error("TFHE server key is incompatible with the circuit-bootstrap context")]
    IncompatibleServerKey,
    /// The circuit parameters belong to a different TFHE accumulator.
    #[error("circuit-bootstrap parameters are incompatible with the TFHE context")]
    IncompatibleParameters,
    /// The trace-projection or scheme-switching key has another layout.
    #[error("circuit-bootstrap key is incompatible with its parameters")]
    IncompatibleCircuitBootstrapKey,
    /// The circuit-bootstrap PBSManyLUT could not be compiled.
    #[error(transparent)]
    LookupTable(#[from] LookupTableError),
}

/// Reusable evaluator for the patched NTT circuit-bootstrap workflow.
///
/// After construction, [`Self::circuit_bootstrap_to`] reuses all scratch
/// buffers and performs no heap allocation.
pub struct CircuitBootstrapEvaluator<'a, T, Table>
where
    T: FheUint,
    Table: NttTable<ValueT = T>,
{
    context: &'a TfheContext<T, Table>,
    server_key: &'a ServerKey<T>,
    parameters: &'a CircuitBootstrapParameters<T>,
    circuit_key: &'a CircuitBootstrapKey<T>,
    lookup_table: ManyLookupTable<T>,
    projection_indices: Vec<usize>,
    // try_new checks resource layouts/bases; secret and NTT identity are caller contracts.
    blind_rotation: NttGlweBlindRotationContext<T>,
    key_switching: NttGlweKeySwitchingContext<T>,
    trace: NttGlweTraceContext<T>,
    scheme_switch: NttGlweSchemeSwitchContext<T>,
    main_glwe: GlweCiphertext<Vec<T>>,
    switched: GlweCiphertext<Vec<T>>,
    small_lwe: LweCiphertext<T>,
    traced: GlevCiphertext<Vec<T>>,
}

impl<'a, T, Table> CircuitBootstrapEvaluator<'a, T, Table>
where
    T: FheUint,
    Table: NttTable<ValueT = T>,
{
    /// Creates an evaluator and compiles the gadget-scaled identity
    /// PBSManyLUT used by circuit bootstrapping.
    ///
    /// Checks parameter, layout and decomposition-basis compatibility.
    ///
    /// # Correctness
    ///
    /// `server_key` and `circuit_key` must be generated from the same paired
    /// client secrets, so blind rotation, trace projection and scheme switching
    /// use the same accumulator GLWE secret. Both keys must use the NTT
    /// representation of `context.table()`. Compatibility checks do not verify
    /// secret or transform identity; see the underlying
    /// [`primus_glwe::NttGlweSchemeSwitchKey::apply_to`] contract.
    pub fn try_new(
        context: &'a TfheContext<T, Table>,
        server_key: &'a ServerKey<T>,
        parameters: &'a CircuitBootstrapParameters<T>,
        circuit_key: &'a CircuitBootstrapKey<T>,
    ) -> Result<Self, CircuitBootstrapEvaluationError> {
        let tfhe = context.parameters();
        if !server_key.is_compatible(tfhe) {
            return Err(CircuitBootstrapEvaluationError::IncompatibleServerKey);
        }
        if !parameters.is_compatible(tfhe) {
            return Err(CircuitBootstrapEvaluationError::IncompatibleParameters);
        }
        if !circuit_key.is_compatible(parameters) {
            return Err(CircuitBootstrapEvaluationError::IncompatibleCircuitBootstrapKey);
        }

        let glwe = tfhe.glwe();
        let modulus = glwe.cipher_modulus();
        let poly_length = glwe.poly_length();
        let domain_len =
            primus_tfhe::lookup_table_domain_len(tfhe.plain_modulus_value(), poly_length)?;
        let gadget_scalars: Vec<T> = parameters.output_basis().scalar_iter().collect();
        let lookup_table = primus_tfhe::compile_encoded_many_lookup_table(
            domain_len,
            poly_length,
            parameters.many_lut_output_count(),
            tfhe.plain_modulus_value(),
            tfhe.small_lwe().cipher_modulus(),
            modulus,
            |input, output_index| {
                let Some(&scalar) = gadget_scalars.get(output_index) else {
                    return Ok(T::ZERO);
                };
                let input =
                    T::try_from(input).map_err(|_| LookupTableError::PlaintextModulusTooLarge)?;
                Ok(modulus.reduce_mul(scalar, input))
            },
        )?;

        let key_switching_glwe_size = tfhe.glwe_key_switching().output().glwe_size();
        let glwe_size = glwe.size();

        Ok(Self {
            context,
            server_key,
            parameters,
            circuit_key,
            lookup_table,
            projection_indices: (0..parameters.output_basis().decompose_length()).collect(),
            blind_rotation: NttGlweBlindRotationContext::new(tfhe.bootstrapping().size()),
            key_switching: NttGlweKeySwitchingContext::new(key_switching_glwe_size),
            trace: NttGlweTraceContext::new(glwe_size),
            scheme_switch: NttGlweSchemeSwitchContext::new(parameters.scheme_switch().size()),
            main_glwe: GlweCiphertext::zero(glwe.glwe_len()),
            switched: GlweCiphertext::zero(tfhe.glwe_key_switching().output().glwe_len()),
            small_lwe: LweCiphertext::zero(tfhe.small_lwe().dimension()),
            traced: GlevCiphertext::zero(parameters.output_size().glev_len()),
        })
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
    pub fn circuit_bootstrap(&mut self, input: &LweCiphertext<T>) -> NttGgsw<Vec<T>> {
        let mut output = NttGgsw::zero(self.parameters.output_size().ggsw_len());
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
    /// budget described by [`CircuitBootstrapParameters`]. CMUX consumption
    /// requires plaintext 0 or 1. The output remains under the accumulator GLWE
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
            tfhe.ciphertext_lwe_dimension(),
            "circuit-bootstrap input dimension mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            self.parameters.output_size().ggsw_len(),
            "circuit-bootstrap output GGSW layout mismatch"
        );

        let small_lwe = match tfhe.pbs_order() {
            PbsOrder::BootstrapKeyswitch => input,
            PbsOrder::KeyswitchBootstrap => {
                prepare_small_lwe(
                    self.context,
                    self.server_key,
                    input,
                    &mut self.main_glwe,
                    &mut self.switched,
                    &mut self.small_lwe,
                    &mut self.key_switching,
                );
                &self.small_lwe
            }
        };
        self.server_key
            .bootstrapping_key()
            .ntt_blind_rotate_many_lookup_table_kernel_to(
                small_lwe,
                self.lookup_table.polynomial(),
                self.lookup_table.output_count(),
                &mut self.main_glwe,
                self.context.parameters().glwe().cipher_modulus(),
                self.context.table(),
                &mut self.blind_rotation,
            );

        self.circuit_key.trace_key().project_coefficients_to(
            &self.main_glwe,
            &self.projection_indices,
            self.traced.as_mut(),
            self.context.parameters().glwe().cipher_modulus(),
            self.context.table(),
            &mut self.trace,
        );
        self.circuit_key.scheme_switch_key().apply_to(
            &self.traced,
            output,
            self.context.parameters().glwe().cipher_modulus(),
            self.context.table(),
            &mut self.scheme_switch,
        );
    }
}
