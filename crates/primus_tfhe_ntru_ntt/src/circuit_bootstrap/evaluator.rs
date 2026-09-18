//! One blind rotation followed by reverse-trace projection and scheme switching.

use primus_data::DataMut;
use primus_integer::FheUint;
use primus_ntru::{NlevCiphertext, NttNgswCiphertext, NttNtruTraceContext};
use primus_ntt::NttTable;
use primus_reduce::ReduceMul;
use primus_tfhe::{InterleavedLookupTable, LookupTableError, LweCiphertext};

use crate::{
    CircuitBootstrapKey, CircuitBootstrapParameters, ServerKey, TfheContext, TfheEvaluationError,
    blind_rotation::{BlindRotationWorkspace, blind_rotate_lookup_table_to},
};

/// Allocation-free online NTRU circuit bootstrapping with optional evaluation keys.
/// Output is NGSW under f_acc, unlike ordinary PBS's LWE output under f_client.
pub struct CircuitBootstrapEvaluator<'a, T, Table>
where
    T: FheUint,
    Table: NttTable<ValueT = T>,
{
    context: &'a TfheContext<T, Table>,
    server_key: &'a ServerKey<T>,
    parameters: &'a CircuitBootstrapParameters<T>,
    circuit_key: &'a CircuitBootstrapKey<T>,
    lookup_table: InterleavedLookupTable<T>,
    blind_rotation: BlindRotationWorkspace<T>,
    trace: NttNtruTraceContext<T>,
    projected: NlevCiphertext<Vec<T>>,
}

impl<'a, T, Table> CircuitBootstrapEvaluator<'a, T, Table>
where
    T: FheUint,
    Table: NttTable<ValueT = T>,
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

    /// Binds resources and compiles gadget-scaled identity outputs once.
    ///
    /// # Correctness
    /// The server and circuit keys were generated from the same accumulator
    /// secret and NTT representation. Layout/basis checks do not prove identity.
    pub fn try_from_parts(
        context: &'a TfheContext<T, Table>,
        server_key: &'a ServerKey<T>,
        parameters: &'a CircuitBootstrapParameters<T>,
        circuit_key: &'a CircuitBootstrapKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        let tfhe = context.parameters();
        if !server_key.is_compatible(tfhe) {
            return Err(TfheEvaluationError::IncompatibleServerKey);
        }
        if !parameters.is_compatible(tfhe) {
            return Err(TfheEvaluationError::IncompatibleCircuitBootstrapParameters);
        }
        if !circuit_key.is_compatible(parameters) {
            return Err(TfheEvaluationError::IncompatibleCircuitBootstrapKey);
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
            context,
            server_key,
            parameters,
            circuit_key,
            lookup_table,
            blind_rotation: BlindRotationWorkspace::new(n),
            trace: NttNtruTraceContext::new(n),
            projected: NlevCiphertext::zero(parameters.output_nlev_len()),
        })
    }

    /// Allocates the output NGSW. Inherits [`Self::circuit_bootstrap_to`]'s contracts.
    #[must_use]
    pub fn circuit_bootstrap(&mut self, input: &LweCiphertext<T>) -> NttNgswCiphertext<Vec<T>> {
        let mut output = NttNgswCiphertext::zero(self.parameters.output_nlev_len());
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
    /// amplification; see [`CircuitBootstrapParameters`]. CMUX use requires m=0/1.
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
        let tfhe = self.context.parameters();
        assert_eq!(
            input.dimension(),
            tfhe.external_lwe_dimension(),
            "circuit-bootstrap input dimension mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            self.parameters.output_nlev_len(),
            "circuit-bootstrap NGSW output length mismatch"
        );
        blind_rotate_lookup_table_to(
            self.server_key,
            input,
            self.lookup_table.polynomial(),
            self.lookup_table.padded_output_count(),
            &mut self.blind_rotation,
            tfhe,
            self.context.table(),
        );
        // A general ManyLUT accumulator does not have a zero message tail.
        // Reverse-trace projection is valid here; prefix expansion is not.
        self.circuit_key.trace_key().project_prefix_coefficients_to(
            &self.blind_rotation.current,
            self.parameters.output_basis().decompose_length(),
            self.projected.as_mut(),
            tfhe.accumulator_ntru().cipher_modulus(),
            self.context.table(),
            &mut self.trace,
        );
        self.circuit_key.scheme_switch_key().apply_to(
            &self.projected,
            output,
            tfhe.accumulator_ntru().cipher_modulus(),
            self.context.table(),
            &mut self.blind_rotation.external_product,
        );
    }
}
