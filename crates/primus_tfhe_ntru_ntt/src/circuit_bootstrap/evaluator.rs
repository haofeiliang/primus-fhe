//! One blind rotation followed by reverse-trace projection and scheme switching.

use primus_data::DataMut;
use primus_integer::FheUint;
use primus_ntru::{NlevCiphertext, NttNgswCiphertext, NttNtruTraceContext};
use primus_ntt::NttTable;
use primus_reduce::ReduceMul;
use primus_tfhe::{LookupTableError, LweCiphertext, ManyLookupTable};

use crate::{
    CircuitBootstrapKey, CircuitBootstrapParameters, ServerKey, TfheContext,
    blind_rotation::{BlindRotationWorkspace, blind_rotate_lookup_table_to},
};

/// Failure to bind fixed CBS resources or compile its internal gadget-scaled LUT.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CircuitBootstrapEvaluationError {
    /// Ordinary BR material is incompatible with the TFHE context.
    #[error("server key does not match the circuit-bootstrap context")]
    IncompatibleServerKey,
    /// CBS ring or input-domain parameters do not match the context.
    #[error("circuit-bootstrap parameters do not match the TFHE context")]
    IncompatibleParameters,
    /// The additional key uses a different ring, trace/key/output basis.
    #[error("circuit-bootstrap key does not match its parameters")]
    IncompatibleCircuitBootstrapKey,
    /// The internal ManyLUT could not be compiled.
    #[error(transparent)]
    LookupTable(#[from] LookupTableError),
}

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
    lookup_table: ManyLookupTable<T>,
    projection_indices: Vec<usize>,
    blind_rotation: BlindRotationWorkspace<T>,
    trace: NttNtruTraceContext<T>,
    projected: NlevCiphertext<Vec<T>>,
}

impl<'a, T, Table> CircuitBootstrapEvaluator<'a, T, Table>
where
    T: FheUint,
    Table: NttTable<ValueT = T>,
{
    /// Binds resources and compiles gadget-scaled identity outputs once.
    ///
    /// # Correctness
    /// The server and circuit keys were generated from the same accumulator
    /// secret and NTT representation. Layout/basis checks do not prove identity.
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
        let n = tfhe.poly_length();
        let modulus = tfhe.bootstrapping().ntru().cipher_modulus();
        let domain_len = primus_tfhe::lookup_table_domain_len(tfhe.plain_modulus_value(), n)?;
        let scalars: Vec<T> = parameters.output_basis().scalar_iter().collect();
        let lookup_table = primus_tfhe::compile_encoded_many_lookup_table(
            domain_len,
            n,
            parameters.many_lut_output_count(),
            tfhe.plain_modulus_value(),
            tfhe.external_lwe().cipher_modulus_value(),
            modulus,
            |input, index| {
                let Some(&scalar) = scalars.get(index) else {
                    return Ok(T::ZERO);
                };
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
            projection_indices: (0..parameters.output_basis().decompose_length()).collect(),
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
            tfhe.external_lwe().dimension(),
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
            self.lookup_table.output_count(),
            &mut self.blind_rotation,
            tfhe,
            self.context.table(),
        );
        // A general ManyLUT accumulator does not have a zero message tail.
        // Reverse-trace projection is valid here; prefix expansion is not.
        self.circuit_key.trace_key().project_coefficients_to(
            &self.blind_rotation.current,
            &self.projection_indices,
            self.projected.as_mut(),
            tfhe.bootstrapping().ntru().cipher_modulus(),
            self.context.table(),
            &mut self.trace,
        );
        self.circuit_key.scheme_switch_key().apply_to(
            &self.projected,
            output,
            tfhe.bootstrapping().ntru().cipher_modulus(),
            self.context.table(),
            &mut self.blind_rotation.external_product,
        );
    }
}
