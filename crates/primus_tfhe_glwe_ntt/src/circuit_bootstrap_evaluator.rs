//! Patched NTT circuit bootstrapping using PBSManyLUT, HomTrace, and scheme
//! switching.

use primus_data::DataMut;
use primus_glwe::{
    GlevCiphertext, GlweCiphertext, NttGadgetDomain, NttGlweKeySwitchingContext,
    NttGlweSchemeSwitchContext, NttGlweTraceContext,
};
use primus_integer::FheUint;
use primus_lattice::ggsw::NttGgsw;
use primus_lwe::LweCiphertext;
use primus_ntt::NttTable;
use primus_reduce::{Modulus, ReduceInv, ReduceMul};
use primus_tfhe::{Ciphertext, LookupTableError, ManyLookupTable};
use primus_tfhe_glwe::GlwePbsOrder as PbsOrder;

use crate::{
    CircuitBootstrapKey, CircuitBootstrapParameters, NttGlweBlindRotationContext, ServerKey,
    TfheContext,
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
    /// The HomTrace or scheme-switching key has another layout.
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
    inverse_poly_length: T,
    key_switching_domain: NttGadgetDomain<'a, T, primus_modulus::BarrettModulus<T>, Table>,
    bootstrapping_domain: NttGadgetDomain<'a, T, primus_modulus::BarrettModulus<T>, Table>,
    trace_domain: NttGadgetDomain<'a, T, primus_modulus::BarrettModulus<T>, Table>,
    scheme_switch_domain: NttGadgetDomain<'a, T, primus_modulus::BarrettModulus<T>, Table>,
    blind_rotation: NttGlweBlindRotationContext<T>,
    key_switching: NttGlweKeySwitchingContext<T>,
    trace: NttGlweTraceContext<T>,
    scheme_switch: NttGlweSchemeSwitchContext<T>,
    main_glwe: GlweCiphertext<Vec<T>>,
    switched: GlweCiphertext<Vec<T>>,
    small_lwe: LweCiphertext<T>,
    refreshed: GlevCiphertext<Vec<T>>,
    traced: GlevCiphertext<Vec<T>>,
}

impl<'a, T, Table> CircuitBootstrapEvaluator<'a, T, Table>
where
    T: FheUint,
    Table: NttTable<ValueT = T>,
{
    /// Creates an evaluator and compiles the gadget-scaled identity
    /// PBSManyLUT used by circuit bootstrapping.
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
        let gadget_scalars: Vec<T> = parameters.output().basis().scalar_iter().collect();
        let lookup_table = primus_tfhe::compile_encoded_many_lookup_table(
            domain_len,
            poly_length,
            parameters.many_lut_output_count(),
            tfhe.small_lwe().plaintext_codec(),
            tfhe.small_lwe().cipher_modulus().explicit_value(),
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

        let poly_length_value = T::try_from(poly_length)
            .expect("validated NTT polynomial length must fit the coefficient type");
        let inverse_poly_length = modulus.reduce_inv(poly_length_value);
        let key_switching_domain = context.key_switching_domain();
        let key_switching_glwe_size = key_switching_domain.size().glwe_size();
        let bootstrapping_domain = context.bootstrapping_domain();
        let trace_domain = NttGadgetDomain::try_new(parameters.trace(), context.table())
            .expect("validated circuit-bootstrap trace domain must match the NTT table");
        let scheme_switch_domain =
            NttGadgetDomain::try_new(parameters.scheme_switch(), context.table())
                .expect("validated scheme-switch domain must match the NTT table");
        let glwe_size = glwe.size();

        Ok(Self {
            context,
            server_key,
            parameters,
            circuit_key,
            lookup_table,
            inverse_poly_length,
            key_switching_domain,
            blind_rotation: NttGlweBlindRotationContext::new(bootstrapping_domain.size()),
            bootstrapping_domain,
            key_switching: NttGlweKeySwitchingContext::new(key_switching_glwe_size),
            trace: NttGlweTraceContext::new(glwe_size),
            scheme_switch: NttGlweSchemeSwitchContext::new(scheme_switch_domain.size()),
            trace_domain,
            scheme_switch_domain,
            main_glwe: GlweCiphertext::zero(glwe.glwe_len()),
            switched: GlweCiphertext::zero(tfhe.glwe_key_switching().output().glwe_len()),
            small_lwe: LweCiphertext::zero(tfhe.small_lwe().dimension()),
            refreshed: GlevCiphertext::zero(parameters.output().glev_len()),
            traced: GlevCiphertext::zero(parameters.output().glev_len()),
        })
    }

    /// Circuit-bootstraps into a newly allocated NTT GGSW ciphertext.
    pub fn circuit_bootstrap(&mut self, input: &Ciphertext<T>) -> NttGgsw<Vec<T>> {
        let mut output = NttGgsw::zero(self.parameters.output().ggsw_len());
        self.circuit_bootstrap_to(input, &mut output);
        output
    }

    /// Converts an external LWE ciphertext into an NTT GGSW under the main
    /// GLWE key.
    pub fn circuit_bootstrap_to<S>(&mut self, input: &Ciphertext<T>, output: &mut NttGgsw<S>)
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
            self.parameters.output().ggsw_len(),
            "circuit-bootstrap output GGSW layout mismatch"
        );

        let small_lwe = match tfhe.pbs_order() {
            PbsOrder::BootstrapKeyswitch => input.as_lwe(),
            PbsOrder::KeyswitchBootstrap => {
                self.prepare_small_lwe(input);
                &self.small_lwe
            }
        };
        self.server_key
            .bootstrapping_key()
            .ntt_blind_rotate_many_lookup_table_to(
                small_lwe,
                self.lookup_table.polynomial(),
                self.lookup_table.output_count(),
                &mut self.main_glwe,
                &self.bootstrapping_domain,
                &mut self.blind_rotation,
            );

        let glwe = tfhe.glwe();
        let poly_length = glwe.poly_length();
        let two_n = 2 * poly_length;
        for (index, mut level) in self.refreshed.iter_glwe_mut(glwe.glwe_len()).enumerate() {
            let exponent = index.wrapping_neg() & (two_n - 1);
            self.main_glwe.mul_monomial_to(
                exponent,
                &mut level,
                poly_length,
                glwe.cipher_modulus(),
            );
        }

        self.refreshed
            .mul_scalar_assign(self.inverse_poly_length, glwe.cipher_modulus());
        for (refreshed, mut traced) in self
            .refreshed
            .iter_glwe(glwe.glwe_len())
            .zip(self.traced.iter_glwe_mut(glwe.glwe_len()))
        {
            self.circuit_key.trace_key().apply_to(
                &refreshed,
                &mut traced,
                &self.trace_domain,
                &mut self.trace,
            );
        }
        self.circuit_key.scheme_switch_key().apply_to(
            &self.traced,
            output,
            &self.scheme_switch_domain,
            &mut self.scheme_switch,
        );
    }

    fn prepare_small_lwe(&mut self, input: &Ciphertext<T>) {
        let tfhe = self.context.parameters();
        let glwe = tfhe.glwe();
        input.as_lwe().inverse_extract_glwe_to(
            &mut self.main_glwe,
            glwe.poly_length(),
            glwe.cipher_modulus(),
        );
        self.server_key.glwe_key_switching_key().key_switch_to(
            &self.main_glwe,
            &mut self.switched,
            &self.key_switching_domain,
            &mut self.key_switching,
        );
        self.switched.extract_compact_lwe_to(
            &mut self.small_lwe,
            glwe.poly_length(),
            glwe.cipher_modulus(),
        );
    }
}
