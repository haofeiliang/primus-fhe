//! Evaluation keys for patched NTT circuit bootstrapping.

use primus_glwe::{
    GadgetSize, NttGadgetDomain, NttGlweSchemeSwitchKey, NttGlweSecretKey, NttGlweTraceKey,
};
use primus_integer::FheUint;
use primus_ntt::NttTable;

use crate::{CircuitBootstrapParameters, ClientKey, KeyGenerator, TfheKeyError};

/// An error produced while generating a circuit-bootstrapping key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CircuitBootstrapKeyError {
    /// The circuit parameters belong to another TFHE accumulator context.
    #[error("circuit-bootstrap parameters are incompatible with the TFHE context")]
    IncompatibleParameters,
    /// The client key does not match the TFHE context.
    #[error(transparent)]
    ClientKey(#[from] TfheKeyError),
}

/// HomTrace and scheme-switching keys used after PBSManyLUT.
///
/// The ordinary PBS bootstrapping key remains in [`crate::ServerKey`]. This
/// object contains only the additional, optional circuit-bootstrapping
/// material.
pub struct CircuitBootstrapKey<T: FheUint> {
    trace: NttGlweTraceKey<T>,
    scheme_switch: NttGlweSchemeSwitchKey<T>,
    output_size: GadgetSize,
    trace_size: GadgetSize,
    scheme_switch_size: GadgetSize,
}

impl<T: FheUint> CircuitBootstrapKey<T> {
    pub(crate) fn is_compatible(&self, parameters: &CircuitBootstrapParameters<T>) -> bool {
        self.output_size == parameters.output_size()
            && self.trace_size == parameters.trace().size()
            && self.scheme_switch_size == parameters.scheme_switch().size()
            && self.trace.basis() == parameters.trace().basis()
            && self.scheme_switch.key_basis() == parameters.scheme_switch().basis()
            && self.scheme_switch.output_size() == parameters.output_size()
            && self.scheme_switch.key_size() == parameters.scheme_switch().size()
    }

    /// Returns the HomTrace key.
    #[inline]
    pub fn trace_key(&self) -> &NttGlweTraceKey<T> {
        &self.trace
    }

    /// Returns the GLev-to-GGSW scheme-switching key.
    #[inline]
    pub fn scheme_switch_key(&self) -> &NttGlweSchemeSwitchKey<T> {
        &self.scheme_switch
    }
}

impl<'a, T, Table> KeyGenerator<'a, T, Table>
where
    T: FheUint,
    Table: NttTable<ValueT = T>,
{
    /// Generates the optional HomTrace and scheme-switching keys.
    pub fn try_generate_circuit_bootstrap_key<R>(
        &mut self,
        client_key: &ClientKey<T>,
        parameters: &CircuitBootstrapParameters<T>,
        rng: &mut R,
    ) -> Result<CircuitBootstrapKey<T>, CircuitBootstrapKeyError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let tfhe = self.context.parameters();
        if !parameters.is_compatible(tfhe) {
            return Err(CircuitBootstrapKeyError::IncompatibleParameters);
        }
        client_key.check_compatible(tfhe)?;

        let coeff_secret_key = client_key.glwe_secret_key();
        let ntt_secret_key =
            NttGlweSecretKey::from_coeff_secret_key(coeff_secret_key, self.context.table());

        let trace_domain = NttGadgetDomain::try_new(parameters.trace(), self.context.table())
            .expect("validated circuit-bootstrap trace domain must match the NTT table");
        self.gadget.resize(trace_domain.size());
        let trace = NttGlweTraceKey::generate(
            coeff_secret_key,
            &ntt_secret_key,
            &trace_domain,
            rng,
            &mut self.gadget,
        );

        let scheme_switch_domain =
            NttGadgetDomain::try_new(parameters.scheme_switch(), self.context.table())
                .expect("validated scheme-switch domain must match the NTT table");
        self.gadget.resize(scheme_switch_domain.size());
        let scheme_switch = NttGlweSchemeSwitchKey::generate(
            coeff_secret_key,
            &ntt_secret_key,
            &scheme_switch_domain,
            parameters.output_size(),
            rng,
            &mut self.gadget,
        );

        Ok(CircuitBootstrapKey {
            trace,
            scheme_switch,
            output_size: parameters.output_size(),
            trace_size: parameters.trace().size(),
            scheme_switch_size: parameters.scheme_switch().size(),
        })
    }
}
