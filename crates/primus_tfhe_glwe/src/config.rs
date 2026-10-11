//! Numerical operation choices; samplers and transforms are prepared at setup.

use crate::{CbsGadgetConfig, GadgetEncryptionConfig, PbsMessageConfig, PbsOrder, SecretKeyDistr};
use primus_glwe::GlweDimension;
use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_shape::PolyLength;
use primus_tfhe::{BlindRotationMethod, LweConfig};

/// Ordinary PBS/ManyLUT/MVB choices, including BR and key switching.
/// Prepared by [`PbsParameters::try_from_config`](crate::PbsParameters::try_from_config).
/// CBS reuses this domain and its KS material for subsequent LWE returns.
/// Numerical preparation does not establish security or an adequate joint noise budget.
#[derive(Debug, Clone, Copy)]
pub struct PbsConfig<T: FheUint, M: RingContext<T>> {
    /// Small BR-control LWE domain; external for BR→KS.
    pub small_lwe: LweConfig<M>,
    /// GLWE mask-polynomial count shared by the accumulator and BSK ciphertexts.
    pub bsk_dimension: GlweDimension,
    /// Ring polynomial length N shared by the accumulator and BSK ciphertexts.
    pub bsk_poly_length: PolyLength,
    /// Distribution for sampling the GLWE secret that encrypts BSK ciphertexts.
    ///
    /// BR output uses this same secret; the public `(0, LUT * X^(-b))`
    /// accumulator initialization needs no secret. The input LWE secret encoded
    /// by the BSK is configured separately in `small_lwe.secret_key_distr`.
    pub bsk_secret_distr: SecretKeyDistr,
    /// BSK GGSW decomposition and coefficient-unit encryption noise.
    ///
    /// Ring encryption clients reuse this noise setting. Public GLWE accumulator
    /// initialization samples no encryption noise.
    pub bsk_gadget: GadgetEncryptionConfig,
    /// Algorithm selected when generating material; never chosen during evaluation.
    pub method: BlindRotationMethod,
    /// Independent KS decomposition and coefficient-unit row noise.
    pub key_switching: GadgetEncryptionConfig,
    /// Default input/output message moduli, selectable independently.
    pub messages: PbsMessageConfig<T>,
    /// KS placement; CBS direct input uses `BootstrapKeyswitch`.
    pub order: PbsOrder,
}

/// CBS extends the same PBS domain with trace, scheme-switch and output gadgets.
/// Direct input uses an independent LWE secret; KS is retained for downstream LWE returns.
/// Pass `pbs` and `gadget` to [`CbsParameters::try_from_config`](crate::CbsParameters::try_from_config).
#[derive(Debug, Clone, Copy)]
pub struct CbsConfig<T: FheUint, M: RingContext<T>> {
    /// Common domain, algorithm and selector-input message modulus.
    /// KS also supports LWE returns after evaluating the ring output.
    pub pbs: PbsConfig<T, M>,
    /// Trace, scheme-switch and output gadget decompositions.
    pub gadget: CbsGadgetConfig,
}
