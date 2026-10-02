//! Parameter construction errors, retaining the numerical cause.

use primus_decompose::ApproxSignedBasisError;
use primus_lattice::GlweSizeError;

/// Invalid GLWE layout, encoding or sampling parameters.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum GlweParameterError {
    /// Invalid ring dimensions or a flattened-length overflow.
    #[error(transparent)]
    Layout(#[from] GlweSizeError),
    /// Invalid message/ciphertext domain or fixed-scale recovery bound.
    #[error(transparent)]
    Encoding(#[from] primus_encoding::CodecError),
    /// Invalid secret sampling configuration, weight or output modulus.
    #[error(transparent)]
    SecretKey(#[from] primus_distr::SecretKeySamplerError),
    /// Invalid coefficient-domain Gaussian noise.
    #[error("invalid GLWE noise distribution")]
    Noise(#[from] primus_distr::GaussianError),
}

/// Invalid GLev/GGSW decomposition parameters or layout.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GlevParameterError {
    /// The decomposition basis could not be constructed.
    #[error(transparent)]
    InvalidBasis(#[from] ApproxSignedBasisError),
    /// The basis and GLWE ciphertext use different moduli.
    #[error("GLev decomposition basis must match the GLWE ciphertext modulus")]
    BasisModulusMismatch,
    /// The gadget layout cannot be represented by `usize` lengths.
    #[error(transparent)]
    InvalidSize(#[from] GlweSizeError),
}
