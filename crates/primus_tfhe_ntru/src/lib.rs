//! Backend-independent client API and parameters for NTRU-based TFHE.
//!
//! # Role in the backend workflow
//!
//! [`PbsConfig`] / [`CbsConfig`] compose numerical operation choices;
//! [`PbsParameters`] owns prepared key domains and sampling state and
//! provides a [`LookupTableCompiler`] for Rounded LUTs. [`ClientKey`] owns the
//! complete setup secrets; [`Encryptor`] and [`Decryptor`] borrow only the external
//! message secret and bind its codec. Choose the NTT/Fourier
//! backend for transform tables, key generation and evaluators. Shared sparse
//! coefficient storage is provided by [`SparseNtruBootstrappingKey`].
//! Concrete backends provide experimental u64 operation/message configurations.
//! This family supplies the shared numerical configuration types and sampling state.
//! [`KeyGenerationError`] and [`TfheClientError`] report key generation and family
//! client construction; operations return shared [`ClientError`] or [`BooleanError`].
//!
//! [`PbsParameters::pbs_codecs`] defaults to equal input/output message moduli
//! through [`PbsMessageConfig`]; its output override preserves independent domains.
//! [`PbsParameters::factorized_pbs_codecs`] instead prepares Scaled MVB outputs.
//! Bind returned LWE decryption to the prepared output codec, not the input codec.
//! For CBS, [`PbsParameters::circuit_bootstrap_codecs`] prepares input and candidate
//! ring-message codecs; [`CbsParameters::compile_lookup_table_fn`]
//! programs gadget-scaled integers independently of those candidate messages.
//!
//! # Public-key clients
//!
//! [`PbsParameters::try_generate_public_key`] returns an [`LwePublicKey`] under
//! the independent binary or ternary external secret. Pass it to
//! [`PbsParameters::public_encryptor`] or a backend context's `public_encryptor`; keep the paired
//! external secret for decryption.
//!
//! Public-key identity and combined-noise requirements are documented on
//! [`EncryptionKey`]; generation parameters and storage size are documented
//! on [`PbsParameters::try_generate_public_key`].
//!
//! # Reusing client ciphertext storage
//!
//! [`Encryptor::encrypt_to`], [`Encryptor::encrypt_padded_to`] and
//! [`Encryptor::encrypt_centered_to`] overwrite a mutable [`Lwe`] view without
//! allocating, for either secret or public keys. Use `as_mut_view()` to reuse
//! an owned ciphertext, and `as_view()` to decrypt it. Message and dimension
//! errors leave output and RNG unchanged. Backend `Encryptor` aliases expose
//! these same methods.
//!
//! # Independent NTRU→LWE returns
//!
//! [`LweReturnEvaluator`] binds coefficient-domain return keys and q,
//! independent of NTT/FFT or one-hot resources. It supports scalar, shared-input
//! prefix and different-input stream returns with separately prepared scalar/batch
//! workspaces and no online allocation.

#![deny(missing_docs)]

mod circuit_bootstrap;
mod client;
mod config;
mod error;
mod key;
mod lookup_table;
mod lwe_return;
mod one_hot;
mod parameters;
mod sparse;

pub use circuit_bootstrap::CbsParameters;
pub use config::{BlindRotationConfig, CbsConfig, PbsConfig};
pub use error::{
    CircuitBootstrapParameterError, KeyGenerationError, SparseBootstrappingKeyError,
    TfheClientError, TfheKeyError, TfheParameterError,
};
pub use key::ClientKey;
pub use lwe_return::{LweReturnBatchWorkspace, LweReturnEvaluator};
pub use one_hot::{NlevSelectors, OneHotBootstrapError, OneHotLookupTable};
pub use parameters::PbsParameters;
pub use primus_tfhe::{LweConfig, ModulusConfig, ModulusConfigError};
pub use sparse::SparseNtruBootstrappingKey;

pub use primus_ntru::{NlevParameters, NtruParameters, NtruSecretKey};
pub use primus_tfhe::{
    BOOLEAN_PLAINTEXT_BITS, BivariateLookupTable, BooleanDecryptor, BooleanEncryptor, BooleanError,
    BooleanEvaluator, BooleanGate, CbsGadgetConfig, CircuitBootstrapCodecs,
    CircuitBootstrapLookupTable, ClientError, DecompositionConfig, Decryptor, EncryptionKey,
    Encryptor, FactorizedPbsCodecs, GadgetEncryptionConfig, InterleavedLookupTable, LookupTable,
    LookupTableCompiler, LookupTableError, Lwe, LweCiphertext, LweSecretKeyRef, PbsCodecs,
    PbsMessageConfig, ProgrammableBootstrap, ProgrammableBootstrapInterleaved, RoundedPbsCodecs,
    TfheEvaluationError,
};

/// LWE public key used by the public-key client encryptor.
pub use primus_lwe::LwePublicKey;
