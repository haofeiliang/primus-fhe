//! NTT backend for NTRU-based TFHE.
//!
//! # Start here
//!
//! 1. Select [`experimental::CLASSIC_PBS_U64`], a numerical [`PbsConfig`], and
//!    call [`PbsConfig::try_prepare`] to prepare sampling state. For existing
//!    LWE parameters/bases, use [`PbsParameters::try_new`].
//! 2. Create a [`TfheContext`] and paired [`ClientKey`]/[`ServerKey`] with
//!    [`TfheContext::try_generate_keys`] and the config's `blind_rotation.algorithm`;
//!    `None` selects ordinary PBS material.
//! 3. Prepare codecs with [`PbsParameters::pbs_codecs`] and [`PbsMessageConfig`].
//!    Bind [`Encryptor`] to the input codec and [`Decryptor`] to the output codec;
//!    create an [`Evaluator`] from the context. Output message moduli default to
//!    the input choice and can be overridden before preparation.
//! 4. Pass the prepared codec pair to [`PbsParameters::lookup_table_compiler`].
//!    Call [`LookupTableCompiler::compile_fn`] and reuse
//!    [`Evaluator::apply_lookup_table_to`] with caller-owned LWE output storage.
//!    Prepared codecs distinguish accumulator-Q LUT output from external-q decoding.
//!
//! # Other operations
//!
//! [`experimental`] pairs sparse PBS, ManyLUT, MVB, CBS and one-hot with their
//! teaching message domains. Each example prepares its matching config once.
//!
//! - [`InterleavedLookupTable`]: several functions of one input using ordinary PBS workspace.
//! - [`factorized`]: a prepared MVB program and [`FactorizedEvaluator`], with Scaled outputs.
//! - [`boolean`]: Boolean clients and gates with plaintext modulus four.
//! - [`circuit_bootstrap`]: optional trace/scheme-switch material and
//!   [`CircuitBootstrapEvaluator`], producing accumulator-secret gadget controls for CMUX.
//! - [`sparse`]: fixed-weight binary bucket material; choose [`BlindRotationAlgorithm::Sparse`]
//!   with [`KeyGenerator::try_generate_server_key`] for an existing client.
//!
//! [`Evaluator`] owns common [`BootstrapResources`] and client-return buffers.
//! CBS/one-hot prepare only their LUT/projection state and borrow common resources
//! for each call. [`FactorizedEvaluator`] borrows PBS for each request, retaining
//! only its extra NTT polynomial. No ownership conversion is needed to alternate.
//! Standalone CBS/one-hot can use resources without allocating return buffers.
//! [`LweReturnEvaluator`] supports independent coefficient-domain returns.
//!
//! Ring-output CBS can use [`TfheContext::try_generate_circuit_bootstrap_keys`]
//! without ordinary return material. [`PbsParameters::circuit_bootstrap_codecs`]
//! prepares the independent input and candidate ring-message encodings. Compile F
//! with [`CbsParameters::compile_lookup_table_fn`] and bind the program
//! with [`CircuitBootstrapEvaluator::try_with_lookup_table`]. CBS output uses its
//! gadget basis; CMux requires bit-valued F across the programmed input domain.
//!
//! # Composition and representation
//!
//! [`key`] contains evaluation material and component generation. Common workflow types
//! are re-exported at this root; lower-level material is documented in its own module.
//! [`BlindRotationKey`], [`primus_ntru::NtruLweKeySwitchingKey`] and
//! [`CircuitBootstrapKey`] can be independently generated and borrowed through
//! [`Evaluator::try_from_parts`] or [`BootstrapResources::try_new`] plus CBS/one-hot
//! `try_new`. [`ServerKey::into_parts`] moves out the bundle's components.
//! CBS/one-hot needs only BR and CBS material; high-precision LUT also needs return.
//! Classic binary/ternary and sparse fixed-weight binary BR support PBS, MVB,
//! CBS and one-hot. CBS/one-hot require trace and scheme-switch material.
//! Only accumulator secrets undergo NTRU invertibility screening; external LWE secrets are independent.
//! Keys and values must use this context's NTT root and ordering convention.
//! Raw ciphertexts do not record secret identity, encoding or noise margins.

#![deny(missing_docs)]

/// Experimental u64 arithmetic fixtures paired with message/operation choices.
///
/// Security and failure probability are unassessed; this module records the
/// source revision and operation contracts. Each constant contains the BR choice.
pub mod experimental;

use primus_modulus::BarrettModulus;

mod accumulator;
mod blind_rotation;
pub mod boolean;
mod bootstrap;
pub use bootstrap::BootstrapResources;
pub mod circuit_bootstrap;
mod client;
mod context;
mod error;
mod evaluator;
pub mod factorized;
pub mod key;
pub mod sparse;

pub use accumulator::AccumulatorClient;
pub use boolean::{
    BooleanDecryptor, BooleanEncryptor, BooleanError, BooleanEvaluator, BooleanGate,
};
pub use context::TfheContext;
pub use error::{
    CircuitBootstrapParameterError, KeyGenerationError, LookupTableError,
    SparseBootstrappingKeyError, TfheClientError, TfheContextError, TfheEvaluationError,
    TfheKeyError, TfheParameterError,
};
#[doc(inline)]
pub use evaluator::Evaluator;
#[doc(inline)]
pub use factorized::{FactorizedEvaluator, NttFactorizedLookupTable};
#[doc(inline)]
pub use key::{
    BlindRotationKey, CircuitBootstrapServerKey, ClassicControls, KeyGenerator, ServerKey,
};
#[doc(no_inline)]
pub use primus_tfhe_ntru::SparseNtruBootstrappingKey;

pub use primus_tfhe::{
    BivariateLookupTable, BlindRotationAlgorithm, CbsGadgetConfig, CircuitBootstrapCodecs,
    CircuitBootstrapLookupTable, ClientError, DecompositionConfig, FactorizedLookupTable,
    FactorizedPbsCodecs, GadgetEncryptionConfig, InterleavedLookupTable, LookupTable,
    LookupTableCompiler, Lwe, LweCiphertext, LweSecretKeyRef, PbsCodecs, PbsMessageConfig,
    RoundedPbsCodecs,
};
pub use primus_tfhe_ntru::{
    ClientKey, EncryptionKey, LwePublicKey, LweReturnBatchWorkspace, LweReturnEvaluator,
};

#[doc(no_inline)]
pub use circuit_bootstrap::CircuitBootstrapKey;
#[doc(inline)]
pub use circuit_bootstrap::{
    CbsParameters, CircuitBootstrapEvaluator, NlevSelectors, NttNgswSelectors,
    OneHotBootstrapError, OneHotCircuitBootstrapEvaluator, OneHotLookupTable, OneHotProjection,
};

/// Secret-key or LWE public-key encryptor for the exact NTT NTRU backend.
pub type Encryptor<'a, T, Key = LweSecretKeyRef<'a, T>, LM = BarrettModulus<T>> =
    primus_tfhe_ntru::Encryptor<'a, T, LM, Key>;

/// Client-key decryptor for the exact NTT NTRU backend.
pub type Decryptor<'a, T, LM = BarrettModulus<T>> = primus_tfhe_ntru::Decryptor<'a, T, LM>;

/// NTRU-TFHE parameters for the explicit-modulus NTT backend.
pub type PbsParameters<T, LM = BarrettModulus<T>> =
    primus_tfhe_ntru::PbsParameters<T, BarrettModulus<T>, LM>;

/// Shared numerical blind-rotation choices for this backend.
pub type BlindRotationConfig<T, LM = BarrettModulus<T>> =
    primus_tfhe_ntru::BlindRotationConfig<BarrettModulus<T>, LM>;

/// Complete numerical PBS choices for this backend.
pub type PbsConfig<T, LM = BarrettModulus<T>> =
    primus_tfhe_ntru::PbsConfig<T, BarrettModulus<T>, LM>;

/// Complete numerical CBS choices for this backend.
pub type CbsConfig<T, LM = BarrettModulus<T>> =
    primus_tfhe_ntru::CbsConfig<T, BarrettModulus<T>, LM>;

pub use primus_tfhe_ntru::{LweConfig, ModulusConfig, ModulusConfigError};
