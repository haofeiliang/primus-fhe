//! Native-torus Fourier backend for GLWE-based TFHE.
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
//! - [`InterleavedLookupTable`]: several functions of one input using ordinary PBS workspace.
//! - [`factorized`]: a prepared MVB program and [`FactorizedEvaluator`], with Scaled outputs.
//! - [`boolean`]: Boolean clients and gates with plaintext modulus four.
//! - [`circuit_bootstrap`]: optional trace/scheme-switch material and
//!   [`CircuitBootstrapEvaluator`], producing accumulator-secret gadget controls for CMUX.
//! - [`sparse`]: fixed-weight binary bucket material; choose [`BlindRotationAlgorithm::Sparse`]
//!   with [`KeyGenerator::try_generate_server_key`] for an existing client.
//!
//! [`Evaluator`] owns common [`BootstrapResources`] and the ordinary return stage.
//! CBS borrows common resources per operation; MVB borrows the complete evaluator.
//! Standalone resources include input KS for KS→BR, but no output KS for BR→KS.
//! The specialized constructors document their allocation and borrowing contracts.
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
//! [`bootstrapping_key`] and [`blind_rotation`] expose raw ring-control operations.
//! [`Evaluator::try_from_parts`] borrows independent BR and ring KS material.
//! CBS component binding omits KS for BR→KS, but requires it for KS→BR input preparation.
//! Both PBS orders and classic binary/ternary or sparse binary keys are supported.
//! Keys and values must use the same FFT table instance; equal lengths do not prove identity.
//! Native MVB requires an even Scaled output scale and an FFT error budget.
//! Raw ciphertexts do not record secret identity, encoding or noise margins.

#![deny(missing_docs)]

/// Experimental u64 arithmetic fixtures paired with message/operation choices.
///
/// Security and failure probability are unassessed; this module records the
/// source revision and operation contracts. Each constant contains the BR choice.
pub mod experimental;

use primus_modulus::NativeModulus;

mod accumulator;
pub mod blind_rotation;
mod bootstrap;
pub mod bootstrapping_key;
pub mod circuit_bootstrap;
mod client;
mod context;
mod error;
mod evaluator;
pub mod factorized;
pub mod key;
pub mod sparse;

pub mod boolean;

pub use error::{
    CircuitBootstrapParameterError, KeyGenerationError, LookupTableError,
    SparseBootstrappingKeyError, TfheClientError, TfheContextError, TfheEvaluationError,
    TfheKeyError, TfheParameterError,
};

pub use accumulator::AccumulatorClient;
#[doc(no_inline)]
pub use blind_rotation::FourierGlweBlindRotationWorkspace;
#[doc(inline)]
pub use bootstrap::BootstrapResources;
#[doc(no_inline)]
pub use bootstrapping_key::FourierGlweBootstrappingKey;
#[doc(no_inline)]
pub use circuit_bootstrap::CircuitBootstrapKey;
#[doc(inline)]
pub use circuit_bootstrap::{CbsParameters, CircuitBootstrapEvaluator};
pub use context::TfheContext;
#[doc(inline)]
pub use evaluator::Evaluator;
#[doc(inline)]
pub use factorized::{FactorizedEvaluator, FourierFactorizedLookupTable};
#[doc(no_inline)]
pub use key::BlindRotationKey;
#[doc(inline)]
pub use key::{CircuitBootstrapServerKey, KeyGenerator, ServerKey};
pub use primus_tfhe::{
    BivariateLookupTable, BlindRotationAlgorithm, CbsGadgetConfig, CircuitBootstrapCodecs,
    CircuitBootstrapLookupTable, ClientError, DecompositionConfig, FactorizedLookupTable,
    FactorizedPbsCodecs, GadgetEncryptionConfig, InterleavedLookupTable, LookupTable,
    LookupTableCompiler, Lwe, LweCiphertext, LweSecretKeyRef, PbsCodecs, PbsMessageConfig,
    RoundedPbsCodecs,
};
pub use primus_tfhe_glwe::SparseGlweBootstrappingKey;
pub use primus_tfhe_glwe::{ClientKey, EncryptionKey, ExternalLweSecretKey, PbsOrder};
#[doc(no_inline)]
pub use sparse::SparseGlweBlindRotationWorkspace;

pub use boolean::{
    BooleanDecryptor, BooleanEncryptor, BooleanError, BooleanEvaluator, BooleanGate,
};

/// Encryptor role for the native-torus Fourier backend.
///
/// Borrows an external LWE secret or public key selected by the context.
pub type Encryptor<'a, T, Key = LweSecretKeyRef<'a, T>> =
    primus_tfhe_glwe::Encryptor<'a, T, NativeModulus<T>, Key>;

/// Client-key decryptor for the native-torus Fourier backend.
pub type Decryptor<'a, T> = primus_tfhe_glwe::Decryptor<'a, T, NativeModulus<T>>;

/// GLWE-TFHE parameters for the native-torus Fourier backend.
pub type PbsParameters<T> = primus_tfhe_glwe::PbsParameters<T, NativeModulus<T>>;

/// Shared numerical blind-rotation choices for this backend.
pub type BlindRotationConfig<T> = primus_tfhe_glwe::BlindRotationConfig<NativeModulus<T>>;

/// Complete numerical PBS choices for this backend.
pub type PbsConfig<T> = primus_tfhe_glwe::PbsConfig<T, NativeModulus<T>>;

/// Complete numerical CBS choices for this backend.
pub type CbsConfig<T> = primus_tfhe_glwe::CbsConfig<T, NativeModulus<T>>;

pub use primus_tfhe_glwe::{CbsInput, LweConfig, ModulusConfig, ModulusConfigError};
