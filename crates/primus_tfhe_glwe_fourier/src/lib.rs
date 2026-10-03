//! Native-torus Fourier backend for GLWE-based TFHE.
//!
//! # Start here
//!
//! 1. Check mathematical choices with [`TfheParameters::try_from_config`].
//! 2. Create a [`TfheContext`] and paired [`ClientKey`]/[`ServerKey`] with
//!    [`TfheContext::try_generate_keys`]; `None` selects ordinary PBS material.
//! 3. Choose a Rounded message codec; bind [`Encryptor`] and [`Decryptor`] with it,
//!    and create an [`Evaluator`] from the context.
//! 4. Pass the input codec to [`TfheParameters::lookup_table_compiler`] and call
//!    [`LookupTableCompiler::compile_fn`]. Reuse [`Evaluator::apply_lookup_table_to`]
//!    with caller-owned LWE output storage. Default outputs retain the input codec's
//!    plaintext modulus and use [`Decryptor::decrypt`].
//!    [`LookupTableCompiler::try_with_output_codec`] selects another output encoding.
//!    Decode [`Decryptor::decrypt_phase`] with that output codec.
//!
//! # Other operations
//!
//! - [`InterleavedLookupTable`]: several functions of one input using ordinary PBS workspace.
//! - [`factorized`]: a prepared MVB program and [`FactorizedEvaluator`], with Scaled outputs.
//! - [`boolean`]: Boolean clients and gates with plaintext modulus four.
//! - [`circuit_bootstrap`]: optional trace/scheme-switch material and
//!   [`CircuitBootstrapEvaluator`], producing accumulator-secret gadget controls for CMUX.
//! - [`sparse`]: fixed-weight binary bucket material; select it explicitly at key generation.
//!
//! [`FactorizedEvaluator::bootstrapper_mut`] and [`CircuitBootstrapEvaluator::bootstrapper_mut`]
//! borrow ordinary PBS operations. MVB uses `into_bootstrapper`; CBS uses
//! [`CircuitBootstrapEvaluator::try_into_bootstrapper`] with an explicit ring KS key.
//! The specialized constructors document their allocation and recovery contracts.
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
#[doc(no_inline)]
pub use bootstrapping_key::FourierGlweBootstrappingKey;
#[doc(no_inline)]
pub use circuit_bootstrap::CircuitBootstrapKey;
#[doc(inline)]
pub use circuit_bootstrap::{CircuitBootstrapEvaluator, CircuitBootstrapParameters};
pub use context::TfheContext;
#[doc(inline)]
pub use evaluator::Evaluator;
#[doc(inline)]
pub use factorized::{FactorizedEvaluator, FourierFactorizedLookupTable};
#[doc(no_inline)]
pub use key::BootstrappingKey;
#[doc(inline)]
pub use key::{KeyGenerator, ServerKey};
pub use primus_tfhe::{
    BivariateLookupTable, CircuitBootstrapConfig, ClientError, DecompositionConfig,
    FactorizedLookupTable, InterleavedLookupTable, LookupTable, LookupTableCompiler, Lwe,
    LweCiphertext, LweSecretKeyRef,
};
pub use primus_tfhe_glwe::{ClientKey, EncryptionKey, ExternalLweSecretKey, PbsOrder};
#[doc(no_inline)]
pub use sparse::{SparseGlweBlindRotationWorkspace, SparseGlweBootstrappingKey};

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
pub type TfheParameters<T> = primus_tfhe_glwe::TfheParameters<T, NativeModulus<T>>;

/// Named mathematical choices for this backend; moduli are derived from the LWE parameters.
pub type TfheConfig<T> = primus_tfhe_glwe::TfheConfig<T, NativeModulus<T>>;
