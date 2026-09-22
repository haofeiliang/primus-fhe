//! NTT backend for GLWE-based TFHE.
//!
//! # Start here
//!
//! 1. Check mathematical choices with [`TfheParameters::try_from_config`].
//! 2. Create a [`TfheContext`] and paired [`ClientKey`]/[`ServerKey`] with
//!    [`TfheContext::try_generate_keys`]; `None` selects ordinary PBS material.
//! 3. Bind [`Encryptor`], [`Decryptor`] and [`Evaluator`] from that context.
//! 4. Compile through [`TfheParameters::compile_lookup_table_fn`], then reuse
//!    [`Evaluator::apply_lookup_table_to`] with caller-owned LWE output storage.
//!    Outputs use the parameter codec and [`Decryptor::decrypt`] by default.
//!    Use [`TfheParameters::compile_lookup_table_with_codec_fn`] for a different output
//!    encoding, then decode [`Decryptor::decrypt_phase`] with that codec.
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
//! borrow ordinary PBS operations; `into_bootstrapper` recovers the underlying evaluator.
//! The specialized constructors document their allocation and recovery contracts.
//!
//! # Composition and representation
//!
//! [`key`] contains evaluation material and component generation. Common workflow types
//! are re-exported at this root; lower-level material is documented in its own module.
//! [`bootstrapping_key`] and [`blind_rotation`] expose raw ring-control operations.
//! Both PBS orders and classic binary/ternary or sparse binary keys are supported.
//! Keys and values must use this context's NTT root and ordering convention.
//! Raw ciphertexts do not record secret identity, encoding or noise margins.

#![deny(missing_docs)]

use primus_modulus::BarrettModulus;

mod accumulator;
pub mod blind_rotation;
pub mod bootstrapping_key;
pub mod circuit_bootstrap;
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
pub use blind_rotation::NttGlweBlindRotationContext;
#[doc(no_inline)]
pub use bootstrapping_key::NttGlweBootstrappingKey;
#[doc(no_inline)]
pub use circuit_bootstrap::CircuitBootstrapKey;
#[doc(inline)]
pub use circuit_bootstrap::{CircuitBootstrapEvaluator, CircuitBootstrapParameters};
pub use context::TfheContext;
#[doc(inline)]
pub use evaluator::Evaluator;
#[doc(inline)]
pub use factorized::{FactorizedEvaluator, NttFactorizedLookupTable};
#[doc(no_inline)]
pub use key::BootstrappingKey;
#[doc(inline)]
pub use key::{KeyGenerator, ServerKey};
pub use primus_tfhe::{
    BivariateLookupTable, CircuitBootstrapConfig, ClientError, DecompositionConfig,
    FactorizedLookupTable, InterleavedLookupTable, LookupTable, LweCiphertext, LweSecretKeyRef,
};
pub use primus_tfhe_glwe::{ClientKey, EncryptionKey, PbsOrder};
#[doc(no_inline)]
pub use sparse::{SparseGlweBlindRotationContext, SparseGlweBootstrappingKey};

pub use boolean::{
    BooleanDecryptor, BooleanEncryptor, BooleanError, BooleanEvaluator, BooleanGate,
};

/// Encryptor role for the explicit-modulus NTT backend.
///
/// Borrows an external LWE secret or public key selected by the context.
pub type Encryptor<'a, T, Key = LweSecretKeyRef<'a, T>> =
    primus_tfhe_glwe::Encryptor<'a, T, BarrettModulus<T>, Key>;

/// Client-key decryptor for the explicit-modulus NTT backend.
pub type Decryptor<'a, T> = primus_tfhe_glwe::Decryptor<'a, T, BarrettModulus<T>>;

/// Named mathematical choices for this backend; moduli are derived from the LWE parameters.
pub type TfheConfig<T> = primus_tfhe_glwe::TfheConfig<T, BarrettModulus<T>>;

/// GLWE-TFHE parameters for the explicit-modulus NTT backend.
pub type TfheParameters<T> = primus_tfhe_glwe::TfheParameters<T, BarrettModulus<T>>;
