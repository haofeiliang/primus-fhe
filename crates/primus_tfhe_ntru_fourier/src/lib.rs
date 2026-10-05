//! Native-torus Fourier backend for NTRU-based TFHE.
//!
//! # Start here
//!
//! 1. Check mathematical choices with [`TfheParameters::try_from_config`].
//! 2. Create a [`TfheContext`] and paired [`ClientKey`]/[`ServerKey`] with
//!    [`TfheContext::try_generate_keys`] for classic BR; `None` selects ordinary PBS material.
//! 3. Bind [`Encryptor`], [`Decryptor`] and [`Evaluator`] from that context.
//! 4. Create a compiler with [`TfheParameters::lookup_table_compiler`] and call
//!    [`LookupTableCompiler::compile_fn`]. Reuse [`Evaluator::apply_lookup_table_to`]
//!    with caller-owned LWE output storage. Default outputs retain the parameter
//!    plaintext modulus and use [`Decryptor::decrypt`].
//!    [`LookupTableCompiler::try_with_output_codec`] selects another output encoding.
//!    Compile at accumulator Q; decode [`Decryptor::decrypt_phase`] with a codec
//!    at external q and the same output plaintext modulus.
//!
//! # Other operations
//!
//! - [`InterleavedLookupTable`]: several functions of one input using ordinary PBS workspace.
//! - [`factorized`]: a prepared MVB program and [`FactorizedEvaluator`], with Scaled outputs.
//! - [`boolean`]: Boolean clients and gates with plaintext modulus four.
//! - [`circuit_bootstrap`]: optional trace/scheme-switch material and
//!   [`CircuitBootstrapEvaluator`], producing accumulator-secret gadget controls for CMUX.
//! - [`sparse`]: fixed-weight binary bucket material; choose [`BlindRotationConfig::Sparse`]
//!   with [`KeyGenerator::try_generate_server_key`] for an existing client.
//!
//! [`Evaluator`] owns common [`BootstrapResources`] and client-return buffers.
//! CBS/one-hot prepare only their LUT/projection state and borrow common resources
//! for each call. [`FactorizedEvaluator`] borrows PBS for each request, retaining
//! only its extra Fourier polynomials. No ownership conversion is needed to alternate.
//! Standalone CBS/one-hot can use resources without allocating return buffers.
//! [`LweReturnEvaluator`] supports independent coefficient-domain returns.
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
//! Keys and values must use the same FFT table instance; equal lengths do not prove identity.
//! Native MVB requires an even Scaled output scale and an FFT error budget.
//! Raw ciphertexts do not record secret identity, encoding or noise margins.

#![deny(missing_docs)]

use primus_modulus::NativeModulus;

mod accumulator;
mod blind_rotation;
pub mod boolean;
mod bootstrap;
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
pub use bootstrap::BootstrapResources;
pub use context::TfheContext;
pub use error::{
    CircuitBootstrapParameterError, KeyGenerationError, LookupTableError,
    SparseBootstrappingKeyError, TfheClientError, TfheContextError, TfheEvaluationError,
    TfheKeyError, TfheParameterError,
};
#[doc(inline)]
pub use evaluator::Evaluator;
#[doc(inline)]
pub use factorized::{FactorizedEvaluator, FourierFactorizedLookupTable};
#[doc(inline)]
pub use key::{BlindRotationKey, ClassicControls, KeyGenerator, ServerKey};
#[doc(no_inline)]
pub use sparse::SparseNtruBootstrappingKey;

pub use primus_tfhe::{
    BivariateLookupTable, BlindRotationConfig, CircuitBootstrapConfig, ClientError,
    DecompositionConfig, FactorizedLookupTable, InterleavedLookupTable, LookupTable,
    LookupTableCompiler, Lwe, LweCiphertext, LweSecretKeyRef,
};
pub use primus_tfhe_ntru::{
    ClientKey, EncryptionKey, LwePublicKey, LweReturnBatchWorkspace, LweReturnEvaluator,
};

#[doc(no_inline)]
pub use circuit_bootstrap::CircuitBootstrapKey;
#[doc(inline)]
pub use circuit_bootstrap::{
    CircuitBootstrapEvaluator, CircuitBootstrapParameters, OneHotBootstrapError,
    OneHotCircuitBootstrapEvaluator, OneHotLookupTable, OneHotProjection,
};

/// Secret-key or LWE public-key encryptor for the Fourier NTRU backend.
pub type Encryptor<'a, T, Key = LweSecretKeyRef<'a, T>, LM = NativeModulus<T>> =
    primus_tfhe_ntru::Encryptor<'a, T, LM, Key>;

/// Client-key decryptor for the Fourier NTRU backend.
pub type Decryptor<'a, T, LM = NativeModulus<T>> = primus_tfhe_ntru::Decryptor<'a, T, LM>;

/// NTRU-TFHE parameters for the native-torus Fourier backend.
pub type TfheParameters<T, LM = NativeModulus<T>> =
    primus_tfhe_ntru::TfheParameters<T, NativeModulus<T>, LM>;

/// Named mathematical choices with independent accumulator Q and external LWE q.
pub type TfheConfig<T, LM = NativeModulus<T>> =
    primus_tfhe_ntru::TfheConfig<T, NativeModulus<T>, LM>;
