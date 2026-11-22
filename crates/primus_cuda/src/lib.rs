//! Concrete CUDA execution plans for canonical modular polynomial arithmetic.
//!
//! Enable `cuda` to compile the kernels and expose the device API. Plans retain
//! their stream, kernels and root buffers. Operations submit work asynchronously;
//! use the stream's synchronization or device-to-host copy API before observing
//! results. Driver errors can be deferred, and do not imply output rollback.
//! Allocate operand views on the plan's stream to order access and deallocation.
//! Default and explicitly created streams are supported. Per-thread pseudo-streams
//! are rejected.
//! Disabling cudarc's event tracking through its unsafe API retains that API's
//! explicit synchronization obligations.

#![deny(missing_docs)]

#[cfg(feature = "cuda")]
mod cuda;

#[cfg(feature = "cuda")]
pub use cuda::{CudaError, CudaNttPlan32, CudaNttPlan64, cuda_smoke};
