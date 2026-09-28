//! Shared TFHE assertions and representative benchmark parameters.
//! Consumers use this crate only as a dev-dependency.
//!
//! - [`boolean`] checks truth tables and chained outputs;
//!   consumers supply their own small-parameter keys and evaluators.
//! - [`benchmark`] describes workload geometry and reference noise units.
//! - [`parameters`] constructs the larger profiles used by benchmarks and the
//!   opt-in `validate_parameters` example, not by ordinary CI tests.
//!
//! The example keeps backend setup and raw-phase checks in separate modules.
//! See `guides/development/tfhe-parameters.md` for the parameter matrix and
//! `guides/development/testing.md` for test ownership and commands.

pub mod benchmark;
pub mod boolean;
pub mod parameters;
