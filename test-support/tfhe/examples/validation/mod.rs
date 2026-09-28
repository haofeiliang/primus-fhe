//! Checks grouped by mathematical family and transform representation.
//!
//! Each backend module has a profile entry point, PBS/ManyLUT/Boolean checks,
//! factorized threshold MVB, and CBS -> CMux. NTRU also checks all one-hot
//! selectors and full high-precision lookup with a shared key setup.
//!
//! These functions drive both client and server in one process. The client
//! creates secret/evaluation keys and encrypted inputs; the server compiles
//! public LUTs, owns evaluation workspaces, and returns encrypted results.
//! Parameters, encodings and LUT layouts are public agreements. `TfheContext`
//! holds public parameters and an immutable transform table, not secret keys
//! or mutable scratch. In Fourier checks both roles share that table instance
//! to preserve its transform order; each role creates its own FFT engine.
//!
//! Decryption, input guards and raw-phase oracles belong to the client. Tests
//! also inspect intermediate CBS controls/selectors with client secrets; a
//! normal lookup/CMux workflow keeps these intermediate ciphertexts on the server.
//!
//! Keep FFT/NTT key construction and gadget-phase oracles explicit. Shared
//! code belongs here only when the meaning is the same across representations:
//! `metrics` owns circular error budgets and the one-hot rotation guard;
//! `compilation` owns public LUT geometry without encryption.

pub(super) mod compilation;
pub(super) mod glwe_fourier;
pub(super) mod glwe_ntt;
mod metrics;
pub(super) mod ntru_fourier;
pub(super) mod ntru_ntt;
