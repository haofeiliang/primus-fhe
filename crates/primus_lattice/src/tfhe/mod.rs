//! TFHE external product in the Fourier domain.
//!
//! Torus type aliases ([`TorusLwe`](crate::lwe::TorusLwe),
//! [`TorusGlwe`](crate::glwe::TorusGlwe),
//! [`TorusGlev`](crate::glev::TorusGlev),
//! [`TorusGgsw`](crate::ggsw::TorusGgsw)) are defined alongside their
//! base ciphertext types. Coefficient ↔ Fourier conversions
//! (`write_fourier_form` / `write_torus_form`) are generated via
//! `impl_fourier_forward!` / `impl_fourier_backward!` in each
//! Fourier variant module.

pub mod cmux;
pub mod external_product;
