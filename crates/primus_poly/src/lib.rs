//! Polynomial types and operations for fully homomorphic encryption.
//!
//! This crate provides several polynomial representations used in FHE schemes:
//! - [`Polynomial`]: standard coefficient-form polynomial (single modulus).
//! - [`NttPolynomial`]: polynomial in NTT domain (single modulus).
//! - [`ArrayBase`]: flat array with element-wise arithmetic.
//! - [`BigUintPolynomial`]: polynomial with big integer coefficients.
//! - [`CrtPolynomial`]: polynomial under Chinese Remainder Theorem decomposition.
//! - [`DcrtPolynomial`]: double-CRT polynomial (CRT + NTT).
//! - [`FourierPolynomial`]: polynomial in the Fourier domain (complex values).
//!
//! The polynomial wrappers are generic over their backing storage. Methods that
//! take `self` consume the wrapper and return it after updating its storage. If
//! the storage is a mutable borrow, the caller's backing slice is updated as
//! well; use the corresponding `*_assign` method when that side effect should
//! be explicit.

#![deny(missing_docs)]

#[macro_use]
mod macros;

mod array;

mod big_uint_poly;
mod crt;
mod dcrt;
mod fourier;
mod ntt;
mod poly;

pub use array::{Array, ArrayBase, ArrayMut, ArrayRef};

pub use big_uint_poly::{BigUintPolynomial, BigUintPolynomialIter, BigUintPolynomialIterMut};

pub use crt::{CrtPolynomial, CrtPolynomialIter, CrtPolynomialIterMut};
pub use dcrt::{DcrtPolynomial, DcrtPolynomialIter, DcrtPolynomialIterMut};

pub use fourier::{
    FourierPolynomial, FourierPolynomialIter, FourierPolynomialIterMut, FourierPolynomialMut,
    FourierPolynomialOwned, FourierPolynomialRef,
};

pub use ntt::{
    NttPolynomial, NttPolynomialIter, NttPolynomialIterMut, NttPolynomialMut, NttPolynomialOwned,
    NttPolynomialRef,
};
pub use poly::{
    Polynomial, PolynomialIter, PolynomialIterMut, PolynomialMut, PolynomialOwned, PolynomialRef,
};
