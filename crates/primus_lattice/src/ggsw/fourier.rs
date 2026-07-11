use num_complex::Complex64;
use primus_data::RawData;

#[allow(unused_imports)]
use super::Ggsw;
#[allow(unused_imports)]
use crate::glev::{FourierGlev, FourierGlevIter, FourierGlevIterMut};

/// Fourier-domain GGSW ciphertext — matrix of
/// [`FourierGlev`], one per row.
///
/// ## Layout
///
/// ```text
/// |--row_0--| ... |--row_k--|
/// ```
///
/// Each row is a [`FourierGlev`] of length
/// `fourier_glev_len`.
/// Total data length: `(k + 1) * fourier_glev_len`.
#[derive(Clone)]
pub struct FourierGgsw<S>(pub S)
where
    S: RawData<Elem = Complex64>;

impl_fourier_iters!(FourierGgsw);
impl_fourier_core!(FourierGgsw);
impl_fourier_iter_sub!(
    FourierGgsw,
    FourierGlev,
    FourierGlevIter,
    FourierGlevIterMut,
    glev
);
impl_fourier_forward!(Ggsw, FourierGgsw);
impl_fourier_backward!(FourierGgsw, Ggsw);
