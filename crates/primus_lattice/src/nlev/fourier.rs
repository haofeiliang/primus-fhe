use num_complex::Complex64;
use primus_data::RawData;

#[allow(unused_imports)]
use crate::ntru::{FourierNtru, FourierNtruIter, FourierNtruIterMut};

#[allow(unused_imports)]
use super::Nlev;

/// A Fourier-domain [`Nlev`] ciphertext.
///
/// Each gadget level contains one independent Fourier representation of an
/// NTRU polynomial. A coefficient polynomial of length `N` occupies `N / 2`
/// complex values.
#[derive(Clone)]
pub struct FourierNlev<S>(pub S)
where
    S: RawData<Elem = Complex64>;

impl_fourier_iters!(FourierNlev);
impl_fourier_core!(FourierNlev);
impl_fourier_iter_sub!(
    FourierNlev,
    FourierNtru,
    FourierNtruIter,
    FourierNtruIterMut,
    ntru
);
impl_fourier_forward!(Nlev, FourierNlev);
impl_fourier_backward!(FourierNlev, Nlev);
