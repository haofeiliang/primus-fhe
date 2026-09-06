use num_complex::Complex64;
use primus_data::RawData;

#[allow(unused_imports)]
use super::Ntru;

/// A scalar NTRU ciphertext represented by independent complex evaluations.
///
/// One negacyclic polynomial of length `N` occupies `N / 2` complex values.
#[derive(Clone)]
pub struct FourierNtru<S>(pub S)
where
    S: RawData<Elem = Complex64>;

impl_fourier_core!(FourierNtru);

impl_fourier_iters!(FourierNtru);

impl_fourier_basic_operation!(FourierNtru);
impl_fourier_polynomial!(FourierNtru);

impl_fourier_conversion!(Ntru, FourierNtru);
