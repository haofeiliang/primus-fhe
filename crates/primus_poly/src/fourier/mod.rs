use num_complex::Complex64;
use primus_data::{Data, DataMut, DataOwned, RawData};

mod add;
mod mul;
mod neg;
mod sub;

/// Owned Fourier polynomial.
pub type FourierPolynomialOwned = FourierPolynomial<Vec<Complex64>>;
/// Borrowed Fourier polynomial.
pub type FourierPolynomialRef<'a> = FourierPolynomial<&'a [Complex64]>;
/// Mutably borrowed Fourier polynomial.
pub type FourierPolynomialMut<'a> = FourierPolynomial<&'a mut [Complex64]>;

/// A polynomial represented by its independent complex evaluations.
#[derive(Debug, Clone, PartialEq)]
pub struct FourierPolynomial<S>(pub S)
where
    S: RawData<Elem = Complex64>;

/// Immutable iterator over Fourier polynomials.
#[derive(Debug, Clone)]
pub struct FourierPolynomialIter<'a> {
    iter: core::slice::ChunksExact<'a, Complex64>,
}
impl<'a> FourierPolynomialIter<'a> {
    /// Creates an iterator with `fourier_len` values per polynomial.
    ///
    /// Any trailing values that do not fill a complete polynomial are not yielded.
    ///
    /// # Panics
    ///
    /// Panics if `fourier_len` is zero.
    #[must_use]
    pub fn new(data: &'a [Complex64], fourier_len: usize) -> Self {
        Self {
            iter: data.chunks_exact(fourier_len),
        }
    }
}
impl<'a> Iterator for FourierPolynomialIter<'a> {
    type Item = FourierPolynomial<&'a [Complex64]>;
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(FourierPolynomial)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}
impl core::iter::DoubleEndedIterator for FourierPolynomialIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.iter.next_back().map(FourierPolynomial)
    }
}
impl core::iter::ExactSizeIterator for FourierPolynomialIter<'_> {}
impl core::iter::FusedIterator for FourierPolynomialIter<'_> {}

/// Mutable iterator over Fourier polynomials.
#[derive(Debug)]
pub struct FourierPolynomialIterMut<'a> {
    iter: core::slice::ChunksExactMut<'a, Complex64>,
}
impl<'a> FourierPolynomialIterMut<'a> {
    /// Creates an iterator with `fourier_len` values per polynomial.
    ///
    /// Any trailing values that do not fill a complete polynomial are not yielded.
    ///
    /// # Panics
    ///
    /// Panics if `fourier_len` is zero.
    #[must_use]
    pub fn new(data: &'a mut [Complex64], fourier_len: usize) -> Self {
        Self {
            iter: data.chunks_exact_mut(fourier_len),
        }
    }
}
impl<'a> Iterator for FourierPolynomialIterMut<'a> {
    type Item = FourierPolynomial<&'a mut [Complex64]>;
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(FourierPolynomial)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}
impl core::iter::DoubleEndedIterator for FourierPolynomialIterMut<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.iter.next_back().map(FourierPolynomial)
    }
}
impl core::iter::ExactSizeIterator for FourierPolynomialIterMut<'_> {}
impl core::iter::FusedIterator for FourierPolynomialIterMut<'_> {}

impl<S: RawData<Elem = Complex64>> FourierPolynomial<S> {
    /// Creates a Fourier polynomial.
    #[must_use]
    pub fn new(values: S) -> Self {
        Self(values)
    }
}
impl<S: DataOwned<Elem = Complex64>> FourierPolynomial<S> {
    /// Creates a zero polynomial.
    #[must_use]
    pub fn zero(fourier_length: usize) -> Self {
        Self(S::from_vec(vec![Complex64::default(); fourier_length]))
    }
    /// Clones a Fourier polynomial from a slice.
    #[must_use]
    pub fn from_slice(data: &[Complex64]) -> Self {
        Self(S::from_slice(data))
    }
    /// Returns the underlying owned storage.
    #[must_use]
    pub fn into_owned(self) -> S {
        self.0
    }
}
impl<S: Data<Elem = Complex64>> FourierPolynomial<S> {
    /// Returns all Fourier values.
    pub fn as_slice(&self) -> &[Complex64] {
        self.0.as_slice()
    }
    /// Returns the number of Fourier values.
    pub fn fourier_length(&self) -> usize {
        self.0.len()
    }
    /// Returns an iterator over Fourier values.
    pub fn iter(&self) -> core::slice::Iter<'_, Complex64> {
        self.0.iter()
    }
    /// Returns whether every Fourier value is zero.
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|x| *x == Complex64::default())
    }
}
impl<S: DataMut<Elem = Complex64>> FourierPolynomial<S> {
    /// Returns all Fourier values mutably.
    pub fn as_mut_slice(&mut self) -> &mut [Complex64] {
        self.0.as_mut_slice()
    }
    /// Returns a mutable iterator over Fourier values.
    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, Complex64> {
        self.0.iter_mut()
    }
    /// Copies Fourier values from `src`.
    pub fn copy_from(&mut self, src: impl AsRef<[Complex64]>) {
        self.0.copy_from_slice(src.as_ref());
    }
    /// Sets every Fourier value to zero.
    pub fn set_zero(&mut self) {
        self.0.fill(Complex64::default());
    }
}
impl<S: Data<Elem = Complex64>> AsRef<[Complex64]> for FourierPolynomial<S> {
    fn as_ref(&self) -> &[Complex64] {
        self.as_slice()
    }
}
impl<S: DataMut<Elem = Complex64>> AsMut<[Complex64]> for FourierPolynomial<S> {
    fn as_mut(&mut self) -> &mut [Complex64] {
        self.as_mut_slice()
    }
}
