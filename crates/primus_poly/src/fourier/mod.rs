use primus_data::{Data, DataMut, DataOwned, RawData};

mod add;
pub(crate) mod constants;
mod mul;
mod neg;
mod simd;
mod sub;

/// Owned [`FourierPolynomial`] backed by a [`Vec`].
pub type FourierPolynomialOwned = FourierPolynomial<Vec<f64>>;
/// Borrowed [`FourierPolynomial`] backed by an immutable slice.
pub type FourierPolynomialRef<'a> = FourierPolynomial<&'a [f64]>;
/// Mutably borrowed [`FourierPolynomial`] backed by a mutable slice.
pub type FourierPolynomialMut<'a> = FourierPolynomial<&'a mut [f64]>;

/// A container for Fourier-domain values in split `[re | im]` f64 layout.
///
/// Represents one negacyclic FFT component in the Fourier domain under
/// `Z[X] / (X^N + 1)`.  Unlike coefficient [`Polynomial`](crate::Polynomial),
/// this type does not carry a modulus or support modular arithmetic —
/// Fourier operations are approximate floating-point arithmetic.
///
/// # Layout
///
/// The underlying storage is `[re_0, ..., re_{m-1}, im_0, ..., im_{m-1}]`
/// where `m = fourier_length()`.  Total element count is `2 * fourier_length()`.
///
/// # Storage polymorphism
///
/// `S` abstracts over the memory backend.  Common aliases:
/// - [`FourierPolynomialOwned`] — owned `Vec<f64>`
/// - [`FourierPolynomialRef`] — borrowed `&[f64]`
/// - [`FourierPolynomialMut`] — mutably borrowed `&mut [f64]`
#[derive(Debug, Clone, PartialEq)]
pub struct FourierPolynomial<S>(pub S)
where
    S: RawData<Elem = f64>;

// ---------------------------------------------------------------------------
// Iterators
// ---------------------------------------------------------------------------

/// Immutable chunked iterator over [`FourierPolynomial`] components.
#[derive(Debug, Clone)]
pub struct FourierPolynomialIter<'a> {
    /// The underlying chunked iterator.
    pub iter: core::slice::ChunksExact<'a, f64>,
}

impl<'a> FourierPolynomialIter<'a> {
    /// Creates a new iterator yielding chunks of `2 * fourier_len` f64 values
    /// (one split Fourier polynomial each).
    #[inline]
    pub fn new(data: &'a [f64], fourier_len: usize) -> Self {
        Self {
            iter: data.chunks_exact(2 * fourier_len),
        }
    }
}

impl<'a> Iterator for FourierPolynomialIter<'a> {
    type Item = FourierPolynomial<&'a [f64]>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(FourierPolynomial)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }

    #[inline]
    fn count(self) -> usize {
        self.len()
    }

    #[inline]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.iter.nth(n).map(FourierPolynomial)
    }

    #[inline]
    fn last(mut self) -> Option<Self::Item> {
        self.next_back()
    }
}

impl<'a> core::iter::FusedIterator for FourierPolynomialIter<'a> {}
impl<'a> core::iter::DoubleEndedIterator for FourierPolynomialIter<'a> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.iter.next_back().map(FourierPolynomial)
    }
    #[inline]
    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        self.iter.nth_back(n).map(FourierPolynomial)
    }
}
impl<'a> core::iter::ExactSizeIterator for FourierPolynomialIter<'a> {}

/// Mutable chunked iterator over [`FourierPolynomial`] components.
#[derive(Debug)]
pub struct FourierPolynomialIterMut<'a> {
    /// The underlying mutable chunked iterator.
    pub iter: core::slice::ChunksExactMut<'a, f64>,
}

impl<'a> FourierPolynomialIterMut<'a> {
    /// Creates a new mutable iterator yielding chunks of `2 * fourier_len` f64
    /// values (one split Fourier polynomial each).
    #[inline]
    pub fn new(data: &'a mut [f64], fourier_len: usize) -> Self {
        Self {
            iter: data.chunks_exact_mut(2 * fourier_len),
        }
    }
}

impl<'a> Iterator for FourierPolynomialIterMut<'a> {
    type Item = FourierPolynomial<&'a mut [f64]>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(FourierPolynomial)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }

    #[inline]
    fn count(self) -> usize {
        self.len()
    }

    #[inline]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.iter.nth(n).map(FourierPolynomial)
    }

    #[inline]
    fn last(mut self) -> Option<Self::Item> {
        self.next_back()
    }
}

impl<'a> core::iter::FusedIterator for FourierPolynomialIterMut<'a> {}
impl<'a> core::iter::DoubleEndedIterator for FourierPolynomialIterMut<'a> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.iter.next_back().map(FourierPolynomial)
    }
    #[inline]
    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        self.iter.nth_back(n).map(FourierPolynomial)
    }
}
impl<'a> core::iter::ExactSizeIterator for FourierPolynomialIterMut<'a> {}

// ---------------------------------------------------------------------------
// Methods: RawData<Elem = f64>
// ---------------------------------------------------------------------------

impl<S> FourierPolynomial<S>
where
    S: RawData<Elem = f64>,
{
    /// Creates a new [`FourierPolynomial`].
    #[inline]
    pub fn new(values: S) -> Self {
        Self(values)
    }
}

// ---------------------------------------------------------------------------
// Methods: DataOwned
// ---------------------------------------------------------------------------

impl<S> FourierPolynomial<S>
where
    S: RawData<Elem = f64> + DataOwned,
{
    /// Creates a [`FourierPolynomial`] with all elements set to zero.
    /// `fourier_length` is the logical number of complex values; the
    /// allocated buffer has `2 * fourier_length` f64 elements.
    #[inline]
    pub fn zero(fourier_length: usize) -> Self {
        Self(S::from_vec(vec![0.0f64; 2 * fourier_length]))
    }

    /// Consumes `self`, returning the underlying storage.
    #[inline]
    pub fn into_owned(self) -> S {
        self.0
    }

    /// Constructs a new Fourier polynomial by cloning elements from a slice.
    #[inline]
    pub fn from_slice(data: &[f64]) -> Self {
        Self::new(S::from_slice(data))
    }
}

// ---------------------------------------------------------------------------
// Methods: DataMut
// ---------------------------------------------------------------------------

impl<S> FourierPolynomial<S>
where
    S: RawData<Elem = f64> + DataMut,
{
    /// Extracts a mutable slice of all elements.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [f64] {
        self.0.as_mut_slice()
    }

    /// Returns a mutable iterator over the elements.
    #[inline]
    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, f64> {
        self.0.iter_mut()
    }

    /// Copies elements from `src` into `self`. Lengths must match.
    #[inline]
    pub fn copy_from(&mut self, src: impl AsRef<[f64]>) {
        self.0.copy_from_slice(src.as_ref());
    }

    /// Sets all elements to zero.
    #[inline]
    pub fn set_zero(&mut self) {
        self.0.fill(0.0f64);
    }

    /// Mutable view of the real part.
    #[inline]
    pub fn re_mut(&mut self) -> &mut [f64] {
        let m = self.fourier_length();
        &mut self.0.as_mut_slice()[..m]
    }

    /// Mutable view of the imaginary part.
    #[inline]
    pub fn im_mut(&mut self) -> &mut [f64] {
        let m = self.fourier_length();
        &mut self.0.as_mut_slice()[m..]
    }
}

// ---------------------------------------------------------------------------
// Methods: Data (read-only)
// ---------------------------------------------------------------------------

impl<S> FourierPolynomial<S>
where
    S: RawData<Elem = f64> + Data,
{
    /// Extracts a slice containing all elements.
    #[inline]
    pub fn as_slice(&self) -> &[f64] {
        self.0.as_slice()
    }

    /// Logical Fourier length (number of complex frequency values).
    /// Total element count is `2 * fourier_length()`.
    #[inline]
    pub fn fourier_length(&self) -> usize {
        self.0.len() / 2
    }

    /// Returns a read-only iterator over the elements.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, f64> {
        self.0.iter()
    }

    /// Returns `true` if all elements are zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&x| x == 0.0f64)
    }

    /// Read-only view of the real part.
    #[inline]
    pub fn re_slice(&self) -> &[f64] {
        let m = self.fourier_length();
        &self.0.as_slice()[..m]
    }

    /// Read-only view of the imaginary part.
    #[inline]
    pub fn im_slice(&self) -> &[f64] {
        let m = self.fourier_length();
        &self.0.as_slice()[m..]
    }
}

// ---------------------------------------------------------------------------
// Trait impls
// ---------------------------------------------------------------------------

impl<S> AsRef<[f64]> for FourierPolynomial<S>
where
    S: RawData<Elem = f64> + Data,
{
    #[inline]
    fn as_ref(&self) -> &[f64] {
        self.as_slice()
    }
}

impl<S> AsMut<[f64]> for FourierPolynomial<S>
where
    S: RawData<Elem = f64> + DataMut,
{
    #[inline]
    fn as_mut(&mut self) -> &mut [f64] {
        self.as_mut_slice()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_and_as_slice() {
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
        let poly = FourierPolynomial::new(data.clone());
        assert_eq!(poly.as_slice(), data.as_slice());
        assert_eq!(poly.fourier_length(), 3);
        assert_eq!(poly.re_slice(), &[1.0, 2.0, 3.0]);
        assert_eq!(poly.im_slice(), &[4.0, 5.0, 6.0]);
    }

    #[test]
    fn test_zero() {
        let poly = FourierPolynomialOwned::zero(4);
        assert_eq!(poly.fourier_length(), 4);
        assert_eq!(poly.as_slice().len(), 8);
        assert!(poly.is_zero());
    }

    #[test]
    fn test_set_zero() {
        let data = vec![1.0; 8];
        let mut poly = FourierPolynomial::new(data);
        assert!(!poly.is_zero());
        poly.set_zero();
        assert!(poly.is_zero());
    }

    #[test]
    fn test_from_slice() {
        let data = vec![1.0, 0.0, 2.0, 0.0, 3.0, 0.0, 4.0, 0.0];
        let poly = FourierPolynomialOwned::from_slice(&data);
        assert_eq!(poly.as_slice(), data.as_slice());
    }

    #[test]
    fn test_into_owned() {
        let data = vec![1.0, 0.0, 0.0, 1.0];
        let poly = FourierPolynomialOwned::from_slice(&data);
        let vec: Vec<f64> = poly.into_owned();
        assert_eq!(vec, data);
    }

    #[test]
    fn test_iter() {
        let data = vec![1.0, 2.0, 3.0, 4.0];
        let poly = FourierPolynomial::new(data.clone());
        let collected: Vec<f64> = poly.iter().copied().collect();
        assert_eq!(collected, data);
    }

    #[test]
    fn test_iter_mut() {
        let data = vec![1.0, 2.0, 3.0, 4.0];
        let mut poly = FourierPolynomial::new(data.clone());
        for x in poly.iter_mut() {
            *x += 1.0;
        }
        assert_eq!(poly.as_slice(), &[2.0, 3.0, 4.0, 5.0]);
    }

    #[test]
    fn test_fourier_iterator_chunks() {
        // 2 Fourier polynomials, each of logical length 3 → 6 f64 each → 12 total
        let data: Vec<f64> = (0..12).map(|i| i as f64).collect();
        let iter = FourierPolynomialIter::new(&data, 3);
        let polys: Vec<_> = iter.collect();
        assert_eq!(polys.len(), 2);
        assert_eq!(polys[0].as_slice(), &data[..6]);
        assert_eq!(polys[1].as_slice(), &data[6..]);
    }

    #[test]
    fn test_is_zero() {
        let poly = FourierPolynomialOwned::zero(4);
        assert!(poly.is_zero());
        let poly2 = FourierPolynomial::new(vec![1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]);
        assert!(!poly2.is_zero());
    }

    #[test]
    fn test_re_im_views() {
        let data = vec![1.0, 2.0, 10.0, 20.0];
        let mut poly = FourierPolynomial::new(data);
        assert_eq!(poly.re_slice(), &[1.0, 2.0]);
        assert_eq!(poly.im_slice(), &[10.0, 20.0]);
        poly.re_mut()[0] = 99.0;
        poly.im_mut()[1] = 88.0;
        assert_eq!(poly.re_slice(), &[99.0, 2.0]);
        assert_eq!(poly.im_slice(), &[10.0, 88.0]);
    }
}
