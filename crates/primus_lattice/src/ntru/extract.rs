//! Sample extraction from the NTRU phase `f * c`.

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_reduce::RingContext;

use super::Ntru;
use crate::lwe::Lwe;

impl<S, T> Ntru<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Extracts the constant-term NTRU phase as an LWE ciphertext.
    ///
    /// For an NTRU ciphertext `c` encrypted under `f`, this writes
    /// `a[0] = -c[0]`, `a[i] = c[N - i]` for `i > 0`, and `b = 0`. Hence the
    /// LWE phase `b - <a, f>` equals the constant coefficient of `f * c` in
    /// `Z_q[X] / (X^N + 1)`.
    ///
    /// # Correctness
    ///
    /// `output` must have LWE dimension `N`.
    ///
    /// Input is one nonempty coefficient polynomial of length `N`, with
    /// canonical values under `modulus`. Extraction uses the coefficient
    /// vector of the NTRU secret `f` as the LWE key; output is overwritten.
    ///
    /// # Panics
    ///
    /// Panics if the NTRU polynomial is empty.
    #[inline]
    pub fn extract_lwe_to<M, A>(&self, output: &mut Lwe<A>, modulus: M)
    where
        M: RingContext<T>,
        A: DataMut<Elem = T>,
    {
        let coefficients = self.as_ref();
        debug_assert_eq!(output.dimension(), coefficients.len());
        self.extract_compact_lwe_to(output, modulus);
    }

    /// Extracts coefficient `index` of the NTRU phase into an LWE buffer.
    ///
    /// For `c` encrypted under `f`, writes `b = 0` and a mask such that
    /// `b - <a, f>` equals coefficient `index` of `f*c` modulo `X^N + 1`.
    /// Canonical input residues produce canonical output without allocation.
    /// `output` must have LWE dimension `N`.
    ///
    /// # Correctness
    ///
    /// Input is one nonempty coefficient polynomial of length `N`, with
    /// canonical values under `modulus`. Extraction uses the coefficient
    /// vector of the NTRU secret `f` as the LWE key; output is overwritten.
    ///
    /// # Panics
    ///
    /// Panics unless `index < N`.
    #[inline]
    pub fn extract_lwe_at_to<M, A>(&self, index: usize, output: &mut Lwe<A>, modulus: M)
    where
        M: RingContext<T>,
        A: DataMut<Elem = T>,
    {
        debug_assert_eq!(
            output.dimension(),
            self.as_ref().len(),
            "LWE output dimension must equal N"
        );
        self.extract_compact_lwe_at_to(index, output, modulus);
    }

    /// Extracts the constant-term phase while omitting a zero-padded suffix.
    ///
    /// If the NTRU secret is `[s_lwe..., 0...]`, an output of dimension
    /// `s_lwe.len()` has the same phase as full extraction without allocating
    /// or processing the omitted mask coefficients.
    ///
    /// # Correctness
    ///
    /// The output dimension must be in `1..=N`, where `N` is the NTRU
    /// polynomial length.
    ///
    /// Input is one nonempty coefficient polynomial of length `N`, with
    /// canonical values under `modulus`. Extraction uses the coefficient
    /// vector of the NTRU secret `f` as the LWE key; output is overwritten.
    ///
    /// # Panics
    ///
    /// Panics if the NTRU polynomial is empty.
    #[inline]
    pub fn extract_compact_lwe_to<M, A>(&self, output: &mut Lwe<A>, modulus: M)
    where
        M: primus_reduce::RingContext<T>,
        A: DataMut<Elem = T>,
    {
        self.extract_compact_lwe_at_to(0, output, modulus);
    }

    /// Extracts coefficient `index`, omitting a zero suffix of the NTRU secret.
    ///
    /// # Correctness
    ///
    /// The secret must be `[s_lwe..., 0...]`, where `s_lwe.len()` equals the
    /// output dimension. The LWE phase equals coefficient `index` of `f*c`.
    /// Canonical input residues produce canonical output without allocation.
    /// The output dimension must belong to `1..=N`.
    ///
    /// Input is one nonempty coefficient polynomial of length `N`, with
    /// canonical values under `modulus`. Extraction uses the coefficient
    /// vector of the NTRU secret `f` as the LWE key; output is overwritten.
    ///
    /// # Panics
    ///
    /// Panics unless `index < N`.
    #[inline]
    pub fn extract_compact_lwe_at_to<M, A>(&self, index: usize, output: &mut Lwe<A>, modulus: M)
    where
        M: RingContext<T>,
        A: DataMut<Elem = T>,
    {
        let coefficients = self.as_ref();
        assert!(
            index < coefficients.len(),
            "NTRU extraction index is out of range"
        );
        let (a, b) = output.a_b_mut();
        debug_assert!(
            (1..=coefficients.len()).contains(&a.len()),
            "invalid compact LWE dimension"
        );
        *b = T::ZERO;
        let split = (index + 1).min(a.len());
        let (negative, wrapped) = a.split_at_mut(split);
        for (output, &input) in negative.iter_mut().zip(coefficients[..=index].iter().rev()) {
            *output = modulus.reduce_neg(input);
        }
        for (output, &input) in wrapped.iter_mut().zip(coefficients.iter().rev()) {
            *output = input;
        }
    }
}
