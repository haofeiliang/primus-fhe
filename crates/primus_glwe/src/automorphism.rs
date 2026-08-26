//! Single-modulus GLWE automorphisms evaluated with NTT key switching.

use num_traits::ConstZero;
use primus_data::{Data, DataMut, RawData};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::{FheUint, WrappingNeg};
use primus_lattice::glwe::{Glwe, NttGlwe};
use primus_modulus::PowOf2Modulus;
use primus_ntt::{NttTable, ReverseLsbs};
use primus_poly::NttPolynomial;
use primus_reduce::{FieldContext, ReduceMul};

use crate::{
    GlweSecretKey, NttGadgetDomain, NttGadgetEncryptContext, NttGlweKeySwitchingContext,
    NttGlweKeySwitchingKey, NttGlweSecretKey, SecretCoefficient,
};

#[derive(Clone, Copy)]
struct CoefficientSource {
    index: u32,
    negate: bool,
}

/// Precomputed coefficient permutation for `X -> X^degree` in
/// `Z_q[X]/(X^N + 1)`.
#[derive(Clone)]
struct CoeffAutoPermutation {
    sources: Vec<CoefficientSource>,
}

impl CoeffAutoPermutation {
    fn new(degree: usize, poly_length: usize) -> Self {
        assert!(
            degree < 2 * poly_length && degree % 2 == 1,
            "GLWE automorphism degree must be odd and less than 2N"
        );
        let modulus = PowOf2Modulus::new(2 * poly_length);
        let mut sources = vec![
            CoefficientSource {
                index: 0,
                negate: false,
            };
            poly_length
        ];
        for source in 0..poly_length {
            let mapped = modulus.reduce_mul(source, degree);
            let (destination, negate) = if mapped < poly_length {
                (mapped, false)
            } else {
                (mapped - poly_length, true)
            };
            sources[destination] = CoefficientSource {
                index: source as u32,
                negate,
            };
        }
        Self { sources }
    }

    #[inline]
    fn poly_length(&self) -> usize {
        self.sources.len()
    }

    fn apply_secret<T: FheUint>(
        &self,
        input: &[SecretCoefficient<T>],
        output: &mut [SecretCoefficient<T>],
    ) {
        debug_assert_eq!(input.len(), self.poly_length());
        debug_assert_eq!(output.len(), self.poly_length());
        for (output, source) in output.iter_mut().zip(&self.sources) {
            let value = input[source.index as usize];
            *output = if source.negate {
                value.wrapping_neg()
            } else {
                value
            };
        }
    }

    fn apply_residues<T, M>(&self, input: &[T], output: &mut [T], modulus: M)
    where
        T: FheUint,
        M: FieldContext<T>,
    {
        debug_assert_eq!(input.len(), self.poly_length());
        debug_assert_eq!(output.len(), self.poly_length());
        for (output, source) in output.iter_mut().zip(&self.sources) {
            let value = input[source.index as usize];
            *output = if source.negate {
                modulus.reduce_neg(value)
            } else {
                value
            };
        }
    }
}

/// Precomputed evaluation-point permutation for `X -> X^degree` in the
/// bit-reversed NTT storage order used by this crate.
#[derive(Clone)]
struct NttAutoPermutation {
    sources: Vec<u32>,
}

impl NttAutoPermutation {
    fn new(degree: usize, poly_length: usize) -> Self {
        assert!(
            degree < 2 * poly_length && degree % 2 == 1,
            "GLWE automorphism degree must be odd and less than 2N"
        );
        let log_n = poly_length.trailing_zeros();
        let modulus = PowOf2Modulus::new(2 * poly_length);
        let mut sources = vec![0; poly_length];

        for i in 0..poly_length {
            let mapped_exponent = modulus.reduce_mul(degree, 2 * i + 1);
            let j = (mapped_exponent - 1) / 2;
            let destination = i.reverse_lsbs(log_n);
            let source = j.reverse_lsbs(log_n);
            sources[destination] = source as u32;
        }

        Self { sources }
    }

    #[inline]
    fn poly_length(&self) -> usize {
        self.sources.len()
    }

    fn apply<T: FheUint>(&self, input: &[T], output: &mut [T]) {
        debug_assert_eq!(input.len(), self.poly_length());
        debug_assert_eq!(output.len(), self.poly_length());
        for (output, &source) in output.iter_mut().zip(&self.sources) {
            *output = input[source as usize];
        }
    }
}

/// Reusable workspace for coefficient- and NTT-domain GLWE automorphisms.
pub struct NttGlweAutomorphismContext<T: FheUint> {
    transformed: Glwe<Vec<T>>,
    permuted_ntt: Vec<T>,
    key_switching: NttGlweKeySwitchingContext<T>,
}

impl<T: FheUint> NttGlweAutomorphismContext<T> {
    /// Creates workspace for one GLWE layout.
    pub fn new(size: primus_lattice::GlweSize) -> Self {
        Self {
            transformed: Glwe::zero(size.glwe_len()),
            permuted_ntt: vec![T::ZERO; size.poly_length()],
            key_switching: NttGlweKeySwitchingContext::new(size),
        }
    }
}

/// Evaluation key for the GLWE automorphism `X -> X^degree`.
///
/// The key switches from the transformed secret `S(X^degree)` back to `S(X)`.
#[derive(Clone)]
pub struct NttGlweAutomorphismKey<T: FheUint> {
    degree: usize,
    key_switching: NttGlweKeySwitchingKey<T>,
    coeff_permutation: CoeffAutoPermutation,
    ntt_permutation: NttAutoPermutation,
}

impl<T: FheUint> NttGlweAutomorphismKey<T> {
    /// Generates an automorphism key under `secret_key`.
    pub fn generate<M, Table, R>(
        degree: usize,
        secret_key: &GlweSecretKey<T>,
        ntt_secret_key: &NttGlweSecretKey<T>,
        domain: &NttGadgetDomain<'_, T, M, Table>,
        rng: &mut R,
        context: &mut NttGadgetEncryptContext<T>,
    ) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let size = secret_key.glwe_size();
        assert_eq!(ntt_secret_key.glwe_size(), size);
        assert_eq!(domain.size().glwe_size(), size);
        let poly_len = size.poly_length();

        let coeff_permutation = CoeffAutoPermutation::new(degree, poly_len);
        let ntt_permutation = NttAutoPermutation::new(degree, poly_len);

        let mut transformed_secret = vec![SecretCoefficient::<T>::ZERO; size.mask_len()];

        for (input, output) in secret_key
            .iter()
            .zip(transformed_secret.chunks_exact_mut(poly_len))
        {
            coeff_permutation.apply_secret::<T>(input, output);
        }

        let transformed_secret = GlweSecretKey::new(transformed_secret, size, secret_key.distr());
        let key_switching = NttGlweKeySwitchingKey::generate(
            &transformed_secret,
            ntt_secret_key,
            domain,
            rng,
            context,
        );

        Self {
            degree,
            key_switching,
            coeff_permutation,
            ntt_permutation,
        }
    }

    /// Returns the odd automorphism degree in `[1, 2N)`.
    #[inline]
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Returns the decomposition basis bound to this key.
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        self.key_switching.basis()
    }

    /// Applies the automorphism and writes a coefficient-domain GLWE under the
    /// original secret key.
    pub fn apply_to<M, Table, A, B>(
        &self,
        input: &Glwe<A>,
        output: &mut Glwe<B>,
        domain: &NttGadgetDomain<'_, T, M, Table>,
        context: &mut NttGlweAutomorphismContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        assert_eq!(
            input.as_ref().len(),
            self.key_switching.input_size().glwe_len(),
            "automorphism input layout mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            self.key_switching.output_size().glwe_len(),
            "automorphism output layout mismatch"
        );
        self.assert_compatible(domain, context);

        self.apply_kernel_to(input, output, domain, context);
    }

    /// Applies the automorphism after the caller has validated the domain,
    /// ciphertext layouts, and workspace.
    pub(crate) fn apply_kernel_to<M, Table, A, B>(
        &self,
        input: &Glwe<A>,
        output: &mut Glwe<B>,
        domain: &NttGadgetDomain<'_, T, M, Table>,
        context: &mut NttGlweAutomorphismContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = self.key_switching.poly_length();
        debug_assert_eq!(
            input.as_ref().len(),
            self.key_switching.input_size().glwe_len()
        );
        debug_assert_eq!(
            output.as_ref().len(),
            self.key_switching.output_size().glwe_len()
        );
        debug_assert_eq!(
            context.transformed.as_ref().len(),
            self.key_switching.input_size().glwe_len()
        );

        let modulus = domain.parameters().cipher_modulus();

        for (input_poly, output_poly) in input
            .as_ref()
            .chunks_exact(poly_length)
            .zip(context.transformed.as_mut().chunks_exact_mut(poly_length))
        {
            self.coeff_permutation
                .apply_residues(input_poly, output_poly, modulus);
        }

        self.key_switching.key_switch_kernel_to(
            &context.transformed,
            output,
            domain,
            &mut context.key_switching,
        );
    }

    /// Applies the automorphism directly to an NTT-domain GLWE ciphertext.
    ///
    /// Mask polynomials are permuted and inverse-transformed for key-switch
    /// decomposition. The body polynomial is permuted and combined entirely
    /// in the NTT domain.
    pub fn apply_ntt_to<M, Table, A, B>(
        &self,
        input: &NttGlwe<A>,
        output: &mut NttGlwe<B>,
        domain: &NttGadgetDomain<'_, T, M, Table>,
        context: &mut NttGlweAutomorphismContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = self.key_switching.poly_length();

        assert_eq!(
            input.as_ref().len(),
            self.key_switching.input_size().glwe_len(),
            "NTT automorphism input layout mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            self.key_switching.output_size().glwe_len(),
            "NTT automorphism output layout mismatch"
        );
        assert_eq!(
            context.permuted_ntt.len(),
            poly_length,
            "NTT automorphism polynomial workspace mismatch"
        );
        self.assert_compatible(domain, context);

        self.apply_ntt_kernel_to(input, output, domain, context);
    }

    /// Applies the NTT automorphism after the caller has validated the domain,
    /// ciphertext layouts, and workspace.
    fn apply_ntt_kernel_to<M, Table, A, B>(
        &self,
        input: &NttGlwe<A>,
        output: &mut NttGlwe<B>,
        domain: &NttGadgetDomain<'_, T, M, Table>,
        context: &mut NttGlweAutomorphismContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = self.key_switching.poly_length();
        debug_assert_eq!(
            input.as_ref().len(),
            self.key_switching.input_size().glwe_len()
        );
        debug_assert_eq!(
            output.as_ref().len(),
            self.key_switching.output_size().glwe_len()
        );
        debug_assert_eq!(context.permuted_ntt.len(), poly_length);

        let table = domain.table();
        let (input_mask, input_body) = input.a_b_slices(poly_length);
        let NttGlweAutomorphismContext {
            transformed,
            permuted_ntt,
            key_switching,
        } = context;

        let (transformed_mask, _) = transformed.a_b_mut_slices(poly_length);
        for (input_poly, output_poly) in input_mask
            .chunks_exact(poly_length)
            .zip(transformed_mask.chunks_exact_mut(poly_length))
        {
            self.ntt_permutation.apply(input_poly, permuted_ntt);
            table.inverse_transform_slice(permuted_ntt);
            output_poly.copy_from_slice(permuted_ntt);
        }

        self.ntt_permutation.apply(input_body, permuted_ntt);
        self.key_switching.key_switch_ntt_kernel_to(
            transformed_mask,
            &NttPolynomial::new(permuted_ntt.as_slice()),
            output,
            domain,
            key_switching,
        );
    }

    /// Validates the domain and reusable workspace shared by both
    /// automorphism output paths.
    pub(crate) fn assert_compatible<M, Table>(
        &self,
        domain: &NttGadgetDomain<'_, T, M, Table>,
        context: &NttGlweAutomorphismContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        assert_eq!(
            context.transformed.as_ref().len(),
            self.key_switching.input_size().glwe_len(),
            "automorphism workspace layout mismatch"
        );
        self.key_switching
            .assert_compatible(domain, &context.key_switching);
    }
}

#[cfg(test)]
mod tests {
    use primus_modulus::BarrettModulus;
    use primus_ntt::{NttTable, UintNttTable};

    use super::{CoeffAutoPermutation, NttAutoPermutation};

    #[test]
    fn ntt_permutation_matches_coefficient_automorphism() {
        const LOG_N: u32 = 4;
        const N: usize = 1 << LOG_N;
        const Q: u32 = 257;

        let modulus = BarrettModulus::new(Q);
        let ntt = UintNttTable::new(LOG_N, modulus).unwrap();
        let input: Vec<u32> = (0..N).map(|index| (19 * index as u32 + 5) % Q).collect();
        let mut input_ntt = input.clone();
        ntt.transform_slice(&mut input_ntt);

        for degree in [1, 3, N + 1, 2 * N - 1] {
            let coefficient = CoeffAutoPermutation::new(degree, N);
            let ntt_permutation = NttAutoPermutation::new(degree, N);

            let mut expected = vec![0; N];
            coefficient.apply_residues(&input, &mut expected, modulus);
            ntt.transform_slice(&mut expected);

            let mut actual = vec![0; N];
            ntt_permutation.apply(&input_ntt, &mut actual);
            assert_eq!(actual, expected, "degree {degree}");
        }
    }
}
