//! Exact NTT automorphisms followed by key switching back to the original secret.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::{MAX_POLY_LENGTH, MIN_POLY_LENGTH, nlev::NttNlev};
use primus_ntt::{NttAutomorphismPermutation, NttTable};
use primus_poly::{CoeffAutomorphismPermutation, Polynomial};
use primus_reduce::FieldContext;
use zeroize::Zeroizing;

use crate::{
    NlevParameters, NtruCiphertext, NtruSecretKey, NttNtruCiphertext,
    NttNtruExternalProductContext, NttNtruGadgetEncryptContext, NttNtruKeySwitchingKey,
    NttNtruSecretKey,
};

/// Reusable permutation and decomposition buffers for NTT NTRU automorphisms.
/// Both coefficient and NTT input paths use this workspace without allocation.
pub struct NttNtruAutomorphismContext<T: FheUint> {
    coefficients: NtruCiphertext<Vec<T>>,
    external_product: NttNtruExternalProductContext<T>,
}

impl<T: FheUint> NttNtruAutomorphismContext<T> {
    /// Allocates workspace for a supported power-of-two NTRU polynomial length.
    ///
    /// # Panics
    ///
    /// Panics if the length is outside the supported NTRU range or not a power of two.
    #[must_use]
    pub fn new(poly_length: usize) -> Self {
        assert!(
            (MIN_POLY_LENGTH..=MAX_POLY_LENGTH).contains(&poly_length)
                && poly_length.is_power_of_two(),
            "automorphism polynomial length must be a supported power of two"
        );
        Self {
            coefficients: NtruCiphertext::zero(poly_length),
            external_product: NttNtruExternalProductContext::new(poly_length),
        }
    }
}

/// Evaluation key for `sigma_d: X -> X^d`, returning scalar NTRU to the same secret.
///
/// For phase `f*c = mu + e`, permutation alone changes the secret to
/// `sigma_d(f)`. This key stores `NLev_f[sigma_d(f)]`, restoring phase
/// `sigma_d(mu)` under `f`, up to key-switch noise. NLev rows can each use this
/// operation; applying it row-wise to NGSW does not preserve NGSW semantics.
#[derive(Clone)]
pub struct NttNtruAutomorphismKey<T: FheUint> {
    degree: usize,
    key_switching: NttNtruKeySwitchingKey<T>,
    coeff_permutation: CoeffAutomorphismPermutation,
    ntt_permutation: NttAutomorphismPermutation,
}

impl<T: FheUint> NttNtruAutomorphismKey<T> {
    /// Generates an automorphism key for the same coefficient and NTT secret.
    ///
    /// # Correctness
    /// The two secret keys represent the same polynomial under the supplied
    /// modulus and NTT representation. Signed coefficient magnitudes must be
    /// below the ciphertext modulus, as in [`NttNtruKeySwitchingKey::generate`].
    /// These numerical and key-identity obligations are not checked.
    ///
    /// # Panics
    /// Panics before sampling for an invalid degree (not odd or outside
    /// `[1, 2N)`), mismatched key/parameter/NTT lengths or moduli, or incompatible
    /// gadget workspace. A panicking RNG can interrupt generation.
    #[must_use]
    pub fn generate<M, Table, R>(
        degree: usize,
        secret_key: &NtruSecretKey<T>,
        ntt_secret_key: &NttNtruSecretKey<T>,
        parameters: &NlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        context: &mut NttNtruGadgetEncryptContext<T>,
    ) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let n = parameters.poly_length();
        assert_eq!(
            secret_key.poly_length(),
            n,
            "automorphism secret length mismatch"
        );
        let coeff_permutation = CoeffAutomorphismPermutation::new(degree, n);
        let ntt_permutation = NttAutomorphismPermutation::new(degree, n);
        let modulus = parameters.ntru().cipher_modulus();
        let mut encoded = Zeroizing::new(vec![T::ZERO; n]);
        let mut permuted = Zeroizing::new(vec![T::ZERO; n]);
        // Permute canonical residues: no signed negation or inversion of
        // sigma(f) is needed. Both temporary secret copies are erased on unwind.
        modulus.encode_signed_slice_to(secret_key.as_slice(), encoded.as_mut_slice());
        coeff_permutation.apply_to(&encoded, &mut permuted, modulus);
        let key_switching = NttNtruKeySwitchingKey::generate_encoded(
            &permuted,
            ntt_secret_key,
            parameters,
            ntt,
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
    #[must_use]
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Returns the bound NTRU polynomial length.
    #[must_use]
    pub fn poly_length(&self) -> usize {
        self.key_switching.poly_length()
    }

    /// Returns the key-switch decomposition basis, including its modulus.
    #[must_use]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        self.key_switching.basis()
    }

    /// Writes the automorphism of a coefficient ciphertext under the original secret.
    ///
    /// # Correctness
    /// Input is canonical under the key's modulus and original secret. The NTT
    /// table uses the representation used during generation. Encryption and
    /// decomposition errors must fit the caller's noise budget.
    ///
    /// # Panics
    /// Panics before output writes if input/output, table or workspace lengths,
    /// or the arithmetic/table moduli do not match the key.
    pub fn apply_to<M, Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        output: &mut NtruCiphertext<B>,
        modulus: M,
        ntt: &Table,
        context: &mut NttNtruAutomorphismContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.assert_lengths(input.as_ref().len(), output.as_ref().len());
        self.key_switching
            .assert_compatible(modulus, ntt, &context.external_product);
        self.apply_kernel_to(input, output, modulus, ntt, context);
    }

    /// Requires validated operand lengths and matching key/table/workspace resources.
    pub(crate) fn apply_kernel_to<M, Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        output: &mut NtruCiphertext<B>,
        modulus: M,
        ntt: &Table,
        context: &mut NttNtruAutomorphismContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.apply_with_scratch_kernel_to(
            input,
            output,
            modulus,
            ntt,
            context.coefficients.as_mut(),
            &mut context.external_product,
        );
    }

    /// Coefficient-only kernel for serial scratch reuse. The caller validates N coefficients
    /// in input, output and permutation scratch, plus matching key/table/product resources.
    pub(crate) fn apply_with_scratch_kernel_to<M, Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        output: &mut NtruCiphertext<B>,
        modulus: M,
        ntt: &Table,
        coefficients: &mut [T],
        external_product: &mut NttNtruExternalProductContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.coeff_permutation
            .apply_to(input.as_ref(), coefficients, modulus);
        self.key_switching.key_switch_kernel_to(
            &NtruCiphertext::new(&*coefficients),
            output,
            modulus,
            ntt,
            external_product,
        );
    }

    /// Writes the automorphism of an NTT ciphertext directly in NTT form.
    ///
    /// The permuted input is recovered to coefficients for signed decomposition;
    /// the product remains transformed, avoiding an inverse/forward output pair.
    ///
    /// # Correctness
    /// Inherits [`Self::apply_to`]'s key, modulus and noise contracts. Input and
    /// output use the supplied table's NTT representation with canonical values.
    ///
    /// # Panics
    /// Inherits [`Self::apply_to`]'s checks, performed before output writes.
    pub fn apply_ntt_to<M, Table, A, B>(
        &self,
        input: &NttNtruCiphertext<A>,
        output: &mut NttNtruCiphertext<B>,
        modulus: M,
        ntt: &Table,
        context: &mut NttNtruAutomorphismContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.assert_lengths(input.as_ref().len(), output.as_ref().len());
        self.key_switching
            .assert_compatible(modulus, ntt, &context.external_product);
        self.ntt_permutation
            .apply_to(input.as_ref(), context.coefficients.as_mut());
        ntt.inverse_transform_slice(context.coefficients.as_mut());
        NttNlev::new(self.key_switching.as_slice()).external_product_ntt_to(
            &Polynomial(context.coefficients.as_ref()),
            output,
            self.basis(),
            modulus,
            ntt,
            &mut context.external_product,
        );
    }

    fn assert_lengths(&self, input: usize, output: usize) {
        assert_eq!(
            input,
            self.poly_length(),
            "automorphism input length mismatch"
        );
        assert_eq!(
            output,
            self.poly_length(),
            "automorphism output length mismatch"
        );
    }

    pub(crate) fn assert_external_product_compatible<M, Table>(
        &self,
        modulus: M,
        ntt: &Table,
        context: &NttNtruExternalProductContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        self.key_switching.assert_compatible(modulus, ntt, context);
    }

    /// Checks the resources shared by all automorphism keys in one trace key.
    pub(crate) fn assert_compatible<M, Table>(
        &self,
        modulus: M,
        ntt: &Table,
        context: &NttNtruAutomorphismContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        self.key_switching
            .assert_compatible(modulus, ntt, &context.external_product);
    }
}
