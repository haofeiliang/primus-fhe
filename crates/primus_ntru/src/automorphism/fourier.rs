//! Native-torus automorphisms bound to the generating FFT table instance.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_lattice::{MAX_POLY_LENGTH, MIN_POLY_LENGTH, nlev::FourierNlev};
use primus_modulus::NativeModulus;
use primus_poly::{CoeffAutomorphismPermutation, Polynomial};
use primus_reduce::EncodeSigned;
use zeroize::Zeroizing;

use crate::{
    FourierNtruCiphertext, FourierNtruExternalProductContext, FourierNtruGadgetEncryptContext,
    FourierNtruKeySwitchingKey, FourierNtruSecretKey, NlevParameters, NtruCiphertext,
    NtruSecretKey,
};

/// Reusable coefficient, Fourier-permutation and decomposition workspace.
/// Both input representations use these buffers without allocation.
pub struct FourierNtruAutomorphismContext<T: TorusFftValue> {
    coefficients: NtruCiphertext<Vec<T>>,
    permuted: Vec<Complex64>,
    external_product: FourierNtruExternalProductContext<T>,
}

impl<T: TorusFftValue> FourierNtruAutomorphismContext<T> {
    /// Allocates workspace for a supported power-of-two NTRU polynomial length.
    ///
    /// # Panics
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
            permuted: vec![Complex64::default(); poly_length / 2],
            external_product: FourierNtruExternalProductContext::new(poly_length),
        }
    }
}

/// Evaluation key for `sigma_d: X -> X^d`, returning scalar NTRU to the same secret.
///
/// Stores `NLev_f[sigma_d(f)]` to switch the permuted secret back to `f`.
/// The key and cached Fourier permutation are bound to the exact FFT table
/// instance used for generation. NLev rows can use this scalar operation;
/// applying it row-wise to NGSW does not preserve NGSW semantics.
#[derive(Clone)]
pub struct FourierNtruAutomorphismKey<T: TorusFftValue> {
    degree: usize,
    key_switching: FourierNtruKeySwitchingKey<T>,
    coeff_permutation: CoeffAutomorphismPermutation,
    fourier_permutation: Vec<(usize, bool)>,
}

impl<T: TorusFftValue> FourierNtruAutomorphismKey<T> {
    /// Generates an automorphism key for matching coefficient and Fourier secrets.
    ///
    /// # Correctness
    /// Both keys represent the same secret. The transformed key was constructed
    /// with this FFT table instance. Floating-point errors must fit the caller's
    /// precision budget, as in [`FourierNtruKeySwitchingKey::generate`].
    ///
    /// # Panics
    /// Panics before sampling for an invalid degree (not odd or outside
    /// `[1, 2N)`) or mismatched key/parameter/FFT/workspace lengths.
    #[must_use]
    pub fn generate<Table, R>(
        degree: usize,
        secret_key: &NtruSecretKey<T>,
        fourier_secret_key: &FourierNtruSecretKey,
        parameters: &NlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierNtruGadgetEncryptContext<T>,
    ) -> Self
    where
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        let n = parameters.poly_length();
        assert_eq!(
            secret_key.poly_length(),
            n,
            "automorphism secret length mismatch"
        );
        assert_eq!(fft.poly_length(), n, "automorphism FFT length mismatch");
        let coeff_permutation = CoeffAutomorphismPermutation::new(degree, n);
        let fourier_permutation = fft.table().automorphism_map(degree);
        let modulus = NativeModulus::new();
        let mut encoded = Zeroizing::new(vec![T::ZERO; n]);
        let mut permuted = Zeroizing::new(vec![T::ZERO; n]);
        // Native-ring negation supports the full signed input range. Both
        // temporary secret copies are erased even if encryption unwinds.
        modulus.encode_signed_slice_to(secret_key.as_slice(), encoded.as_mut_slice());
        coeff_permutation.apply_to(&encoded, &mut permuted, modulus);
        let key_switching = FourierNtruKeySwitchingKey::generate_encoded(
            &permuted,
            fourier_secret_key,
            parameters,
            fft,
            rng,
            context,
        );
        Self {
            degree,
            key_switching,
            coeff_permutation,
            fourier_permutation,
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

    /// Returns the native-torus key-switch decomposition basis.
    #[must_use]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        self.key_switching.basis()
    }

    /// Writes the automorphism of a coefficient ciphertext under the original secret.
    ///
    /// # Correctness
    /// Input uses the key's native modulus, integer width and original secret.
    /// The FFT must use the exact table instance used for generation. Encryption,
    /// decomposition and floating-point errors must fit the caller's noise budget.
    ///
    /// # Panics
    /// Panics before output writes if input/output, FFT or workspace lengths
    /// do not match this key.
    pub fn apply_to<Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        output: &mut NtruCiphertext<B>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruAutomorphismContext<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.assert_lengths(
            input.as_ref().len(),
            output.as_ref().len(),
            self.poly_length(),
        );
        self.key_switching
            .assert_compatible(fft, &context.external_product);
        self.apply_kernel_to(input, output, fft, context);
    }

    /// Requires validated operand lengths and matching key/table/workspace resources.
    pub(crate) fn apply_kernel_to<Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        output: &mut NtruCiphertext<B>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruAutomorphismContext<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.apply_with_scratch_kernel_to(
            input,
            output,
            fft,
            context.coefficients.as_mut(),
            &mut context.external_product,
        );
    }

    /// Coefficient-only kernel for serial scratch reuse. The caller validates N coefficients
    /// in input, output and permutation scratch, plus matching key/table/product resources.
    pub(crate) fn apply_with_scratch_kernel_to<Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        output: &mut NtruCiphertext<B>,
        fft: &mut FftEngine<'_, Table>,
        coefficients: &mut [T],
        external_product: &mut FourierNtruExternalProductContext<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.coeff_permutation
            .apply_to(input.as_ref(), coefficients, NativeModulus::new());
        self.key_switching.key_switch_kernel_to(
            &NtruCiphertext::new(&*coefficients),
            output,
            fft,
            external_product,
        );
    }

    /// Writes the automorphism of a Fourier ciphertext directly in Fourier form.
    ///
    /// Permutation uses the cached table-specific order and conjugations. The
    /// permuted input is recovered to torus coefficients for decomposition;
    /// the product remains transformed without output torus rounding.
    ///
    /// # Correctness
    /// Inherits [`Self::apply_to`]'s key and noise contracts. Input and output
    /// use the same table's normalized torus Fourier representation.
    ///
    /// # Panics
    /// Panics before output writes if input/output lengths are not `N/2`, or
    /// the FFT or workspace polynomial length differs from the key's `N`.
    pub fn apply_fourier_to<Table, A, B>(
        &self,
        input: &FourierNtruCiphertext<A>,
        output: &mut FourierNtruCiphertext<B>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruAutomorphismContext<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = Complex64>,
        B: DataMut<Elem = Complex64>,
    {
        self.assert_lengths(
            input.as_ref().len(),
            output.as_ref().len(),
            self.poly_length() / 2,
        );
        self.key_switching
            .assert_compatible(fft, &context.external_product);
        for (output, &(source, conjugate)) in
            context.permuted.iter_mut().zip(&self.fourier_permutation)
        {
            let value = input.as_ref()[source];
            *output = if conjugate { value.conj() } else { value };
        }
        fft.backward_as_torus(&context.permuted, context.coefficients.as_mut());
        FourierNlev::new(self.key_switching.as_slice()).external_product_fourier_to(
            &Polynomial(context.coefficients.as_ref()),
            output,
            self.basis(),
            fft,
            &mut context.external_product,
        );
    }

    fn assert_lengths(&self, input: usize, output: usize, expected: usize) {
        assert_eq!(input, expected, "automorphism input length mismatch");
        assert_eq!(output, expected, "automorphism output length mismatch");
    }

    pub(crate) fn assert_external_product_compatible<Table>(
        &self,
        fft: &FftEngine<'_, Table>,
        context: &FourierNtruExternalProductContext<T>,
    ) where
        Table: FftTable,
    {
        self.key_switching.assert_compatible(fft, context);
    }

    /// Checks the resources shared by all automorphism keys in one trace key.
    pub(crate) fn assert_compatible<Table: FftTable>(
        &self,
        fft: &FftEngine<'_, Table>,
        context: &FourierNtruAutomorphismContext<T>,
    ) {
        self.key_switching
            .assert_compatible(fft, &context.external_product);
    }
}
