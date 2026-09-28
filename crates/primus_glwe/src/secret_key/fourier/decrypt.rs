//! Fourier GLWE phase extraction and decoding.

use super::{FourierGlweDecryptWorkspace, FourierGlweSecretKey};
use crate::{FourierGlweCiphertext, GlweParameters};
use primus_data::{Data, DataMut};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_modulus::NativeModulus;
use primus_poly::{Polynomial, PolynomialOwned};

impl FourierGlweSecretKey {
    /// Computes `b - sum(a_i * s_i)` and writes the encoded torus phase in
    /// coefficient form.
    ///
    /// # Correctness
    ///
    /// Input must use torus-scaled Fourier values. Input, key generation and
    /// evaluation must use the same FFT table instance.
    ///
    /// # Panics
    ///
    /// Panics if ciphertext/output, FFT, or workspace lengths do not match
    /// the key layout. Checks precede output writes.
    pub fn phase_to<T, Table, A, B>(
        &self,
        input: &FourierGlweCiphertext<A>,
        output: &mut Polynomial<B>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweDecryptWorkspace,
    ) where
        Table: FftTable,
        A: Data<Elem = Complex64>,
        B: DataMut<Elem = T>,
        T: TorusFftValue,
    {
        assert_eq!(
            fft.poly_length(),
            self.poly_length(),
            "FFT polynomial length mismatch"
        );
        assert_eq!(
            input.as_ref().len(),
            self.size.fourier_glwe_len(),
            "Fourier GLWE input layout mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            self.size.poly_length(),
            "GLWE phase output length mismatch"
        );

        let fourier_length = fft.fourier_length();
        let (mut mask, body) = input.a_b(fourier_length);

        assert_eq!(
            workspace.phase.fourier_length(),
            fourier_length,
            "Fourier phase workspace length mismatch"
        );
        let phase = &mut workspace.phase;

        let mut secret = self.iter();
        let si = secret.next().expect("GLWE dimension must be non-zero");
        let ai = mask.next().expect("GLWE ciphertext mask is missing");

        ai.mul_to(&si, phase);

        for (si, ai) in secret.zip(mask) {
            phase.add_mul_assign(&ai, &si);
        }

        body.sub_rev_assign(phase);

        fft.backward_as_torus(phase.as_ref(), output.as_mut());
    }

    /// Decrypts a native-torus Fourier-domain GLWE ciphertext.
    /// Inherits [`Self::phase_to`]'s representation requirements.
    ///
    /// # Panics
    ///
    /// Panics if the parameter layout differs from this key or the inputs
    /// violate [`Self::phase_to`]'s compatibility checks.
    #[must_use]
    pub fn decrypt<T, Table, A>(
        &self,
        input: &FourierGlweCiphertext<A>,
        params: &GlweParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweDecryptWorkspace,
    ) -> PolynomialOwned<T>
    where
        Table: FftTable,
        A: Data<Elem = Complex64>,
        T: TorusFftValue,
    {
        let mut output = PolynomialOwned::zero(self.size.poly_length());
        self.decrypt_to(input, &mut output, params, fft, workspace);
        output
    }

    /// Decrypts into an existing plaintext polynomial.
    /// Inherits [`Self::phase_to`]'s representation requirements.
    ///
    /// # Panics
    ///
    /// Panics if the parameter layout differs from this key or the inputs
    /// violate [`Self::phase_to`]'s compatibility checks.
    pub fn decrypt_to<T, Table, A, B>(
        &self,
        input: &FourierGlweCiphertext<A>,
        output: &mut Polynomial<B>,
        params: &GlweParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweDecryptWorkspace,
    ) where
        Table: FftTable,
        A: Data<Elem = Complex64>,
        B: DataMut<Elem = T>,
        T: TorusFftValue,
    {
        assert_eq!(self.size, params.size(), "GLWE parameter layout mismatch");
        self.phase_to(input, output, fft, workspace);
        params
            .plaintext_codec()
            .decode_slice_assign(output.as_mut());
    }
}
