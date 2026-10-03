//! Client-side coefficient-ring encryption and decryption under the accumulator secret.

use primus_data::{Data, DataMut};
use primus_encoding::ScaledCodec;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_glwe::{
    FourierGlweCiphertext, FourierGlweDecryptWorkspace, FourierGlweEncryptWorkspace,
    FourierGlweSecretKey, GlweCiphertext, GlweParameters,
};
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;

use crate::{ClientKey, TfheClientError, TfheContext};

/// Prepared private-key client for the accumulator GLWE domain.
///
/// Owns one transformed accumulator secret and reusable conversion workspace,
/// borrowing the transform context and owning independently bound message parameters.
/// Ciphertexts use coefficient representation and the accumulator secret, which
/// differs from the external LWE domain used by [`crate::Encryptor`].
/// Construction prepares all buffers; `encrypt_to` and `decrypt_to` do not allocate.
pub struct AccumulatorClient<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    context: &'a TfheContext<T, Table>,
    parameters: GlweParameters<T, NativeModulus<T>>,
    secret: FourierGlweSecretKey,
    transformed: FourierGlweCiphertext<Vec<Complex64>>,
    fft: FftEngine<'a, Table>,
    encrypt: FourierGlweEncryptWorkspace<T>,
    decrypt: FourierGlweDecryptWorkspace,
}

impl<'a, T, Table> AccumulatorClient<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Binds the client key and a Scaled message codec to the accumulator domain.
    /// Rejects an incompatible key or codec modulus before preparing the secret.
    pub fn try_new(
        context: &'a TfheContext<T, Table>,
        client_key: &ClientKey<T>,
        codec: ScaledCodec<T, NativeModulus<T>>,
    ) -> Result<Self, TfheClientError> {
        client_key.check_compatible(context.parameters())?;
        let parameters =
            GlweParameters::try_from_glev(context.parameters().blind_rotation_ggsw(), codec)
                .map_err(|_| crate::ClientError::CodecModulusMismatch)?;
        let mut fft = context.new_fft_engine();
        let secret =
            FourierGlweSecretKey::from_coeff_secret_key(client_key.glwe_secret_key(), &mut fft);
        Ok(Self {
            context,
            secret,
            transformed: FourierGlweCiphertext::zero(parameters.size().fourier_glwe_len()),
            fft,
            encrypt: FourierGlweEncryptWorkspace::new(parameters.poly_length()),
            decrypt: FourierGlweDecryptWorkspace::new(parameters.poly_length()),
            parameters,
        })
    }

    /// Encrypts an unsigned polynomial into a newly allocated coefficient ciphertext.
    /// Inherits [`Self::encrypt_to`]'s message and panic contracts.
    #[must_use]
    pub fn encrypt<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        message: &[T],
        rng: &mut R,
    ) -> GlweCiphertext<Vec<T>> {
        let mut output = self.context.allocate_accumulator_ciphertext();
        self.encrypt_to(message, &mut output, rng);
        output
    }

    /// Encrypts exactly N unsigned coefficients in `[0, t)` under the accumulator secret.
    /// Uses this client's Scaled codec and overwrites the entire coefficient output.
    ///
    /// # Panics
    /// Panics before sampling if message or output length is wrong. A plaintext-range
    /// or RNG panic may consume randomness and modify scratch; transform panics may
    /// partially write output. See
    /// [`FourierGlweSecretKey::encrypt_to`].
    pub fn encrypt_to<R, S>(&mut self, message: &[T], output: &mut GlweCiphertext<S>, rng: &mut R)
    where
        R: rand::Rng + rand::CryptoRng,
        S: DataMut<Elem = T>,
    {
        let parameters = &self.parameters;
        assert_eq!(
            (message.len(), output.as_ref().len()),
            (parameters.poly_length().get(), parameters.glwe_len()),
            "accumulator encryption layout mismatch"
        );
        self.secret.encrypt_to(
            &Polynomial::new(message),
            &mut self.transformed,
            parameters,
            &mut self.fft,
            rng,
            &mut self.encrypt,
        );
        self.transformed.write_torus_form(output, &mut self.fft);
    }

    /// Allocates and decodes all N coefficients. Inherits [`Self::decrypt_to`]'s contracts.
    #[must_use]
    pub fn decrypt<S: Data<Elem = T>>(&mut self, input: &GlweCiphertext<S>) -> Vec<T> {
        let n = self
            .context
            .parameters()
            .blind_rotation_ggsw()
            .poly_length()
            .get();
        let mut output = vec![T::ZERO; n];
        self.decrypt_to(input, &mut output);
        output
    }

    /// Decodes to exactly N unsigned coefficients in `[0, t)`, overwriting `output`.
    ///
    /// # Correctness
    /// Input must use this accumulator secret, modulus and plaintext codec, with
    /// noise within the decoding margin. Ciphertexts carry no key/encoding metadata.
    ///
    /// # Panics
    /// Panics before output writes if ciphertext or plaintext length is wrong.
    pub fn decrypt_to<S: Data<Elem = T>>(&mut self, input: &GlweCiphertext<S>, output: &mut [T]) {
        let parameters = &self.parameters;
        assert_eq!(
            (input.as_ref().len(), output.len()),
            (parameters.glwe_len(), parameters.poly_length().get()),
            "accumulator decryption layout mismatch"
        );
        input.write_fourier_form(&mut self.transformed, &mut self.fft);
        self.secret.decrypt_to(
            &self.transformed,
            &mut Polynomial::new(output),
            parameters,
            &mut self.fft,
            &mut self.decrypt,
        );
    }
}

impl<T, Table> TfheContext<T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Prepares private-key encryption/decryption in the accumulator ring domain.
    /// Inherits [`crate::AccumulatorClient::try_new`]'s contracts and errors.
    pub fn accumulator_client(
        &self,
        client_key: &ClientKey<T>,
        codec: ScaledCodec<T, NativeModulus<T>>,
    ) -> Result<crate::AccumulatorClient<'_, T, Table>, crate::TfheClientError> {
        crate::AccumulatorClient::try_new(self, client_key, codec)
    }
}
