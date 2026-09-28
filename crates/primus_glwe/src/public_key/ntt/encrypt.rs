//! NTT public-key encryption.

use super::{NttGlwePublicEncryptWorkspace, NttGlwePublicKey};
use crate::{GlweParameters, NttGlweCiphertext, PlaintextEmbedding};
use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

impl<S, T> NttGlwePublicKey<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Encrypts an unsigned plaintext polynomial into `output` without allocating.
    ///
    /// `workspace` holds one reusable ephemeral polynomial of `params.poly_length()`
    /// coefficients. It may be reused across keys with the same polynomial length.
    ///
    /// # Panics
    ///
    /// Panics if key/output/message/workspace lengths differ from `params`, or the table
    /// has a different polynomial length or modulus. Checks precede output writes.
    ///
    /// Also panics if any plaintext coefficient is outside `[0, t)`. That check
    /// occurs in the codec and may leave partial output or consume randomness.
    pub fn encrypt_to<M, Table, R, A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut NttGlweCiphertext<B>,
        params: &GlweParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttGlwePublicEncryptWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(
            input.as_ref().len(),
            params.poly_length(),
            "GLWE message length mismatch"
        );
        self.encrypt_kernel_to(output, params, ntt, rng, workspace, |body| {
            params.plaintext_codec().add_encode_slice_assign(
                body,
                input.as_ref(),
                PlaintextEmbedding::Unsigned,
            );
        });
    }

    /// Encrypts a polynomial using centered plaintext embedding into `output`.
    ///
    /// # Panics
    ///
    /// Inherits [`Self::encrypt_to`]'s layout and plaintext-range panic conditions.
    pub fn encrypt_centered_to<M, Table, R, A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut NttGlweCiphertext<B>,
        params: &GlweParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttGlwePublicEncryptWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(
            input.as_ref().len(),
            params.poly_length(),
            "GLWE message length mismatch"
        );
        self.encrypt_kernel_to(output, params, ntt, rng, workspace, |body| {
            params.plaintext_codec().add_encode_slice_assign(
                body,
                input.as_ref(),
                PlaintextEmbedding::Centered,
            );
        });
    }

    /// Encrypts an already encoded coefficient polynomial without plaintext scaling.
    ///
    /// # Correctness
    ///
    /// Input coefficients must be canonical residues modulo the ciphertext modulus.
    /// Use [`crate::NttGlweSecretKey::phase_to`] to recover encoded coefficients with noise;
    /// ordinary decryption also applies plaintext decoding.
    ///
    /// # Panics
    ///
    /// Panics on the compatibility mismatches described by [`Self::encrypt_to`].
    pub fn encrypt_encoded_to<M, Table, R, A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut NttGlweCiphertext<B>,
        params: &GlweParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttGlwePublicEncryptWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(
            input.as_ref().len(),
            params.poly_length(),
            "GLWE message length mismatch"
        );
        self.encrypt_kernel_to(output, params, ntt, rng, workspace, |body| {
            Polynomial::new(body).add_assign(input, params.cipher_modulus());
        });
    }

    /// Encrypts a polynomial into a newly allocated NTT-domain ciphertext.
    ///
    /// # Panics
    ///
    /// Inherits [`Self::encrypt_to`]'s layout and plaintext-range panic conditions.
    #[must_use]
    pub fn encrypt<M, Table, R, A>(
        &self,
        input: &Polynomial<A>,
        params: &GlweParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttGlwePublicEncryptWorkspace<T>,
    ) -> NttGlweCiphertext<Vec<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
    {
        let mut output = NttGlweCiphertext::zero(params.glwe_len());
        self.encrypt_to(input, &mut output, params, ntt, rng, workspace);
        output
    }

    /// Encrypts zero into `output`.
    ///
    /// # Panics
    ///
    /// Panics on incompatible layouts or transform parameters, as described
    /// by [`Self::encrypt_to`]; zero encryption has no message-length check.
    pub fn encrypt_zeros_to<M, Table, R, B>(
        &self,
        output: &mut NttGlweCiphertext<B>,
        params: &GlweParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttGlwePublicEncryptWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = T>,
    {
        self.encrypt_kernel_to(output, params, ntt, rng, workspace, |_| {});
    }

    /// Encrypts zero into a newly allocated NTT-domain ciphertext.
    ///
    /// # Panics
    ///
    /// Panics on incompatible layouts or transform parameters, as described
    /// by [`Self::encrypt_to`]; zero encryption has no message-length check.
    #[must_use]
    pub fn encrypt_zeros<M, Table, R>(
        &self,
        params: &GlweParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttGlwePublicEncryptWorkspace<T>,
    ) -> NttGlweCiphertext<Vec<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let mut output = NttGlweCiphertext::zero(params.glwe_len());
        self.encrypt_zeros_to(&mut output, params, ntt, rng, workspace);
        output
    }

    /// Validates layouts, then encrypts using a statically dispatched body addition.
    /// The owning boundary must check the input length. `add_message` runs once
    /// after body noise sampling and before its forward transform.
    fn encrypt_kernel_to<M, Table, R, B>(
        &self,
        output: &mut NttGlweCiphertext<B>,
        params: &GlweParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttGlwePublicEncryptWorkspace<T>,
        add_message: impl FnOnce(&mut [T]),
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = T>,
    {
        let size = params.size();
        let poly_length = size.poly_length();
        assert_eq!(
            self.key.as_ref().len(),
            size.glwe_len(),
            "GLWE public key layout mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            size.glwe_len(),
            "GLWE output layout mismatch"
        );
        assert_eq!(
            ntt.poly_length(),
            poly_length,
            "NTT polynomial length mismatch"
        );
        assert_eq!(
            workspace.ephemeral.len(),
            poly_length,
            "public encryption workspace length mismatch"
        );
        assert_eq!(
            ntt.modulus(),
            params.cipher_modulus().value(),
            "NTT ciphertext modulus mismatch"
        );

        let modulus = params.cipher_modulus();
        let ephemeral = &mut workspace.ephemeral;
        primus_distr::sample_sparse_ternary_values_to(
            ephemeral,
            params.cipher_modulus_minus_one(),
            rng,
        );
        ntt.transform_slice(ephemeral);
        let ephemeral = NttPolynomial(ephemeral.as_slice());

        let (mask, mut body) = output.a_b_mut(poly_length);
        let (public_mask, public_body) = self.key.a_b(poly_length);
        for (mut output, public_key_component) in mask.zip(public_mask) {
            primus_distr::sample_gaussian_values_to(
                output.as_mut(),
                params.noise_distribution(),
                rng,
            );
            ntt.transform_slice(output.as_mut());
            output.add_mul_assign(&public_key_component, &ephemeral, modulus);
        }

        primus_distr::sample_gaussian_values_to(body.as_mut(), params.noise_distribution(), rng);
        add_message(body.as_mut());
        ntt.transform_slice(body.as_mut());
        body.add_mul_assign(&public_body, &ephemeral, modulus);
    }
}
