//! NTT GLWE encryption.

use super::NttGlweSecretKey;
use crate::{GlweParameters, GlweParametersInner, NttGlweCiphertext, PlaintextEmbedding};
use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::Polynomial;
use primus_reduce::FieldContext;

impl<T: FheUint> NttGlweSecretKey<T> {
    /// Encrypts an unsigned plaintext polynomial into a newly allocated ciphertext.
    ///
    /// # Panics
    ///
    /// Inherits the layout and plaintext-range panic conditions of [`Self::encrypt_to`].
    #[must_use]
    pub fn encrypt<M, Table, R, A>(
        &self,
        input: &Polynomial<A>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) -> NttGlweCiphertext<Vec<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
    {
        let mut output = NttGlweCiphertext::zero(self.size.glwe_len());
        self.encrypt_to(input, &mut output, params, ntt_table, rng);
        output
    }

    /// Encrypts a polynomial message into an NTT-domain GLWE ciphertext.
    ///
    /// # Panics
    ///
    /// Panics if the key, parameter layout, transform, message length,
    /// or output length are incompatible. Compatibility is checked before
    /// writing the ciphertext.
    ///
    /// Also panics if any plaintext coefficient is outside `[0, t)`. That check
    /// occurs in the codec and may leave partial output or consume randomness.
    pub fn encrypt_to<M, Table, R, A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut NttGlweCiphertext<B>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.assert_encrypt_compatible(output, params, ntt_table);
        assert_eq!(
            input.as_ref().len(),
            self.poly_length(),
            "GLWE message length mismatch"
        );
        self.encrypt_kernel_to(output, params.inner(), ntt_table, rng, |body| {
            params.plaintext_codec().add_encode_slice_assign(
                body,
                input.as_ref(),
                PlaintextEmbedding::Unsigned,
            );
        });
    }

    /// Encrypts a polynomial using centered plaintext embedding.
    ///
    /// # Panics
    ///
    /// Inherits [`Self::encrypt_to`]'s panic conditions, including plaintext-range
    /// checks that may leave partial output or consume randomness.
    pub fn encrypt_centered_to<M, Table, R, A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut NttGlweCiphertext<B>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.assert_encrypt_compatible(output, params, ntt_table);
        assert_eq!(
            input.as_ref().len(),
            self.poly_length(),
            "GLWE message length mismatch"
        );
        self.encrypt_kernel_to(output, params.inner(), ntt_table, rng, |body| {
            params.plaintext_codec().add_encode_slice_assign(
                body,
                input.as_ref(),
                PlaintextEmbedding::Centered,
            );
        });
    }

    /// Encrypts a polynomial whose coefficients are already encoded in
    /// `[0, q)`. The plaintext codec and delta scaling are not applied.
    ///
    /// # Correctness
    ///
    /// Input coefficients must be canonical residues modulo the ciphertext modulus.
    /// Use [`Self::phase_to`] to recover the noisy encoded polynomial.
    ///
    /// # Panics
    ///
    /// Panics on incompatible layouts or transform parameters, as described
    /// by [`Self::encrypt_to`].
    pub fn encrypt_encoded_to<M, Table, R, A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut NttGlweCiphertext<B>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.assert_encrypt_compatible(output, params, ntt_table);
        assert_eq!(
            input.as_ref().len(),
            self.poly_length(),
            "GLWE message length mismatch"
        );
        self.encrypt_encoded_kernel_to(input, output, params.inner(), ntt_table, rng);
    }

    /// Encrypts zeros (randomized encryption of zero).
    ///
    /// # Panics
    ///
    /// Panics on incompatible layouts or transform parameters, as described
    /// by [`Self::encrypt_to`]; zero encryption has no message-length check.
    #[must_use]
    pub fn encrypt_zeros<M, Table, R>(
        &self,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) -> NttGlweCiphertext<Vec<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let mut output: NttGlweCiphertext<Vec<T>> = NttGlweCiphertext::zero(self.size.glwe_len());
        self.encrypt_zeros_to(&mut output, params, ntt_table, rng);
        output
    }

    /// Encrypts zero into the existing ciphertext output.
    ///
    /// # Panics
    ///
    /// Panics on incompatible layouts or transform parameters, as described
    /// by [`Self::encrypt_to`]; zero encryption has no message-length check.
    pub fn encrypt_zeros_to<M, Table, R, A>(
        &self,
        output: &mut NttGlweCiphertext<A>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: DataMut<Elem = T>,
    {
        self.assert_encrypt_compatible(output, params, ntt_table);
        self.encrypt_zeros_kernel_to(output, params.inner(), ntt_table, rng);
    }

    /// Encrypts an encoded coefficient polynomial without repeating boundary checks.
    ///
    /// The caller must validate key/output layouts and matching parameter/transform
    /// domains before entering this kernel.
    /// Input length must equal the key's polynomial length; coefficients must be
    /// canonical in the ciphertext ring. No plaintext or gadget scaling is applied.
    #[inline]
    pub(super) fn encrypt_encoded_kernel_to<M, Table, R, A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut NttGlweCiphertext<B>,
        params: &GlweParametersInner<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.encrypt_kernel_to(output, params, ntt_table, rng, |body| {
            Polynomial::new(body).add_assign(input, params.cipher_modulus());
        });
    }

    /// Encrypts zero without repeating boundary checks.
    ///
    /// The caller must validate key/output layouts and matching parameter/transform
    /// domains before entering this kernel.
    #[inline]
    pub(super) fn encrypt_zeros_kernel_to<M, Table, R, A>(
        &self,
        output: &mut NttGlweCiphertext<A>,
        params: &GlweParametersInner<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: DataMut<Elem = T>,
    {
        self.encrypt_kernel_to(output, params, ntt_table, rng, |_| {});
    }

    /// Validates layout and transform compatibility before sampling or writing output.
    #[inline]
    fn assert_encrypt_compatible<M, Table, B>(
        &self,
        output: &NttGlweCiphertext<B>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        B: Data<Elem = T>,
    {
        assert_eq!(self.size, params.size(), "GLWE parameter layout mismatch");
        assert_eq!(
            ntt_table.poly_length().get(),
            self.poly_length(),
            "NTT polynomial length mismatch"
        );
        assert_eq!(
            ntt_table.modulus(),
            params.cipher_modulus().value(),
            "NTT ciphertext modulus mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            self.size.glwe_len(),
            "GLWE output layout mismatch"
        );
    }

    /// Encrypts with validated layouts and matching parameter/transform domains.
    /// Calls `add_message` once on the sampled coefficient noise, before transforming
    /// the body. Its concrete closure type specializes plaintext/encoded/zero paths
    /// without dynamic dispatch or an intermediate message buffer.
    fn encrypt_kernel_to<M, Table, R, B>(
        &self,
        output: &mut NttGlweCiphertext<B>,
        params: &GlweParametersInner<T, M>,
        ntt_table: &Table,
        rng: &mut R,
        add_message: impl FnOnce(&mut [T]),
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = T>,
    {
        let poly_length = self.size.poly_length().get();
        debug_assert_eq!(ntt_table.poly_length().get(), poly_length);
        debug_assert_eq!(output.as_ref().len(), self.size.glwe_len());

        let modulus = params.cipher_modulus();
        let (a, mut b) = output.a_b_mut(poly_length);

        // Sample noise into b
        primus_distr::sample_gaussian_values_to(b.as_mut(), params.noise_distribution(), rng);

        add_message(b.as_mut());
        ntt_table.transform_slice(b.as_mut());

        // Sample each a_i, then accumulate a_i * s_i into b pointwise.
        let uniform_distribution = params.cipher_modulus_uniform_distr();
        for (si, mut ai) in self.iter().zip(a) {
            primus_distr::sample_uniform_values_to(ai.as_mut(), &uniform_distribution, rng);
            b.add_mul_assign(&ai, &si, modulus);
        }
    }
}
