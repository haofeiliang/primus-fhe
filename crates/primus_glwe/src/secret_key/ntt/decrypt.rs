//! NTT GLWE phase extraction, decoding and noise diagnostics.

use super::NttGlweSecretKey;
use crate::{GlweParameters, NttGlweCiphertext, PlaintextEmbedding};
use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, Polynomial, PolynomialOwned};
use primus_reduce::FieldContext;

impl<T: FheUint> NttGlweSecretKey<T> {
    /// Performs `b - ∑ a_i * s_i` (phase), leaving output in coefficient domain.
    ///
    /// # Correctness
    ///
    /// Input values must be canonical residues modulo `modulus`, in the same
    /// NTT representation as this key and `ntt_table`.
    ///
    /// # Panics
    ///
    /// Panics if ciphertext/output/table lengths do not match the key layout,
    /// or the key, arithmetic and table moduli differ. Checks precede output writes.
    pub fn phase_to<M, Table, A, B>(
        &self,
        input: &NttGlweCiphertext<A>,
        output: &mut Polynomial<B>,
        modulus: M,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let poly_length = self.size.poly_length().get();
        self.assert_ntt_compatible(modulus, ntt_table);
        assert_eq!(
            output.as_ref().len(),
            poly_length,
            "GLWE phase output length mismatch"
        );
        assert_eq!(
            input.as_ref().len(),
            self.size.glwe_len(),
            "GLWE input layout mismatch"
        );

        let (mut a, b) = input.a_b(poly_length);
        let mut secret = self.iter();

        let mut result_poly = NttPolynomial(output.as_mut());
        let si = secret.next().expect("GLWE dimension must be non-zero");
        let ai = a.next().expect("GLWE ciphertext mask is missing");

        ai.mul_to(&si, &mut result_poly, modulus);

        secret.zip(a).for_each(|(si, ai)| {
            result_poly.add_mul_assign(&ai, &si, modulus);
        });
        b.sub_rev_assign(&mut result_poly, modulus);

        ntt_table.inverse_transform_slice(output.as_mut())
    }

    /// Decrypts an NTT GLWE ciphertext into a newly allocated plaintext polynomial.
    /// Inherits [`Self::phase_to`]'s representation requirements.
    ///
    /// # Panics
    ///
    /// Panics if the parameter layout differs from this key or the inputs
    /// violate [`Self::phase_to`]'s compatibility checks.
    #[must_use]
    pub fn decrypt<M, Table, A>(
        &self,
        input: &NttGlweCiphertext<A>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
    ) -> PolynomialOwned<T>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        let mut output = PolynomialOwned::zero(self.size.poly_length().get());
        self.decrypt_to(input, &mut output, params, ntt_table);
        output
    }

    /// Decrypts an NTT GLWE ciphertext into `output`.
    ///
    /// Inherits [`Self::phase_to`]'s representation requirements. The ciphertext
    /// has `params.glwe_len()` values; output has `params.poly_length().get()` values.
    ///
    /// # Panics
    ///
    /// Panics if the parameter layout differs from this key or the inputs
    /// violate [`Self::phase_to`]'s compatibility checks.
    pub fn decrypt_to<M, Table, A, B>(
        &self,
        input: &NttGlweCiphertext<A>,
        output: &mut Polynomial<B>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(self.size, params.size(), "GLWE parameter layout mismatch");
        self.phase_to(input, output, params.cipher_modulus(), ntt_table);

        params
            .plaintext_codec()
            .decode_slice_assign(output.as_mut());
    }

    /// Decrypts a ciphertext and returns both its message and the absolute
    /// coefficient-wise noise modulo `q`.
    ///
    /// # Panics
    ///
    /// Panics on the same parameter and input mismatches as [`Self::decrypt_to`].
    #[must_use]
    pub fn decrypt_with_noise<M, Table, A>(
        &self,
        input: &NttGlweCiphertext<A>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
    ) -> (PolynomialOwned<T>, PolynomialOwned<T>)
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        self.decrypt_with_noise_and_embedding(
            input,
            params,
            ntt_table,
            PlaintextEmbedding::Unsigned,
        )
    }

    /// Decrypts a centered ciphertext and returns both its message and the
    /// absolute coefficient-wise noise modulo `q`.
    ///
    /// # Panics
    ///
    /// Panics on the same parameter and input mismatches as [`Self::decrypt_to`].
    #[must_use]
    pub fn decrypt_centered_with_noise<M, Table, A>(
        &self,
        input: &NttGlweCiphertext<A>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
    ) -> (PolynomialOwned<T>, PolynomialOwned<T>)
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        self.decrypt_with_noise_and_embedding(
            input,
            params,
            ntt_table,
            PlaintextEmbedding::Centered,
        )
    }

    /// Decrypts a ciphertext and measures its coefficient-wise noise using
    /// the selected plaintext embedding.
    ///
    /// # Panics
    ///
    /// Panics on the same parameter and input mismatches as [`Self::decrypt_to`].
    #[must_use]
    pub fn decrypt_with_noise_and_embedding<M, Table, A>(
        &self,
        input: &NttGlweCiphertext<A>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
        embedding: PlaintextEmbedding,
    ) -> (PolynomialOwned<T>, PolynomialOwned<T>)
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        assert_eq!(self.size, params.size(), "GLWE parameter layout mismatch");
        let modulus = params.cipher_modulus();
        let mut message = PolynomialOwned::zero(self.size.poly_length().get());
        self.phase_to(input, &mut message, modulus, ntt_table);

        let mut noise = PolynomialOwned::zero(self.size.poly_length().get());
        message
            .iter_mut()
            .zip(noise.iter_mut())
            .for_each(|(phase, noise)| {
                let phase_mod_q = *phase;
                let decoded = params.plaintext_codec().decode_value(phase_mod_q);
                let encoded = params.plaintext_codec().encode_value(decoded, embedding);

                *phase = decoded;
                *noise = modulus
                    .reduce_sub(phase_mod_q, encoded)
                    .min(modulus.reduce_sub(encoded, phase_mod_q));
            });

        (message, noise)
    }
}
