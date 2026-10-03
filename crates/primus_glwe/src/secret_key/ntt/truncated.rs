//! Coefficient-domain GLWE ciphertexts with a truncated body.

use super::NttGlweSecretKey;
use crate::{GlweParameters, TruncatedGlweCiphertext};
use primus_data::Data;
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

impl<T: FheUint> NttGlweSecretKey<T> {
    /// Encrypts several zero messages in one coefficient-domain GLWE sample
    /// whose body is truncated to `message_count` coefficients.
    ///
    /// This is useful when only the first few coefficient extractions are
    /// needed. `message_count` must not exceed the polynomial length.
    ///
    /// # Panics
    ///
    /// Panics before sampling if the key/parameter/table moduli or layouts differ,
    /// or `message_count` exceeds the polynomial length.
    #[must_use]
    pub fn encrypt_truncated_zeros<M, Table, R>(
        &self,
        message_count: usize,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) -> TruncatedGlweCiphertext<Vec<T>>
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let size = params.size();
        let poly_length = size.poly_length().get();
        assert_eq!(self.size, size, "GLWE parameter layout mismatch");
        self.assert_ntt_compatible(params.cipher_modulus(), ntt_table);
        assert!(
            message_count <= poly_length,
            "GLWE message count exceeds polynomial length"
        );

        let mask_len = size.mask_len();
        let mut data = vec![T::ZERO; mask_len + poly_length];
        let (mask, body) = data.split_at_mut(mask_len);
        primus_distr::sample_uniform_values_to(mask, &params.cipher_modulus_uniform_distr(), rng);

        let modulus = params.cipher_modulus();
        let mut masks = mask.chunks_exact(poly_length);
        let mut secrets = self.iter();
        let first_mask = masks.next().expect("GLWE dimension must be non-zero");
        let first_secret = secrets.next().expect("GLWE dimension must be non-zero");
        body.copy_from_slice(first_mask);
        ntt_table.transform_slice(body);
        NttPolynomial(&mut *body).mul_assign(&first_secret, modulus);

        if masks.len() != 0 {
            let mut transformed_mask = vec![T::ZERO; poly_length];
            for (mask, secret) in masks.zip(secrets) {
                transformed_mask.copy_from_slice(mask);
                ntt_table.transform_slice(&mut transformed_mask);
                NttPolynomial(&mut *body).add_mul_assign(
                    &NttPolynomial(transformed_mask.as_slice()),
                    &secret,
                    modulus,
                );
            }
        }
        ntt_table.inverse_transform_slice(body);
        Polynomial(&mut *body).add_random_gaussian_assign(
            params.noise_distribution(),
            modulus,
            rng,
        );

        data.truncate(mask_len + message_count);
        TruncatedGlweCiphertext::new(data)
    }

    /// Returns the retained coefficient phases of a truncated GLWE
    /// ciphertext as a newly allocated vector. Internal scratch still holds full
    /// polynomials, even when the returned vector is shorter than N.
    ///
    /// # Correctness
    ///
    /// Input coefficients must be canonical modulo `modulus`. This key and
    /// `ntt_table` must use the same NTT roots and evaluation order.
    ///
    /// # Panics
    ///
    /// Panics if the key/arithmetic/table moduli or table length differ, or the ciphertext
    /// does not contain a full mask and at most one polynomial of body values.
    #[must_use]
    pub fn phase_truncated<M, Table, A>(
        &self,
        input: &TruncatedGlweCiphertext<A>,
        modulus: M,
        ntt_table: &Table,
    ) -> Vec<T>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        let size = self.size;
        let poly_length = size.poly_length().get();
        self.assert_ntt_compatible(modulus, ntt_table);
        let (mask, body) = input.a_b_slices(size);
        assert!(
            body.len() <= poly_length,
            "GLWE body exceeds polynomial length"
        );

        let mut masks = mask.chunks_exact(poly_length);
        let mut secrets = self.iter();
        let first_mask = masks.next().expect("GLWE dimension must be non-zero");
        let first_secret = secrets.next().expect("GLWE dimension must be non-zero");
        let mut phase_mask = first_mask.to_vec();
        ntt_table.transform_slice(&mut phase_mask);
        NttPolynomial(phase_mask.as_mut_slice()).mul_assign(&first_secret, modulus);

        if masks.len() != 0 {
            let mut transformed_mask = vec![T::ZERO; poly_length];
            for (mask, secret) in masks.zip(secrets) {
                transformed_mask.copy_from_slice(mask);
                ntt_table.transform_slice(&mut transformed_mask);
                NttPolynomial(phase_mask.as_mut_slice()).add_mul_assign(
                    &NttPolynomial(transformed_mask.as_slice()),
                    &secret,
                    modulus,
                );
            }
        }
        ntt_table.inverse_transform_slice(&mut phase_mask);

        body.iter()
            .zip(phase_mask)
            .map(|(&body, mask)| modulus.reduce_sub(body, mask))
            .collect()
    }

    /// Decrypts all retained messages in a truncated GLWE ciphertext.
    ///
    /// Returns coefficients in the key's integer type, as with [`Self::decrypt`].
    /// Inherits [`Self::phase_truncated`]'s representation and scratch requirements.
    ///
    /// # Panics
    ///
    /// Panics if the parameter layout differs from this key or the inputs
    /// violate [`Self::phase_truncated`]'s compatibility checks.
    #[must_use]
    pub fn decrypt_truncated<M, Table, A>(
        &self,
        input: &TruncatedGlweCiphertext<A>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
    ) -> Vec<T>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        assert_eq!(self.size, params.size(), "GLWE parameter layout mismatch");
        let mut messages = self.phase_truncated(input, params.cipher_modulus(), ntt_table);
        params.plaintext_codec().decode_slice_assign(&mut messages);

        messages
    }
}
