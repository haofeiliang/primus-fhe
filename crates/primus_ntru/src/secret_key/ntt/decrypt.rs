//! Phase extraction and plaintext decoding.

use super::NttNtruSecretKey;
use crate::{NtruParameters, NttNtruCiphertext};
use primus_data::{Data, DataMut};
use primus_encoding::PlaintextEmbedding;
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, Polynomial, PolynomialOwned};
use primus_reduce::FieldContext;

impl<T: FheUint> NttNtruSecretKey<T> {
    /// Computes `f * c` and writes `e + Delta * m` in coefficient form.
    pub fn phase_to<M, Table, A, B>(
        &self,
        cipher: &NttNtruCiphertext<A>,
        result: &mut Polynomial<B>,
        params: &NtruParameters<T, M>,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.assert_domain(params, ntt_table);
        assert_eq!(cipher.as_ref().len(), self.poly_length());
        assert_eq!(result.as_ref().len(), self.poly_length());

        NttPolynomial(cipher.as_ref()).mul_to(
            &self.key,
            &mut NttPolynomial(result.as_mut()),
            params.cipher_modulus(),
        );
        ntt_table.inverse_transform_slice(result.as_mut());
    }

    /// Decrypts a ciphertext with unsigned plaintext embedding.
    pub fn decrypt<M, Table, A>(
        &self,
        cipher: &NttNtruCiphertext<A>,
        params: &NtruParameters<T, M>,
        ntt_table: &Table,
    ) -> PolynomialOwned<T>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        let mut result = PolynomialOwned::zero(self.poly_length());
        self.decrypt_to(cipher, &mut result, params, ntt_table);
        result
    }

    /// Decrypts a ciphertext into `result`.
    pub fn decrypt_to<M, Table, A, B>(
        &self,
        cipher: &NttNtruCiphertext<A>,
        result: &mut Polynomial<B>,
        params: &NtruParameters<T, M>,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.phase_to(cipher, result, params, ntt_table);
        params
            .plaintext_codec()
            .decode_slice_assign(result.as_mut());
    }

    /// Decrypts and returns the absolute coefficient-wise error modulo `q`.
    pub fn decrypt_with_noise<M, Table, A>(
        &self,
        cipher: &NttNtruCiphertext<A>,
        params: &NtruParameters<T, M>,
        ntt_table: &Table,
    ) -> (PolynomialOwned<T>, PolynomialOwned<T>)
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        let modulus = params.cipher_modulus();
        let mut message = PolynomialOwned::zero(self.poly_length());
        self.phase_to(cipher, &mut message, params, ntt_table);
        let mut noise = PolynomialOwned::zero(self.poly_length());

        for (phase, noise) in message.iter_mut().zip(noise.iter_mut()) {
            let phase_mod_q = *phase;
            let decoded = params.plaintext_codec().decode_value(phase_mod_q);
            let encoded = params
                .plaintext_codec()
                .encode_value(decoded, PlaintextEmbedding::Unsigned);
            *phase = decoded;
            *noise = modulus
                .reduce_sub(phase_mod_q, encoded)
                .min(modulus.reduce_sub(encoded, phase_mod_q));
        }
        (message, noise)
    }
}
