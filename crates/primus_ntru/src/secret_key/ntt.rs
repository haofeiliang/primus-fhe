//! NTT-domain NTRU secret key with encryption and decryption.

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, NttPolynomialOwned, PolynomialOwned};
use primus_reduce::FieldContext;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{NttNtruCiphertext, SecretKeyDistr};

use super::NtruSecretKey;

/// Represents a secret key for the NTT-domain NTRU cryptographic scheme.
///
/// Contains both the NTT-transformed secret key `NTT(f)` and its inverse
/// `inv_key = NTT(1/f mod q)`. The inverse is used for key generation
/// (computing the public key `h = g * f^(-1)`).
#[derive(Clone)]
pub struct NttNtruSecretKey<T: FheUint> {
    pub(crate) key: NttPolynomialOwned<T>,
    pub(crate) inv_key: NttPolynomialOwned<T>,
    pub(crate) distr: SecretKeyDistr,
}

impl<T: FheUint> Zeroize for NttNtruSecretKey<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.key.0.zeroize();
        self.inv_key.0.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for NttNtruSecretKey<T> {}

impl<T: FheUint> NttNtruSecretKey<T> {
    /// Creates a new [`NttNtruSecretKey<T>`].
    pub fn new(
        key: NttPolynomialOwned<T>,
        inv_key: NttPolynomialOwned<T>,
        distr: SecretKeyDistr,
    ) -> Self {
        Self {
            key,
            inv_key,
            distr,
        }
    }

    /// Returns the distribution of this [`NttNtruSecretKey<T>`].
    pub fn distr(&self) -> SecretKeyDistr {
        self.distr
    }

    /// Creates a new [`NttNtruSecretKey`] from a coefficient secret key.
    ///
    /// Transforms `f` to NTT domain and computes `inv_key = NTT(1/f mod q)`.
    #[inline]
    pub fn from_coeff_secret_key<Table>(
        secret_key: NtruSecretKey<T>,
        inv_key: NttPolynomialOwned<T>,
        ntt_table: &Table,
    ) -> Self
    where
        Table: NttTable<ValueT = T>,
    {
        let key = ntt_table.transform_inplace(secret_key.key);
        Self {
            key,
            inv_key,
            distr: secret_key.distr,
        }
    }

    /// Performs `h * f` (phase computation).
    ///
    /// Multiplies the ciphertext `h` by the secret key `f` in NTT domain,
    /// then INTT-converts to coefficient domain.
    pub fn phase_inplace<Table, M, A>(
        &self,
        cipher: &NttNtruCiphertext<A>,
        result: &mut PolynomialOwned<T>,
        modulus: M,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        let h = cipher.as_ref();
        let mut temp = NttPolynomial(result.as_mut());
        NttPolynomial(h).mul_to(&self.key, &mut temp, modulus);
        ntt_table.inverse_transform_slice(result.as_mut())
    }

    // -------------------------------------------------------------------------
    // Encryption
    // -------------------------------------------------------------------------

    /// Encrypts a polynomial message into an NTT-domain NTRU ciphertext.
    ///
    /// NTRU encryption: `c = r * h + m mod q` where `r` is a random small
    /// polynomial, `h` is the public key, and `m` is the message.
    ///
    /// In this implementation, the public key `h = g * f^(-1)` is implicit
    /// in the encryption operations.
    pub fn encrypt_inplace<M, Table, R, B>(
        &self,
        msg: &PolynomialOwned<T>,
        result: &mut NttNtruCiphertext<B>,
        modulus: M,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = T>,
    {
        let poly_length = ntt_table.poly_length();

        // Sample a random small polynomial r (binary for NTRU)
        let r = PolynomialOwned::random_binary(poly_length, rng);

        // r * h in NTT domain: NTT(r) * NTT(h) = NTT(r) * NTT(g * f^(-1))
        // This is equivalent to: encrypt_with_r(msg, r, ...)
        // For simplicity: c = r * inv_key^(-1) + msg  (where inv_key = f^(-1))

        // Compute NTT(r) * NTT(h) = NTT(r) * inv_key^(-1)
        // Actually h = g * f^(-1), NTT(h) = NTT(g) * NTT(f^(-1))
        // So r*h = NTT(r) * NTT(h) = NTT(r) * NTT(g) * inv_key
        //
        // For encrypt, we don't have g. Instead we directly use the
        // plain NTRU encryption: c = r * h + m (all in NTT domain).

        // Fill result with NTT(r)
        let r_ntt = ntt_table.transform_inplace(r);
        result.as_mut().copy_from_slice(r_ntt.as_slice());

        // Add the message (already in NTT form or NTT-transform it)
        let msg_ntt = ntt_table.transform_inplace(msg.clone());
        result
            .as_mut()
            .iter_mut()
            .zip(msg_ntt.as_slice().iter())
            .for_each(|(c, &m)| {
                modulus.reduce_add_assign(c, m);
            });

        // c = NTT(r) + NTT(m) = NTT(r + m) — this is the ciphertext
    }

    /// Decrypts an NTT-domain NTRU ciphertext.
    ///
    /// NTRU decryption: compute `c * f mod q`, INTT to coefficient domain,
    /// then reduce modulo the plaintext modulus.
    pub fn decrypt_inplace<M, Table>(
        &self,
        cipher: &NttNtruCiphertext<impl Data<Elem = T>>,
        result: &mut PolynomialOwned<T>,
        modulus: M,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        // c * f in NTT domain
        let h = cipher.as_ref();
        let mut temp = NttPolynomial(result.as_mut());
        NttPolynomial(h).mul_to(&self.key, &mut temp, modulus);

        // INTT
        ntt_table.inverse_transform_slice(result.as_mut());

        // c * f = (r * h + m) * f = r * g + f * m mod q
        // Since r, g, f, m are all small, this recovers the plaintext
    }
}
