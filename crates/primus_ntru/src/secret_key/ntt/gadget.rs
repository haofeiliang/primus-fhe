//! NLev and NGSW encryption.

use super::{NttNtruGadgetEncryptContext, NttNtruSecretKey};
use crate::{NlevParameters, NttNgswCiphertext, NttNlevCiphertext};
use primus_data::{Data, DataMut};
use primus_integer::{FheUint, SignedInteger};
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

impl<T: FheUint> NttNtruSecretKey<T> {
    /// Generates an NTT NLev encryption of a polynomial already encoded in `[0, q)`.
    pub fn encrypt_nlev_to<M, Table, R, A, B>(
        &self,
        message: &Polynomial<A>,
        result: &mut NttNlevCiphertext<B>,
        params: &NlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        context: &mut NttNtruGadgetEncryptContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.assert_gadget_domain(params, ntt, context);
        assert_eq!(
            message.as_ref().len(),
            self.poly_length(),
            "gadget input length mismatch"
        );
        assert_eq!(
            result.as_ref().len(),
            params.nlev_len(),
            "gadget output length mismatch"
        );

        let poly_length = self.poly_length();
        let ntru_params = params.ntru();
        let modulus = ntru_params.cipher_modulus();
        for (scalar, mut level) in params
            .basis()
            .scalar_iter()
            .zip(result.iter_ntt_ntru_mut(poly_length))
        {
            message.mul_scalar_to(scalar, &mut context.encoded, modulus);
            self.encrypt_encoded_to_unchecked(&context.encoded, &mut level, ntru_params, ntt, rng);
        }
    }

    /// Encrypts a constant ring element as NLev without plaintext scaling.
    /// Each level has phase `g_l * input + e_l`; input `1` initializes an
    /// encrypted accumulator through an NLev external product.
    /// Reuses output and scratch, zeroing the coefficient tail once per call.
    ///
    /// # Panics
    ///
    /// Panics before sampling or writes for incompatible key/parameter/table,
    /// output or workspace lengths or a constant outside `[0, q)`.
    ///
    /// # Correctness
    ///
    /// The secret key must use the supplied transform representation and modulus.
    pub fn encrypt_nlev_constant_to<M, Table, R, B>(
        &self,
        input: T,
        output: &mut NttNlevCiphertext<B>,
        params: &NlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        context: &mut NttNtruGadgetEncryptContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = T>,
    {
        self.assert_gadget_domain(params, ntt, context);
        assert_eq!(
            output.as_ref().len(),
            params.nlev_len(),
            "NLev output length mismatch"
        );
        let modulus = params.ntru().cipher_modulus();
        assert!(
            input < modulus.value(),
            "NLev constant must be a canonical residue"
        );
        context.encoded.as_mut().fill(T::ZERO);
        for (scalar, mut level) in params
            .basis()
            .scalar_iter()
            .zip(output.iter_ntt_ntru_mut(self.poly_length()))
        {
            context.encoded.as_mut()[0] = modulus.reduce_mul(input, scalar);
            self.encrypt_encoded_to_unchecked(
                &context.encoded,
                &mut level,
                params.ntru(),
                ntt,
                rng,
            );
        }
    }

    /// Generates an NTT NGSW encryption of a polynomial already encoded in `[0, q)`.
    pub fn encrypt_ngsw_to<M, Table, R, A, B>(
        &self,
        message: &Polynomial<A>,
        result: &mut NttNgswCiphertext<B>,
        params: &NlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        context: &mut NttNtruGadgetEncryptContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.assert_gadget_domain(params, ntt, context);
        assert_eq!(
            message.as_ref().len(),
            self.poly_length(),
            "gadget input length mismatch"
        );
        assert_eq!(
            result.as_ref().len(),
            params.nlev_len(),
            "gadget output length mismatch"
        );

        let poly_length = self.poly_length();
        let ntru_params = params.ntru();
        let modulus = ntru_params.cipher_modulus();
        for (scalar, mut level) in params
            .basis()
            .scalar_iter()
            .zip(result.iter_ntt_ntru_mut(poly_length))
        {
            message.mul_scalar_to(scalar, &mut context.encoded, modulus);
            ntt.transform_slice(context.encoded.as_mut());
            self.encrypt_zeros_to_unchecked(&mut level, ntru_params, ntt, rng);
            NttPolynomial(level.as_mut())
                .add_assign(&NttPolynomial(context.encoded.as_ref()), modulus);
        }
    }

    /// Encrypts signed constants into contiguous NTT NGSWs without plaintext scaling.
    ///
    /// Accepts coefficient-secret slices directly, including negative constants.
    /// Output uses `[input][level][NTT coefficient]` layout and must contain
    /// `input.len() * params.nlev_len()` values. Checks the complete batch before
    /// sampling or writes; empty input/output consumes no randomness.
    /// A constant has the same value at every NTT evaluation, so this path needs
    /// neither polynomial scratch nor a message transform.
    ///
    /// # Panics
    ///
    /// Panics on incompatible key/parameters/table, output length or size overflow,
    /// or if any constant's unsigned magnitude is not below the modulus.
    /// A panicking RNG or transform can leave partial output.
    ///
    /// # Correctness
    ///
    /// The secret key must use the supplied modulus and NTT representation.
    pub fn encrypt_ngsw_signed_constant_batch_to<M, Table, R>(
        &self,
        input: &[T::SignedInteger],
        output: &mut [T],
        params: &NlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.assert_domain(params.ntru(), ntt);
        let nlev_len = params.nlev_len();
        let expected = input
            .len()
            .checked_mul(nlev_len)
            .expect("NGSW batch length overflow");
        assert_eq!(output.len(), expected, "NGSW batch output length mismatch");
        let modulus = params.ntru().cipher_modulus();
        // Scan all secret coefficients rather than stopping at the first bad one.
        assert!(
            input.iter().fold(true, |valid, &value| valid
                & (value.unsigned_abs() < modulus.value())),
            "NGSW constant magnitude must be below the modulus"
        );
        for (&value, block) in input.iter().zip(output.chunks_exact_mut(nlev_len)) {
            let constant = modulus.encode_signed(value);
            for (scalar, level) in params
                .basis()
                .scalar_iter()
                .zip(block.chunks_exact_mut(self.poly_length()))
            {
                let mut level = crate::NttNtruCiphertext::new(level);
                self.encrypt_zeros_to_unchecked(&mut level, params.ntru(), ntt, rng);
                let diagonal = modulus.reduce_mul(constant, scalar);
                for coefficient in level.as_mut() {
                    *coefficient = modulus.reduce_add(*coefficient, diagonal);
                }
            }
        }
    }

    fn assert_gadget_domain<M, Table>(
        &self,
        params: &NlevParameters<T, M>,
        ntt: &Table,
        context: &NttNtruGadgetEncryptContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        self.assert_domain(params.ntru(), ntt);
        assert_eq!(context.encoded.as_ref().len(), self.poly_length());
    }
}
