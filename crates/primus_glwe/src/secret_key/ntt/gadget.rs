//! NTT GLev and GGSW generation.

use super::{NttGadgetEncryptContext, NttGlweSecretKey};
use crate::{GlevParameters, NttGgswCiphertext, NttGlevCiphertext};
use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

impl<T: FheUint> NttGlweSecretKey<T> {
    /// Generates an NTT GLev encryption of a coefficient-domain ring polynomial.
    ///
    /// Applies gadget basis scaling without applying the plaintext codec.
    /// GLev uses only polynomial workspace; its cached level count need not match.
    ///
    /// # Correctness
    ///
    /// Input coefficients must be canonical residues modulo `params.cipher_modulus()`.
    /// This secret key must use the supplied table's NTT representation.
    ///
    /// # Panics
    ///
    /// Panics if the key layout, input/output lengths, NTT length/modulus or
    /// polynomial workspace do not match `params`. Checks precede all output writes.
    pub fn encrypt_glev_to<M, Table, R, A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut NttGlevCiphertext<B>,
        params: &GlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        context: &mut NttGadgetEncryptContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.assert_gadget_compatible(params, ntt);
        context.assert_glev_compatible(params.size());
        assert_eq!(
            input.as_ref().len(),
            self.poly_length(),
            "gadget input length mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            params.glev_len(),
            "NTT GLev output layout mismatch"
        );

        self.encrypt_glev_kernel_to(input, output, params, ntt, rng, context);
    }

    /// Encrypts a GLev after the caller validates key, input/output, table and workspace.
    pub(crate) fn encrypt_glev_kernel_to<M, Table, R, A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut NttGlevCiphertext<B>,
        params: &GlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        context: &mut NttGadgetEncryptContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let modulus = params.cipher_modulus();
        for (scalar, mut glwe) in params
            .basis()
            .scalar_iter()
            .zip(output.iter_ntt_glwe_mut(params.glwe_len()))
        {
            input.mul_scalar_to(scalar, &mut context.encoded, modulus);
            self.encrypt_encoded_kernel_to(&context.encoded, &mut glwe, params.inner(), ntt, rng);
        }
    }

    /// Generates an NTT GGSW encryption of a coefficient-domain ring polynomial.
    ///
    /// Applies gadget basis scaling without applying the plaintext codec.
    ///
    /// # Correctness
    ///
    /// Input coefficients must be canonical residues modulo `params.cipher_modulus()`.
    /// This secret key must use the supplied table's NTT representation.
    ///
    /// # Panics
    ///
    /// Panics if the key, input, transform, output, or workspace lengths do
    /// not match the gadget parameters, or the NTT modulus differs.
    /// Checks precede all output writes.
    pub fn encrypt_ggsw_to<M, Table, R, A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut NttGgswCiphertext<B>,
        params: &GlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        context: &mut NttGadgetEncryptContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.assert_gadget_compatible(params, ntt);
        context.assert_ggsw_compatible(params.size());
        assert_eq!(
            input.as_ref().len(),
            self.poly_length(),
            "gadget input length mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            params.ggsw_len(),
            "NTT GGSW output layout mismatch"
        );

        self.encrypt_ggsw_kernel_to(input, output, params, ntt, rng, context);
    }

    /// Encrypts a GGSW after the caller validates key, input/output, table and workspace.
    pub(crate) fn encrypt_ggsw_kernel_to<M, Table, R, A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut NttGgswCiphertext<B>,
        params: &GlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        context: &mut NttGadgetEncryptContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        context.encoded.as_mut().copy_from_slice(input.as_ref());
        let poly_length = self.poly_length();
        let modulus = params.cipher_modulus();

        // NTT(g_l * m) = g_l * NTT(m) modulo q. Reuse the GLev encoding
        // buffer for this transform and cache each scaled level across rows.
        ntt.transform_slice(context.encoded.as_mut());
        let transformed_input = NttPolynomial::new(context.encoded.as_ref());
        for (scalar, transformed) in params
            .basis()
            .scalar_iter()
            .zip(context.level_transforms.chunks_exact_mut(poly_length))
        {
            transformed_input.mul_scalar_to(scalar, &mut NttPolynomial::new(transformed), modulus);
        }

        self.encrypt_ggsw_from_levels_to(output, params, ntt, rng, context);
    }

    /// Encrypts the prepared NTT levels after the caller validates all layouts.
    pub(super) fn encrypt_ggsw_from_levels_to<M, Table, R, B>(
        &self,
        output: &mut NttGgswCiphertext<B>,
        params: &GlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        context: &NttGadgetEncryptContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = T>,
    {
        let poly_length = self.poly_length();
        let modulus = params.cipher_modulus();
        let glwe_len = params.glwe_len();

        // Stream [row][level][component] storage, reusing the cached levels.
        // Add each diagonal only after zero encryption has accumulated the
        // original masks into the body; adding it earlier changes the phase.
        for (row, mut glev) in output.iter_ntt_glev_mut(params.glev_len()).enumerate() {
            let diagonal_start = row * poly_length;
            for (mut glwe, transformed) in glev
                .iter_ntt_glwe_mut(glwe_len)
                .zip(context.level_transforms.chunks_exact(poly_length))
            {
                self.encrypt_zeros_kernel_to(&mut glwe, params.inner(), ntt, rng);
                NttPolynomial::new(
                    &mut glwe.as_mut()[diagonal_start..diagonal_start + poly_length],
                )
                .add_assign(&NttPolynomial::new(transformed), modulus);
            }
        }
    }

    /// Validates shared generation parameters before any output write or sampling.
    pub(crate) fn assert_gadget_compatible<M, Table>(
        &self,
        params: &GlevParameters<T, M>,
        ntt: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        assert_eq!(
            self.glwe_size(),
            params.glwe_size(),
            "GLWE parameter layout mismatch"
        );
        assert_eq!(
            ntt.poly_length(),
            self.poly_length(),
            "NTT polynomial length mismatch"
        );
        assert_eq!(
            ntt.modulus(),
            params.cipher_modulus().value(),
            "NTT ciphertext modulus mismatch"
        );
    }
}
