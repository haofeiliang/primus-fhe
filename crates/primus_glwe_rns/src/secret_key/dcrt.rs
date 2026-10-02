//! DCRT-domain (NTT within CRT, multi-modulus) GLWE secret key with full
//! encryption/decryption and GLev encryption.

use primus_data::{Data, DataMut};
use primus_encoding::PlaintextEmbedding;
use primus_integer::FheUint;
use primus_lattice::{RnsGlweSize, glev::DcrtGlev};
use primus_ntt::{DcrtTable, NttTable};
use primus_poly::{
    CrtPolynomial, DcrtPolynomial, DcrtPolynomialIter, DcrtPolynomialIterMut, Polynomial,
    PolynomialOwned,
};
use primus_reduce::FieldContext;
use primus_rns::Residues;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    CrtGlevParameters, CrtGlweParameters, DcrtGadgetDomain, DcrtGlweCiphertext, SecretKeyDistr,
};

use super::{GlweSecretKey, encode_secret_polynomial_to};

/// A GLWE secret key represented in NTT form for every ordered RNS modulus.
/// Key storage is securely erased on drop.
#[derive(Clone)]
pub struct DcrtGlweSecretKey<T: FheUint> {
    pub(crate) key: Vec<T>,
    pub(crate) distr: SecretKeyDistr,
    pub(crate) size: RnsGlweSize,
}

impl<T: FheUint> Zeroize for DcrtGlweSecretKey<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for DcrtGlweSecretKey<T> {}

impl<T: FheUint> Drop for DcrtGlweSecretKey<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T: FheUint> DcrtGlweSecretKey<T> {
    pub(crate) fn key(&self) -> &[T] {
        &self.key
    }

    /// Returns the distr of this [`DcrtGlweSecretKey<T>`].
    pub fn distr(&self) -> SecretKeyDistr {
        self.distr
    }

    /// Returns the RNS GLWE layout of this secret key.
    #[inline]
    pub fn rns_glwe_size(&self) -> RnsGlweSize {
        self.size
    }

    /// Iterates over the DCRT secret polynomials in GLWE component order.
    pub fn iter_dcrt_poly(&self) -> DcrtPolynomialIter<'_, T> {
        DcrtPolynomialIter::new(self.key.as_slice(), self.size.rns_poly_len())
    }

    /// Creates a modulus-specific DCRT representation of a canonical signed
    /// [`GlweSecretKey<T>`].
    /// Partially converted key storage is erased if encoding or transformation
    /// unwinds; the source secret remains unchanged.
    ///
    /// # Correctness
    ///
    /// Each signed secret coefficient's magnitude must be less than every
    /// modulus in `table`. The table's NTT representation requirements apply;
    /// see [`NttTable::new`].
    ///
    /// # Panics
    ///
    /// Panics if the secret and table polynomial lengths differ, the table has
    /// no moduli, or the derived RNS storage length overflows.
    #[inline]
    pub fn from_coeff_secret_key<Table>(
        secret_key: &GlweSecretKey<T>,
        table: &DcrtTable<Table>,
    ) -> Self
    where
        Table: NttTable<ValueT = T>,
    {
        assert_eq!(secret_key.poly_length(), table.poly_length().get());

        let size = RnsGlweSize::new(secret_key.glwe_size(), table.moduli_count());
        let poly_length = size.poly_length().get();
        let rns_poly_len = size.rns_poly_len();
        // Establish erasing ownership before writing secrets or invoking a
        // transform, so unwinding also erases a partially converted key.
        let mut key = Self {
            key: vec![T::ZERO; size.rns_mask_len()],
            distr: secret_key.distr(),
            size,
        };

        for (coefficients, mut dcrt_secret) in secret_key.iter().zip(DcrtPolynomialIterMut::new(
            key.key.as_mut_slice(),
            rns_poly_len,
        )) {
            for (ntt_table, modulus_limb) in table
                .iter()
                .zip(dcrt_secret.iter_each_modulus_mut(poly_length))
            {
                encode_secret_polynomial_to(coefficients, modulus_limb, ntt_table.modulus());
                ntt_table.transform_slice(modulus_limb);
            }
        }

        key
    }

    // -------------------------------------------------------------------------
    // Encryption
    // -------------------------------------------------------------------------

    /// Encrypts an already-decomposed CRT plaintext polynomial.
    ///
    /// The message contains unscaled plaintext lifts reduced into each `[0, q_i)`,
    /// in coefficient-domain CRT layout. This method applies `floor(Q/t)` scaling;
    /// passing the already-scaled output of [`crate::BfvRnsCodec::encode_coeffs_to`]
    /// would apply the scale twice.
    pub fn encrypt_inplace<R, M, Table, A, B>(
        &self,
        msg: &CrtPolynomial<A>,
        result: &mut DcrtGlweCiphertext<B>,
        params: &CrtGlweParameters<T, M>,
        table: &DcrtTable<Table>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.encrypt_kernel_to(
            DcrtEncryptionMessage::Crt(msg.as_view()),
            result.as_mut_view(),
            params,
            table,
            rng,
        );
    }

    /// Encrypts a raw plaintext polynomial using unsigned embedding.
    pub fn encrypt_plaintext_inplace<R, M, Table, A, B>(
        &self,
        msg: &Polynomial<A>,
        result: &mut DcrtGlweCiphertext<B>,
        params: &CrtGlweParameters<T, M>,
        table: &DcrtTable<Table>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.encrypt_kernel_to(
            DcrtEncryptionMessage::Plaintext {
                polynomial: msg.as_view(),
                embedding: PlaintextEmbedding::Unsigned,
            },
            result.as_mut_view(),
            params,
            table,
            rng,
        );
    }

    /// Encrypts a raw plaintext polynomial using centered embedding.
    pub fn encrypt_centered_plaintext_inplace<R, M, Table, A, B>(
        &self,
        msg: &Polynomial<A>,
        result: &mut DcrtGlweCiphertext<B>,
        params: &CrtGlweParameters<T, M>,
        table: &DcrtTable<Table>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.encrypt_kernel_to(
            DcrtEncryptionMessage::Plaintext {
                polynomial: msg.as_view(),
                embedding: PlaintextEmbedding::Centered,
            },
            result.as_mut_view(),
            params,
            table,
            rng,
        );
    }

    /// Encrypts zero into an existing DCRT GLWE allocation.
    ///
    /// The result is overwritten and must match `params` and `table`.
    pub fn encrypt_zeros_inplace<R, M, Table, A>(
        &self,
        result: &mut DcrtGlweCiphertext<A>,
        params: &CrtGlweParameters<T, M>,
        table: &DcrtTable<Table>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: DataMut<Elem = T>,
    {
        self.encrypt_kernel_to(
            DcrtEncryptionMessage::Zero,
            result.as_mut_view(),
            params,
            table,
            rng,
        );
    }

    /// Samples coefficient noise, injects the BFV message, then transforms the body.
    /// Uniform masks are sampled in DCRT form afterward, in secret-component order.
    /// The caller maintains complete key/message/output layouts and the matching
    /// ordered parameter/table domain; views do not validate these preconditions.
    fn encrypt_kernel_to<R, M, Table>(
        &self,
        message: DcrtEncryptionMessage<'_, T>,
        mut result: DcrtGlweCiphertext<&mut [T]>,
        params: &CrtGlweParameters<T, M>,
        table: &DcrtTable<Table>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let poly_length = params.poly_length().get();
        let rns_poly_len = params.rns_poly_len();
        let moduli = params.cipher_moduli();
        let uniform_distrs = params.cipher_moduli_uniform_distr();
        let (a, mut b) = result.a_b_mut(rns_poly_len);

        primus_distr::sample_crt_gaussian_values_to(
            b.as_mut(),
            poly_length,
            params.cipher_moduli_value(),
            params.noise_distribution(),
            rng,
        );
        match message {
            DcrtEncryptionMessage::Crt(message) => {
                CrtPolynomial(b.as_mut()).add_mul_factor_assign(
                    &message,
                    params.delta_factor_mod_q().as_ref(),
                    poly_length,
                    params.cipher_moduli_value(),
                );
            }
            DcrtEncryptionMessage::Plaintext {
                polynomial,
                embedding,
            } => {
                params.codec().add_encode_coeffs_assign(
                    &polynomial,
                    &mut CrtPolynomial(b.as_mut()),
                    embedding,
                );
            }
            DcrtEncryptionMessage::Zero => {}
        }
        table.transform_slice(b.as_mut());

        self.iter_dcrt_poly().zip(a).for_each(|(si, mut ai)| {
            primus_distr::sample_crt_uniform_values_to(
                ai.as_mut(),
                poly_length,
                uniform_distrs,
                rng,
            );
            b.add_mul_assign(&ai, &si, poly_length, moduli);
        });
    }

    // -------------------------------------------------------------------------
    // GLev encryption helpers (for key-switching key generation)
    // -------------------------------------------------------------------------

    /// Transforms coefficient noise before adding the scaled evaluation-domain message.
    /// Operands and residues must use complete layouts in the parameter/table basis order.
    /// The caller owns these preconditions; this helper performs no boundary validation.
    fn encrypt_dcrt_msg_to_dcrt_glwe_inplace_with_custom_delta<R, M, Table>(
        &self,
        dcrt_msg: DcrtPolynomial<&[T]>,
        delta_residues: Residues<&[T]>,
        mut result: DcrtGlweCiphertext<&mut [T]>,
        params: &CrtGlevParameters<T, M>,
        table: &DcrtTable<Table>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let poly_length = params.poly_length().get();
        let moduli = params.cipher_moduli();
        let uniform_distrs = params.cipher_moduli_uniform_distr();

        let (a, mut b) = result.a_b_mut(params.rns_poly_len());

        primus_distr::sample_crt_gaussian_values_to(
            b.as_mut(),
            poly_length,
            params.cipher_moduli_value(),
            params.noise_distribution(),
            &mut *rng,
        );

        table.transform_slice(b.as_mut());
        b.add_mul_scalar_assign(&dcrt_msg, delta_residues.as_ref(), poly_length, moduli);

        self.iter_dcrt_poly().zip(a).for_each(|(si, mut ai)| {
            primus_distr::sample_crt_uniform_values_to(
                ai.as_mut(),
                poly_length,
                uniform_distrs,
                &mut *rng,
            );
            b.add_mul_assign(&ai, &si, poly_length, moduli);
        });
    }

    /// Encrypts a DCRT plaintext polynomial into an existing DCRT GLev allocation.
    ///
    /// The plaintext, result, parameters, and table must share the same ordered
    /// RNS basis and polynomial length.
    pub fn encrypt_dcrt_msg_to_dcrt_glev_inplace<R, M, Table, A, B>(
        &self,
        dcrt_msg: &DcrtPolynomial<A>,
        result: &mut DcrtGlev<B>,
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let params = domain.parameters();
        assert_eq!(result.as_ref().len(), params.rns_glev_len());
        self.encrypt_dcrt_glev_kernel_to(dcrt_msg.as_view(), result.as_mut_view(), domain, rng);
    }

    /// Reuses the DCRT message at every gadget level, adding it after the noise
    /// transform. Output length has been checked; secret/message/domain layouts
    /// and representations remain caller-maintained preconditions.
    fn encrypt_dcrt_glev_kernel_to<R, M, Table>(
        &self,
        dcrt_msg: DcrtPolynomial<&[T]>,
        mut result: DcrtGlev<&mut [T]>,
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let params = domain.parameters();
        let table = domain.table();
        result
            .iter_dcrt_glwe_mut(params.rns_glwe_len())
            .zip(params.scalar_residue_iter())
            .for_each(|(dcrt_glwe, scalar_residues)| {
                self.encrypt_dcrt_msg_to_dcrt_glwe_inplace_with_custom_delta(
                    dcrt_msg.as_view(),
                    scalar_residues.view(),
                    dcrt_glwe,
                    params,
                    table,
                    rng,
                );
            });
    }

    /// Scales the message in coefficient form before the body transform.
    /// Operands and residues must use complete layouts in the parameter/table basis order.
    /// The caller owns these preconditions; this helper performs no boundary validation.
    fn encrypt_crt_msg_to_dcrt_glwe_inplace_with_custom_delta<R, M, Table>(
        &self,
        crt_msg: CrtPolynomial<&[T]>,
        delta_residues: Residues<&[T]>,
        mut result: DcrtGlweCiphertext<&mut [T]>,
        params: &CrtGlevParameters<T, M>,
        table: &DcrtTable<Table>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let poly_length = params.poly_length().get();
        let moduli = params.cipher_moduli();
        let uniform_distrs = params.cipher_moduli_uniform_distr();

        let (a, mut b) = result.a_b_mut(params.rns_poly_len());

        primus_distr::sample_crt_gaussian_values_to(
            b.as_mut(),
            poly_length,
            params.cipher_moduli_value(),
            params.noise_distribution(),
            &mut *rng,
        );

        let mut b_crt_poly = CrtPolynomial(b.as_mut());
        b_crt_poly.add_mul_scalar_assign(&crt_msg, delta_residues.as_ref(), poly_length, moduli);
        table.transform_slice(b.as_mut());

        self.iter_dcrt_poly().zip(a).for_each(|(si, mut ai)| {
            primus_distr::sample_crt_uniform_values_to(
                ai.as_mut(),
                poly_length,
                uniform_distrs,
                &mut *rng,
            );
            b.add_mul_assign(&ai, &si, poly_length, moduli);
        });
    }

    /// Encrypts a CRT plaintext polynomial into an existing DCRT GLev allocation.
    ///
    /// The result is overwritten and must match the domain's gadget layout.
    pub fn encrypt_crt_msg_to_dcrt_glev_inplace<R, M, Table, A, B>(
        &self,
        crt_msg: &CrtPolynomial<A>,
        result: &mut DcrtGlev<B>,
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let params = domain.parameters();
        assert_eq!(result.as_ref().len(), params.rns_glev_len());
        self.encrypt_crt_glev_kernel_to(crt_msg.as_view(), result.as_mut_view(), domain, rng);
    }

    /// Reuses the CRT message at every gadget level, adding it before the body
    /// transform. Output length has been checked; secret/message/domain layouts
    /// and representations remain caller-maintained preconditions.
    fn encrypt_crt_glev_kernel_to<R, M, Table>(
        &self,
        crt_msg: CrtPolynomial<&[T]>,
        mut result: DcrtGlev<&mut [T]>,
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let params = domain.parameters();
        let table = domain.table();
        result
            .iter_dcrt_glwe_mut(params.rns_glwe_len())
            .zip(params.scalar_residue_iter())
            .for_each(|(dcrt_glwe, scalar_residues)| {
                self.encrypt_crt_msg_to_dcrt_glwe_inplace_with_custom_delta(
                    crt_msg.as_view(),
                    scalar_residues.view(),
                    dcrt_glwe,
                    params,
                    table,
                    rng,
                );
            });
    }

    // -------------------------------------------------------------------------
    // Phase / Decryption
    // -------------------------------------------------------------------------

    /// Performs `b - ∑ a*s`.
    pub fn phase_inplace<M, A, B>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        msg_mod_q: &mut DcrtPolynomial<B>,
        params: &CrtGlweParameters<T, M>,
    ) where
        M: FieldContext<T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.phase_kernel_to(ciphertext.as_view(), msg_mod_q.as_mut_view(), params);
    }

    /// Computes the DCRT phase with complete, matching layouts in parameter basis order.
    fn phase_kernel_to<M>(
        &self,
        ciphertext: DcrtGlweCiphertext<&[T]>,
        mut msg_mod_q: DcrtPolynomial<&mut [T]>,
        params: &CrtGlweParameters<T, M>,
    ) where
        M: FieldContext<T>,
    {
        let poly_length = params.poly_length().get();
        let moduli = params.cipher_moduli();

        let (a, b) = ciphertext.a_b(params.rns_poly_len());

        msg_mod_q.set_zero();

        self.iter_dcrt_poly().zip(a).for_each(|(si, ai)| {
            msg_mod_q.add_mul_assign(&ai, &si, poly_length, moduli);
        });

        b.sub_rev_assign(&mut msg_mod_q, poly_length, moduli);
    }

    /// Decrypts a DCRT GLWE ciphertext into a newly allocated plaintext polynomial.
    pub fn decrypt<M, Table, A>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        params: &CrtGlweParameters<T, M>,
        table: &DcrtTable<Table>,
        workspace: &mut DcrtGlweDecryptWorkspace<T>,
    ) -> PolynomialOwned<T>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        let mut msg = PolynomialOwned::zero(params.poly_length().get());
        self.decrypt_inplace(ciphertext, &mut msg, params, table, workspace);
        msg
    }

    /// Decrypts a DCRT GLWE ciphertext into `msg` using reusable workspace.
    ///
    /// The ciphertext, output, parameters, table, and workspace must share the
    /// same polynomial length and ordered RNS basis.
    pub fn decrypt_inplace<M, Table, A, B>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        msg: &mut Polynomial<B>,
        params: &CrtGlweParameters<T, M>,
        table: &DcrtTable<Table>,
        workspace: &mut DcrtGlweDecryptWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(workspace.size(), params.size());
        self.decrypt_kernel_to(
            ciphertext.as_view(),
            msg.as_mut_view(),
            params,
            table,
            workspace,
        );
    }

    /// Uses a layout-checked erasing workspace. All other operands and the table
    /// must share the parameter basis and transform representation. Phase extraction
    /// overwrites scratch before inverse transformation and BFV decoding.
    fn decrypt_kernel_to<M, Table>(
        &self,
        ciphertext: DcrtGlweCiphertext<&[T]>,
        mut msg: Polynomial<&mut [T]>,
        params: &CrtGlweParameters<T, M>,
        table: &DcrtTable<Table>,
        workspace: &mut DcrtGlweDecryptWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let DcrtGlweDecryptWorkspaceRefMut {
            msg_mod_q,
            fast_convert_buffer,
        } = workspace.as_mut();

        self.phase_kernel_to(ciphertext, msg_mod_q.as_mut_view(), params);

        table.inverse_transform_slice(msg_mod_q.as_mut());

        params.codec().decode_coeffs_to(
            &mut CrtPolynomial(msg_mod_q.as_mut()),
            &mut msg,
            fast_convert_buffer,
        );
    }
}

/// Borrowed message modes for the coefficient body of ordinary DCRT encryption.
/// CRT input contains unscaled plaintext lifts; raw plaintext uses the requested
/// embedding. Both receive BFV scaling before the forward transform.
enum DcrtEncryptionMessage<'a, T: FheUint> {
    Crt(CrtPolynomial<&'a [T]>),
    Plaintext {
        polynomial: Polynomial<&'a [T]>,
        embedding: PlaintextEmbedding,
    },
    Zero,
}

// ---------------------------------------------------------------------------
// Decryption workspace
// ---------------------------------------------------------------------------

/// Reusable workspace for DCRT GLWE decryption.
///
/// Decryption overwrites both internal buffers. Their contents are securely
/// erased on drop; explicit [`Zeroize::zeroize`] also preserves the allocations
/// and layout so the workspace can be reused.
pub struct DcrtGlweDecryptWorkspace<T: FheUint> {
    size: RnsGlweSize,
    msg_mod_q: DcrtPolynomial<Vec<T>>,
    fast_convert_buffer: Vec<T>,
}

impl<T: FheUint> Zeroize for DcrtGlweDecryptWorkspace<T> {
    fn zeroize(&mut self) {
        self.msg_mod_q.as_mut().iter_mut().zeroize();
        self.fast_convert_buffer.iter_mut().zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for DcrtGlweDecryptWorkspace<T> {}

impl<T: FheUint> Drop for DcrtGlweDecryptWorkspace<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

struct DcrtGlweDecryptWorkspaceRefMut<'a, T: FheUint> {
    msg_mod_q: &'a mut DcrtPolynomial<Vec<T>>,
    fast_convert_buffer: &'a mut [T],
}

impl<T: FheUint> DcrtGlweDecryptWorkspace<T> {
    /// Creates a new [`DcrtGlweDecryptWorkspace<T>`].
    #[inline]
    pub fn new(size: RnsGlweSize) -> Self {
        let msg_mod_q: DcrtPolynomial<Vec<T>> = DcrtPolynomial::zero(size.rns_poly_len());
        // The codec's one-modulus converter borrows the phase directly.
        let conversion_len = if size.moduli_count() == 1 {
            0
        } else {
            size.rns_poly_len()
        };
        let fast_convert_buffer = vec![T::ZERO; conversion_len];

        Self {
            size,
            msg_mod_q,
            fast_convert_buffer,
        }
    }

    #[inline]
    fn as_mut(&mut self) -> DcrtGlweDecryptWorkspaceRefMut<'_, T> {
        DcrtGlweDecryptWorkspaceRefMut {
            msg_mod_q: &mut self.msg_mod_q,
            fast_convert_buffer: &mut self.fast_convert_buffer,
        }
    }

    /// Returns the RNS GLWE layout bound to this workspace.
    #[must_use]
    #[inline]
    pub fn size(&self) -> RnsGlweSize {
        self.size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use primus_lattice::GlweDimension;
    use primus_lattice::GlweSize;
    use primus_poly::PolyLength;

    #[test]
    fn decrypt_workspace_erases_both_buffers_without_changing_layout() {
        for count in [1, 2] {
            let size = RnsGlweSize::new(
                GlweSize::new(GlweDimension::new(1), PolyLength::new(32)),
                count,
            );
            let mut workspace = DcrtGlweDecryptWorkspace::<u64>::new(size);
            workspace.msg_mod_q.as_mut().fill(0xfeed);
            workspace.fast_convert_buffer.fill(0xbeef);
            let phase_ptr = workspace.msg_mod_q.as_ref().as_ptr();
            let conversion_ptr = workspace.fast_convert_buffer.as_ptr();
            let conversion_len = workspace.fast_convert_buffer.len();
            workspace.zeroize();
            assert_eq!(workspace.size(), size);
            assert_eq!(workspace.msg_mod_q.as_ref(), vec![0; size.rns_poly_len()]);
            assert_eq!(workspace.fast_convert_buffer, vec![0; conversion_len]);
            assert_eq!(workspace.msg_mod_q.as_ref().as_ptr(), phase_ptr);
            assert_eq!(workspace.fast_convert_buffer.as_ptr(), conversion_ptr);
        }
    }
}
