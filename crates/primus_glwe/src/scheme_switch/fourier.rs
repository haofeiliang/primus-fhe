//! Native-torus GLev-to-Fourier-GGSW scheme switching.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::SignedInteger;
use primus_lattice::{
    GadgetSize,
    context::FourierGlweExternalProductContext,
    ggsw::{FourierGgsw, FourierGgswIter},
    glev::Glev,
};
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;
use zeroize::Zeroizing;

use crate::{FourierGadgetEncryptContext, FourierGlweSecretKey, GlevParameters, GlweSecretKey};

/// Fourier GGSW encryptions of the negated GLWE secret polynomials.
///
/// Each mask row is obtained by an external product with an encryption of
/// `-s_i`. The body row inherits the input GLev, transformed to Fourier form.
#[derive(Clone)]
pub struct FourierGlweSchemeSwitchKey<T: TorusFftValue> {
    data: Vec<Complex64>,
    key_size: GadgetSize,
    output_size: GadgetSize,
    key_basis: ApproxSignedBasis<T>,
}

impl<T: TorusFftValue> FourierGlweSchemeSwitchKey<T> {
    /// Generates a scheme-switching key for one output GGSW layout.
    ///
    /// # Correctness
    ///
    /// Both secret keys must represent the same secret. The Fourier key must
    /// have been constructed with the supplied FFT table instance.
    ///
    /// # Panics
    ///
    /// Panics before sampling if key/output layouts, FFT length or gadget
    /// workspace do not match `key_parameters`, or key storage length overflows.
    pub fn generate<Table, R>(
        secret_key: &GlweSecretKey<T>,
        fourier_secret_key: &FourierGlweSecretKey,
        output_size: GadgetSize,
        key_parameters: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierGadgetEncryptContext<T>,
    ) -> Self
    where
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        fourier_secret_key.assert_gadget_compatible(key_parameters, fft);
        context.assert_ggsw_compatible(key_parameters.size());
        let key_size = key_parameters.size();
        assert_eq!(
            secret_key.glwe_size(),
            key_size.glwe_size(),
            "scheme-switch secret layout mismatch"
        );
        assert_eq!(
            output_size.glwe_size(),
            key_size.glwe_size(),
            "scheme-switch output GLWE layout mismatch"
        );
        let length = key_size
            .glwe_size()
            .dimension()
            .checked_mul(key_size.fourier_ggsw_len())
            .expect("scheme-switch key length overflow");
        let mut data = vec![Complex64::default(); length];
        let mut negated_secret = Zeroizing::new(vec![T::ZERO; key_size.glwe_size().poly_length()]);
        for (secret, entry) in secret_key
            .iter()
            .zip(data.chunks_exact_mut(key_size.fourier_ggsw_len()))
        {
            for (output, &value) in negated_secret.iter_mut().zip(secret) {
                *output = value.cast_to_unsigned().wrapping_neg();
            }
            fourier_secret_key.encrypt_ggsw_kernel_to(
                &Polynomial::new(negated_secret.as_slice()),
                &mut FourierGgsw::new(entry),
                key_parameters,
                fft,
                rng,
                context,
            );
        }
        Self {
            data,
            key_size,
            output_size,
            key_basis: key_parameters.basis().clone(),
        }
    }

    /// Returns the scheme-switching key gadget layout.
    #[must_use]
    pub fn key_size(&self) -> GadgetSize {
        self.key_size
    }

    /// Returns the output GGSW layout.
    #[must_use]
    pub fn output_size(&self) -> GadgetSize {
        self.output_size
    }

    /// Returns the basis used to decompose external products with this key.
    #[must_use]
    pub fn key_basis(&self) -> &ApproxSignedBasis<T> {
        &self.key_basis
    }

    /// Converts a coefficient-domain native-torus GLev into a Fourier GGSW.
    ///
    /// Preserves the input's gadget scaling; the key basis only decomposes
    /// external products. Overwrites output without allocating or inverse FFTs.
    ///
    /// Bind `context` to [`Self::key_size`]. It can be reused by other external
    /// products through [`FourierGlweExternalProductContext::rebind`]; restore the
    /// key layout before calling this method.
    ///
    /// # Correctness
    ///
    /// Input must use the secret from key generation. Use the same FFT table
    /// instance as at key generation. Input noise, key noise, decomposition
    /// error and floating-point error must fit the intended precision budget.
    ///
    /// # Panics
    ///
    /// Panics before writes if input/output, FFT or workspace layouts differ
    /// from this key's layouts.
    pub fn apply_to<Table, A, B>(
        &self,
        input: &Glev<A>,
        output: &mut FourierGgsw<B>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierGlweExternalProductContext<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = Complex64>,
    {
        assert_eq!(
            input.as_ref().len(),
            self.output_size.glev_len(),
            "scheme-switch input GLev layout mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            self.output_size.fourier_ggsw_len(),
            "scheme-switch output GGSW layout mismatch"
        );
        assert_eq!(
            fft.poly_length(),
            self.key_size.glwe_size().poly_length(),
            "scheme-switch FFT polynomial length mismatch"
        );
        assert_eq!(
            context.size(),
            self.key_size,
            "scheme-switch workspace layout mismatch"
        );

        let size = self.output_size.glwe_size();
        let mut rows = output.iter_glev_mut(self.output_size.fourier_glev_len());
        for (key, mut row) in
            FourierGgswIter::new(&self.data, self.key_size.fourier_ggsw_len()).zip(&mut rows)
        {
            for (input, mut output) in input
                .iter_glwe(size.glwe_len())
                .zip(row.iter_glwe_mut(size.fourier_glwe_len()))
            {
                key.external_product_fourier_to(&input, &mut output, &self.key_basis, fft, context);
            }
        }
        let mut body = rows
            .next()
            .expect("scheme-switch output is missing its body row");
        for (input, output) in input
            .as_ref()
            .chunks_exact(size.poly_length())
            .zip(body.as_mut().chunks_exact_mut(size.fourier_poly_len()))
        {
            fft.forward_as_torus(input, output);
        }
        debug_assert!(rows.next().is_none());
    }
}
