use core::marker::PhantomData;

use primus_data::{Data, RawData};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_modulus::NativeModulus;
use primus_ntt::NttTable;
use primus_poly::PolynomialOwned;
use primus_reduce::FieldContext;

use primus_lattice::ggsw::{FourierGgsw, FourierGgswIter, NttGgsw, NttGgswIter};

use crate::{
    FourierGadgetEncryptContext, FourierGlweSecretKey, GlevCommonSize, GlevParameters,
    LweSecretKey, LweSecretKeyType, NttGadgetEncryptContext, NttGlweSecretKey,
};

/// A bootstrapping key containing one GGSW encryption per input LWE secret
/// coefficient.
///
/// The first implementation supports binary input LWE secret keys. `S`
/// selects the Fourier or NTT storage backend.
#[derive(Clone)]
pub struct FunctionalBootstrappingKey<T: FheUint, S> {
    data: S,
    input_dimension: usize,
    common_size: GlevCommonSize,
    cipher_modulus: Option<T>,
    value_type: PhantomData<T>,
}

/// Fourier-domain functional bootstrapping key for a native torus.
pub type FourierFunctionalBootstrappingKey<T> = FunctionalBootstrappingKey<T, Vec<Complex64>>;

/// NTT-domain functional bootstrapping key for an explicit prime modulus.
pub type NttFunctionalBootstrappingKey<T> = FunctionalBootstrappingKey<T, Vec<T>>;

impl<T: FheUint, S> FunctionalBootstrappingKey<T, S> {
    /// Returns the input LWE dimension.
    #[inline]
    pub fn input_dimension(&self) -> usize {
        self.input_dimension
    }

    /// Returns the GGSW/GLWE layout bound to this key.
    #[inline]
    pub fn common_size(&self) -> GlevCommonSize {
        self.common_size
    }

    /// Returns the explicit ciphertext modulus, or `None` for the native
    /// torus backend.
    #[inline]
    pub fn cipher_modulus(&self) -> Option<T> {
        self.cipher_modulus
    }
}

impl<T, S> FunctionalBootstrappingKey<T, S>
where
    T: FheUint,
    S: RawData + Data,
{
    /// Returns the backend-domain values stored by this key.
    #[inline]
    pub fn as_slice(&self) -> &[S::Elem] {
        self.data.as_slice()
    }
}

impl<T> FunctionalBootstrappingKey<T, Vec<Complex64>>
where
    T: FheUint + TorusFftValue,
{
    /// Generates a Fourier bootstrapping key encrypting every binary input
    /// LWE secret coefficient under `output_secret_key`.
    pub fn generate_fourier<Table, R>(
        input_secret_key: &LweSecretKey<T>,
        output_secret_key: &FourierGlweSecretKey<T>,
        params: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierGadgetEncryptContext<T>,
    ) -> Self
    where
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        assert_eq!(input_secret_key.distr(), LweSecretKeyType::Binary);
        assert_eq!(output_secret_key.dimension(), params.dimension());
        assert_eq!(output_secret_key.poly_length(), params.poly_length());

        let input_dimension = input_secret_key.dimension();
        let ggsw_len = params.fourier_ggsw_len();
        let total_len = input_dimension
            .checked_mul(ggsw_len)
            .expect("Fourier bootstrapping-key length overflow");
        let mut data = vec![Complex64::default(); total_len];
        let mut message = PolynomialOwned::zero(params.poly_length());

        for (&secret, chunk) in input_secret_key
            .as_ref()
            .iter()
            .zip(data.chunks_exact_mut(ggsw_len))
        {
            message.as_mut()[0] = secret;
            output_secret_key.encrypt_ggsw_to(
                &message,
                &mut FourierGgsw::new(chunk),
                params,
                fft,
                rng,
                context,
            );
        }

        Self {
            data,
            input_dimension,
            common_size: params.common_size(),
            cipher_modulus: None,
            value_type: PhantomData,
        }
    }

    /// Iterates over the Fourier GGSW encryptions.
    #[inline]
    pub fn iter_fourier_ggsw(&self) -> FourierGgswIter<'_> {
        FourierGgswIter::new(&self.data, self.common_size.fourier_ggsw_len())
    }
}

impl<T: FheUint> FunctionalBootstrappingKey<T, Vec<T>> {
    /// Generates an NTT bootstrapping key encrypting every binary input LWE
    /// secret coefficient under `output_secret_key`.
    pub fn generate_ntt<M, Table, R>(
        input_secret_key: &LweSecretKey<T>,
        output_secret_key: &NttGlweSecretKey<T>,
        params: &GlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        context: &mut NttGadgetEncryptContext<T>,
    ) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        assert_eq!(input_secret_key.distr(), LweSecretKeyType::Binary);
        assert_eq!(output_secret_key.dimension(), params.dimension());
        assert_eq!(output_secret_key.poly_length(), params.poly_length());

        let input_dimension = input_secret_key.dimension();
        let ggsw_len = params.ggsw_len();
        let total_len = input_dimension
            .checked_mul(ggsw_len)
            .expect("NTT bootstrapping-key length overflow");
        let mut data = vec![T::ZERO; total_len];
        let mut message = PolynomialOwned::zero(params.poly_length());

        for (&secret, chunk) in input_secret_key
            .as_ref()
            .iter()
            .zip(data.chunks_exact_mut(ggsw_len))
        {
            message.as_mut()[0] = secret;
            output_secret_key.encrypt_ggsw_to(
                &message,
                &mut NttGgsw::new(chunk),
                params,
                ntt,
                rng,
                context,
            );
        }

        Self {
            data,
            input_dimension,
            common_size: params.common_size(),
            cipher_modulus: Some(params.cipher_modulus().value()),
            value_type: PhantomData,
        }
    }

    /// Iterates over the NTT GGSW encryptions.
    #[inline]
    pub fn iter_ntt_ggsw(&self) -> NttGgswIter<'_, T> {
        NttGgswIter::new(&self.data, self.common_size.ggsw_len())
    }
}
