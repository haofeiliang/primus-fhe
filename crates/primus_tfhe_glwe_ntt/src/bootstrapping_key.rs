//! NTT-domain functional bootstrapping key and blind rotation.

use primus_data::{Data, DataMut, RawData};
use primus_glwe::{NttGadgetDomain, NttGadgetEncryptContext, NttGlweSecretKey, SecretKeyDistr};
use primus_integer::FheUint;
use primus_lattice::{
    GadgetSize,
    context::NttExternalProductContext,
    ggsw::{NttGgsw, NttGgswIter},
    glwe::Glwe,
    lwe::Lwe,
};
use primus_lwe::{LweParameters, LweSecretKey};
use primus_ntt::NttTable;
use primus_poly::PolynomialOwned;
use primus_reduce::{FieldContext, RingContext};
use primus_tfhe::backend_support::{direct_exponent, modulus_switch};

/// An NTT bootstrapping key containing one GGSW encryption per input LWE
/// secret coefficient.
#[derive(Clone)]
pub struct NttFunctionalBootstrappingKey<T: FheUint> {
    data: Vec<T>,
    input_dimension: usize,
    input_modulus: Option<T>,
    size: GadgetSize,
    cipher_modulus: T,
}

impl<T: FheUint> NttFunctionalBootstrappingKey<T> {
    /// Returns the input LWE dimension.
    #[inline]
    pub fn input_dimension(&self) -> usize {
        self.input_dimension
    }

    /// Returns the explicit input LWE modulus, or `None` for a native torus.
    #[inline]
    pub fn input_modulus(&self) -> Option<T> {
        self.input_modulus
    }

    /// Returns the GGSW/GLWE layout bound to this key.
    #[inline]
    pub fn size(&self) -> GadgetSize {
        self.size
    }

    /// Returns the explicit NTT ciphertext modulus.
    #[inline]
    pub fn cipher_modulus(&self) -> Option<T> {
        Some(self.cipher_modulus)
    }

    /// Returns the NTT-domain values stored by this key.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    /// Generates an NTT bootstrapping key encrypting every binary input LWE
    /// secret coefficient under `output_secret_key`.
    pub fn generate_ntt<LM, M, Table, R>(
        input_secret_key: &LweSecretKey<T>,
        input_parameters: &LweParameters<T, LM>,
        output_secret_key: &NttGlweSecretKey<T>,
        domain: &NttGadgetDomain<'_, T, M, Table>,
        rng: &mut R,
        context: &mut NttGadgetEncryptContext<T>,
    ) -> Self
    where
        LM: RingContext<T>,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = domain.parameters();
        assert_eq!(input_secret_key.distr(), SecretKeyDistr::Binary);
        assert_eq!(input_secret_key.dimension(), input_parameters.dimension());
        assert_eq!(input_parameters.secret_key_distr(), SecretKeyDistr::Binary);
        assert_eq!(output_secret_key.glwe_size(), parameters.glwe_size());

        let input_dimension = input_secret_key.dimension();
        let ggsw_len = parameters.ggsw_len();
        let total_len = input_dimension
            .checked_mul(ggsw_len)
            .expect("NTT bootstrapping-key length overflow");
        let mut data = vec![T::ZERO; total_len];
        let mut message = PolynomialOwned::zero(parameters.poly_length());

        for (&secret, chunk) in input_secret_key
            .as_ref()
            .iter()
            .zip(data.chunks_exact_mut(ggsw_len))
        {
            message.as_mut()[0] = secret;
            output_secret_key.encrypt_ggsw_to(
                &message,
                &mut NttGgsw::new(chunk),
                domain,
                rng,
                context,
            );
        }

        Self {
            data,
            input_dimension,
            input_modulus: input_parameters.cipher_modulus().explicit_value(),
            size: parameters.size(),
            cipher_modulus: parameters.cipher_modulus().value(),
        }
    }

    /// Iterates over the NTT GGSW encryptions.
    #[inline]
    pub fn iter_ntt_ggsw(&self) -> NttGgswIter<'_, T> {
        NttGgswIter::new(&self.data, self.size.ggsw_len())
    }

    /// Blind-rotates an explicit-modulus GLWE accumulator using this key.
    pub fn ntt_blind_rotate_to<M, Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        accumulator: &Glwe<B>,
        output: &mut Glwe<C>,
        domain: &NttGadgetDomain<'_, T, M, Table>,
        context: &mut NttBlindRotationContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
    {
        let two_n = domain.parameters().poly_length() * 2;
        let modulus = self.input_modulus();
        self.blind_rotate_with(input, accumulator, output, domain, context, |x| {
            modulus_switch(x, modulus, two_n)
        });
    }

    /// Blind-rotates from an LWE whose coefficients are exponents in `[0, 2N)`.
    pub fn ntt_blind_rotate_exponents_to<M, Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        accumulator: &Glwe<B>,
        output: &mut Glwe<C>,
        domain: &NttGadgetDomain<'_, T, M, Table>,
        context: &mut NttBlindRotationContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
    {
        let two_n = 2 * domain.parameters().poly_length();
        self.blind_rotate_with(input, accumulator, output, domain, context, |x| {
            direct_exponent(x, two_n)
        });
    }

    fn blind_rotate_with<M, Table, A, B, C, F>(
        &self,
        input: &Lwe<A>,
        accumulator: &Glwe<B>,
        output: &mut Glwe<C>,
        domain: &NttGadgetDomain<'_, T, M, Table>,
        context: &mut NttBlindRotationContext<T>,
        exponent_of: F,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
        F: Fn(T) -> usize,
    {
        let parameters = domain.parameters();
        let ntt = domain.table();
        let modulus = parameters.cipher_modulus();
        let poly_length = parameters.poly_length();
        let two_n = 2 * poly_length;
        debug_assert_eq!(
            (
                input.dimension(),
                accumulator.as_ref().len(),
                output.as_ref().len(),
            ),
            (
                self.input_dimension(),
                self.size().glwe_len(),
                self.size().glwe_len(),
            )
        );

        let initial_exponent = exponent_of(input.b()).wrapping_neg() & (two_n - 1);
        accumulator.mul_monomial_to(initial_exponent, output, poly_length, modulus);

        let NttBlindRotationContext {
            scratch,
            external_product,
        } = context;
        let mut output_is_current = true;
        for (&coefficient, control) in input.a().iter().zip(self.iter_ntt_ggsw()) {
            let exponent = exponent_of(coefficient);
            if exponent == 0 {
                continue;
            }
            if output_is_current {
                control.cmux_monomial_to(
                    output,
                    exponent,
                    scratch,
                    parameters.basis(),
                    modulus,
                    ntt,
                    external_product,
                );
            } else {
                control.cmux_monomial_to(
                    scratch,
                    exponent,
                    output,
                    parameters.basis(),
                    modulus,
                    ntt,
                    external_product,
                );
            }
            output_is_current = !output_is_current;
        }
        if !output_is_current {
            output.as_mut().copy_from_slice(scratch.as_ref());
        }
    }
}

/// Reusable workspace for NTT blind rotation.
pub struct NttBlindRotationContext<T: FheUint> {
    scratch: Glwe<Vec<T>>,
    external_product: NttExternalProductContext<T>,
}

impl<T: FheUint> NttBlindRotationContext<T> {
    /// Creates a workspace for a checked GLWE size.
    pub fn new(size: GadgetSize) -> Self {
        Self {
            scratch: Glwe::zero(size.glwe_len()),
            external_product: NttExternalProductContext::new(size),
        }
    }

    /// Rebinds the workspace to another decomposition layout without reallocating.
    pub fn rebind(&mut self, size: GadgetSize) {
        self.external_product.rebind(size);
    }

    /// Rebinds the workspace to a new GLWE layout.
    pub fn resize(&mut self, size: GadgetSize) {
        if self.external_product.size().glwe_size() == size.glwe_size() {
            self.rebind(size);
            return;
        }
        self.external_product.resize(size);
        self.scratch.0.resize(size.glwe_len(), T::ZERO);
    }
}
