use itertools::izip;
use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_lattice::{ggsw::DcrtGgsw, glev::DcrtGlev, glwe::DcrtGlwe};
use primus_ntt::{DcrtTable, NttTable};
use primus_poly::{CrtPolynomial, DcrtPolynomial};
use primus_reduce::FieldContext;

use crate::{CrtGgswParameters, CrtGlevParameters, CrtGlweParameters, DcrtGlweSecretKey};

#[derive(Clone)]
/// A public GLWE encryption key stored in DCRT form.
pub struct DcrtGlwePublicKey<T: FheUint> {
    key: DcrtGlwe<Vec<T>>,
}

impl<T: FheUint> DcrtGlwePublicKey<T> {
    /// Creates a new [`DcrtGlwePublicKey<T>`] from bytes `data`.
    #[inline]
    pub fn read_bytes(&mut self, data: &[u8]) {
        self.key.read_bytes(data);
    }

    /// Converts [`DcrtGlwePublicKey<T>`] into bytes, stored in `data`.
    #[inline]
    pub fn write_bytes(&self, data: &mut [u8]) {
        self.key.write_bytes(data);
    }

    /// Returns the bytes count of [`DcrtGlwePublicKey<T>`].
    #[inline]
    pub fn byte_count(&self) -> usize {
        self.key.byte_count()
    }

    /// Generates a public key for `secret_key` using the supplied DCRT table.
    pub fn new<Table, R, M>(
        secret_key: &DcrtGlweSecretKey<T>,
        params: &CrtGlweParameters<T, M>,
        table: &DcrtTable<Table>,
        rng: &mut R,
    ) -> DcrtGlwePublicKey<T>
    where
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
    {
        let poly_length = params.poly_length();
        let dcrt_glwe_len = params.rns_glwe_len();

        let moduli = params.cipher_moduli();
        let moduli_value = params.cipher_moduli_value();
        let uniform_distrs = params.cipher_moduli_uniform_distr();

        let mut data: DcrtGlwe<Vec<T>> = DcrtGlwe::zero(dcrt_glwe_len);

        let (a, mut b) = data.a_b_mut(params.rns_poly_len());

        primus_distr::sample_crt_gaussian_values_to(
            b.0,
            poly_length,
            moduli_value,
            params.noise_distribution(),
            rng,
        );

        table.transform_slice(b.0);

        secret_key.iter_dcrt_poly().zip(a).for_each(|(si, ai)| {
            primus_distr::sample_crt_uniform_values_to(ai.0, poly_length, uniform_distrs, rng);
            b.add_mul_assign(&ai, &si, poly_length, moduli);
        });

        Self { key: data }
    }

    /// Encrypts one CRT plaintext polynomial into a newly allocated ciphertext.
    pub fn encrypt<R, M, Table, A>(
        &self,
        message: &CrtPolynomial<A>,
        params: &CrtGlweParameters<T, M>,
        table: &DcrtTable<Table>,
        rng: &mut R,
    ) -> DcrtGlwe<Vec<T>>
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        let dimension = params.dimension();
        let poly_length = params.poly_length();
        let rns_poly_len = params.rns_poly_len();
        let dcrt_glwe_len = params.rns_glwe_len();

        let moduli = params.cipher_moduli();

        let mut result = DcrtGlwe::zero(dcrt_glwe_len);
        let mut v = vec![T::ZERO; rns_poly_len];

        primus_distr::sample_crt_ternary_values_to(
            &mut v,
            poly_length,
            params.cipher_moduli_minus_one(),
            rng,
        );
        table.transform_slice(&mut v);
        let v_dcrt_poly = DcrtPolynomial(v.as_slice());

        result
            .iter_dcrt_poly_mut(rns_poly_len)
            .zip(self.key.iter_dcrt_poly(rns_poly_len))
            .enumerate()
            .for_each(|(i, (mut ai, pk_ai))| {
                primus_distr::sample_crt_gaussian_values_to(
                    ai.0,
                    poly_length,
                    params.cipher_moduli_value(),
                    params.noise_distribution(),
                    rng,
                );

                if i == dimension {
                    CrtPolynomial(&mut *ai.0).add_assign(message, poly_length, moduli);
                }
                table.transform_slice(ai.0);
                ai.add_mul_assign(&v_dcrt_poly, &pk_ai, poly_length, moduli);
            });

        result
    }

    #[allow(clippy::too_many_arguments)]
    fn encrypt_monomial_in_dcrt_glev_inplace<R, Table, M>(
        &self,
        index: usize,
        coeff_residues: &[T],
        degree: usize,
        dcrt_glev: &mut DcrtGlev<&mut [T]>,
        params: &CrtGlevParameters<T, M>,
        table: &DcrtTable<Table>,
        v: &mut [T],
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        Table: NttTable<ValueT = T>,
        M: FieldContext<T>,
    {
        let poly_length = params.poly_length();
        let dcrt_poly_len = params.rns_poly_len();
        let dcrt_glwe_len = params.rns_glwe_len();

        let moduli = params.cipher_moduli();

        dcrt_glev
            .iter_dcrt_glwe_mut(dcrt_glwe_len)
            .zip(params.basis().iter_scalar_residues())
            .for_each(|(mut dcrt_glwe, scalar_residues)| {
                primus_distr::sample_crt_ternary_values_to(
                    v,
                    poly_length,
                    params.cipher_moduli_minus_one(),
                    rng,
                );
                table.transform_slice(v);
                let v_poly = DcrtPolynomial(&*v);

                dcrt_glwe
                    .iter_dcrt_poly_mut(dcrt_poly_len)
                    .zip(self.key.iter_dcrt_poly(dcrt_poly_len))
                    .enumerate()
                    .for_each(|(i, (mut ai, pk_ai))| {
                        primus_distr::sample_crt_gaussian_values_to(
                            ai.0,
                            poly_length,
                            params.cipher_moduli_value(),
                            params.noise_distribution(),
                            rng,
                        );

                        if i == index {
                            izip!(
                                ai.iter_each_modulus_mut(poly_length),
                                coeff_residues,
                                scalar_residues,
                                moduli,
                            )
                            .for_each(
                                |(poly, &coeff_residue, &scalar_residue, &modulus)| {
                                    poly[degree] = modulus.reduce_mul_add(
                                        coeff_residue,
                                        scalar_residue,
                                        poly[degree],
                                    );
                                },
                            );
                        }

                        table.transform_slice(ai.0);

                        ai.add_mul_assign(&v_poly, &pk_ai, poly_length, moduli);
                    });
            });
    }

    /// Generate a [`DcrtGgsw`] ciphertext which encrypted `coeff*X^degree`.
    pub fn encrypt_monomial_ggsw<R, Table, M>(
        &self,
        coeff_residues: &[T],
        degree: usize,
        params: &CrtGgswParameters<T, M>,
        table: &DcrtTable<Table>,
        rng: &mut R,
    ) -> DcrtGgsw<Vec<T>>
    where
        R: rand::Rng + rand::CryptoRng,
        Table: NttTable<ValueT = T>,
        M: FieldContext<T>,
    {
        let dcrt_ggsw_len = params.rns_ggsw_len();

        let mut result: DcrtGgsw<Vec<T>> = DcrtGgsw::zero(dcrt_ggsw_len);

        self.encrypt_monomial_ggsw_inplace(coeff_residues, degree, &mut result, params, table, rng);

        result
    }

    /// Generate a [`DcrtGgsw`] ciphertext which encrypted `coeff*X^degree`.
    pub fn encrypt_monomial_ggsw_inplace<R, Table, M, A>(
        &self,
        coeff_residues: &[T],
        degree: usize,
        result: &mut DcrtGgsw<A>,
        params: &CrtGgswParameters<T, M>,
        table: &DcrtTable<Table>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        Table: NttTable<ValueT = T>,
        M: FieldContext<T>,
        A: DataMut<Elem = T>,
    {
        let rns_poly_len = params.rns_poly_len();
        let dcrt_glev_len = params.rns_glev_len();

        assert_eq!(result.as_ref().len(), params.rns_ggsw_len());
        assert!(degree < params.poly_length());

        let mut v = vec![T::ZERO; rns_poly_len];

        result
            .iter_dcrt_glev_mut(dcrt_glev_len)
            .enumerate()
            .for_each(|(i, mut dcrt_glev)| {
                self.encrypt_monomial_in_dcrt_glev_inplace(
                    i,
                    coeff_residues,
                    degree,
                    &mut dcrt_glev,
                    params,
                    table,
                    &mut v,
                    rng,
                );
            });
    }
}
