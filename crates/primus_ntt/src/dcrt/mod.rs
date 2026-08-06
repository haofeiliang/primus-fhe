use primus_data::{DataMut, RawData};
use primus_poly::{CrtPolynomial, DcrtPolynomial};
use primus_reduce::FieldContext;

use crate::{MonomialNttTable, NttError, NttTable, U32NttTable, U64NttTable, UintNttTable};

/// A collection of NTT tables sharing the same polynomial length.
///
/// Each contained table operates on one CRT modulus. The number of moduli is
/// fixed after construction because the table slice is not exposed mutably.
#[derive(Clone)]
pub struct DcrtTable<Ntt> {
    ntt_tables: Vec<Ntt>,
    poly_length: usize,
}

/// DCRT table using the generic unsigned-integer NTT implementation.
pub type UintDcrtTable<T> = DcrtTable<UintNttTable<T>>;

/// DCRT table using the optimized 32-bit NTT implementation.
pub type U32DcrtTable = DcrtTable<U32NttTable>;

/// DCRT table using the optimized 64-bit NTT implementation.
pub type U64DcrtTable = DcrtTable<U64NttTable>;

impl<Ntt> DcrtTable<Ntt>
where
    Ntt: NttTable,
{
    /// Creates one NTT table for every CRT modulus.
    pub fn new<M>(log_n: u32, moduli: &[M]) -> Result<Self, NttError<Ntt::ValueT>>
    where
        M: FieldContext<Ntt::ValueT>,
    {
        let poly_length = 1 << log_n;
        let ntt_tables = moduli
            .iter()
            .map(|&modulus| Ntt::new(log_n, modulus))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            ntt_tables,
            poly_length,
        })
    }

    /// Returns the NTT table for every CRT modulus.
    #[inline]
    pub fn ntt_tables(&self) -> &[Ntt] {
        &self.ntt_tables
    }

    /// Returns an iterator over the NTT tables.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, Ntt> {
        self.ntt_tables.iter()
    }

    /// Returns the polynomial length shared by all NTT tables.
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.poly_length
    }

    /// Returns the number of CRT moduli.
    #[inline]
    pub fn moduli_count(&self) -> usize {
        self.ntt_tables.len()
    }

    /// Returns the total number of coefficients across all CRT moduli.
    #[inline]
    pub fn crt_poly_length(&self) -> usize {
        self.poly_length * self.moduli_count()
    }

    /// Transforms a CRT polynomial in place into a DCRT polynomial.
    #[inline]
    pub fn transform_inplace<S>(&self, mut crt_poly: CrtPolynomial<S>) -> DcrtPolynomial<S>
    where
        S: RawData<Elem = Ntt::ValueT> + DataMut,
    {
        let poly_length = self.poly_length();
        debug_assert_eq!(self.crt_poly_length(), crt_poly.crt_poly_length());

        self.iter()
            .zip(crt_poly.iter_each_modulus_mut(poly_length))
            .for_each(|(table, poly)| table.transform_slice(poly));

        DcrtPolynomial::new(crt_poly.0)
    }

    /// Inversely transforms a DCRT polynomial in place into a CRT polynomial.
    #[inline]
    pub fn inverse_transform_inplace<S>(&self, mut dcrt_poly: DcrtPolynomial<S>) -> CrtPolynomial<S>
    where
        S: RawData<Elem = Ntt::ValueT> + DataMut,
    {
        let poly_length = self.poly_length();
        debug_assert_eq!(self.crt_poly_length(), dcrt_poly.dcrt_poly_length());

        self.iter()
            .zip(dcrt_poly.iter_each_modulus_mut(poly_length))
            .for_each(|(table, poly)| table.inverse_transform_slice(poly));

        CrtPolynomial::new(dcrt_poly.0)
    }

    /// Lazily transforms every CRT limb in place.
    #[inline]
    pub fn lazy_transform_slice(&self, poly: &mut [Ntt::ValueT]) {
        let poly_length = self.poly_length();
        debug_assert_eq!(self.crt_poly_length(), poly.len());
        self.iter()
            .zip(poly.chunks_exact_mut(poly_length))
            .for_each(|(table, poly)| table.lazy_transform_slice(poly));
    }

    /// Transforms every CRT limb in place.
    #[inline]
    pub fn transform_slice(&self, poly: &mut [Ntt::ValueT]) {
        let poly_length = self.poly_length();
        debug_assert_eq!(self.crt_poly_length(), poly.len());
        self.iter()
            .zip(poly.chunks_exact_mut(poly_length))
            .for_each(|(table, poly)| table.transform_slice(poly));
    }

    /// Lazily inversely transforms every DCRT limb in place.
    #[inline]
    pub fn lazy_inverse_transform_slice(&self, poly: &mut [Ntt::ValueT]) {
        let poly_length = self.poly_length();
        debug_assert_eq!(self.crt_poly_length(), poly.len());
        self.iter()
            .zip(poly.chunks_exact_mut(poly_length))
            .for_each(|(table, values)| table.lazy_inverse_transform_slice(values));
    }

    /// Inversely transforms every DCRT limb in place.
    #[inline]
    pub fn inverse_transform_slice(&self, poly: &mut [Ntt::ValueT]) {
        let poly_length = self.poly_length();
        debug_assert_eq!(self.crt_poly_length(), poly.len());
        self.iter()
            .zip(poly.chunks_exact_mut(poly_length))
            .for_each(|(table, values)| table.inverse_transform_slice(values));
    }
}

impl<Ntt> DcrtTable<Ntt>
where
    Ntt: MonomialNttTable,
{
    /// Transforms `coeff * X^degree` for every CRT modulus.
    pub fn transform_monomial(
        &self,
        coeff: Ntt::ValueT,
        degree: usize,
        values: &mut [Ntt::ValueT],
    ) {
        let poly_length = self.poly_length();
        debug_assert_eq!(self.crt_poly_length(), values.len());
        self.iter()
            .zip(values.chunks_exact_mut(poly_length))
            .for_each(|(table, values)| table.transform_monomial(coeff, degree, values));
    }

    /// Transforms `X^degree` for every CRT modulus.
    pub fn transform_coeff_one_monomial(&self, degree: usize, values: &mut [Ntt::ValueT]) {
        let poly_length = self.poly_length();
        debug_assert_eq!(self.crt_poly_length(), values.len());
        self.iter()
            .zip(values.chunks_exact_mut(poly_length))
            .for_each(|(table, values)| table.transform_coeff_one_monomial(degree, values));
    }

    /// Transforms `-X^degree` for every CRT modulus.
    pub fn transform_coeff_minus_one_monomial(&self, degree: usize, values: &mut [Ntt::ValueT]) {
        let poly_length = self.poly_length();
        debug_assert_eq!(self.crt_poly_length(), values.len());
        self.iter()
            .zip(values.chunks_exact_mut(poly_length))
            .for_each(|(table, values)| table.transform_coeff_minus_one_monomial(degree, values));
    }
}
