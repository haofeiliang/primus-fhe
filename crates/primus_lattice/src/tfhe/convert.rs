//! Coefficient ↔ Fourier domain conversion for GLWE, GLev, and GGSW.
//!
//! Each method iterates over flat storage by polynomial-sized chunks
//! and calls [`FftTable::forward_torus_slice`] or
//! [`FftTable::inverse_torus_slice`] per chunk.  Fourier data is stored
//! in split `[re | im]` f64 layout, which matches the FFT table's native
//! format — no intermediate conversion is needed.

use primus_data::{Data, DataMut, RawData};
use primus_fft::{FftTable, TorusFftValue};

use crate::ggsw::Ggsw;
use crate::ggsw::fourier::FourierGgsw;
use crate::glev::Glev;
use crate::glev::fourier::FourierGlev;
use crate::glwe::Glwe;
use crate::glwe::fourier::FourierGlwe;

// ---------------------------------------------------------------------------
// Forward: coefficient (torus) → Fourier (split f64)
// ---------------------------------------------------------------------------

impl<S, T> Glwe<S>
where
    S: RawData<Elem = T> + Data,
    T: TorusFftValue,
{
    /// Writes this GLWE into a Fourier-domain [`FourierGlwe`].
    #[inline]
    pub fn write_fourier_form<Table, A>(&self, result: &mut FourierGlwe<A>, fft: &Table)
    where
        Table: FftTable,
        A: RawData<Elem = f64> + DataMut,
    {
        for (coeff, fourier) in self
            .iter_poly(fft.poly_length())
            .zip(result.iter_fourier_poly_mut(fft.fourier_length()))
        {
            fft.forward_torus_slice(coeff.0, fourier.0);
        }
    }
}

impl<S, T> Glev<S>
where
    S: RawData<Elem = T> + Data,
    T: TorusFftValue,
{
    /// Writes this GLev into a Fourier-domain [`FourierGlev`].
    #[inline]
    pub fn write_fourier_form<Table, A>(&self, result: &mut FourierGlev<A>, fft: &Table)
    where
        Table: FftTable,
        A: RawData<Elem = f64> + DataMut,
    {
        let poly_len = fft.poly_length();
        for (coeff, fourier) in self
            .as_ref()
            .chunks_exact(poly_len)
            .zip(result.as_mut().chunks_exact_mut(fft.buffer_len()))
        {
            fft.forward_torus_slice(coeff, fourier);
        }
    }
}

impl<S, T> Ggsw<S>
where
    S: RawData<Elem = T> + Data,
    T: TorusFftValue,
{
    /// Writes this GGSW into a Fourier-domain [`FourierGgsw`].
    #[inline]
    pub fn write_fourier_form<Table, A>(&self, result: &mut FourierGgsw<A>, fft: &Table)
    where
        Table: FftTable,
        A: RawData<Elem = f64> + DataMut,
    {
        let poly_len = fft.poly_length();
        for (coeff, fourier) in self
            .as_ref()
            .chunks_exact(poly_len)
            .zip(result.as_mut().chunks_exact_mut(fft.buffer_len()))
        {
            fft.forward_torus_slice(coeff, fourier);
        }
    }
}

// ---------------------------------------------------------------------------
// Inverse: Fourier (split f64) → coefficient (torus)
// ---------------------------------------------------------------------------

impl<S> FourierGlwe<S>
where
    S: RawData<Elem = f64> + Data,
{
    /// Writes this Fourier GLWE back into a coefficient-domain [`Glwe`].
    #[inline]
    pub fn write_torus_form<Table, A, T>(&self, result: &mut Glwe<A>, fft: &Table)
    where
        Table: FftTable,
        A: RawData<Elem = T> + DataMut,
        T: TorusFftValue,
    {
        for (fourier, coeff) in self
            .iter_fourier_poly(fft.fourier_length())
            .zip(result.iter_poly_mut(fft.poly_length()))
        {
            fft.inverse_torus_slice(fourier.0, coeff.0);
        }
    }
}

impl<S> FourierGlev<S>
where
    S: RawData<Elem = f64> + Data,
{
    /// Writes this Fourier GLev back into a coefficient-domain [`Glev`].
    #[inline]
    pub fn write_torus_form<Table, A, T>(&self, result: &mut Glev<A>, fft: &Table)
    where
        Table: FftTable,
        A: RawData<Elem = T> + DataMut,
        T: TorusFftValue,
    {
        let poly_len = fft.poly_length();
        for (fourier, coeff) in self
            .as_ref()
            .chunks_exact(fft.buffer_len())
            .zip(result.as_mut().chunks_exact_mut(poly_len))
        {
            fft.inverse_torus_slice(fourier, coeff);
        }
    }
}

impl<S> FourierGgsw<S>
where
    S: RawData<Elem = f64> + Data,
{
    /// Writes this Fourier GGSW back into a coefficient-domain [`Ggsw`].
    #[inline]
    pub fn write_torus_form<Table, A, T>(&self, result: &mut Ggsw<A>, fft: &Table)
    where
        Table: FftTable,
        A: RawData<Elem = T> + DataMut,
        T: TorusFftValue,
    {
        let poly_len = fft.poly_length();
        for (fourier, coeff) in self
            .as_ref()
            .chunks_exact(fft.buffer_len())
            .zip(result.as_mut().chunks_exact_mut(poly_len))
        {
            fft.inverse_torus_slice(fourier, coeff);
        }
    }
}
