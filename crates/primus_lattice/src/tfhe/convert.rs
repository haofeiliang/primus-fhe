//! Coefficient/Fourier conversions for TFHE ciphertexts.

use primus_data::{Data, DataMut, RawData};
use primus_fft::{Complex64, FftTable, TorusFftValue};

use crate::{
    ggsw::{FourierGgsw, Ggsw},
    glev::{FourierGlev, Glev},
    glwe::{FourierGlwe, Glwe},
};

macro_rules! impl_forward {
    ($coeff:ident, $fourier:ident) => {
        impl<S, T> $coeff<S>
        where
            S: RawData<Elem = T> + Data,
            T: TorusFftValue,
        {
            /// Writes this ciphertext in normalized torus Fourier form.
            pub fn write_fourier_form<Table, A>(&self, result: &mut $fourier<A>, fft: &Table)
            where
                Table: FftTable,
                A: RawData<Elem = Complex64> + DataMut,
            {
                for (coeff, fourier) in self
                    .as_ref()
                    .chunks_exact(fft.poly_length())
                    .zip(result.as_mut().chunks_exact_mut(fft.fourier_length()))
                {
                    fft.forward_as_torus(coeff, fourier);
                }
            }
        }
    };
}
impl_forward!(Glwe, FourierGlwe);
impl_forward!(Glev, FourierGlev);
impl_forward!(Ggsw, FourierGgsw);

macro_rules! impl_backward {
    ($fourier:ident, $coeff:ident) => {
        impl<S> $fourier<S>
        where
            S: RawData<Elem = Complex64> + Data,
        {
            /// Writes this Fourier ciphertext back to torus coefficient form.
            pub fn write_torus_form<Table, A, T>(&self, result: &mut $coeff<A>, fft: &Table)
            where
                Table: FftTable,
                A: RawData<Elem = T> + DataMut,
                T: TorusFftValue,
            {
                for (fourier, coeff) in self
                    .as_ref()
                    .chunks_exact(fft.fourier_length())
                    .zip(result.as_mut().chunks_exact_mut(fft.poly_length()))
                {
                    fft.backward_as_torus(fourier, coeff);
                }
            }
        }
    };
}
impl_backward!(FourierGlwe, Glwe);
impl_backward!(FourierGlev, Glev);
impl_backward!(FourierGgsw, Ggsw);
