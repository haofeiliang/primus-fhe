//! Batch encryption of constant polynomials into Fourier GGSWs.

use super::{FourierGadgetEncryptContext, FourierGlweSecretKey};
use crate::{FourierGgswCiphertext, GlevParameters};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_modulus::NativeModulus;

impl FourierGlweSecretKey {
    /// Encrypts native-ring constants into consecutive Fourier GGSWs.
    ///
    /// Each input is a constant polynomial, scaled by the gadget basis without
    /// plaintext encoding. Output uses `[input][row][level][component][Fourier
    /// coefficient]` layout, with exactly `input.len() * params.fourier_ggsw_len()`
    /// entries. Output and scratch are reused without allocating; shared
    /// resources are checked once. Empty input/output consumes no randomness.
    ///
    /// # Panics
    ///
    /// Panics before sampling or writes on incompatible key, FFT, workspace or
    /// output lengths, or a batch length overflow. RNG/FFT panics can leave
    /// partial output and modified scratch.
    ///
    /// # Correctness
    ///
    /// Use the FFT table instance with which this secret key was constructed.
    pub fn encrypt_ggsw_constant_batch_to<T, Table, R>(
        &self,
        input: &[T],
        output: &mut [Complex64],
        params: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierGadgetEncryptContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        self.assert_gadget_compatible(params, fft);
        context.assert_ggsw_compatible(params.size());
        let ggsw_len = params.fourier_ggsw_len();
        let expected = input
            .len()
            .checked_mul(ggsw_len)
            .expect("Fourier GGSW batch length overflow");
        assert_eq!(
            output.len(),
            expected,
            "Fourier GGSW batch output layout mismatch"
        );

        context.encoded.as_mut().fill(T::ZERO);
        for (&constant, block) in input.iter().zip(output.chunks_exact_mut(ggsw_len)) {
            // Native-ring scaling must precede torus lifting. Keep the same
            // per-level FFT path as ordinary GGSW encryption, including rounding.
            for (scalar, transformed) in params.basis().scalar_iter().zip(
                context
                    .level_transforms
                    .chunks_exact_mut(fft.fourier_length()),
            ) {
                context.encoded.as_mut()[0] = constant.wrapping_mul(scalar);
                fft.forward_as_torus(context.encoded.as_ref(), transformed);
            }
            self.encrypt_ggsw_from_levels_to(
                &mut FourierGgswCiphertext::new(block),
                params,
                fft,
                rng,
                context,
            );
        }
    }
}
