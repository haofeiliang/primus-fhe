//! NTRU secret key types.

mod coeff;
mod fourier;
mod gadget;
mod ntt;

use primus_integer::{FheUint, WrappingNeg};
use primus_reduce::RingContext;

use crate::SecretCoefficient;

pub use coeff::NtruSecretKey;
pub use fourier::{FourierNtruDecryptContext, FourierNtruEncryptContext, FourierNtruSecretKey};
pub use gadget::{FourierNtruGadgetEncryptContext, NttNtruGadgetEncryptContext};
pub use ntt::NttNtruSecretKey;

/// Writes canonical signed secret coefficients as ciphertext-ring residues.
///
/// This is representation encoding, not plaintext encoding: it applies no
/// plaintext modulus, embedding scale, or message codec. A negative
/// coefficient `-a` is represented by `q - a` for an explicit modulus and by
/// its wrapping two's-complement residue for the native modulus.
pub(crate) fn encode_secret_polynomial_to<T: FheUint, M: RingContext<T>>(
    coefficients: &[SecretCoefficient<T>],
    output: &mut [T],
    modulus: M,
) {
    assert_eq!(output.len(), coefficients.len());
    output
        .iter_mut()
        .zip(coefficients)
        .for_each(|(output, &coefficient)| {
            *output = if coefficient < T::ZERO.cast_to_signed() {
                let magnitude = T::cast_from_signed(coefficient.wrapping_neg());
                modulus.reduce_neg(modulus.reduce(magnitude))
            } else {
                modulus.reduce(T::cast_from_signed(coefficient))
            };
        });
}
