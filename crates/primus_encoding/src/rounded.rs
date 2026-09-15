use super::decode;
use super::helpers;
use super::helpers::{check_message, lift_centered_from_raw};
use crate::PlaintextEmbedding;
use primus_integer::FheUint;
use primus_modulus::{ModulusSwitch, UintModulus};
use primus_reduce::{PrepareModulusSwitch, PreparedModulusSwitch, ReduceAdd};

/// Per-message rounding: `round(lift(m) * q / t) mod q`, returned in `[0,q)`,
/// with ties away from zero before modular reduction.
/// Decoding rounds `c * t / q` to the nearest integer, ties upward, modulo `t`.
/// Inputs to decoding and accumulators must be canonical residues in `[0,q)`.
///
/// This keeps modulus-shape checks and shift/mask computation out of hot
/// coefficient loops while hiding strategy-specific precomputation.
#[derive(Clone, Copy, Debug)]
pub struct RoundedCodec<T: FheUint, M: PrepareModulusSwitch<ValueT = T>> {
    t: T,
    centered_half: T,
    encoder: ModulusSwitch<T>,
    modulus: M,
    decoder: M::Prepared,
}

impl<T, M> RoundedCodec<T, M>
where
    T: FheUint,
    M: ReduceAdd<T, Output = T> + PrepareModulusSwitch<ValueT = T>,
{
    /// Creates a codec for plaintext modulus `t` and ciphertext modulus `q`.
    ///
    /// `NativeModulus<T>` selects the native wrapping modulus `2^T::BITS`.
    ///
    /// # Panics
    ///
    /// Panics if `t <= 1` or an explicit `q` is not greater than `t`.
    #[must_use]
    #[inline]
    pub fn new(t: T, modulus: M) -> Self {
        helpers::validate_moduli(t, modulus);
        let plaintext_modulus = UintModulus(t);
        Self {
            t,
            centered_half: helpers::centered_half(t),
            encoder: plaintext_modulus.prepare_switch_to(modulus),
            decoder: modulus.prepare_switch_to(plaintext_modulus),
            modulus,
        }
    }

    /// Returns the plaintext modulus `t` used by this codec.
    #[must_use]
    #[inline]
    pub fn t(&self) -> T {
        self.t
    }
}

impl<T, M> RoundedCodec<T, M>
where
    T: FheUint,
    M: ReduceAdd<T, Output = T> + PrepareModulusSwitch<ValueT = T>,
{
    /// Decodes a ciphertext residue into a canonical plaintext residue in `[0,t)`.
    ///
    /// # Correctness
    ///
    /// `value` must be in `[0,q)`. This range is not checked.
    #[must_use]
    #[inline]
    pub fn decode_value(&self, value: T) -> T {
        self.decoder.switch(value)
    }

    /// Replaces ciphertext residues with canonical plaintext residues in `[0,t)`.
    ///
    /// # Correctness
    ///
    /// Every input must be in `[0,q)`. This range is not checked.
    #[inline]
    pub fn decode_slice_assign(&self, values: &mut [T]) {
        decode::assign(&self.decoder, values);
    }

    /// Decodes into an equally sized output slice of canonical residues in `[0,t)`.
    ///
    /// # Correctness
    ///
    /// Every input must be in `[0,q)`. This range is not checked.
    ///
    /// # Panics
    ///
    /// Panics if the slices differ in length, before writing any output.
    #[inline]
    pub fn decode_slice_to(&self, input: &[T], output: &mut [T]) {
        decode::to(&self.decoder, input, output);
    }
}

impl<T, M> RoundedCodec<T, M>
where
    T: FheUint,
    M: ReduceAdd<T, Output = T> + PrepareModulusSwitch<ValueT = T>,
{
    /// Encodes a message in `[0,t)` into a canonical ciphertext residue in `[0,q)`.
    ///
    /// # Panics
    ///
    /// Panics if the message lies outside the plaintext domain `[0,t)`.
    #[must_use]
    #[inline]
    pub fn encode_value(&self, message: T, embedding: PlaintextEmbedding) -> T {
        check_message(message, self.t);
        let mut output = T::ZERO;
        self.encode::<false, _>(core::iter::once((&mut output, message)), embedding);
        output
    }

    /// Encodes `messages` into canonical residues in `output` using the selected embedding.
    /// The previous output is overwritten; validation completes before any writes.
    ///
    /// # Panics
    ///
    /// Panics if the slices differ in length or a message lies outside the
    /// plaintext domain `[0,t)`.
    #[inline]
    pub fn encode_slice_to(&self, messages: &[T], output: &mut [T], embedding: PlaintextEmbedding) {
        self.validate(messages, output.len());
        self.encode::<false, _>(output.iter_mut().zip(messages.iter().copied()), embedding);
    }

    /// Replaces plaintext residues with canonical ciphertext residues using the
    /// selected embedding. Validation completes before any writes.
    ///
    /// # Panics
    ///
    /// Panics if a value lies outside the plaintext domain `[0,t)`.
    #[inline]
    pub fn encode_slice_assign(&self, values: &mut [T], embedding: PlaintextEmbedding) {
        self.validate(values, values.len());
        self.encode::<false, _>(
            values.iter_mut().map(|out| {
                let message = *out;
                (out, message)
            }),
            embedding,
        );
    }
}

impl<T, M> RoundedCodec<T, M>
where
    T: FheUint,
    M: ReduceAdd<T, Output = T> + PrepareModulusSwitch<ValueT = T>,
{
    /// Encodes `message` and adds it modulo `q` to `accumulator` without clearing it.
    ///
    /// # Correctness
    ///
    /// `accumulator` must be in `[0,q)` and remains canonical after the addition.
    /// Its range is not checked.
    ///
    /// # Panics
    ///
    /// Panics if the message is outside `[0,t)`.
    #[inline]
    pub fn add_encode_value_assign(
        &self,
        accumulator: &mut T,
        message: T,
        embedding: PlaintextEmbedding,
    ) {
        check_message(message, self.t);
        self.encode::<true, _>(core::iter::once((accumulator, message)), embedding);
    }

    /// Encodes each message and adds it modulo `q` to the corresponding accumulator.
    /// The accumulator is not cleared; message validation completes before any writes.
    ///
    /// # Correctness
    ///
    /// Every accumulator must be in `[0,q)` and remains canonical after addition.
    /// Accumulator ranges are not checked.
    ///
    /// # Panics
    ///
    /// Panics on a length mismatch or a message outside `[0,t)`.
    #[inline]
    pub fn add_encode_slice_assign(
        &self,
        accumulator: &mut [T],
        messages: &[T],
        embedding: PlaintextEmbedding,
    ) {
        self.validate(messages, accumulator.len());
        self.encode::<true, _>(
            accumulator.iter_mut().zip(messages.iter().copied()),
            embedding,
        );
    }
}

impl<T, M> RoundedCodec<T, M>
where
    T: FheUint,
    M: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
{
    fn validate(&self, messages: &[T], output_len: usize) {
        assert_eq!(messages.len(), output_len, "encoding slice length mismatch");
        assert!(
            messages.iter().copied().max().is_none_or(|m| m < self.t),
            "message outside plaintext domain"
        );
    }

    /// The caller validates messages and, for ADD, supplies canonical accumulators.
    /// A negative lift has nonzero magnitude; q > t makes its encoding nonzero.
    /// Carrying sign/output through switch_map keeps arithmetic dispatch outside
    /// the loop and fuses the final write or modular addition.
    #[inline]
    fn encode<'a, const ADD: bool, I>(&self, input: I, embedding: PlaintextEmbedding)
    where
        I: Iterator<Item = (&'a mut T, T)>,
        T: 'a,
    {
        let write = |value, out: &mut T| {
            *out = if ADD {
                self.modulus.reduce_add(*out, value)
            } else {
                value
            };
        };
        match embedding {
            PlaintextEmbedding::Unsigned => {
                self.encoder
                    .switch_map(input.map(|(out, m)| (m, out)), write);
            }
            PlaintextEmbedding::Centered => {
                self.encoder.switch_map(
                    input.map(|(out, m)| {
                        let (magnitude, negative) =
                            lift_centered_from_raw(m, self.t, self.centered_half);
                        (magnitude, (negative, out))
                    }),
                    |value, (negative, out)| {
                        let value = if negative {
                            self.modulus.minus_one() - value + T::ONE
                        } else {
                            value
                        };
                        write(value, out);
                    },
                );
            }
        }
    }
}
