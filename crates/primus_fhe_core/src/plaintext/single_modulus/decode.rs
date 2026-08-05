use primus_integer::FheUint;

use super::{
    PlaintextCodec,
    helpers::try_from_decoded,
    strategy::{CodecStrategy, dispatch_strategy},
};

impl<T: FheUint> PlaintextCodec<T> {
    /// Decodes one ciphertext-modulus value into a plaintext value.
    ///
    /// # Panics
    ///
    /// Panics if the decoded value cannot be represented by `M`.
    #[inline]
    pub fn decode_value<M>(&self, value: T) -> M
    where
        M: TryFrom<T>,
    {
        let decoded = dispatch_strategy!(&self.strategy, codec => {
            codec.decode(value, self.t)
        });
        try_from_decoded(decoded)
    }

    /// Decodes all values in place.
    #[inline]
    pub fn decode_slice_inplace(&self, values: &mut [T]) {
        let t = self.t;
        dispatch_strategy!(&self.strategy, codec => {
            for value in values {
                *value = codec.decode(*value, t);
            }
        });
    }

    /// Decodes `input` into `output`.
    ///
    /// # Panics
    ///
    /// Panics if the slices differ in length or a decoded value cannot be
    /// represented by `M`.
    #[inline]
    pub fn decode_slice_to<M>(&self, input: &[T], output: &mut [M])
    where
        M: TryFrom<T>,
    {
        assert_eq!(input.len(), output.len());
        let t = self.t;

        dispatch_strategy!(&self.strategy, codec => {
            for (&value, output) in input.iter().zip(output) {
                *output = try_from_decoded(codec.decode(value, t));
            }
        });
    }
}
