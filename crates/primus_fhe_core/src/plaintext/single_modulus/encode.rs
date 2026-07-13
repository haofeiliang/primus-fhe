use primus_integer::FheUint;

use super::{
    PlaintextCodec,
    helpers::{checked_message, lift_centered_from_raw},
    strategy::{CodecStrategy, dispatch_strategy},
};
use crate::PlaintextEmbedding;

impl<T: FheUint> PlaintextCodec<T> {
    #[inline]
    pub fn encode_value<M>(&self, message: M, embedding: PlaintextEmbedding) -> T
    where
        M: TryInto<T>,
    {
        let message = checked_message(message);
        let (magnitude, is_negative) = match embedding {
            PlaintextEmbedding::Unsigned => (message, false),
            PlaintextEmbedding::Centered => {
                lift_centered_from_raw(message, self.t, self.centered_half)
            }
        };

        dispatch_strategy!(&self.strategy, codec => {
            let encoded = codec.encode_exact(magnitude, self.t);
            if is_negative {
                codec.neg(encoded)
            } else {
                encoded
            }
        })
    }

    #[inline]
    pub fn encode_slice_to(&self, messages: &[T], output: &mut [T], embedding: PlaintextEmbedding) {
        assert_eq!(messages.len(), output.len());
        let t = self.t;

        dispatch_strategy!(&self.strategy, codec => {
            match embedding {
                PlaintextEmbedding::Unsigned => {
                    for (&message, output) in messages.iter().zip(output) {
                        *output = codec.encode_exact(message, t);
                    }
                }
                PlaintextEmbedding::Centered => {
                    for (&message, output) in messages.iter().zip(output) {
                        let (magnitude, is_negative) =
                            lift_centered_from_raw(message, t, self.centered_half);
                        let encoded = codec.encode_exact(magnitude, t);
                        *output = if is_negative {
                            codec.neg(encoded)
                        } else {
                            encoded
                        };
                    }
                }
            }
        });
    }

    #[inline]
    pub fn encode_slice_inplace(&self, values: &mut [T], embedding: PlaintextEmbedding) {
        let t = self.t;

        dispatch_strategy!(&self.strategy, codec => {
            match embedding {
                PlaintextEmbedding::Unsigned => {
                    for value in values {
                        *value = codec.encode_exact(*value, t);
                    }
                }
                PlaintextEmbedding::Centered => {
                    for value in values {
                        let (magnitude, is_negative) =
                            lift_centered_from_raw(*value, t, self.centered_half);
                        let encoded = codec.encode_exact(magnitude, t);
                        *value = if is_negative {
                            codec.neg(encoded)
                        } else {
                            encoded
                        };
                    }
                }
            }
        });
    }

    /// Encodes `message` as `lift(message) * delta mod q`.
    #[inline]
    pub fn encode_value_with_delta<M>(&self, message: M, embedding: PlaintextEmbedding) -> T
    where
        M: TryInto<T>,
    {
        let message = checked_message(message);
        let (magnitude, is_negative) = match embedding {
            PlaintextEmbedding::Unsigned => (message, false),
            PlaintextEmbedding::Centered => {
                lift_centered_from_raw(message, self.t, self.centered_half)
            }
        };

        dispatch_strategy!(&self.strategy, codec => {
            let encoded = codec.encode_delta(magnitude, self.t);
            if is_negative {
                codec.neg(encoded)
            } else {
                encoded
            }
        })
    }
}
