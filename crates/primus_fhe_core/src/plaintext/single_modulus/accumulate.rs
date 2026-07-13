use primus_integer::FheUint;

use super::{
    PlaintextCodec,
    helpers::{checked_message, lift_centered_from_raw},
    strategy::{CodecStrategy, dispatch_strategy},
};
use crate::PlaintextEmbedding;

impl<T: FheUint> PlaintextCodec<T> {
    /// Batch version of [`PlaintextCodec::encode_value_with_delta`].
    #[inline]
    pub fn add_encode_slice_assign_with_delta(
        &self,
        accumulator: &mut [T],
        messages: &[T],
        embedding: PlaintextEmbedding,
    ) {
        assert_eq!(accumulator.len(), messages.len());
        let t = self.t;

        dispatch_strategy!(&self.strategy, codec => {
            match embedding {
                PlaintextEmbedding::Unsigned => {
                    codec.add_delta_slice_assign(accumulator, messages, t);
                }
                PlaintextEmbedding::Centered => {
                    for (accumulator, &message) in accumulator.iter_mut().zip(messages) {
                        let (magnitude, is_negative) =
                            lift_centered_from_raw(message, t, self.centered_half);
                        let encoded = codec.encode_delta(magnitude, t);
                        let encoded = if is_negative {
                            codec.neg(encoded)
                        } else {
                            encoded
                        };
                        codec.add_assign(accumulator, encoded);
                    }
                }
            }
        });
    }

    /// Encodes `message` and modular-adds into `accumulator`.
    #[inline]
    pub fn add_encode_value<M>(
        &self,
        accumulator: &mut T,
        message: M,
        embedding: PlaintextEmbedding,
    ) where
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
            let encoded = if is_negative {
                codec.neg(encoded)
            } else {
                encoded
            };
            codec.add_assign(accumulator, encoded);
        });
    }

    /// Encodes each message and modular-adds into the corresponding accumulator element.
    #[inline]
    pub fn add_encode_slice_assign<M>(
        &self,
        accumulator: &mut [T],
        messages: &[M],
        embedding: PlaintextEmbedding,
    ) where
        M: Copy + TryInto<T>,
    {
        assert_eq!(accumulator.len(), messages.len());
        let t = self.t;

        dispatch_strategy!(&self.strategy, codec => {
            match embedding {
                PlaintextEmbedding::Unsigned => {
                    for (accumulator, &message) in accumulator.iter_mut().zip(messages) {
                        let magnitude = checked_message(message);
                        let encoded = codec.encode_exact(magnitude, t);
                        codec.add_assign(accumulator, encoded);
                    }
                }
                PlaintextEmbedding::Centered => {
                    for (accumulator, &message) in accumulator.iter_mut().zip(messages) {
                        let message = checked_message(message);
                        let (magnitude, is_negative) =
                            lift_centered_from_raw(message, t, self.centered_half);
                        let encoded = codec.encode_exact(magnitude, t);
                        let encoded = if is_negative {
                            codec.neg(encoded)
                        } else {
                            encoded
                        };
                        codec.add_assign(accumulator, encoded);
                    }
                }
            }
        });
    }
}
