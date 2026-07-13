use primus_factor::{FactorBase, FactorMul, FactorSliceOps, ShoupFactor};
use primus_integer::FheUint;

mod helpers;

use helpers::{
    centered_half, checked_message, mul_div_round, narrow_mul_div_round, lift_centered,
    lift_centered_from_raw, try_from_decoded,
};

use super::PlaintextEmbedding;

/// Preselected plaintext encoding/decoding strategy for fixed parameters.
///
/// This keeps modulus-shape checks and shift/mask computation out of hot
/// coefficient loops.
#[derive(Clone, Copy, Debug)]
pub enum PlaintextCodec<T: FheUint> {
    /// Native modulus `2^T::BITS` with power-of-two plaintext modulus.
    NativePow2 {
        encode_shift: u32,
        decode_shift: u32,
        mask: T,
    },
    /// Explicit power-of-two ciphertext and plaintext moduli.
    Pow2 {
        encode_shift: u32,
        decode_shift: u32,
        mask: T,
        q: T,
    },
    /// Native modulus `2^T::BITS` with arbitrary plaintext modulus.
    NativeScaled { t: T, delta: T },
    /// Explicit arbitrary ciphertext/plaintext moduli whose products fit in `T`.
    ScaledNarrow {
        t: T,
        q: T,
        delta_factor: ShoupFactor<T>,
    },
    /// Explicit arbitrary ciphertext/plaintext moduli requiring wide products.
    Scaled {
        t: T,
        q: T,
        delta_factor: ShoupFactor<T>,
    },
}

impl<T: FheUint> PlaintextCodec<T> {
    #[inline]
    pub fn new(t: T, q: Option<T>) -> Self {
        assert!(t > T::ONE);
        match q {
            None if t.is_power_of_two() => {
                let encode_shift = T::BITS - t.trailing_zeros();
                assert!(encode_shift > 1);
                Self::NativePow2 {
                    encode_shift,
                    decode_shift: encode_shift - 1,
                    mask: t - T::ONE,
                }
            }
            None => {
                // delta = round(2^BITS / t) = floor((2^BITS + t/2) / t)
                let delta = T::div_wide(t >> 1u32, T::ONE, t);
                Self::NativeScaled { t, delta }
            }
            Some(q) if q.is_power_of_two() && t.is_power_of_two() => {
                assert!(q > t);
                let encode_shift = q.trailing_zeros() - t.trailing_zeros();
                assert!(encode_shift > 1);
                Self::Pow2 {
                    encode_shift,
                    decode_shift: encode_shift - 1,
                    mask: t - T::ONE,
                    q,
                }
            }
            Some(q) => {
                assert!(q > t);
                let (mut delta, rem) = q.div_rem(t);
                if rem > (t - T::ONE) / T::TWO {
                    delta += T::ONE;
                }
                let delta_factor = ShoupFactor::new(delta, q);
                if q.checked_mul(t).is_some() {
                    return Self::ScaledNarrow { t, q, delta_factor };
                }
                Self::Scaled { t, q, delta_factor }
            }
        }
    }

    #[inline]
    pub fn encode_value<M>(&self, message: M, embedding: PlaintextEmbedding) -> T
    where
        M: TryInto<T>,
    {
        let message = checked_message(message);
        match embedding {
            PlaintextEmbedding::Unsigned => self.encode_unsigned_value(message),
            PlaintextEmbedding::Centered => {
                let t = self.t();
                let (magnitude, is_negative) = lift_centered(message, t);
                match *self {
                    Self::NativePow2 {
                        encode_shift, mask, ..
                    } => {
                        assert!(magnitude <= mask);
                        let encoded = magnitude << encode_shift;
                        if is_negative {
                            encoded.wrapping_neg()
                        } else {
                            encoded
                        }
                    }
                    Self::Pow2 {
                        encode_shift,
                        mask,
                        q,
                        ..
                    } => {
                        assert!(magnitude <= mask);
                        let encoded = magnitude << encode_shift;
                        if is_negative {
                            if encoded.is_zero() {
                                T::ZERO
                            } else {
                                q - encoded
                            }
                        } else {
                            encoded
                        }
                    }
                    Self::NativeScaled { t, .. } => {
                        assert!(magnitude < t);
                        let encoded = T::div_wide(t >> 1u32, magnitude, t);
                        if is_negative {
                            encoded.wrapping_neg()
                        } else {
                            encoded
                        }
                    }
                    Self::Scaled { t, q, .. } => {
                        assert!(magnitude < t);
                        let encoded = mul_div_round(magnitude, q, t);
                        if is_negative {
                            if encoded.is_zero() {
                                T::ZERO
                            } else {
                                q - encoded
                            }
                        } else {
                            encoded
                        }
                    }
                    Self::ScaledNarrow { t, q, .. } => {
                        assert!(magnitude < t);
                        let encoded = narrow_mul_div_round(magnitude, q, t);
                        if is_negative {
                            if encoded.is_zero() {
                                T::ZERO
                            } else {
                                q - encoded
                            }
                        } else {
                            encoded
                        }
                    }
                }
            }
        }
    }

    #[inline]
    pub fn encode_slice_to(&self, messages: &[T], output: &mut [T], embedding: PlaintextEmbedding) {
        assert_eq!(messages.len(), output.len());

        match embedding {
            PlaintextEmbedding::Unsigned => self.encode_unsigned_slice_to(messages, output),
            PlaintextEmbedding::Centered => {
                let t = self.t();
                let half = centered_half(t);
                match *self {
                    Self::NativePow2 {
                        encode_shift, mask, ..
                    } => {
                        for (message, output) in messages.iter().zip(output) {
                            let (magnitude, is_negative) =
                                lift_centered_from_raw(*message, t, half);
                            assert!(magnitude <= mask);
                            let encoded = magnitude << encode_shift;
                            *output = if is_negative {
                                encoded.wrapping_neg()
                            } else {
                                encoded
                            };
                        }
                    }
                    Self::Pow2 {
                        encode_shift,
                        mask,
                        q,
                        ..
                    } => {
                        for (message, output) in messages.iter().zip(output) {
                            let (magnitude, is_negative) =
                                lift_centered_from_raw(*message, t, half);
                            assert!(magnitude <= mask);
                            let encoded = magnitude << encode_shift;
                            *output = if is_negative {
                                if encoded.is_zero() {
                                    T::ZERO
                                } else {
                                    q - encoded
                                }
                            } else {
                                encoded
                            };
                        }
                    }
                    Self::NativeScaled { t, .. } => {
                        for (message, output) in messages.iter().zip(output) {
                            let (magnitude, is_negative) =
                                lift_centered_from_raw(*message, t, half);
                            assert!(magnitude < t);
                            let encoded = T::div_wide(t >> 1u32, magnitude, t);
                            *output = if is_negative {
                                encoded.wrapping_neg()
                            } else {
                                encoded
                            };
                        }
                    }
                    Self::Scaled { t, q, .. } => {
                        for (message, output) in messages.iter().zip(output) {
                            let (magnitude, is_negative) =
                                lift_centered_from_raw(*message, t, half);
                            assert!(magnitude < t);
                            let encoded = mul_div_round(magnitude, q, t);
                            *output = if is_negative {
                                if encoded.is_zero() {
                                    T::ZERO
                                } else {
                                    q - encoded
                                }
                            } else {
                                encoded
                            };
                        }
                    }
                    Self::ScaledNarrow { t, q, .. } => {
                        for (message, output) in messages.iter().zip(output) {
                            let (magnitude, is_negative) =
                                lift_centered_from_raw(*message, t, half);
                            assert!(magnitude < t);
                            let encoded = narrow_mul_div_round(magnitude, q, t);
                            *output = if is_negative {
                                if encoded.is_zero() {
                                    T::ZERO
                                } else {
                                    q - encoded
                                }
                            } else {
                                encoded
                            };
                        }
                    }
                }
            }
        }
    }

    #[inline]
    pub fn encode_slice_inplace(&self, values: &mut [T], embedding: PlaintextEmbedding) {
        match embedding {
            PlaintextEmbedding::Unsigned => self.encode_unsigned_slice_inplace(values),
            PlaintextEmbedding::Centered => {
                let t = self.t();
                let half = centered_half(t);
                match *self {
                    Self::NativePow2 {
                        encode_shift, mask, ..
                    } => {
                        for value in values.iter_mut() {
                            let (magnitude, is_negative) = lift_centered_from_raw(*value, t, half);
                            assert!(magnitude <= mask);
                            let encoded = magnitude << encode_shift;
                            *value = if is_negative {
                                encoded.wrapping_neg()
                            } else {
                                encoded
                            };
                        }
                    }
                    Self::Pow2 {
                        encode_shift,
                        mask,
                        q,
                        ..
                    } => {
                        for value in values.iter_mut() {
                            let (magnitude, is_negative) = lift_centered_from_raw(*value, t, half);
                            assert!(magnitude <= mask);
                            let encoded = magnitude << encode_shift;
                            *value = if is_negative {
                                if encoded.is_zero() {
                                    T::ZERO
                                } else {
                                    q - encoded
                                }
                            } else {
                                encoded
                            };
                        }
                    }
                    Self::NativeScaled { t, .. } => {
                        for value in values.iter_mut() {
                            let (magnitude, is_negative) = lift_centered_from_raw(*value, t, half);
                            assert!(magnitude < t);
                            let encoded = T::div_wide(t >> 1u32, magnitude, t);
                            *value = if is_negative {
                                encoded.wrapping_neg()
                            } else {
                                encoded
                            };
                        }
                    }
                    Self::Scaled { t, q, .. } => {
                        for value in values.iter_mut() {
                            let (magnitude, is_negative) = lift_centered_from_raw(*value, t, half);
                            assert!(magnitude < t);
                            let encoded = mul_div_round(magnitude, q, t);
                            *value = if is_negative {
                                if encoded.is_zero() {
                                    T::ZERO
                                } else {
                                    q - encoded
                                }
                            } else {
                                encoded
                            };
                        }
                    }
                    Self::ScaledNarrow { t, q, .. } => {
                        for value in values.iter_mut() {
                            let (magnitude, is_negative) = lift_centered_from_raw(*value, t, half);
                            assert!(magnitude < t);
                            let encoded = narrow_mul_div_round(magnitude, q, t);
                            *value = if is_negative {
                                if encoded.is_zero() {
                                    T::ZERO
                                } else {
                                    q - encoded
                                }
                            } else {
                                encoded
                            };
                        }
                    }
                }
            }
        }
    }

    /// Encodes `message` as `lift(message) * delta mod q` using the
    /// precomputed Shoup factor (`Scaled`) or a trivial shift (`Pow2`).
    #[inline]
    pub fn encode_value_with_delta<M>(&self, message: M, embedding: PlaintextEmbedding) -> T
    where
        M: TryInto<T>,
    {
        let message = checked_message(message);

        match embedding {
            PlaintextEmbedding::Unsigned => self.encode_delta_magnitude(message),
            PlaintextEmbedding::Centered => {
                let t = self.t();
                let half = centered_half(t);
                let (magnitude, is_negative) = lift_centered_from_raw(message, t, half);
                let encoded = self.encode_delta_magnitude(magnitude);
                if is_negative {
                    self.neg_encoded(encoded)
                } else {
                    encoded
                }
            }
        }
    }

    /// Batch version of [`PlaintextCodec::encode_value_with_delta`]: lifts, encodes with delta, and
    /// adds into `accumulator` modulo the ciphertext modulus.
    #[inline]
    pub fn add_encode_slice_assign_with_delta(
        &self,
        accumulator: &mut [T],
        messages: &[T],
        embedding: PlaintextEmbedding,
    ) {
        assert_eq!(accumulator.len(), messages.len());

        match embedding {
            PlaintextEmbedding::Unsigned => match *self {
                Self::Scaled {
                    delta_factor, q, ..
                }
                | Self::ScaledNarrow {
                    delta_factor, q, ..
                } => {
                    delta_factor.add_factor_mul_slice_assign(accumulator, messages, q);
                }
                Self::NativeScaled { delta, .. } => {
                    for (acc, &message) in accumulator.iter_mut().zip(messages) {
                        Self::reduce_add_native(acc, message.wrapping_mul(delta));
                    }
                }
                Self::NativePow2 {
                    encode_shift, mask, ..
                } => {
                    for (acc, &message) in accumulator.iter_mut().zip(messages) {
                        assert!(message <= mask);
                        Self::reduce_add_native(acc, message << encode_shift);
                    }
                }
                Self::Pow2 {
                    encode_shift,
                    mask,
                    q,
                    ..
                } => {
                    for (acc, &message) in accumulator.iter_mut().zip(messages) {
                        assert!(message <= mask);
                        Self::reduce_add_mod(acc, message << encode_shift, q);
                    }
                }
            },
            PlaintextEmbedding::Centered => {
                let t = self.t();
                let half = centered_half(t);
                match *self {
                    Self::Scaled {
                        delta_factor, q, ..
                    }
                    | Self::ScaledNarrow {
                        delta_factor, q, ..
                    } => {
                        for (acc, &message) in accumulator.iter_mut().zip(messages) {
                            let (magnitude, is_negative) = lift_centered_from_raw(message, t, half);
                            let encoded = delta_factor.factor_mul_modulo(magnitude, q);
                            let encoded = if is_negative && !encoded.is_zero() {
                                q - encoded
                            } else {
                                encoded
                            };
                            Self::reduce_add_mod(acc, encoded, q);
                        }
                    }
                    Self::NativeScaled { delta, .. } => {
                        for (acc, &message) in accumulator.iter_mut().zip(messages) {
                            let (magnitude, is_negative) = lift_centered_from_raw(message, t, half);
                            let encoded = magnitude.wrapping_mul(delta);
                            let encoded = if is_negative {
                                encoded.wrapping_neg()
                            } else {
                                encoded
                            };
                            Self::reduce_add_native(acc, encoded);
                        }
                    }
                    Self::NativePow2 {
                        encode_shift, mask, ..
                    } => {
                        for (acc, &message) in accumulator.iter_mut().zip(messages) {
                            let (magnitude, is_negative) = lift_centered_from_raw(message, t, half);
                            assert!(magnitude <= mask);
                            let encoded = magnitude << encode_shift;
                            let encoded = if is_negative {
                                encoded.wrapping_neg()
                            } else {
                                encoded
                            };
                            Self::reduce_add_native(acc, encoded);
                        }
                    }
                    Self::Pow2 {
                        encode_shift,
                        mask,
                        q,
                        ..
                    } => {
                        for (acc, &message) in accumulator.iter_mut().zip(messages) {
                            let (magnitude, is_negative) = lift_centered_from_raw(message, t, half);
                            assert!(magnitude <= mask);
                            let encoded = magnitude << encode_shift;
                            let encoded = if is_negative && !encoded.is_zero() {
                                q - encoded
                            } else {
                                encoded
                            };
                            Self::reduce_add_mod(acc, encoded, q);
                        }
                    }
                }
            }
        }
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
        self.reduce_add_in_place(accumulator, self.encode_value(message, embedding));
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

        match embedding {
            PlaintextEmbedding::Unsigned => match *self {
                Self::NativePow2 {
                    encode_shift, mask, ..
                } => {
                    for (acc, &message) in accumulator.iter_mut().zip(messages) {
                        let v: T = checked_message(message);
                        assert!(v <= mask);
                        Self::reduce_add_native(acc, v << encode_shift);
                    }
                }
                Self::Pow2 {
                    encode_shift,
                    mask,
                    q,
                    ..
                } => {
                    for (acc, &message) in accumulator.iter_mut().zip(messages) {
                        let v: T = checked_message(message);
                        assert!(v <= mask);
                        Self::reduce_add_mod(acc, v << encode_shift, q);
                    }
                }
                Self::NativeScaled { t, .. } => {
                    for (acc, &message) in accumulator.iter_mut().zip(messages) {
                        let v: T = checked_message(message);
                        assert!(v < t);
                        Self::reduce_add_native(acc, T::div_wide(t >> 1u32, v, t));
                    }
                }
                Self::Scaled { t, q, .. } => {
                    for (acc, &message) in accumulator.iter_mut().zip(messages) {
                        let v: T = checked_message(message);
                        assert!(v < t);
                        Self::reduce_add_mod(acc, mul_div_round(v, q, t), q);
                    }
                }
                Self::ScaledNarrow { t, q, .. } => {
                    for (acc, &message) in accumulator.iter_mut().zip(messages) {
                        let v: T = checked_message(message);
                        assert!(v < t);
                        Self::reduce_add_mod(acc, narrow_mul_div_round(v, q, t), q);
                    }
                }
            },
            PlaintextEmbedding::Centered => {
                let t = self.t();
                let half = centered_half(t);
                match *self {
                    Self::NativePow2 {
                        encode_shift, mask, ..
                    } => {
                        for (acc, &message) in accumulator.iter_mut().zip(messages) {
                            let v: T = checked_message(message);
                            let (magnitude, is_negative) = lift_centered_from_raw(v, t, half);
                            let encoded = {
                                assert!(magnitude <= mask);
                                magnitude << encode_shift
                            };
                            let encoded = if is_negative {
                                encoded.wrapping_neg()
                            } else {
                                encoded
                            };
                            Self::reduce_add_native(acc, encoded);
                        }
                    }
                    Self::Pow2 {
                        encode_shift,
                        mask,
                        q,
                        ..
                    } => {
                        for (acc, &message) in accumulator.iter_mut().zip(messages) {
                            let v: T = checked_message(message);
                            let (magnitude, is_negative) = lift_centered_from_raw(v, t, half);
                            let encoded = {
                                assert!(magnitude <= mask);
                                magnitude << encode_shift
                            };
                            let encoded = if is_negative {
                                if encoded.is_zero() {
                                    T::ZERO
                                } else {
                                    q - encoded
                                }
                            } else {
                                encoded
                            };
                            Self::reduce_add_mod(acc, encoded, q);
                        }
                    }
                    Self::NativeScaled { t, .. } => {
                        for (acc, &message) in accumulator.iter_mut().zip(messages) {
                            let v: T = checked_message(message);
                            let (magnitude, is_negative) = lift_centered_from_raw(v, t, half);
                            let encoded = {
                                assert!(magnitude < t);
                                T::div_wide(t >> 1u32, magnitude, t)
                            };
                            let encoded = if is_negative {
                                encoded.wrapping_neg()
                            } else {
                                encoded
                            };
                            Self::reduce_add_native(acc, encoded);
                        }
                    }
                    Self::Scaled { t, q, .. } => {
                        for (acc, &message) in accumulator.iter_mut().zip(messages) {
                            let v: T = checked_message(message);
                            let (magnitude, is_negative) = lift_centered_from_raw(v, t, half);
                            let encoded = {
                                assert!(magnitude < t);
                                mul_div_round(magnitude, q, t)
                            };
                            let encoded = if is_negative {
                                if encoded.is_zero() {
                                    T::ZERO
                                } else {
                                    q - encoded
                                }
                            } else {
                                encoded
                            };
                            Self::reduce_add_mod(acc, encoded, q);
                        }
                    }
                    Self::ScaledNarrow { t, q, .. } => {
                        for (acc, &message) in accumulator.iter_mut().zip(messages) {
                            let v: T = checked_message(message);
                            let (magnitude, is_negative) = lift_centered_from_raw(v, t, half);
                            let encoded = {
                                assert!(magnitude < t);
                                narrow_mul_div_round(magnitude, q, t)
                            };
                            let encoded = if is_negative {
                                if encoded.is_zero() {
                                    T::ZERO
                                } else {
                                    q - encoded
                                }
                            } else {
                                encoded
                            };
                            Self::reduce_add_mod(acc, encoded, q);
                        }
                    }
                }
            }
        }
    }

    #[inline]
    fn reduce_add_in_place(&self, acc: &mut T, value: T) {
        match *self {
            Self::NativePow2 { .. } | Self::NativeScaled { .. } => {
                Self::reduce_add_native(acc, value)
            }
            Self::Pow2 { q, .. } | Self::Scaled { q, .. } | Self::ScaledNarrow { q, .. } => {
                Self::reduce_add_mod(acc, value, q)
            }
        };
    }

    #[inline]
    fn reduce_add_native(acc: &mut T, value: T) {
        *acc = acc.wrapping_add(value);
    }

    #[inline]
    fn reduce_add_mod(acc: &mut T, value: T, q: T) {
        let old = *acc;
        let sum = old.wrapping_add(value);
        // Since a,b < q < 2^BITS, a+b < 2q. One subtraction of q is
        // enough even when wrapping_add overflows (2q may exceed 2^BITS).
        *acc = if sum < old || sum >= q {
            sum.wrapping_sub(q)
        } else {
            sum
        };
    }

    #[inline]
    fn encode_delta_magnitude(&self, magnitude: T) -> T {
        match *self {
            Self::Scaled {
                delta_factor, q, ..
            }
            | Self::ScaledNarrow {
                delta_factor, q, ..
            } => delta_factor.factor_mul_modulo(magnitude, q),
            Self::NativeScaled { delta, .. } => magnitude.wrapping_mul(delta),
            Self::NativePow2 {
                encode_shift, mask, ..
            }
            | Self::Pow2 {
                encode_shift, mask, ..
            } => {
                assert!(magnitude <= mask);
                magnitude << encode_shift
            }
        }
    }

    #[inline]
    fn neg_encoded(&self, encoded: T) -> T {
        match *self {
            Self::NativePow2 { .. } | Self::NativeScaled { .. } => encoded.wrapping_neg(),
            Self::Pow2 { q, .. } | Self::Scaled { q, .. } | Self::ScaledNarrow { q, .. } => {
                if encoded.is_zero() {
                    T::ZERO
                } else {
                    q - encoded
                }
            }
        }
    }

    #[inline]
    fn encode_unsigned_value(&self, message: T) -> T {
        match *self {
            Self::NativePow2 {
                encode_shift, mask, ..
            }
            | Self::Pow2 {
                encode_shift, mask, ..
            } => {
                assert!(message <= mask);
                message << encode_shift
            }
            Self::NativeScaled { t, .. } => {
                assert!(message < t);
                T::div_wide(t >> 1u32, message, t)
            }
            Self::Scaled { t, q, .. } => {
                assert!(message < t);
                mul_div_round(message, q, t)
            }
            Self::ScaledNarrow { t, q, .. } => {
                assert!(message < t);
                narrow_mul_div_round(message, q, t)
            }
        }
    }

    #[inline]
    fn encode_unsigned_slice_to(&self, messages: &[T], output: &mut [T]) {
        match *self {
            Self::NativePow2 {
                encode_shift, mask, ..
            }
            | Self::Pow2 {
                encode_shift, mask, ..
            } => {
                for (message, output) in messages.iter().zip(output) {
                    assert!(*message <= mask);
                    *output = *message << encode_shift;
                }
            }
            Self::NativeScaled { t, .. } => {
                for (message, output) in messages.iter().zip(output) {
                    assert!(*message < t);
                    *output = T::div_wide(t >> 1u32, *message, t);
                }
            }
            Self::Scaled { t, q, .. } => {
                for (message, output) in messages.iter().zip(output) {
                    assert!(*message < t);
                    *output = mul_div_round(*message, q, t);
                }
            }
            Self::ScaledNarrow { t, q, .. } => {
                for (message, output) in messages.iter().zip(output) {
                    assert!(*message < t);
                    *output = narrow_mul_div_round(*message, q, t);
                }
            }
        }
    }

    #[inline]
    fn encode_unsigned_slice_inplace(&self, values: &mut [T]) {
        match *self {
            Self::NativePow2 {
                encode_shift, mask, ..
            }
            | Self::Pow2 {
                encode_shift, mask, ..
            } => {
                for value in values.iter_mut() {
                    assert!(*value <= mask);
                    *value <<= encode_shift;
                }
            }
            Self::NativeScaled { t, .. } => {
                for value in values.iter_mut() {
                    assert!(*value < t);
                    *value = T::div_wide(t >> 1u32, *value, t);
                }
            }
            Self::Scaled { t, q, .. } => {
                for value in values.iter_mut() {
                    assert!(*value < t);
                    *value = mul_div_round(*value, q, t);
                }
            }
            Self::ScaledNarrow { t, q, .. } => {
                for value in values.iter_mut() {
                    assert!(*value < t);
                    *value = narrow_mul_div_round(*value, q, t);
                }
            }
        }
    }

    #[inline]
    pub fn decode_value<M>(&self, value: T) -> M
    where
        M: TryFrom<T>,
    {
        let decoded = match *self {
            Self::NativePow2 {
                decode_shift, mask, ..
            }
            | Self::Pow2 {
                decode_shift, mask, ..
            } => {
                let temp = value >> decode_shift;
                ((temp + T::ONE) >> 1u32) & mask
            }
            Self::NativeScaled { t, .. } => {
                let mut decoded = value.carrying_mul_hw(t, T::ONE << (T::BITS - 1));
                if decoded >= t {
                    decoded -= t;
                }
                decoded
            }
            Self::Scaled { t, q, .. } => {
                let mut decoded = mul_div_round(value, t, q);
                if decoded >= t {
                    decoded -= t;
                }
                decoded
            }
            Self::ScaledNarrow { t, q, .. } => {
                debug_assert!(value <= q);
                let mut decoded = narrow_mul_div_round(value, t, q);
                if decoded >= t {
                    decoded -= t;
                }
                decoded
            }
        };

        try_from_decoded(decoded)
    }

    #[inline]
    pub fn decode_slice_inplace(&self, values: &mut [T]) {
        match *self {
            Self::NativePow2 {
                decode_shift, mask, ..
            }
            | Self::Pow2 {
                decode_shift, mask, ..
            } => {
                for value in values {
                    let temp = *value >> decode_shift;
                    *value = ((temp + T::ONE) >> 1u32) & mask;
                }
            }
            Self::NativeScaled { t, .. } => {
                for value in values {
                    let mut decoded = value.carrying_mul_hw(t, T::ONE << (T::BITS - 1));
                    if decoded >= t {
                        decoded -= t;
                    }
                    *value = decoded;
                }
            }
            Self::Scaled { t, q, .. } => {
                for value in values {
                    let mut decoded = mul_div_round(*value, t, q);
                    if decoded >= t {
                        decoded -= t;
                    }
                    *value = decoded;
                }
            }
            Self::ScaledNarrow { t, q, .. } => {
                for value in values {
                    debug_assert!(*value <= q);
                    let mut decoded = narrow_mul_div_round(*value, t, q);
                    if decoded >= t {
                        decoded -= t;
                    }
                    *value = decoded;
                }
            }
        }
    }

    #[inline]
    pub fn decode_slice_to<M>(&self, input: &[T], output: &mut [M])
    where
        M: TryFrom<T>,
    {
        assert_eq!(input.len(), output.len());

        match *self {
            Self::NativePow2 {
                decode_shift, mask, ..
            }
            | Self::Pow2 {
                decode_shift, mask, ..
            } => {
                for (&value, output) in input.iter().zip(output) {
                    let temp = value >> decode_shift;
                    *output = try_from_decoded(((temp + T::ONE) >> 1u32) & mask);
                }
            }
            Self::NativeScaled { t, .. } => {
                for (&value, output) in input.iter().zip(output) {
                    let mut decoded = value.carrying_mul_hw(t, T::ONE << (T::BITS - 1));
                    if decoded >= t {
                        decoded -= t;
                    }
                    *output = try_from_decoded(decoded);
                }
            }
            Self::Scaled { t, q, .. } => {
                for (&value, output) in input.iter().zip(output) {
                    let mut decoded = mul_div_round(value, t, q);
                    if decoded >= t {
                        decoded -= t;
                    }
                    *output = try_from_decoded(decoded);
                }
            }
            Self::ScaledNarrow { t, q, .. } => {
                for (&value, output) in input.iter().zip(output) {
                    debug_assert!(value <= q);
                    let mut decoded = narrow_mul_div_round(value, t, q);
                    if decoded >= t {
                        decoded -= t;
                    }
                    *output = try_from_decoded(decoded);
                }
            }
        }
    }

    #[inline]
    fn t(&self) -> T {
        match *self {
            Self::NativePow2 { mask, .. } | Self::Pow2 { mask, .. } => mask + T::ONE,
            Self::NativeScaled { t, .. }
            | Self::Scaled { t, .. }
            | Self::ScaledNarrow { t, .. } => t,
        }
    }
}
