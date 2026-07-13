use primus_factor::{FactorMul, FactorSliceOps, ShoupFactor};
use primus_integer::FheUint;
use primus_modulus::{
    PowOf2Modulus,
    common::uint::{reduce_add_assign, reduce_neg},
};
use primus_reduce::{ReduceAddAssign, ReduceNeg};

use super::helpers::{mul_div_round, narrow_mul_div_round};

#[derive(Clone, Copy, Debug)]
pub(super) enum CodecStrategy<T: FheUint> {
    NativePow2(NativePow2Codec<T>),
    ExplicitPow2(ExplicitPow2Codec<T>),
    NativeScaled(NativeScaledCodec<T>),
    ExplicitScaled(ExplicitScaledCodec<T>),
}

#[derive(Clone, Copy, Debug)]
pub(super) struct NativePow2Codec<T: FheUint> {
    pub(super) encode_shift: u32,
    pub(super) decode_shift: u32,
    pub(super) plain_mask: T,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ExplicitPow2Codec<T: FheUint> {
    pub(super) encode_shift: u32,
    pub(super) decode_shift: u32,
    pub(super) plain_mask: T,
    pub(super) modulus: PowOf2Modulus<T>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct NativeScaledCodec<T: FheUint> {
    pub(super) delta: T,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ExplicitScaledCodec<T: FheUint> {
    pub(super) q: T,
    pub(super) delta_factor: ShoupFactor<T>,
    pub(super) arithmetic: ScaledArithmetic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ScaledArithmetic {
    Narrow,
    Wide,
}

macro_rules! dispatch_strategy {
    ($strategy:expr, $codec:ident => $body:expr) => {
        match $strategy {
            CodecStrategy::NativePow2($codec) => $body,
            CodecStrategy::ExplicitPow2($codec) => $body,
            CodecStrategy::NativeScaled($codec) => $body,
            CodecStrategy::ExplicitScaled($codec) => $body,
        }
    };
}

pub(super) use dispatch_strategy;

impl<T: FheUint> NativePow2Codec<T> {
    #[inline]
    pub(super) fn encode_exact(&self, magnitude: T, _t: T) -> T {
        assert!(magnitude <= self.plain_mask);
        magnitude << self.encode_shift
    }

    #[inline]
    pub(super) fn encode_delta(&self, magnitude: T, t: T) -> T {
        self.encode_exact(magnitude, t)
    }

    #[inline]
    pub(super) fn add_delta_slice_assign(&self, accumulator: &mut [T], messages: &[T], t: T) {
        for (accumulator, &message) in accumulator.iter_mut().zip(messages) {
            let encoded = self.encode_delta(message, t);
            self.add_assign(accumulator, encoded);
        }
    }

    #[inline]
    pub(super) fn neg(&self, encoded: T) -> T {
        encoded.wrapping_neg()
    }

    #[inline]
    pub(super) fn add_assign(&self, accumulator: &mut T, encoded: T) {
        *accumulator = accumulator.wrapping_add(encoded);
    }

    #[inline]
    pub(super) fn decode(&self, encoded: T, _t: T) -> T {
        let temp = encoded >> self.decode_shift;
        ((temp + T::ONE) >> 1u32) & self.plain_mask
    }
}

impl<T: FheUint> ExplicitPow2Codec<T> {
    #[inline]
    pub(super) fn encode_exact(&self, magnitude: T, _t: T) -> T {
        assert!(magnitude <= self.plain_mask);
        magnitude << self.encode_shift
    }

    #[inline]
    pub(super) fn encode_delta(&self, magnitude: T, t: T) -> T {
        self.encode_exact(magnitude, t)
    }

    #[inline]
    pub(super) fn add_delta_slice_assign(&self, accumulator: &mut [T], messages: &[T], t: T) {
        for (accumulator, &message) in accumulator.iter_mut().zip(messages) {
            let encoded = self.encode_delta(message, t);
            self.add_assign(accumulator, encoded);
        }
    }

    #[inline]
    pub(super) fn neg(&self, encoded: T) -> T {
        self.modulus.reduce_neg(encoded)
    }

    #[inline]
    pub(super) fn add_assign(&self, accumulator: &mut T, encoded: T) {
        self.modulus.reduce_add_assign(accumulator, encoded);
    }

    #[inline]
    pub(super) fn decode(&self, encoded: T, _t: T) -> T {
        let temp = encoded >> self.decode_shift;
        ((temp + T::ONE) >> 1u32) & self.plain_mask
    }
}

impl<T: FheUint> NativeScaledCodec<T> {
    #[inline]
    pub(super) fn encode_exact(&self, magnitude: T, t: T) -> T {
        assert!(magnitude < t);
        T::div_wide(t >> 1u32, magnitude, t)
    }

    #[inline]
    pub(super) fn encode_delta(&self, magnitude: T, _t: T) -> T {
        magnitude.wrapping_mul(self.delta)
    }

    #[inline]
    pub(super) fn add_delta_slice_assign(&self, accumulator: &mut [T], messages: &[T], _t: T) {
        for (accumulator, &message) in accumulator.iter_mut().zip(messages) {
            *accumulator = accumulator.wrapping_add(message.wrapping_mul(self.delta));
        }
    }

    #[inline]
    pub(super) fn neg(&self, encoded: T) -> T {
        encoded.wrapping_neg()
    }

    #[inline]
    pub(super) fn add_assign(&self, accumulator: &mut T, encoded: T) {
        *accumulator = accumulator.wrapping_add(encoded);
    }

    #[inline]
    pub(super) fn decode(&self, encoded: T, t: T) -> T {
        let mut decoded = encoded.carrying_mul_hw(t, T::ONE << (T::BITS - 1));
        if decoded >= t {
            decoded -= t;
        }
        decoded
    }
}

impl<T: FheUint> ExplicitScaledCodec<T> {
    #[inline]
    pub(super) fn encode_exact(&self, magnitude: T, t: T) -> T {
        assert!(magnitude < t);
        match self.arithmetic {
            ScaledArithmetic::Narrow => narrow_mul_div_round(magnitude, self.q, t),
            ScaledArithmetic::Wide => mul_div_round(magnitude, self.q, t),
        }
    }

    #[inline]
    pub(super) fn encode_delta(&self, magnitude: T, _t: T) -> T {
        self.delta_factor.factor_mul_modulo(magnitude, self.q)
    }

    #[inline]
    pub(super) fn add_delta_slice_assign(&self, accumulator: &mut [T], messages: &[T], _t: T) {
        self.delta_factor
            .add_factor_mul_slice_assign(accumulator, messages, self.q);
    }

    #[inline]
    pub(super) fn neg(&self, encoded: T) -> T {
        reduce_neg(self.q, encoded)
    }

    #[inline]
    pub(super) fn add_assign(&self, accumulator: &mut T, encoded: T) {
        reduce_add_assign(self.q, accumulator, encoded);
    }

    #[inline]
    pub(super) fn decode(&self, encoded: T, t: T) -> T {
        if self.arithmetic == ScaledArithmetic::Narrow {
            debug_assert!(encoded <= self.q);
        }

        let mut decoded = match self.arithmetic {
            ScaledArithmetic::Narrow => narrow_mul_div_round(encoded, t, self.q),
            ScaledArithmetic::Wide => mul_div_round(encoded, t, self.q),
        };
        if decoded >= t {
            decoded -= t;
        }
        decoded
    }
}
