//! Arithmetic selected once for a fixed source/target modulus pair.
use crate::{BarrettModulus, CompactModulus, NativeModulus, PowOf2Modulus, UintModulus};
use primus_integer::FheUint;
use primus_reduce::{Modulus, PrepareModulusSwitch, PreparedModulusSwitch};

/// Prepared nearest rounding between two moduli of the same coefficient type.
/// Construction accepts native or explicit moduli. Execution needs only source
/// residues; it returns canonical target residues and allocates nothing.
#[derive(Clone, Copy, Debug)]
pub struct ModulusSwitch<T: FheUint> {
    kernel: Kernel<T>,
}

/// Strategies for `round(x * p / q) mod p`, where `q` is the source modulus,
/// `p` the target modulus, and `w = T::BITS`. Rounding uses ties upward.
/// Native moduli equal `2^w`; explicit moduli fit in `T`.
#[derive(Clone, Copy, Debug)]
enum Kernel<T> {
    /// `q = p`: the canonical input is already the output.
    Identity,
    /// `q = 2^a > p = 2^b`: rounded right shift by `a - b`.
    /// `mask = p - 1` wraps a rounded endpoint of `p` back to zero.
    BinaryDown { shift: u32, mask: T },
    /// `p = scale * q`: exact expansion by an integer factor, without rounding.
    Multiply(T),
    /// `p = 2^shift * q`: exact expansion by a left shift, including native `p`.
    MultiplyShift(u32),
    /// `p > q`, with `p = quotient * q + remainder`: compute
    /// `x * quotient + round(x * remainder / q)`. The biased remainder product
    /// fits in `T`, avoiding wide arithmetic even when `p` is native.
    Decomposed {
        source: T,
        quotient: T,
        remainder: T,
    },
    /// Explicit `q = scale * p`: rounded division by the integer ratio,
    /// followed by wrapping a rounded endpoint of `p` to zero.
    Divide { scale: T, target: T },
    /// Explicit `q = 2^shift * p`: rounded right shift when the moduli are
    /// not both powers of two; endpoint wrapping uses `p` instead of a mask.
    DivideShift { shift: u32, target: T },
    /// Native `q = 2^w` to explicit `p`: take the high word of
    /// `x * p + 2^(w - 1)`, then wrap the rounded endpoint.
    Native { target: T },
    /// Explicit `q = 2^source_log` to explicit `p`: form the biased two-word
    /// product, then shift across both words instead of dividing by `q`.
    PowerOfTwo { source_log: u32, target: T },
    /// General explicit pair with `q * p` fitting in `T`: divide the one-word
    /// product `x * p` by `q` and use its remainder to round.
    Narrow { source: T, target: T },
    /// General explicit pair requiring wide arithmetic: divide the two-word
    /// numerator `x * p + floor(q / 2)` by `q`, then wrap the rounded endpoint.
    Wide { source: T, target: T },
    /// Explicit `q` to native `p = 2^w`: divide the two-word numerator
    /// `x * 2^w + floor(q / 2)` by `q` when no expansion shortcut applies.
    ToNative { source: T },
}

impl<T: FheUint> ModulusSwitch<T> {
    /// Prepares `round(value * target / source) mod target`, with ties upward.
    ///
    /// # Panics
    /// Panics if either explicit modulus is less than two.
    #[must_use]
    pub fn new<S: Modulus<ValueT = T>, D: Modulus<ValueT = T>>(source: S, target: D) -> Self {
        let source = source.explicit_value();
        let target = target.explicit_value();
        assert!(source.is_none_or(|q| q >= T::TWO), "invalid source modulus");
        assert!(target.is_none_or(|q| q >= T::TWO), "invalid target modulus");
        Self {
            kernel: prepare(source, target),
        }
    }
}

fn binary_log<T: FheUint>(modulus: Option<T>) -> Option<u32> {
    match modulus {
        None => Some(T::BITS),
        Some(q) => q.is_power_of_two().then(|| q.trailing_zeros()),
    }
}

/// Both modulus values are valid; None represents the native modulus.
fn prepare<T: FheUint>(source: Option<T>, target: Option<T>) -> Kernel<T> {
    if source == target {
        return Kernel::Identity;
    }
    if let (Some(source_log), Some(target_log)) = (binary_log(source), binary_log(target)) {
        return if target_log > source_log {
            // Widening is exact; no rounding, right shift or mask is needed.
            Kernel::MultiplyShift(target_log - source_log)
        } else {
            Kernel::BinaryDown {
                shift: source_log - target_log,
                mask: T::MAX >> (T::BITS - target_log),
            }
        };
    }

    if let Some(source) = source {
        if target.is_none_or(|q| q > source) {
            let (quotient, remainder) = match target {
                Some(target) => target.div_rem(source),
                None => {
                    let quotient = T::div_wide(T::ZERO, T::ONE, source);
                    (
                        quotient,
                        T::ZERO.wrapping_sub(quotient.wrapping_mul(source)),
                    )
                }
            };
            if remainder == T::ZERO {
                return if quotient.is_power_of_two() {
                    Kernel::MultiplyShift(quotient.trailing_zeros())
                } else {
                    Kernel::Multiply(quotient)
                };
            }
            // target = quotient*source + remainder. For x < source, both
            // terms and their sum are canonical; only the biased remainder
            // product needs a width check before selecting this kernel.
            if (source - T::ONE)
                .checked_mul(remainder)
                .and_then(|p| p.checked_add(source >> 1u32))
                .is_some()
            {
                return Kernel::Decomposed {
                    source,
                    quotient,
                    remainder,
                };
            }
        } else if let Some(target) = target {
            let (scale, remainder) = source.div_rem(target);
            if remainder == T::ZERO {
                return if scale.is_power_of_two() {
                    Kernel::DivideShift {
                        shift: scale.trailing_zeros(),
                        target,
                    }
                } else {
                    Kernel::Divide { scale, target }
                };
            }
        }
    }
    match (source, target) {
        (None, Some(target)) => Kernel::Native { target },
        (Some(source), None) => Kernel::ToNative { source },
        (Some(source), Some(target)) if source.is_power_of_two() => Kernel::PowerOfTwo {
            source_log: source.trailing_zeros(),
            target,
        },
        (Some(source), Some(target)) if source.checked_mul(target).is_some() => {
            Kernel::Narrow { source, target }
        }
        (Some(source), Some(target)) => Kernel::Wide { source, target },
        (None, None) => Kernel::Identity,
    }
}

impl<T: FheUint> PreparedModulusSwitch for ModulusSwitch<T> {
    type ValueT = T;

    #[inline]
    fn switch(&self, value: T) -> T {
        let mut result = T::ZERO;
        self.switch_map(core::iter::once((value, &mut result)), |value, out| {
            *out = value
        });
        result
    }

    #[inline]
    fn switch_map<I, P, F>(&self, input: I, output: F)
    where
        I: Iterator<Item = (T, P)>,
        F: FnMut(T, P),
    {
        // Resolve the complete ratio strategy before entering the iterator.
        match self.kernel {
            Kernel::Identity => map(input, output, |x| x),
            Kernel::BinaryDown { shift, mask } => map(input, output, |x| {
                ((x >> shift) + ((x >> (shift - 1)) & T::ONE)) & mask
            }),
            Kernel::Multiply(scale) => map(input, output, |x| x * scale),
            Kernel::MultiplyShift(shift) => map(input, output, |x| x << shift),
            Kernel::Decomposed {
                source,
                quotient,
                remainder,
            } => map(input, output, |x| {
                x * quotient + (x * remainder + (source >> 1u32)) / source
            }),
            Kernel::Divide { scale, target } => map(input, output, |x| {
                let (quotient, remainder) = x.div_rem(scale);
                canonical(quotient + T::as_from(remainder >= half_ceil(scale)), target)
            }),
            Kernel::DivideShift { shift, target } => map(input, output, |x| {
                canonical((x >> shift) + ((x >> (shift - 1)) & T::ONE), target)
            }),
            Kernel::Native { target } => map(input, output, |x| {
                canonical(x.carrying_mul_hw(target, T::ONE << (T::BITS - 1)), target)
            }),
            Kernel::PowerOfTwo { source_log, target } => map(input, output, |x| {
                // 1 <= source_log < BITS; the rounded quotient fits T.
                let (lo, hi) = x.carrying_mul(target, T::ONE << (source_log - 1));
                canonical((lo >> source_log) | (hi << (T::BITS - source_log)), target)
            }),
            Kernel::Narrow { source, target } => map(input, output, |x| {
                let (quotient, remainder) = (x * target).div_rem(source);
                canonical(
                    quotient + T::as_from(remainder >= half_ceil(source)),
                    target,
                )
            }),
            Kernel::Wide { source, target } => map(input, output, |x| {
                let (lo, hi) = x.carrying_mul(target, source >> 1u32);
                canonical(T::div_wide(lo, hi, source), target)
            }),
            Kernel::ToNative { source } => map(input, output, |x| {
                // x < source makes the high limb valid for div_wide.
                T::div_wide(source >> 1u32, x, source)
            }),
        }
    }
}

#[inline]
fn half_ceil<T: FheUint>(value: T) -> T {
    (value >> 1u32) + (value & T::ONE)
}
#[inline]
fn canonical<T: FheUint>(value: T, target: T) -> T {
    if value >= target {
        value - target
    } else {
        value
    }
}
#[inline]
fn map<T, I, P, F, K>(input: I, mut output: F, kernel: K)
where
    I: Iterator<Item = (T, P)>,
    F: FnMut(T, P),
    K: Fn(T) -> T,
{
    for (value, payload) in input {
        output(kernel(value), payload);
    }
}

macro_rules! impl_prepare {
    ($($modulus:ident),+ $(,)?) => {$(
        impl<T: FheUint> PrepareModulusSwitch for $modulus<T> {
            type Prepared = ModulusSwitch<T>;
            #[inline]
            fn prepare_switch_to<D: Modulus<ValueT = T>>(self, target: D) -> Self::Prepared {
                ModulusSwitch::new(self, target)
            }
        }
    )+};
}
impl_prepare!(
    NativeModulus,
    PowOf2Modulus,
    UintModulus,
    CompactModulus,
    BarrettModulus
);
