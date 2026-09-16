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
enum Kernel<T: FheUint> {
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
    /// Compact explicit `q` to explicit `p`: divide the biased two-word
    /// product using `floor(2^(2w) / q)` and one exact quotient correction.
    Barrett {
        source: BarrettModulus<T>,
        target: T,
    },
    /// Compact explicit pair whose biased numerator fits one word: the high
    /// reciprocal limb `floor(2^w/q)` suffices for an estimate within one.
    BarrettNarrow { source: T, reciprocal: T, target: T },
    /// Compact explicit `q` to native `p`, using the same reciprocal quotient.
    BarrettToNative { source: BarrettModulus<T> },
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
        Self {
            kernel: prepare(source, target, None),
        }
    }
}

fn binary_log<T: FheUint>(modulus: Option<T>) -> Option<u32> {
    match modulus {
        None => Some(T::BITS),
        Some(q) => q.is_power_of_two().then(|| q.trailing_zeros()),
    }
}

/// None represents the native modulus. Reuse a source Barrett context when
/// available; other source types only construct one if the chosen kernel needs it.
/// When supplied, `barrett` must represent `source`.
fn prepare<T: FheUint>(
    source: Option<T>,
    target: Option<T>,
    barrett: Option<BarrettModulus<T>>,
) -> Kernel<T> {
    assert!(source.is_none_or(|q| q >= T::TWO), "invalid source modulus");
    assert!(target.is_none_or(|q| q >= T::TWO), "invalid target modulus");
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
            // Preserve a binary divisor as a shift, even when remainder
            // decomposition could fit its numerator in one word.
            if source.is_power_of_two()
                && let Some(target) = target
            {
                return Kernel::PowerOfTwo {
                    source_log: source.trailing_zeros(),
                    target,
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
    if let Some(source) = source.filter(|q| q.leading_zeros() > 1 && !q.is_power_of_two()) {
        // Keep the exact-ratio and remainder-decomposition shortcuts above.
        let source = barrett.unwrap_or_else(|| BarrettModulus::new_unchecked(source));
        return match target {
            Some(target)
                if (source.value() - T::ONE)
                    .checked_mul(target)
                    .and_then(|x| x.checked_add(source.value() >> 1u32))
                    .is_some() =>
            {
                Kernel::BarrettNarrow {
                    source: source.value(),
                    reciprocal: source.ratio()[1],
                    target,
                }
            }
            Some(target) => Kernel::Barrett { source, target },
            None => Kernel::BarrettToNative { source },
        };
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
            Kernel::Barrett { source, target } => map(input, output, |x| {
                let (lo, hi) = x.carrying_mul(target, source.value() >> 1u32);
                canonical(barrett_quotient(lo, hi, source), target)
            }),
            Kernel::BarrettNarrow {
                source,
                reciprocal,
                target,
            } => map(input, output, |x| {
                let numerator = x * target + (source >> 1u32);
                let quotient = numerator.widening_mul_hw(reciprocal);
                let remainder = numerator - quotient * source;
                canonical(quotient + T::as_from(remainder >= source), target)
            }),
            Kernel::BarrettToNative { source } => map(input, output, |x| {
                barrett_quotient(source.value() >> 1u32, x, source)
            }),
            Kernel::ToNative { source } => map(input, output, |x| {
                // x < source makes the high limb valid for div_wide.
                T::div_wide(source >> 1u32, x, source)
            }),
        }
    }
}

/// For `n = hi*B + lo < q*B` and `q < B/4`, returns `floor(n/q)`.
/// With `mu = floor(B²/q)`, `floor(n*mu/B²)` underestimates by at most one.
/// The quotient fits one word; the residual is below `2q < B`, so its low
/// limb suffices for the exact correction, including when `n` spans two words.
#[inline]
fn barrett_quotient<T: FheUint>(lo: T, hi: T, source: BarrettModulus<T>) -> T {
    let [r0, r1] = source.ratio();
    let ah = lo.widening_mul_hw(r0);
    let b = lo.carrying_mul(r1, ah);
    let c = hi.widening_mul(r0);
    let upper = b.1.carrying_add(c.1, b.0.overflowing_add(c.0).1).0;
    let quotient = hi.wrapping_mul(r1).wrapping_add(upper);
    let remainder = lo.wrapping_sub(quotient.wrapping_mul(source.value()));
    quotient + T::as_from(remainder >= source.value())
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
impl_prepare!(NativeModulus, PowOf2Modulus, UintModulus, CompactModulus);

impl<T: FheUint> PrepareModulusSwitch for BarrettModulus<T> {
    type Prepared = ModulusSwitch<T>;

    #[inline]
    fn prepare_switch_to<D: Modulus<ValueT = T>>(self, target: D) -> Self::Prepared {
        ModulusSwitch {
            kernel: prepare(Some(self.value()), target.explicit_value(), Some(self)),
        }
    }
}
