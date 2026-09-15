//! Prepared nearest rounding between a fixed pair of moduli.
use crate::Modulus;
use primus_integer::FheUint;

/// Prepares a conversion from this modulus to a fixed target modulus.
/// Included in [`crate::RingContext`], but also usable without ring arithmetic.
/// Target-dependent arithmetic is selected during preparation, before
/// coefficient processing; the returned conversion owns its execution state.
pub trait PrepareModulusSwitch: Modulus {
    /// Reusable, allocation-free conversion parameters.
    type Prepared: PreparedModulusSwitch<ValueT = Self::ValueT>;

    /// Prepares `round(value * target / source) mod target`, where `self`
    /// supplies the source. Rounding is to nearest, with ties upward.
    /// Both moduli must represent integers at least two; either may be native.
    #[must_use]
    fn prepare_switch_to<M: Modulus<ValueT = Self::ValueT>>(self, target: M) -> Self::Prepared;
}

/// A conversion whose source, target and rounding strategy are already fixed.
/// Results are canonical target residues, including endpoint wrap to zero.
pub trait PreparedModulusSwitch: Copy + core::fmt::Debug {
    /// Coefficient type shared by the source and target moduli.
    type ValueT: FheUint;

    /// Converts one canonical source residue without allocating.
    ///
    /// # Correctness
    /// `value` must be in `[0, source)` for the source used during preparation.
    #[must_use]
    fn switch(&self, value: Self::ValueT) -> Self::ValueT;

    /// Converts an iterator while carrying each item's payload to `output`.
    /// This permits fused sign handling, output writes and subsequent arithmetic
    /// without an intermediate buffer. Implementations can select a kernel once
    /// for the whole iterator; the default uses the scalar operation.
    /// If the iterator or callback panics, earlier callback effects remain.
    ///
    /// # Correctness
    /// Every coefficient must satisfy [`Self::switch`]'s source range.
    #[inline]
    fn switch_map<I, P, F>(&self, input: I, mut output: F)
    where
        I: Iterator<Item = (Self::ValueT, P)>,
        F: FnMut(Self::ValueT, P),
    {
        for (value, payload) in input {
            output(self.switch(value), payload);
        }
    }
}
