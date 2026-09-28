//! Batch decoding shared by codecs holding a prepared q-to-t switch.
use primus_integer::FheUint;
use primus_reduce::ModulusSwitch;

#[inline]
pub(super) fn assign<T: FheUint>(switch: &ModulusSwitch<T>, values: &mut [T]) {
    switch.switch_map(values.iter_mut().map(|out| (*out, out)), |value, out| {
        *out = value
    });
}

/// Canonical inputs are required. Length is checked before writing.
#[inline]
pub(super) fn to<T: FheUint>(switch: &ModulusSwitch<T>, input: &[T], output: &mut [T]) {
    assert_eq!(input.len(), output.len(), "decoding slice length mismatch");
    switch.switch_map(input.iter().copied().zip(output), |value, out| *out = value);
}
