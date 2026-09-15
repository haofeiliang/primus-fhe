//! Batch decoding shared by codecs holding a prepared q-to-t switch.
use primus_reduce::PreparedModulusSwitch;

#[inline]
pub(super) fn assign<S>(switch: &S, values: &mut [S::ValueT])
where
    S: PreparedModulusSwitch,
{
    switch.switch_map(values.iter_mut().map(|out| (*out, out)), |value, out| {
        *out = value
    });
}

/// Canonical inputs are required. Length is checked before writing.
#[inline]
pub(super) fn to<S>(switch: &S, input: &[S::ValueT], output: &mut [S::ValueT])
where
    S: PreparedModulusSwitch,
{
    assert_eq!(input.len(), output.len(), "decoding slice length mismatch");
    switch.switch_map(input.iter().copied().zip(output), |value, out| *out = value);
}
