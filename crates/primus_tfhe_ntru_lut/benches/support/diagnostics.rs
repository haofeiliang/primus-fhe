//! Opt-in resource/phase reporting for the existing lookup fixture.
//! `PRIMUS_LUT_DIAGNOSTICS=1` with Criterion `--test` runs this report without
//! statistical sampling. The ordinary path neither counts nor prints resources.

use primus_test_allocations::measure;

/// One workload label and its explicit diagnostic switch; never used in b.iter.
pub(super) struct Diagnostics<'a> {
    name: &'a str,
    enabled: bool,
}

impl<'a> Diagnostics<'a> {
    pub(super) fn new(name: &'a str) -> Self {
        Self {
            name,
            enabled: std::env::var_os("PRIMUS_LUT_DIAGNOSTICS").is_some_and(|value| value == "1"),
        }
    }

    /// Report retained requested heap, excluding allocator overhead and RSS.
    /// The returned object stays alive after measurement; temporary allocations cancel.
    pub(super) fn setup<R>(&self, role: &str, create: impl FnOnce() -> R) -> R {
        if !self.enabled {
            return create();
        }
        let (result, allocation) = measure(create);
        eprintln!(
            "memory,{}/{role},{}",
            self.name,
            allocation.allocated_bytes - allocation.released_bytes
        );
        result
    }

    /// The existing untimed result probe also checks online allocations in diagnostic mode.
    pub(super) fn evaluate(&self, run: impl FnOnce()) {
        if self.enabled {
            let ((), online) = measure(run);
            assert_eq!(online.count, 0);
            eprintln!("online_allocations,{},{}", self.name, online.count);
        } else {
            run();
        }
    }

    /// The iterator decrypts phases lazily, only in diagnostic mode. Expected values
    /// are raw two-bit digits; this fixture uses q=2^24 and padded t=8 in both backends.
    pub(super) fn phases(&self, phases: impl Iterator<Item = (u64, u64)>) {
        if !self.enabled {
            return;
        }
        let max_error = phases
            .map(|(phase, digit)| {
                let distance = phase.abs_diff(digit * (1 << 21));
                distance.min((1 << 24) - distance)
            })
            .max()
            .unwrap_or(0);
        eprintln!("phase_error_max,{},{}", self.name, max_error);
    }
}
