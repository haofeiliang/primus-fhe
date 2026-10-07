//! Shared Criterion policy and case identities; numerical calls stay in backend modules.

use std::time::Duration;

use criterion::{BenchmarkGroup, BenchmarkId, Criterion, SamplingMode, measurement::WallTime};

pub mod metadata;

/// All concrete backends register into the operation's single Criterion group.
pub type Group<'a> = BenchmarkGroup<'a, WallTime>;

/// One explicit workload identity, shared by Criterion and numerical metadata.
/// Geometry belongs in metadata; the workload labels distinguish retained cases.
pub struct Case<'a> {
    pub family: &'a str,
    pub engine: &'a str,
    pub word_bits: u32,
    pub workload: String,
}

impl<'a> Case<'a> {
    #[must_use]
    pub fn new(
        family: &'a str,
        engine: &'a str,
        word_bits: u32,
        workload: impl Into<String>,
    ) -> Self {
        Self {
            family,
            engine,
            word_bits,
            workload: workload.into(),
        }
    }

    /// Places the mathematical workload before family, transform and word width.
    #[must_use]
    pub fn id(&self) -> BenchmarkId {
        BenchmarkId::new(
            &self.workload,
            format!("{}/{}/u{}", self.family, self.engine, self.word_bits),
        )
    }

    /// Exact Criterion full ID used to join metadata and result files.
    #[must_use]
    pub fn full_id(&self, operation: &str) -> String {
        format!(
            "{operation}/{}/{}/{}/u{}",
            self.workload, self.family, self.engine, self.word_bits
        )
    }
}

/// Uniform defaults, overridable with Criterion's native command-line options.
/// Filtering stays inside Criterion: --list never invokes a fixture callback.
pub fn run(operation: &str, register: impl FnOnce(&mut Group<'_>)) {
    if std::env::var_os("PRIMUS_LUT_DIAGNOSTICS").is_some_and(|v| v == "1") {
        assert!(
            std::env::args().any(|arg| arg == "--test"),
            "LUT resource diagnostics require --test"
        );
    }
    let mut criterion = Criterion::default()
        .sample_size(30)
        .warm_up_time(Duration::from_secs(3))
        .measurement_time(Duration::from_secs(5))
        .configure_from_args();
    let mut group = criterion.benchmark_group(operation);
    group.sampling_mode(SamplingMode::Flat);
    register(&mut group);
    group.finish();
    criterion.final_summary();
}
