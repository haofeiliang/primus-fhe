//! NTRU lookup stages and complete lookup; setup, validation and allocation are untimed.
//! cargo bench -p primus_tfhe_ntru_lut --bench pipeline
//! SIMD: cargo +nightly bench -p primus_tfhe_ntru_lut --bench pipeline --features simd
//!
//! Compile the real evaluator sources into this benchmark to time private stages
//! without adding public benchmark hooks or duplicating the selection algorithms.
//! Public accessors unused by this standalone harness may be dead code here.
use criterion::{Criterion, criterion_group, criterion_main};
use std::time::Duration;

#[global_allocator]
static ALLOCATOR: primus_test_allocations::CountingAllocator =
    primus_test_allocations::CountingAllocator;

#[path = "../src/lookup_table.rs"]
#[allow(dead_code)]
mod lookup_table;
use lookup_table::{HighPrecisionLookupTable, LookupTableConfig, LookupTableError};
mod support;

#[path = "support/fourier.rs"]
mod fourier;
#[path = "support/ntt.rs"]
mod ntt;

fn pipeline(c: &mut Criterion) {
    ntt::benchmark(c);
    fourier::benchmark::<primus_fft::RustFftTable>(c, "rustfft");
    fourier::benchmark::<primus_fft::TfheFftTable>(c, "tfhe_fft");
}
criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20)
        .warm_up_time(Duration::from_millis(300)).measurement_time(Duration::from_secs(1));
    targets = pipeline
}
criterion_main!(benches);
