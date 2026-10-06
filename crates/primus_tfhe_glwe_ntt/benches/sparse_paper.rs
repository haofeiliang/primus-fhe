//! Explicit paper-shaped sparse PBS comparison; parameters and boundaries live in `paper`.
//! Run: cargo bench -p primus_tfhe_glwe_ntt --bench sparse_paper -- --list

use criterion::{criterion_group, criterion_main};

#[global_allocator]
static ALLOCATOR: primus_test_allocations::CountingAllocator =
    primus_test_allocations::CountingAllocator;

mod paper;

criterion_group!(benches, paper::benchmark);
criterion_main!(benches);
