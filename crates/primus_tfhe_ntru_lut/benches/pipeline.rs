//! Public high-precision lookup: 8 two-bit input/output chunks, d=5, n800/h32/N1024.
//! `create_lut_and_drop` measures public LUT allocation, filling and destruction.
//! `evaluate` measures one homomorphic lookup producing all output chunks;
//! keys, public LUT creation, encryption and reusable buffers are untimed.
//! Classic/sparse pairs use the same fixed-weight client and independently seeded inputs.
//! IDs without a workload suffix use the polynomial example; `dense_seed42` adds a fixed dense
//! mapping to distinguish general evaluation costs from repeated-subtable gains.
//! `shared_middle_chunk` exercises cross-output sharing and skipped selectors.
//! No production-source copies or private-stage hooks are used.
//! Run: cargo bench -p primus_tfhe_ntru_lut --bench pipeline --features ntt,rustfft,tfhe-fft

use criterion::{Criterion, criterion_group, criterion_main};

#[global_allocator]
static ALLOCATOR: primus_test_allocations::CountingAllocator =
    primus_test_allocations::CountingAllocator;

mod support;
use support::{fourier, ntt};

// Keep u64 NTT and one primary FFT engine; creation is measured once per modulus.
fn pipeline(c: &mut Criterion) {
    ntt::benchmark::<u64, primus_ntt::U64NttTable>(c);
    #[cfg(feature = "rustfft")]
    fourier::benchmark::<u64, primus_fft::RustFftTable>(c, "rustfft");
    #[cfg(all(not(feature = "rustfft"), feature = "tfhe-fft"))]
    fourier::benchmark::<u64, primus_fft::TfheFftTable>(c, "tfhe_fft");
}

criterion_group!(benches, pipeline);
criterion_main!(benches);
