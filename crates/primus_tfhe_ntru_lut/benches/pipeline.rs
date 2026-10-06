//! Public high-precision lookup: 8 two-bit input/output chunks, d=5, n800/h32/N1024.
//! `create_lut_and_drop` measures public LUT allocation, filling and destruction.
//! `evaluate` measures one homomorphic lookup producing all output chunks;
//! keys, public LUT creation, encryption and reusable buffers are untimed.
//! Classic/sparse pairs use the same fixed-weight client and independently seeded inputs.
//! IDs without a workload suffix use the polynomial example; `dense_seed42` adds a fixed dense
//! mapping to distinguish general evaluation costs from repeated-subtable gains.
//! `shared_middle_chunk` exercises cross-output sharing and skipped selectors.
//! No production-source copies or private-stage hooks are used.
//! Run: cargo bench -p primus_tfhe_ntru_lut --bench pipeline --features ntt,rustfft

// The Cargo target accepts NTT or either FFT engine independently.
#[cfg(any(feature = "ntt", feature = "rustfft", feature = "tfhe-fft"))]
use criterion::{Criterion, criterion_group, criterion_main};

#[global_allocator]
static ALLOCATOR: primus_test_allocations::CountingAllocator =
    primus_test_allocations::CountingAllocator;

#[cfg(any(feature = "ntt", feature = "rustfft", feature = "tfhe-fft"))]
mod support;

// Keep u64 NTT and one primary FFT engine; creation is measured once per modulus.
#[cfg(any(feature = "ntt", feature = "rustfft", feature = "tfhe-fft"))]
fn pipeline(c: &mut Criterion) {
    #[cfg(feature = "ntt")]
    support::ntt::benchmark::<u64, primus_ntt::U64NttTable>(c);
    #[cfg(feature = "rustfft")]
    support::fourier::benchmark::<u64, primus_fft::RustFftTable>(c, "rustfft");
    #[cfg(all(not(feature = "rustfft"), feature = "tfhe-fft"))]
    support::fourier::benchmark::<u64, primus_fft::TfheFftTable>(c, "tfhe_fft");
}

#[cfg(any(feature = "ntt", feature = "rustfft", feature = "tfhe-fft"))]
criterion_group!(benches, pipeline);
#[cfg(any(feature = "ntt", feature = "rustfft", feature = "tfhe-fft"))]
criterion_main!(benches);

#[cfg(not(any(feature = "ntt", feature = "rustfft", feature = "tfhe-fft")))]
fn main() {
    eprintln!("Enable ntt, rustfft or tfhe-fft to run this benchmark.");
}
