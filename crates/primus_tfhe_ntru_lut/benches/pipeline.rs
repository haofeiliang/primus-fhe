//! Public high-precision lookup: 8 two-bit input/output chunks, d=5, n800/N1024.
//! One complete lookup per iteration; keys, tables, encryption and reusable buffers
//! are untimed. Separate compilation IDs include allocation/filling/drop of a LUT.
//! No production-source copies or private-stage hooks are used.
//! Run: cargo bench -p primus_tfhe_ntru_lut --bench pipeline

use criterion::{Criterion, criterion_group, criterion_main};

#[global_allocator]
static ALLOCATOR: primus_test_allocations::CountingAllocator =
    primus_test_allocations::CountingAllocator;

mod support;
use support::{fourier, ntt};

fn pipeline(c: &mut Criterion) {
    ntt::benchmark::<u32, primus_ntt::U32NttTable>(c);
    ntt::benchmark::<u64, primus_ntt::U64NttTable>(c);
    fourier::benchmark::<u32, primus_fft::RustFftTable>(c, "rustfft");
    fourier::benchmark::<u64, primus_fft::RustFftTable>(c, "rustfft");
    fourier::benchmark::<u32, primus_fft::TfheFftTable>(c, "tfhe_fft");
    fourier::benchmark::<u64, primus_fft::TfheFftTable>(c, "tfhe_fft");
}

criterion_group!(benches, pipeline);
criterion_main!(benches);
