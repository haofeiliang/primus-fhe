//! Public high-precision lookup: 8 two-bit input/output chunks, d=5, n800/h32/N1024.
//! `create_lut_and_drop` measures public LUT allocation, filling and destruction.
//! `evaluate` measures one homomorphic lookup producing all output chunks;
//! keys, public LUT creation, encryption and reusable buffers are untimed.
//! Classic/sparse pairs use the same fixed-weight client and independently seeded inputs.
//! IDs without a workload suffix use the polynomial example; `dense_seed42` adds a fixed dense
//! mapping to distinguish general evaluation costs from repeated-subtable gains.
//! `shared_middle_chunk` exercises cross-output sharing and skipped selectors.
//! No production-source copies or private-stage hooks are used.
//! Run: cargo bench -p primus_tfhe_benchmarks --bench high_precision_lut --features lut,ntru-ntt,ntru-fourier,rustfft

#[cfg(any(
    feature = "ntru-ntt",
    all(
        feature = "ntru-fourier",
        any(feature = "rustfft", feature = "tfhe-fft")
    )
))]
#[path = "high_precision_lut/mod.rs"]
mod support;
fn main() {
    primus_tfhe_benchmarks::measurement::run("high_precision_lut", |group| {
        #[cfg(feature = "ntru-ntt")]
        support::ntt::benchmark::<u64, primus_ntt::U64NttTable>(group);
        #[cfg(all(feature = "ntru-fourier", feature = "rustfft"))]
        support::fourier::benchmark::<u64, primus_fft::RustFftTable>(group, "rustfft");
        #[cfg(all(
            feature = "ntru-fourier",
            not(feature = "rustfft"),
            feature = "tfhe-fft"
        ))]
        support::fourier::benchmark::<u64, primus_fft::TfheFftTable>(group, "tfhe_fft");
        let _ = group;
    });
}
