//! cbs comparisons; backend features select concrete registrations.

use primus_tfhe_benchmarks::measurement;

#[cfg(feature = "glwe-ntt")]
#[path = "cbs/glwe_ntt.rs"]
mod glwe_ntt;

#[cfg(all(
    feature = "glwe-fourier",
    any(feature = "rustfft", feature = "tfhe-fft")
))]
#[path = "cbs/glwe_fourier.rs"]
mod glwe_fourier;

#[cfg(feature = "ntru-ntt")]
#[path = "cbs/ntru_ntt.rs"]
mod ntru_ntt;

#[cfg(all(
    feature = "ntru-fourier",
    any(feature = "rustfft", feature = "tfhe-fft")
))]
#[path = "cbs/ntru_fourier.rs"]
mod ntru_fourier;

fn main() {
    measurement::run("cbs", |group| {
        #[cfg(feature = "glwe-ntt")]
        glwe_ntt::bench_cbs(group);
        #[cfg(all(
            feature = "glwe-fourier",
            any(feature = "rustfft", feature = "tfhe-fft")
        ))]
        glwe_fourier::bench_cbs(group);
        #[cfg(feature = "ntru-ntt")]
        ntru_ntt::bench_cbs(group);
        #[cfg(all(
            feature = "ntru-fourier",
            any(feature = "rustfft", feature = "tfhe-fft")
        ))]
        ntru_fourier::bench_cbs(group);
        let _ = group;
    });
}
