//! pbs comparisons; backend features select concrete registrations.

use primus_tfhe_benchmarks::measurement;

#[cfg(feature = "glwe-ntt")]
#[path = "pbs/glwe_ntt.rs"]
mod glwe_ntt;

#[cfg(all(
    feature = "glwe-fourier",
    any(feature = "rustfft", feature = "tfhe-fft")
))]
#[path = "pbs/glwe_fourier.rs"]
mod glwe_fourier;

#[cfg(feature = "ntru-ntt")]
#[path = "pbs/ntru_ntt.rs"]
mod ntru_ntt;

#[cfg(all(
    feature = "ntru-fourier",
    any(feature = "rustfft", feature = "tfhe-fft")
))]
#[path = "pbs/ntru_fourier.rs"]
mod ntru_fourier;

fn main() {
    measurement::run("pbs", |group| {
        #[cfg(feature = "glwe-ntt")]
        glwe_ntt::bench_pbs(group);
        #[cfg(all(
            feature = "glwe-fourier",
            any(feature = "rustfft", feature = "tfhe-fft")
        ))]
        glwe_fourier::bench_pbs(group);
        #[cfg(feature = "ntru-ntt")]
        ntru_ntt::bench_pbs(group);
        #[cfg(all(
            feature = "ntru-fourier",
            any(feature = "rustfft", feature = "tfhe-fft")
        ))]
        ntru_fourier::bench_pbs(group);
        let _ = group;
    });
}
