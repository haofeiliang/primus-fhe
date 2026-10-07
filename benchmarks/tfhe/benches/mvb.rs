//! mvb comparisons; backend features select concrete registrations.

use primus_tfhe_benchmarks::measurement;

#[cfg(feature = "glwe-ntt")]
#[path = "mvb/glwe_ntt.rs"]
mod glwe_ntt;

#[cfg(all(
    feature = "glwe-fourier",
    any(feature = "rustfft", feature = "tfhe-fft")
))]
#[path = "mvb/glwe_fourier.rs"]
mod glwe_fourier;

#[cfg(feature = "ntru-ntt")]
#[path = "mvb/ntru_ntt.rs"]
mod ntru_ntt;

#[cfg(all(
    feature = "ntru-fourier",
    any(feature = "rustfft", feature = "tfhe-fft")
))]
#[path = "mvb/ntru_fourier.rs"]
mod ntru_fourier;

fn main() {
    measurement::run("mvb", |group| {
        #[cfg(feature = "glwe-ntt")]
        glwe_ntt::bench_mvb(group);
        #[cfg(all(
            feature = "glwe-fourier",
            any(feature = "rustfft", feature = "tfhe-fft")
        ))]
        glwe_fourier::bench_mvb(group);
        #[cfg(feature = "ntru-ntt")]
        ntru_ntt::bench_mvb(group);
        #[cfg(all(
            feature = "ntru-fourier",
            any(feature = "rustfft", feature = "tfhe-fft")
        ))]
        ntru_fourier::bench_mvb(group);
        let _ = group;
    });
}
