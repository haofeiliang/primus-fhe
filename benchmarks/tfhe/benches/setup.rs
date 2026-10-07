//! setup comparisons; backend features select concrete registrations.

use primus_tfhe_benchmarks::measurement;

#[cfg(feature = "glwe-ntt")]
#[path = "setup/glwe_ntt.rs"]
mod glwe_ntt;

#[cfg(all(
    feature = "glwe-fourier",
    any(feature = "rustfft", feature = "tfhe-fft")
))]
#[path = "setup/glwe_fourier.rs"]
mod glwe_fourier;

#[cfg(feature = "ntru-ntt")]
#[path = "setup/ntru_ntt.rs"]
mod ntru_ntt;

#[cfg(all(
    feature = "ntru-fourier",
    any(feature = "rustfft", feature = "tfhe-fft")
))]
#[path = "setup/ntru_fourier.rs"]
mod ntru_fourier;

fn main() {
    measurement::run("setup", |group| {
        #[cfg(feature = "glwe-ntt")]
        glwe_ntt::bench_setup(group);
        #[cfg(all(
            feature = "glwe-fourier",
            any(feature = "rustfft", feature = "tfhe-fft")
        ))]
        glwe_fourier::bench_setup(group);
        #[cfg(feature = "ntru-ntt")]
        ntru_ntt::bench_setup(group);
        #[cfg(all(
            feature = "ntru-fourier",
            any(feature = "rustfft", feature = "tfhe-fft")
        ))]
        ntru_fourier::bench_setup(group);
        let _ = group;
    });
}
