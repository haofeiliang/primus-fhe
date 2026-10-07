//! sparse_pbs comparisons; backend features select concrete registrations.

use primus_tfhe_benchmarks::measurement;

#[cfg(feature = "glwe-ntt")]
#[path = "sparse_pbs/glwe_ntt.rs"]
mod glwe_ntt;

#[cfg(all(
    feature = "glwe-fourier",
    any(feature = "rustfft", feature = "tfhe-fft")
))]
#[path = "sparse_pbs/glwe_fourier.rs"]
mod glwe_fourier;

#[cfg(feature = "ntru-ntt")]
#[path = "sparse_pbs/ntru_ntt.rs"]
mod ntru_ntt;

#[cfg(all(
    feature = "ntru-fourier",
    any(feature = "rustfft", feature = "tfhe-fft")
))]
#[path = "sparse_pbs/ntru_fourier.rs"]
mod ntru_fourier;

fn main() {
    measurement::run("sparse_pbs", |group| {
        #[cfg(feature = "glwe-ntt")]
        glwe_ntt::bench_sparse(group);
        #[cfg(all(
            feature = "glwe-fourier",
            any(feature = "rustfft", feature = "tfhe-fft")
        ))]
        glwe_fourier::bench_sparse(group);
        #[cfg(feature = "ntru-ntt")]
        ntru_ntt::bench_sparse(group);
        #[cfg(all(
            feature = "ntru-fourier",
            any(feature = "rustfft", feature = "tfhe-fft")
        ))]
        ntru_fourier::bench_sparse(group);
        let _ = group;
    });
}
