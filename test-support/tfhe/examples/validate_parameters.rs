//! Opt-in numerical validation of the representative TFHE parameter matrix.
//!
//! Run all profiles:
//! `cargo run --release -p primus_tfhe_test_support --example validate_parameters --features rustfft,tfhe-fft`
//!
//! Select either FFT feature independently; no FFT feature still offers NTT.
//! Use `-- --list` to discover profiles without generating keys.
//!
//! Append a substring such as `ntru/ntt/u32`, `glwe/rustfft` or `lut/compile`
//! after `--` to select profiles before key generation. Ordinary CI tests use
//! small parameters; this developer diagnostic checks larger benchmark profiles.
//! Product-crate examples show the shorter, recommended user workflows.
//!
//! Each encrypted profile runs both fixed seeds and checks decoded results and
//! raw-phase error budgets. The compilation profile only checks public LUT
//! geometry. Reports are observations, not failure-probability estimates.
//! Fixed seeds reproduce sampling; TFHE-FFT measures its plan at runtime, so
//! raw floating-point residuals need not be bit-identical across runs.

mod validation;

#[cfg(feature = "rustfft")]
use primus_fft::RustFftTable;
#[cfg(feature = "tfhe-fft")]
use primus_fft::TfheFftTable;
use primus_ntt::{U32NttTable, U64NttTable};
use primus_tfhe_test_support::parameters::VALIDATION_SEEDS;
use validation::{compilation, glwe_ntt, ntru_ntt};
#[cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
use validation::{glwe_fourier, ntru_fourier};

/// One backend/word profile, with a fixed seed and a diagnostic label.
type ValidateProfile = fn(seed: u64, name: &str);

// Only dispatch is shared: each function owns its family's parameter choices,
// key generation, secret/order coverage and representation-specific phase checks.
const PROFILES: &[(&str, ValidateProfile)] = &[
    ("ntru/ntt/u32", ntru_ntt::validate::<u32, U32NttTable>),
    ("ntru/ntt/u64", ntru_ntt::validate::<u64, U64NttTable>),
    #[cfg(feature = "rustfft")]
    (
        "ntru/rustfft/u32",
        ntru_fourier::validate::<u32, RustFftTable>,
    ),
    #[cfg(feature = "rustfft")]
    (
        "ntru/rustfft/u64",
        ntru_fourier::validate::<u64, RustFftTable>,
    ),
    #[cfg(feature = "tfhe-fft")]
    (
        "ntru/tfhe_fft/u32",
        ntru_fourier::validate::<u32, TfheFftTable>,
    ),
    #[cfg(feature = "tfhe-fft")]
    (
        "ntru/tfhe_fft/u64",
        ntru_fourier::validate::<u64, TfheFftTable>,
    ),
    ("glwe/ntt/u32", glwe_ntt::validate::<u32, U32NttTable>),
    ("glwe/ntt/u64", glwe_ntt::validate::<u64, U64NttTable>),
    #[cfg(feature = "rustfft")]
    (
        "glwe/rustfft/u32",
        glwe_fourier::validate::<u32, RustFftTable>,
    ),
    #[cfg(feature = "rustfft")]
    (
        "glwe/rustfft/u64",
        glwe_fourier::validate::<u64, RustFftTable>,
    ),
    #[cfg(feature = "tfhe-fft")]
    (
        "glwe/tfhe_fft/u32",
        glwe_fourier::validate::<u32, TfheFftTable>,
    ),
    #[cfg(feature = "tfhe-fft")]
    (
        "glwe/tfhe_fft/u64",
        glwe_fourier::validate::<u64, TfheFftTable>,
    ),
];

/// Selects profiles, runs the fixed seeds and rejects filters that match nothing.
fn main() {
    let filter = std::env::args().nth(1).unwrap_or_default();
    if filter == "--list" {
        println!("lut/compile");
        for (name, _) in PROFILES {
            println!("{name}");
        }
        return;
    }
    let mut count = 0;
    if "lut/compile".contains(&filter) {
        compilation::validate();
        println!("lut/compile: u32/u64, N=1024/2048, native/pow2/Barrett passed");
        count += 1;
    }
    for &(name, validate) in PROFILES {
        if name.contains(&filter) {
            count += 1;
            for seed in VALIDATION_SEEDS {
                eprintln!("checking {name}, seed={seed}");
                validate(seed, name);
            }
        }
    }
    assert!(count > 0, "no parameter profile matches {filter:?}");
    println!("validated {count} parameter groups");
}
