//! Opt-in numerical validation of the representative TFHE parameter matrix.
//!
//! Run all profiles:
//! `cargo run --release -p primus_tfhe_test_support --example validate_parameters`
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

use primus_fft::{RustFftTable, TfheFftTable};
use primus_ntt::{U32NttTable, U64NttTable};
use primus_tfhe_test_support::parameters::VALIDATION_SEEDS;
use validation::{compilation, glwe_fourier, glwe_ntt, ntru_fourier, ntru_ntt};

/// One backend/word profile, with a fixed seed and a diagnostic label.
type ValidateProfile = fn(seed: u64, name: &str);

// Only dispatch is shared: each function owns its family's parameter choices,
// key generation, secret/order coverage and representation-specific phase checks.
const PROFILES: [(&str, ValidateProfile); 12] = [
    ("ntru/ntt/u32", ntru_ntt::validate::<u32, U32NttTable>),
    ("ntru/ntt/u64", ntru_ntt::validate::<u64, U64NttTable>),
    (
        "ntru/rustfft/u32",
        ntru_fourier::validate::<u32, RustFftTable>,
    ),
    (
        "ntru/rustfft/u64",
        ntru_fourier::validate::<u64, RustFftTable>,
    ),
    (
        "ntru/tfhe_fft/u32",
        ntru_fourier::validate::<u32, TfheFftTable>,
    ),
    (
        "ntru/tfhe_fft/u64",
        ntru_fourier::validate::<u64, TfheFftTable>,
    ),
    ("glwe/ntt/u32", glwe_ntt::validate::<u32, U32NttTable>),
    ("glwe/ntt/u64", glwe_ntt::validate::<u64, U64NttTable>),
    (
        "glwe/rustfft/u32",
        glwe_fourier::validate::<u32, RustFftTable>,
    ),
    (
        "glwe/rustfft/u64",
        glwe_fourier::validate::<u64, RustFftTable>,
    ),
    (
        "glwe/tfhe_fft/u32",
        glwe_fourier::validate::<u32, TfheFftTable>,
    ),
    (
        "glwe/tfhe_fft/u64",
        glwe_fourier::validate::<u64, TfheFftTable>,
    ),
];

/// Selects profiles, runs the fixed seeds and rejects filters that match nothing.
fn main() {
    let filter = std::env::args().nth(1).unwrap_or_default();
    let mut count = 0;
    if "lut/compile".contains(&filter) {
        compilation::validate();
        println!("lut/compile: u32/u64, N=1024/2048, native/pow2/Barrett passed");
        count += 1;
    }
    for (name, validate) in PROFILES {
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
