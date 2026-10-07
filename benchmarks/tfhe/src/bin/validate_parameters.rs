//! Opt-in numerical validation of the representative TFHE parameter matrix.
//!
//! Run all profiles:
//! `cargo run --release -p primus_tfhe_benchmarks --bin validate_parameters --features validation,ntt,fourier,rustfft,tfhe-fft -- --all`
//!
//! Select backend and engine features independently; no arguments lists profiles.
//! Use `-- --list` to discover profiles without generating keys.
//! Use `-- --help` for selection syntax; --list, --all and FILTER are exclusive.
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

use clap::{
    Arg, ArgAction, ArgGroup, Command, builder::NonEmptyStringValueParser, error::ErrorKind,
};
use primus_tfhe_benchmarks::parameters::VALIDATION_SEEDS;
use validation::compilation;

/// One backend/word profile, with a fixed seed and a diagnostic label.
type ValidateProfile = fn(seed: u64, name: &str);

// Concrete backend functions retain their phase oracles and key construction.
const PROFILES: &[(&str, ValidateProfile)] = &[
    #[cfg(feature = "ntru-ntt")]
    (
        "ntru/ntt/u32",
        validation::ntru_ntt::validate::<u32, primus_ntt::U32NttTable>,
    ),
    #[cfg(feature = "ntru-ntt")]
    (
        "ntru/ntt/u64",
        validation::ntru_ntt::validate::<u64, primus_ntt::U64NttTable>,
    ),
    #[cfg(all(feature = "ntru-fourier", feature = "rustfft"))]
    (
        "ntru/rustfft/u32",
        validation::ntru_fourier::validate::<u32, primus_fft::RustFftTable>,
    ),
    #[cfg(all(feature = "ntru-fourier", feature = "rustfft"))]
    (
        "ntru/rustfft/u64",
        validation::ntru_fourier::validate::<u64, primus_fft::RustFftTable>,
    ),
    #[cfg(all(feature = "ntru-fourier", feature = "tfhe-fft"))]
    (
        "ntru/tfhe_fft/u32",
        validation::ntru_fourier::validate::<u32, primus_fft::TfheFftTable>,
    ),
    #[cfg(all(feature = "ntru-fourier", feature = "tfhe-fft"))]
    (
        "ntru/tfhe_fft/u64",
        validation::ntru_fourier::validate::<u64, primus_fft::TfheFftTable>,
    ),
    #[cfg(feature = "glwe-ntt")]
    (
        "glwe/ntt/u32",
        validation::glwe_ntt::validate::<u32, primus_ntt::U32NttTable>,
    ),
    #[cfg(feature = "glwe-ntt")]
    (
        "glwe/ntt/u64",
        validation::glwe_ntt::validate::<u64, primus_ntt::U64NttTable>,
    ),
    #[cfg(all(feature = "glwe-fourier", feature = "rustfft"))]
    (
        "glwe/rustfft/u32",
        validation::glwe_fourier::validate::<u32, primus_fft::RustFftTable>,
    ),
    #[cfg(all(feature = "glwe-fourier", feature = "rustfft"))]
    (
        "glwe/rustfft/u64",
        validation::glwe_fourier::validate::<u64, primus_fft::RustFftTable>,
    ),
    #[cfg(all(feature = "glwe-fourier", feature = "tfhe-fft"))]
    (
        "glwe/tfhe_fft/u32",
        validation::glwe_fourier::validate::<u32, primus_fft::TfheFftTable>,
    ),
    #[cfg(all(feature = "glwe-fourier", feature = "tfhe-fft"))]
    (
        "glwe/tfhe_fft/u64",
        validation::glwe_fourier::validate::<u64, primus_fft::TfheFftTable>,
    ),
];

/// Declares exclusive selection modes; only an explicit nonempty filter or --all
/// runs validation. Backend/engine features determine which profiles exist.
fn command() -> Command {
    Command::new("validate_parameters")
        .about("Check numerical TFHE parameter profiles; list available profiles by default")
        .arg(
            Arg::new("filter")
                .value_name("FILTER")
                .value_parser(NonEmptyStringValueParser::new())
                .help("Run profiles whose names contain FILTER (e.g. ntru/ntt/u32 or lut/compile)"),
        )
        .arg(
            Arg::new("list")
                .long("list")
                .action(ArgAction::SetTrue)
                .help("List profiles enabled by the compiled backend and engine features"),
        )
        .arg(
            Arg::new("all")
                .long("all")
                .action(ArgAction::SetTrue)
                .help("Run all available profiles, including expensive encrypted checks"),
        )
        .group(ArgGroup::new("selection").args(["filter", "list", "all"]))
}

/// List by default; large encrypted profiles require an explicit filter or --all.
fn main() {
    let mut command = command();
    let args = command.get_matches_mut();
    let filter = args.get_one::<String>("filter");
    if args.get_flag("list") || (filter.is_none() && !args.get_flag("all")) {
        println!("lut/compile");
        for (name, _) in PROFILES {
            println!("{name}");
        }
        return;
    }
    let filter = filter.map_or("", String::as_str);
    let mut count = 0;
    if "lut/compile".contains(filter) {
        compilation::validate();
        println!("lut/compile: u32/u64, N=1024/2048, native/pow2/Barrett passed");
        count += 1;
    }
    for &(name, validate) in PROFILES {
        if name.contains(filter) {
            count += 1;
            for seed in VALIDATION_SEEDS {
                eprintln!("checking {name}, seed={seed}");
                validate(seed, name);
            }
        }
    }
    if count == 0 {
        command
            .error(
                ErrorKind::InvalidValue,
                format!(
                    "no parameter profile matches {filter:?}; use --list to see available profiles"
                ),
            )
            .exit();
    }
    println!("validated {count} parameter groups");
}
