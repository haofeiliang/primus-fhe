set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]
export RUSTDOCFLAGS := "-D warnings"

default: fmt-check (lint "*" "ntt,fourier,rustfft,tfhe-fft,validation") (test "*" "ntt,fourier,rustfft,tfhe-fft,validation")

# CI selects stable; local commands use the active toolchain.
ci: default test-doc
  python3 -m unittest discover -s benchmarks/tfhe/tools -p 'test_*.py'
  cargo check -p primus_data --lib --no-default-features
  cargo check -p primus_fft -p primus_lwe -p primus_tfhe_glwe -p primus_tfhe_ntru -p primus_tfhe_ntru_lut --lib --no-default-features
  cargo check -p 'primus_tfhe*_ntt' -p primus_glwe_rns -p primus_tfhe_ntru_lut --lib --features primus_tfhe_ntru_lut/ntt
  cargo check -p 'primus_tfhe*_fourier' -p primus_tfhe_ntru_lut --lib --features rustfft
  cargo check -p primus_encoding --lib --no-default-features
  cargo check -p primus_modulus -p primus_distr --lib --features primus_modulus/derive,primus_distr/high_precision

# Separate toolchain/job. Build strict rustdoc only once, with all features.
ci-nightly: simd
  cargo +nightly test --workspace --doc --all-features
  cargo +nightly doc --workspace --no-deps --document-private-items --all-features
  cargo +nightly check -p primus_modulus -p primus_encoding -p primus_tfhe_glwe -p primus_tfhe_ntru -p primus_tfhe_ntru_lut --lib --no-default-features --features simd

fmt:
  cargo fmt --all

fmt-check:
  cargo fmt --all -- --check

check package="*" features="":
  cargo check -p '{{package}}' --features '{{features}}' --all-targets

lint package="*" features="":
  cargo clippy -p '{{package}}' --features '{{features}}' --all-targets -- -D warnings

# All-targets is for compilation; keep Criterion out of nextest.
test package="*" features="":
  cargo nextest run -p '{{package}}' --features '{{features}}' --lib --tests

# Nextest does not execute doctests.
test-doc package="*":
  cargo test -p '{{package}}' --doc

simd package="*":
  cargo +nightly clippy -p '{{package}}' --all-targets --all-features -- -D warnings
  cargo +nightly nextest run -p '{{package}}' --lib --tests --all-features

tfhe: (lint "primus_tfhe*" "ntt,fourier,rustfft,tfhe-fft,validation") (test "primus_tfhe*" "ntt,fourier,rustfft,tfhe-fft,validation")

tfhe-simd: (simd "primus_tfhe*")

# Common u64 workloads across supported backends: just bench <operation> [backend]
bench operation *args:
  @python3 benchmarks/tfhe/tools/measure.py quick '{{operation}}' {{args}}

# Explicit target, one Criterion process, no statistical sampling.
bench-smoke package target *cargo-args:
  cargo bench -p '{{package}}' --bench '{{target}}' {{cargo-args}} -- --test

new-lib name:
  cargo new crates/{{name}} --lib
