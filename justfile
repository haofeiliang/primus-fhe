set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]
export RUSTDOCFLAGS := "-D warnings"

default: fmt-check lint test

# CI selects stable; local commands use the active toolchain.
ci: default test-doc
  cargo check -p primus_data --lib --no-default-features
  cargo check -p primus_lattice --lib --no-default-features
  cargo check -p primus_encoding --lib --no-default-features
  cargo check -p primus_modulus -p primus_distr --lib --features primus_modulus/derive,primus_distr/high_precision

# Separate toolchain/job. Build strict rustdoc only once, with all features.
ci-nightly: simd
  cargo +nightly test --workspace --doc --all-features
  cargo +nightly doc --workspace --no-deps --document-private-items --all-features
  cargo +nightly check -p primus_modulus -p primus_lattice -p primus_encoding --lib --no-default-features --features primus_modulus/simd,primus_lattice/simd,primus_encoding/simd

fmt:
  cargo fmt --all

fmt-check:
  cargo fmt --all -- --check

check package="*":
  cargo check -p '{{package}}' --all-targets

lint package="*":
  cargo clippy -p '{{package}}' --all-targets -- -D warnings

# All-targets is for compilation; keep Criterion out of nextest.
test package="*":
  cargo nextest run -p '{{package}}' --lib --tests

# Nextest does not execute doctests.
test-doc package="*":
  cargo test -p '{{package}}' --doc

simd package="*":
  cargo +nightly clippy -p '{{package}}' --all-targets --all-features -- -D warnings
  cargo +nightly nextest run -p '{{package}}' --lib --tests --all-features

tfhe: (lint "primus_tfhe*") (test "primus_tfhe*")

tfhe-simd: (simd "primus_tfhe*")

# Explicit target, one Criterion process, no statistical sampling.
bench-smoke package target *cargo-args:
  cargo bench -p '{{package}}' --bench '{{target}}' {{cargo-args}} -- --test

new-lib name:
  cargo new crates/{{name}} --lib
