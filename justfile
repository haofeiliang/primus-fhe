set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

simd-packages := "-p primus_integer -p primus_modulus -p primus_barrett_derive -p primus_factor -p primus_rns -p primus_decompose"
simd-features := "primus_integer/simd,primus_modulus/simd,primus_barrett_derive/simd,primus_factor/simd,primus_rns/simd,primus_decompose/simd"

tfhe-packages := "-p primus_tfhe -p primus_tfhe_glwe -p primus_tfhe_glwe_ntt -p primus_tfhe_glwe_fourier -p primus_tfhe_ntru -p primus_tfhe_ntru_ntt -p primus_tfhe_ntru_fourier -p primus_tfhe_ntru_lut -p primus_tfhe_test_support -p primus_test_allocations"

default: fmt check lint test

ci: fmt-check check lint test test-doc simd tfhe-simd

simd: check-simd lint-simd test-simd

new-lib name:
  cargo new crates/{{name}} --lib

fmt:
  cargo fmt --all

fmt-check:
  cargo fmt --all -- --check

check:
  cargo check --workspace --all-targets

check-simd:
  cargo +nightly check {{simd-packages}} --all-targets --features {{simd-features}}

lint:
  cargo clippy --workspace --all-targets -- -D warnings

lint-simd:
  cargo +nightly clippy {{simd-packages}} --all-targets --features {{simd-features}} -- -D warnings

# Run unit/integration tests; Criterion targets belong to bench-smoke.
test:
  cargo nextest run --workspace --lib --tests

test-simd:
  cargo +nightly nextest run {{simd-packages}} --lib --tests --features {{simd-features}}

# Nextest does not execute rustdoc examples.
test-doc:
  cargo test --workspace --doc

# Run one Criterion target once, including setup and assertions, without sampling.
bench-smoke package target *cargo-args:
  cargo bench -p {{package}} --bench {{target}} {{cargo-args}} -- --test

# The same target with nightly SIMD; extra arguments are Cargo feature options.
bench-smoke-simd package target *cargo-args:
  cargo +nightly bench -p {{package}} --bench {{target}} --features simd {{cargo-args}} -- --test

# Eight TFHE crates, test support, doctests and complete NTRU lookup examples.
tfhe: fmt-check
  cargo check {{tfhe-packages}} --all-targets
  cargo clippy {{tfhe-packages}} --all-targets -- -D warnings
  cargo test {{tfhe-packages}}
  cargo run -p primus_tfhe_ntru_lut --example ntt_lookup
  cargo run -p primus_tfhe_ntru_lut --example fourier_lookup
  cargo doc {{tfhe-packages}} --no-deps

# Explicit selection enables SIMD in every TFHE crate.
tfhe-simd:
  cargo +nightly check {{tfhe-packages}} --all-targets --features simd
  cargo +nightly clippy {{tfhe-packages}} --all-targets --features simd -- -D warnings
  cargo +nightly test {{tfhe-packages}} --features simd
  cargo +nightly run -p primus_tfhe_ntru_lut --example ntt_lookup --features simd
  cargo +nightly run -p primus_tfhe_ntru_lut --example fourier_lookup --features simd
