# Crate review route

Use this route only after selecting full review of a crate. Mentioning a crate or its `Cargo.toml` in a bounded question does not select this route.

## Required inventory

The main agent inventories:

- `Cargo.toml`, `src/**/*.rs`, crate-local `tests/`, `examples/`, and `benches/`.
- Features, optional dependencies, build scripts, generated sources, public re-exports, and workspace callers.
- Major representations, API families, scalar/SIMD or checked/lazy variants, and high-risk kernels.

Read every handwritten source file, including private kernels and feature-gated implementations; inspect generators and generated contracts where applicable. Coverage may be divided among agents. The main agent reads the crate root, manifest, public API definitions, and evidence for every proposed finding, and accounts for remaining files.

## Coverage dimensions and optional delegation

Cover all three dimensions, directly or through independent read-only assignments sized to the actual workload:

1. **API and consistency:** types, visibility, re-exports, naming, function-family matrices, parameter design/order, ownership, rustdoc, and workspace callers.
2. **Math, safety, and performance:** representations, ranges, overflow, validation boundaries, unsafe preconditions, scalar/SIMD agreement, allocation, dispatch, and hot loops.
3. **Validation surface:** tests, examples, benchmarks, features, platform-specific paths, and cross-crate behavioral impact.

Use the delegation policy in `SKILL.md`; do not start one agent per dimension automatically. For multiple crates, group shared infrastructure and separate backend work to avoid redundant inspections.

Inventory workspace references to the public surface. Read all contract-sensitive and high-risk caller bodies; lower-risk callers may be sampled with an explicit selection boundary. Inspect all crate-local tests, examples, benchmarks, and docs. Sequential work must provide the same coverage.

## Validation

Start narrow and expand in proportion to risk:

1. Named tests or feature-specific checks for suspected defects; use formatting check mode if formatting is relevant.
2. `cargo check -p <crate> --all-targets`.
3. `cargo test -p <crate>`.
4. `cargo clippy -p <crate> --all-targets -- -D warnings`.
5. Workspace or nightly SIMD validation only when cross-crate, feature, or architecture evidence requires it.

For a pure review, do not repair unrelated failures or weaken checks. Report commands that were not run and why.

## Coverage ledger

Report:

- Manifest and source inventory: exhaustive file count and exclusions.
- Public API and workspace callers: exhaustive or precisely bounded.
- Major implementation families and representations compared.
- Tests, examples, benchmarks, features, generated and platform-specific paths inspected.
- Delegation, if used: assignments completed, findings independently verified, and any work taken over.
- Validation: commands run, failures, and intentionally unverified paths.

A crate review is incomplete if it samples source files without an inventory, omits workspace callers of public contracts, or equates passing commands with source review.
