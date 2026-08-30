# Crate review route

Use this route for a crate name, crate root, or crate `Cargo.toml`.

## Required inventory

Before delegation, the main agent inventories:

- `Cargo.toml`, `src/**/*.rs`, crate-local `tests/`, `examples/`, and `benches/`.
- Features, optional dependencies, build scripts, generated sources, public re-exports, and workspace callers.
- Major representations, API families, scalar/SIMD or checked/lazy variants, and high-risk kernels.

The main agent reads the crate root, manifest, all public API definitions, and every file cited by a finding. Delegation supplements this ownership; it does not replace it.

## Read-only review lanes

When sub-agent delegation is available, use these three materially independent lanes:

1. **API and consistency:** types, visibility, re-exports, naming, function-family matrices, parameter design/order, ownership, rustdoc, and workspace callers.
2. **Math, safety, and performance:** representations, ranges, overflow, validation boundaries, unsafe preconditions, scalar/SIMD agreement, allocation, dispatch, and hot loops.
3. **Validation surface:** tests, examples, benchmarks, features, platform-specific paths, and cross-crate behavioral impact.

Each lane is read-only and must return its inspected file list, precise evidence, residual gaps, and suggested validation. The main agent independently checks each proposed finding against source and callers, removes duplicates, resolves contradictions, and owns severity.

If delegation is unavailable, execute all three lanes sequentially and state that fact. Never reduce crate coverage merely because only one agent is active.

## Validation

Start narrow and expand in proportion to risk:

1. Named tests or feature-specific checks for suspected defects.
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
- Delegation: lanes used and how findings were independently verified; or sequential fallback.
- Validation: commands run, failures, and intentionally unverified paths.

A crate review is incomplete if it samples source files without an inventory, omits workspace callers of public contracts, or equates passing commands with source review.
