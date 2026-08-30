# Module review route

Use this route for a module directory, a `mod.rs` plus child files, or a named Rust module.

## Required coverage

1. Inventory the module root, all declared child modules, feature-gated files, public re-exports, local tests, and adjacent examples or benchmarks.
2. Read every source file in the module. If generated code exists, inspect the generator and the generated contract rather than treating generated bulk as ordinary handwritten code.
3. Build a module-level map of representations, constructors, conversions, function families, shared helpers, and dispatch paths.
4. Exhaustively search and inventory workspace symbol references to the module's public surface and all cross-file private kernels. Read every contract-sensitive or high-risk caller body; representative lower-risk bodies may be sampled when the coverage ledger states the selection boundary.
5. Compare naming and parameter matrices across the whole module, not file by file.
6. Trace each public boundary to its kernels and confirm where validation, normalization, allocation, and feature dispatch occur.
7. Inspect all module-specific tests, examples, benchmarks, rustdoc, and meaningful feature combinations.

## Optional delegation

Delegate only when the module has independent lanes such as scalar versus SIMD implementations, separate mathematical representations, or API surface versus test/feature coverage. Keep inventory, caller tracing, finding adjudication, and final validation in the main agent.

## Coverage ledger

Report:

- Module files: exhaustive list, including feature-gated files.
- API and caller surface: exhaustive symbol inventory, caller bodies read, sampling rule, and exclusions.
- Implementation families: which pairs or variants were compared.
- Tests/docs/examples/bench/features: inspected and excluded surfaces.
- Validation: focused commands and any untested feature or architecture paths.

A module review is incomplete if any declared child file, public re-export, or module-specific validation surface is omitted without explanation.
