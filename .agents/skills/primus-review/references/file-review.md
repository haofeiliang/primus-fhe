# File review route

Use this route for one explicitly named `.rs` file.

## Required coverage

1. Read the entire file, including tests and feature-gated sections.
2. Identify its parent module, public re-exports, imported contracts, and sibling files that define the same function families or representations.
3. Search every public or contract-sensitive item in workspace callers. For private helpers, trace at least every caller in the parent module.
4. Compare paired implementations such as scalar/SIMD, checked/lazy, allocating/in-place, forward/reverse, or constructor/reset.
5. Inspect tests, examples, benchmarks, and rustdoc that directly exercise or describe the file.
6. Run focused validation only after the static review. Prefer the owning crate's check or a named test over workspace-wide commands unless the finding crosses crates.

## Coverage ledger

Report:

- Target file: fully read.
- Supporting definitions and sibling APIs: list each inspected file.
- Callers: state whether exhaustive for public items and private helpers.
- Tests/docs/bench/features: list inspected surfaces and any exclusions.
- Validation: commands run and paths intentionally not run.

A file review is incomplete if it only comments on the target file without checking the contracts it imports and the callers that rely on it.
