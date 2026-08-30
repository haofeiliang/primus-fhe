---
name: primus-review
description: Review Primus FHE Rust source at file, module, or crate scope. Use when the user asks to inspect, review, audit, or re-review Rust code in this repository, including readability, maintainability, API consistency, mathematical contracts, safety, performance, macro complexity, callers, tests, features, examples, benchmarks, and documentation.
---

# Primus Review

Perform an evidence-backed review without changing source code unless the user separately asks for implementation.

## Select the scope

1. Read `references/checklist.md` completely.
2. Classify the requested target and read exactly one matching scope guide completely:
   - A single `.rs` file: `references/file-review.md`.
   - A Rust module directory, a `mod.rs` plus its child files, or a named module: `references/module-review.md`.
   - A crate name, crate root, or `Cargo.toml`: `references/crate-review.md`.
3. If the user's wording and path disagree, use the semantic target. For example, a directory path means module scope even if it contains `mod.rs`.
4. If multiple targets are requested, inventory each target and use the largest applicable scope guide.

## Establish repository state

- Read the applicable `AGENTS.md` files and `HANDOFF.md` before reviewing. Treat still-current decisions in `HANDOFF.md` as settled constraints; do not relabel them as findings or gaps without new contradictory evidence.
- Inspect `git status` and the relevant staged and unstaged diffs. Treat existing changes as user-owned evidence, not as review fixes.
- Inventory the files, feature gates, public re-exports, tests, examples, benchmarks, and workspace callers required by the selected scope.
- Create a coverage ledger before drawing conclusions. The final response must distinguish inspected, sampled, and intentionally excluded surfaces.

## Review the target

- Trace public contracts from their highest owning boundary into private kernels and representative callers.
- Compare related APIs as a family rather than judging names and parameter order in isolation.
- Check whether control flow, ownership, abstractions, and numerical invariants remain locally understandable and whether each layer of indirection or code generation has a concrete maintenance benefit.
- Verify mathematical statements against implementation and call paths: input domain, representation, layout, normalization, output range, overflow bounds, panic behavior, and workspace requirements.
- Concentrate release checks at safe public or batch boundaries. Accept `debug_assert!` or documented unchecked private kernels only when their preconditions are established before use and no memory-safety condition depends on debug mode.
- For scalar and SIMD implementations of the same operation, verify semantic agreement, tail handling, dispatch, and feature coverage.
- Run the narrowest useful validation after source inspection. Do not use successful commands as a substitute for coverage.
- Do not add deterministic tests merely to demonstrate an already-proven implementation. Recommend a test only when it protects an independent public contract or provides durable differential diagnostics.

## Use delegation deliberately

- For one file, review directly unless the file contains clearly independent implementations that materially benefit from separate inspection.
- For a module, delegate only independent lanes when doing so improves coverage; the main agent still owns the module inventory and validates every reported finding.
- For a full crate, when sub-agent delegation is available, use the three read-only lanes defined in `references/crate-review.md`. If it is unavailable, execute the same lanes sequentially and disclose that in the coverage statement.
- Never relay a sub-agent finding without checking the cited code, contract, and caller evidence yourself.

## Report results

- Lead with confirmed findings ordered as P0 (critical), P1 (high), P2 (normal), and P3 (low), each with a precise file and line reference. Do not assign priorities to optional improvements or residual risks.
- For every finding, state the violated contract, the triggering conditions, the observable impact, and why an existing boundary or invariant does not make it safe.
- Separate confirmed defects from intentional design contracts, residual test gaps, and optional consistency improvements.
- When there are no findings, say so plainly and name the most important residual risks or unverified paths.
- End with the coverage ledger and validation performed. Do not update `HANDOFF.md` during a review unless the user asks; when asked, record only current recoverable state rather than a history log.
