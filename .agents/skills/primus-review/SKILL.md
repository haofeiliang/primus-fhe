---
name: primus-review
description: Review Primus FHE Rust changes or audit a named file, module, or crate; also use for source-based refactoring analysis. Not for routine implementation validation or planning solely from an existing report.
---

# Primus Review

Apply [repository conventions](../../../AGENTS.md). Pure review is read-only, including tests and HANDOFF; honor implementation or documentation changes already authorized by the user.

## Choose depth

| Request | Coverage |
| --- | --- |
| Change review | Selected diff, affected definitions, imported contracts, callers and validation assets; follow dependencies beyond the diff where needed |
| Focused analysis | Trace the named question, operation or API family; expand only when evidence requires it |
| Full review | Entire requested file, module or crate plus its contracts, callers and validation assets |

Choose by the requested outcome. A question about one constructor remains bounded; an unqualified review of a whole file/module/crate is full review. For mixed requests, state each boundary. A crate's `src/lib.rs` alone is file scope unless the user requests the crate.

Use relevant parts of [checklist.md](references/checklist.md) for bounded work. Full reviews read the whole checklist and [full-review.md](references/full-review.md). Do not claim omitted or unfinished coverage as complete.

## Inspect and validate

- Trace public boundaries to kernels and representative consumers; compare paired APIs and representations. Verify mathematical premises against current contracts, not historical preferences.
- Record inspected sources, callers, assets and gaps. Passing commands do not replace source coverage; choose focused validation from actual risks using AGENTS.
- Delegate read-only work only when independent portions and workload justify it, not one agent per review dimension. Give explicit boundaries; the main agent owns inventory, verifies finding evidence and covers any incomplete assignment.

## Report

- Defect reviews lead with confirmed P0–P3 findings and precise file/line references. Explain the violated contract, trigger, observable impact and why existing checks do not prevent it.
- Refactoring analysis leads with decisions and tradeoffs. Keep optional improvements, intentional behavior and unproven risks separate from defects; a missing test alone is a recommendation unless it violates an explicit requirement.
- If no defect is confirmed, say so and identify material residual risks. End with scope-sized coverage and actual validation; full reviews use the [coverage ledger](references/full-review.md#coverage-ledger). Update HANDOFF only when requested, with current recoverable state.
