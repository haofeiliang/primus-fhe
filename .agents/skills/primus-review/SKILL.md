---
name: primus-review
description: Review changes, investigate a specific code question, or fully audit Primus FHE Rust files, modules, and crates. Use for requested code reviews and source-based refactoring analysis; not for routine implementation or planning solely from an existing report.
---

# Primus Review

Perform an evidence-backed review. Review or analysis alone does not authorize source changes; honor implementation authorization already given in the conversation.

## Select depth before file scope

Choose from the user's requested outcome, not merely the path or the presence of a crate name:

| Depth | Coverage |
| --- | --- |
| Change review | Inspect the selected diff, affected definitions, imported contracts, callers, and relevant validation assets. Search beyond changed lines when their correctness depends on unchanged code. |
| Focused analysis | Trace the named question, operation, or API family through its dependencies and consumers. Expand only where evidence requires it. |
| Full review | Inventory and inspect the whole requested file, module, or crate, including its validation assets and contract-sensitive callers. |

“Review this new constructor in crate X” is bounded; “fully review crate X” is exhaustive. An unqualified request to review a whole named file/module/crate uses full review. For mixed requests, assign depth per target rather than expanding every target to the largest scope. State the selected boundary briefly; ask only when missing scope materially prevents useful work.

For change review and focused analysis, use the relevant sections of [checklist.md](references/checklist.md); no full-scope guide is required. For full review, read the entire checklist and the matching guide for each distinct scope: [file](references/file-review.md), [module](references/module-review.md), or [crate](references/crate-review.md). A whole crate directory is crate scope; an explicitly requested `src/lib.rs` file review remains file scope unless the user asks for the whole crate. A module directory is module scope. Exclusions must be explicit, and unfinished full coverage must not be reported as complete.

## Establish repository state

- Follow applicable `AGENTS.md`. Read current status in `HANDOFF.md`, then only decisions or linked notes relevant to the target. Do not reread unchanged instructions already available in context.
- Respect explicit user scope decisions. Verify mathematical premises against current contracts. Revisit historical implementation or performance choices when their assumptions, callers, parameters, platform, or measurements change; explain the new evidence rather than treating preferences as permanent prohibitions.
- Inspect `git status` and the relevant staged and unstaged diffs. Treat existing changes as user-owned evidence, not as review fixes.
- Track inspected files, contract-sensitive callers, relevant features/assets, and gaps as work proceeds. A short task needs only a compact coverage statement; full reviews use the chosen guide's ledger.

## Review the target

- Trace public contracts from their highest owning boundary into private kernels and representative callers.
- Compare related APIs as a family rather than judging names and parameter order in isolation.
- Use the checklist to examine numerical invariants and maintenance costs; distinguish actual defects from style preferences.
- Choose validation from inspected risks. Pure reviews use read-only formatting checks (`cargo fmt --all -- --check`) when useful, never formatting writes. Do not change tests, repair unrelated failures, or weaken checks without implementation authorization. Passing commands do not establish source coverage.
- Recommend tests for independent contracts or durable diagnostics, not merely to mirror the implementation. Keep test and benchmark cleanup within the requested scope.

## Use delegation deliberately

- Delegate read-only work only when independent portions and sufficient workload justify it. Small targets can be reviewed directly; API, math/performance, and validation are coverage dimensions, not a required number of agents.
- Assign explicit boundaries and request inspected files, evidence, gaps, and suggested checks. The main agent owns the inventory, adjudicates findings against source and callers, and resolves contradictions.
- If a sub-agent fails or cannot finish, take over the uncovered work using its evidence; do not count unfinished work as reviewed or repeat verified coverage without a reason.

## Report results

- For defect reviews, lead with confirmed findings ordered as P0 (critical), P1 (high), P2 (normal), and P3 (low), each with a precise file and line reference. For refactoring analysis, organize around the requested decisions while keeping confirmed defects separate.
- For every finding, state the violated contract, the triggering conditions, the observable impact, and why an existing boundary or invariant does not make it safe.
- Separate confirmed defects from intentional contracts, residual risks, and improvements; do not assign defect priorities to optional improvements or unproven risks. A missing test alone is a validation recommendation, not a prioritized defect, unless it violates an explicit testing requirement; do not infer a behavior bug from absent coverage.
- When there are no findings, say so plainly and name the most important residual risks or unverified paths.
- End with scope-sized coverage (inspected, sampled, excluded) and validation performed. Do not update `HANDOFF.md` during a review unless the user asks; when asked, record only current recoverable state rather than a history log.
