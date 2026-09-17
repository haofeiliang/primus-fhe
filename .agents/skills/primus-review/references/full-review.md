# Full review coverage

Use only after selecting full review in SKILL.md. Review standards come from AGENTS and the checklist; this guide defines completeness.

## Inventory by scope

| Scope | Required inventory |
| --- | --- |
| File | Entire target, tests and feature gates; parent module, public re-exports, imported contracts and siblings implementing the same API/representation families |
| Module | Root and all declared children, feature-gated sources, re-exports, local tests and associated examples/benches/docs |
| Crate | Manifest, all source files, tests/examples/benches/docs, features/optional dependencies, build scripts and generated-source entry points |

Read every handwritten source file in scope, including private kernels and gated paths. For generated code, inspect generators and generated contracts. Inventory representations, construction/conversion paths and paired implementations; trace validation, normalization, allocation and dispatch from public boundaries into kernels.

## Callers and validation

Search workspace references to all public or contract-sensitive items. A file review traces every private helper caller in its parent module; module/crate reviews also inventory cross-file private-kernel references. Read every contract-sensitive or high-risk caller body. Lower-risk caller bodies may be sampled only with an explicit selection boundary.

Inspect all validation assets specific to the scope and relevant feature combinations. A whole crate review includes every crate-local test, example and benchmark. Run focused checks according to risk; tests passing cannot substitute for source review.

Delegation must preserve this coverage. The main agent reads roots/manifests/public boundaries, checks each finding's evidence and accounts for unfinished assignments. Sequential work has the same completeness requirement.

## Coverage ledger

Keep a compact ledger of:

- Source/manifest inventory, including feature-gated and generated paths: read, delegated/completed, or explicitly excluded.
- Public API and caller search: exhaustive symbol coverage, bodies read, sampling rule and gaps.
- Representation/API families compared and contract-sensitive dependencies inspected.
- Tests, docs, examples, benches, features and architecture paths covered or excluded.
- Commands actually run, failures and intentionally unverified paths.

Unexplained omissions make the review incomplete. A file-only read is not a complete review if imported contracts or consumers remain unchecked; a crate review cannot be a source sample presented as exhaustive.
