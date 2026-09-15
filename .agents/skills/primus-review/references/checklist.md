# Shared review checklist

Apply sections relevant to the selected depth and target. For full review, consider every section; record material exclusions or unverified paths without enumerating routine non-applicable items. Repository conventions remain in `AGENTS.md`.

## 1. Contract and representation

- Identify the mathematical operation, input domain, output range, modulus convention, canonical or lazy state, and exact representation.
- Check coefficient order, polynomial layout, CRT/RNS limb order, NTT/Fourier domain, signedness, word width, alignment, and buffer length.
- Confirm that constructors and conversions establish the invariants later methods rely on.
- Check overflow proofs, narrowing conversions, shifts, wrapping operations, and edge moduli against actual integer widths.
- Verify panic, error, and `unsafe` preconditions. Memory-safety requirements must hold in release builds.

## 2. Types and API surface

- Does each type name expose its mathematical role and representation without unnecessary abbreviations?
- Does the type enforce a real invariant, prevent misuse, or own reusable state? Check abstraction and naming choices against `AGENTS.md` and concrete callers.
- Check visibility, re-exports, feature gates, trait implementations, conversions, ownership, borrowing, and the validity of `Default`.

## 3. Readability, maintainability, and macros

- Confirm that key control flow, ownership, representation changes, and numerical invariants can be understood locally without unnecessary indirection.
- Trace helpers for fragmented control flow or hidden numerical differences; identify the concrete cost before recommending a change.
- Comments should explain non-obvious contracts and algorithmic reasons rather than restate code. Dense optimized kernels should document the proof or invariant that justifies their shape.
- For non-trivial declarative or procedural macros, inspect the definition, representative invocations, generated API, relevant expansion when needed, and diagnostic/maintenance cost.
- Assess macro expansion and diagnostic costs against the abstraction criteria in `AGENTS.md`.
- Do not report style preference alone as a finding; identify the concrete comprehension, modification, diagnostic, or misuse cost.

## 4. Function families

Build a small signature matrix for non-trivial families. Include the operation stem, input roles, output location, scratch/context, normalization state, and return type.

- Keep scalar, slice, SIMD, checked, lazy, conversion, and in-place variants on the same operation stem when their contracts are equivalent.
- Check the repository meanings of `try_`, `lazy_`, `_assign`, `_to`, `_slice`, `_rev_assign`, `new`, `from_raw`, `set`, and `set_modulus`.
- Do not force similar names onto operations whose representation, range, ownership, or failure contract differs.
- Check symmetry between forward/reverse or left/right variants and whether asymmetry is intentional and documented.
- Search workspace callers before recommending a rename or signature change.

## 5. Parameters

- Compare parameter roles and order within the relevant API layer and function family; make input/output aliasing explicit rather than imposing a workspace-wide order.
- Check whether scalar values, slices, contexts, and scratch storage are passed with appropriate ownership and mutability.
- Identify whether repeated parameters represent independent choices or duplicate an invariant already owned elsewhere.
- Confirm exact length relationships and whether they belong in the signature, documentation, a public boundary check, or a private `debug_assert!`.

## 6. Correctness and safety

- Trace boundary validation into kernels; look for missing checks as well as repeated release checks in hot paths.
- Distinguish caller-controlled invalid input from internal invariant violations.
- Avoid caller-triggerable `unreachable!`, accidental wrapping, invalid shifts, and unchecked indexing or pointer arithmetic without a release-mode proof.
- Compare scalar, SIMD, NTT, Fourier, CRT/DCRT, and RNS backends when they implement the same semantics.
- Check zero lengths, tails, aliasing, overlap, non-canonical inputs, and maximum supported modulus where applicable.

## 7. Performance

- Inspect hot loops for allocation, cloning, collection, repeated conversion, repeated validation, avoidable branches, and dispatch inside inner loops.
- Check reuse of precomputation, representation, scratch, and context storage.
- Prefer `chunks_exact` where divisibility is already proven and select scalar/SIMD or specialized/general kernels outside inner loops.
- Treat performance concerns as findings only with a clear hot path and mechanism; require measurement before claiming an improvement.

## 8. Callers, docs, and validation assets

- Search direct callers, trait adapters, public re-exports, tests, examples, benchmarks, and documentation.
- Rustdoc for public APIs and non-trivial internals should state assumptions, representation changes, output range/location, accumulator behavior, panic conditions, and workspace requirements when signatures cannot.
- Within the review scope, map tests to independent contracts or diagnostic purposes. Recommend cleanup only for demonstrated redundancy, without removing distinct boundary coverage or expanding a local review into crate-wide test cleanup.
- Prefer deterministic inputs or a simple oracle and focused differential coverage for paired backends, but do not add a test merely to demonstrate an already-proven implementation.
- Within scope, map benchmarks to stable performance questions; identify redundant cases or comparisons whose alternative no longer exists.
- Benchmarks should measure equivalent work and keep setup outside timed closures unless setup is the subject.
- Check feature combinations that change implementation or API surface.

## 9. Finding threshold

Use the finding threshold and decision-handling rules in `SKILL.md`. Missing coverage alone is a validation recommendation, not evidence of incorrect behavior. Explain concrete misuse or maintenance costs separately from optional consistency preferences.
