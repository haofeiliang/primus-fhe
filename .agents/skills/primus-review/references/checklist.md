# Shared review checklist

Apply every section that is relevant to the requested scope. Record non-applicable sections in the coverage ledger instead of silently skipping them.

## 1. Contract and representation

- Identify the mathematical operation, input domain, output range, modulus convention, canonical or lazy state, and exact representation.
- Check coefficient order, polynomial layout, CRT/RNS limb order, NTT/Fourier domain, signedness, word width, alignment, and buffer length.
- Confirm that constructors and conversions establish the invariants later methods rely on.
- Check overflow proofs, narrowing conversions, shifts, wrapping operations, and edge moduli against actual integer widths.
- Verify panic, error, and `unsafe` preconditions. Memory-safety requirements must hold in release builds.

## 2. Types and API surface

- Does each type name expose its mathematical role and representation without unnecessary abbreviations?
- Are equivalent roles named consistently across sibling modules and crates?
- Does the type enforce a real invariant, prevent misuse, or own reusable state? Flag wrappers that only move parameters or branches without doing so.
- Check visibility, re-exports, feature gates, trait implementations, conversions, ownership, borrowing, and the validity of `Default`.
- Check `#[must_use]` on constructors, accessors, conversions, and pure computations whose discarded result is probably a mistake; do not add it to in-place operations.

## 3. Readability, maintainability, and macros

- Confirm that key control flow, ownership, representation changes, and numerical invariants can be understood locally without unnecessary indirection.
- Check whether helpers and abstractions centralize a real invariant or stable repeated structure. Flag one-off wrappers, fragmented control flow, premature generalization, and abstractions that hide important differences between numerical backends.
- Comments should explain non-obvious contracts and algorithmic reasons rather than restate code. Dense optimized kernels should document the proof or invariant that justifies their shape.
- For non-trivial declarative or procedural macros, inspect the definition, representative invocations, generated API, relevant expansion when needed, and diagnostic/maintenance cost.
- Keep a complex macro only when it materially removes stable repetition, centralizes generated invariants that must remain synchronized, or performs necessary compile-time generation more clearly than ordinary Rust. Otherwise prefer explicit functions, generics, traits, or implementations and recommend removing the macro.
- Do not report style preference alone as a finding; identify the concrete comprehension, modification, diagnostic, or misuse cost.

## 4. Function families

Build a small signature matrix for non-trivial families. Include the operation stem, input roles, output location, scratch/context, normalization state, and return type.

- Keep scalar, slice, SIMD, checked, lazy, conversion, and in-place variants on the same operation stem when their contracts are equivalent.
- Check the repository meanings of `try_`, `lazy_`, `_assign`, `_to`, `_slice`, `_rev_assign`, `new`, `from_raw`, `set`, and `set_modulus`.
- Do not force similar names onto operations whose representation, range, ownership, or failure contract differs.
- Check symmetry between forward/reverse or left/right variants and whether asymmetry is intentional and documented.
- Search workspace callers before recommending a rename or signature change.

## 5. Parameters

- Names should identify roles such as `input`, `lhs`, `rhs`, `addend`, `acc`, `output`, `scratch`, `context`, and `modulus`.
- Within one API layer and function family, keep equivalent roles in the same order. Do not impose one global order across public wrappers, trait methods, and private kernels when their established conventions differ.
- Prefer output and accumulator placement that matches sibling APIs and makes aliasing clear.
- Check whether scalar values, slices, contexts, and scratch storage are passed with appropriate ownership and mutability.
- Reject repeated parameters only when a context or type would centralize a proven invariant, remove confirmed duplication, prevent common misuse, or measurably improve a hot path.
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
- Map every retained test to an independent contract, regression, or diagnostic purpose. Recommend deleting duplicate coverage, mechanical forwarding tests, checks of standard-library behavior, and temporary investigation tests.
- Prefer deterministic inputs or a simple oracle and focused differential coverage for paired backends, but do not add a test merely to demonstrate an already-proven implementation.
- Map every retained benchmark to a stable performance question or long-term regression signal. Recommend deleting redundant cases, comparisons whose alternative no longer exists, and investigative benchmarks after their decision is made.
- Benchmarks should measure equivalent work and keep setup outside timed closures unless setup is the subject.
- Check feature combinations that change implementation or API surface.

## 9. Finding threshold

Report a finding only when code and callers establish a concrete defect, contract mismatch, unsafe condition, maintainability inconsistency with real misuse cost, or durable coverage gap. Record plausible but unproven concerns as residual risks, not findings. Do not reopen a still-current `HANDOFF.md` decision unless new source, caller, or validation evidence contradicts the basis for that decision.
