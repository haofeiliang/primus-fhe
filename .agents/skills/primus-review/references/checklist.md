# Review checklist

AGENTS defines coding, numerical, testing and documentation standards. Use this checklist to trace evidence rather than repeat those standards. Bounded analysis reads relevant sections; full review covers all sections.

## Contracts and numerical behavior

- Identify the exact operation, input domain, output range, representation, ordering, normalization and buffer lengths. Check constructors, imported contracts and public consumers agree.
- Follow overflow, narrowing, shifts, wrapping, lazy ranges and unsafe access; distinguish checked errors from unchecked mathematical preconditions and partial output writes.
- Trace where validation occurs. Confirm kernels receive established invariants without duplicated per-coefficient checks; safe public APIs must still establish memory safety in release.
- Compare scalar/SIMD, NTT/Fourier, CRT/DCRT/RNS and checked/lazy variants on the same mathematical operation. Include zero lengths, tails, aliasing, boundary moduli and feature/platform dispatch where relevant.

## API families and implementation

- Compare constructors/reset/rebind, allocating/`_to`/`_assign`, forward/reverse and scalar/slice methods as families. Check ownership, visibility, re-exports, names, parameter roles and rustdoc against their real contracts.
- Determine whether each abstraction concentrates an actual invariant or merely hides parameters and representation differences. Inspect macro generators and representative expansions when they own the contract.
- Trace fragmented helpers and dispatch before proposing consolidation. Explain concrete misuse or comprehension costs, not stylistic preference.

## Performance

- Find online allocations, clones, collects, conversions, repeated preparation and dispatch; check scratch lifetime, reset and reuse across calls.
- Distinguish likely cost mechanisms from measured regressions. Microbenchmarks do not establish full PBS/KSK/BR performance or equal security parameters.
- Check benchmarks compare equivalent work with truthful IDs, throughput and timing boundaries; retain only stable performance questions within the requested scope.

## Consumers and validation assets

- Search direct callers, adapters, re-exports and contract-sensitive consumers outside the target. Check feature gates and parameter/representation transitions.
- Map tests to independent contracts or regressions. Distinguish redundant forwarding tests from separate boundaries and paired-backend oracles; assess examples and benchmark setup too.
- Check rustdoc/README explains hidden range, layout, normalization, output, clearing and workspace requirements, including inherited premises. Verify paired language documents and links when affected.
- Validate suspected defects narrowly before broad commands. Report untested features/platforms and unrelated failures without weakening checks or expanding a pure review into repairs.
