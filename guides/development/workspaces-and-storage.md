# Workspaces, storage and serial reuse

Use the [library guide](README.md#distinguish-environment-from-workspace) for API navigation. This note records the ownership choices and measurements behind the workspace APIs.

## Names and binding

A `Workspace` owns reusable temporary buffers and their shape. NTT/Fourier external products, CMux, encryption, decryption, key switching, automorphisms, trace, RNS conversion and expansion use this name. Borrowed groups use `WorkspaceRefMut`. The lattice entry point is `primus_lattice::workspace`; scheme crates re-export their workspaces.

FFT backends implement `FftTable::Workspace` and `new_workspace`. `FftEngine::from_workspace`, `zeroize_workspace` and `into_parts` support explicit reuse. Built-in FFT workspaces retain their allocation and length when erased. Local temporary slices and third-party `PodBuffer`/`PodStack` remain scratch; they are not new wrapper types.

`TfheContext` retains validated parameters and a transform table. `RingContext` and `FieldContext` describe arithmetic capabilities. An `Evaluator` or `FftEngine` binds resources and runs operations. The private NTRU `RotationState` couples a borrowed control-key variant with its required workspace. These roles are distinct from a buffer group.

Workspace lengths do not establish key identity, a decomposition basis, a modulus, or an FFT table's evaluation order. Read each operation's representation requirements. GLWE external-product `rebind` changes decomposition metadata without allocation when the GLWE shape is unchanged; `with_rebound` restores the original layout on unwind. Resizing to another GLWE shape may allocate.

## Storage decisions

| Consumer | Storage and reason |
| --- | --- |
| NTRU external products; GLWE Fourier key switching | Existing aligned numeric arrays use `ABox`; ordinary carries/digits use `Box`. Their lengths are fixed, and views remain ordinary slices. |
| NTRU CMux; GLWE ternary CMux; DCRT GLev decomposition; exact RNS conversion; NTRU-to-LWE return | Ordinary `Box` expresses the bound geometry. No stronger alignment requirement is introduced. |
| High-precision LUT selectors, factors, candidates and ciphertext temporaries | Ordinary `Box`; binding determines every length. Public output allocation still returns the existing owned ciphertext types. |
| Resizable GLWE external products, BR and gadget-generation workspaces | Keep `Vec`/`AVec`, including capacity reuse and existing resize/rebind semantics. |
| FFT tables and workspaces | Keep existing aligned boxed buffers and backend-specific `PodBuffer`, including their erase/drop behavior. |
| Secret keys and private encryption/decryption intermediates | Keep existing storage and erasure. Secret-key zeroization may invalidate a key by clearing its length; workspace zeroization may instead preserve its shape. |
| Public, BR, sparse, KS, trace and scheme-switch keys | Keep existing coefficient storage. The alignment experiment below does not justify a general migration. Object-vector alignment would not align each object's separate allocation. |
| Modulus tables, RNS bases, metadata and public owned-output aliases | Keep their current representations; a buffer cleanup does not change mathematical tables or introduce an allocator framework. |

A fixed-length container is an ownership choice, not a speed claim. The migrated arrays are initialized at their final length. With aligned-vec 0.6.4, `into_boxed_slice` transfers a full-capacity allocation; its shrink path runs only when capacity exceeds length. No extra online conversion or allocation is needed. `primus_data` continues to support aligned `Data`/`DataMut`, without forcing them into the iterator-based `DataOwned` contract.

A cache-aligned base pointer does not align every subview. Polynomial strides in the measured N=1024 workload preserve alignment; an LWE entry has n+1 coefficients and generally does not. Public arithmetic still accepts normally aligned slices, including offset inputs. Keys or workspaces must not add padding without a separate layout design.

## Serial reuse in high-precision lookup

One-hot CBS already reuses PBS's external-product workspace for BR, trace and scheme switching. Table selection and encrypted rotation now borrow that same workspace between one-hot calls. The NTT entry point is `OneHotCircuitBootstrapEvaluator::external_product_workspace`; Fourier's `external_product_workspaces` returns the FFT engine and external-product buffers together. Borrowers retain polynomial lengths and the FFT table identity. Every subsequent one-hot call overwrites its scratch before reading it.

The high-precision evaluator therefore owns no second external-product workspace or FFT engine. Each evaluator still has independent mutable state, and borrowing excludes concurrent mutation. Existing one-hot/PBS conversion and recovery retain their ownership contracts. The separate return workspace belongs to the outer lookup output stage; no general mutable view into all PBS internals is exposed.

Existing size/domain boundaries and semantic polynomial/ciphertext iterators describe batches. Table groups contain M polynomials; ciphertext iterators traverse one complete object at a time. Candidate compaction remains indexed because a group must be consumed before its result overwrites the prefix. No additional generic batch abstraction is needed.

Partial reverse trace with r>1 retains r equally spaced coefficients; CBS needs separate constant projections of gadget entries. It cannot replace those projections. The real serial consumer already uses `project_prefix_coefficients_with_scratch_to`. Standalone partial-trace callers have their own trace workspace, so an additional partial-trace scratch API currently has no independent consumer.

## Measurements

Measured on 2026-09-28 with AMD Ryzen 9 9955HX3D, x86_64 Linux, rustc 1.100.0-nightly (bff8e12ff5, LLVM 23.1.0), and the repository's `target-cpu=native` configuration. The comparison baseline is `85ea4cf` plus the naming-only changes. These are functional fixtures, not security recommendations.

Temporary variants of the existing lattice NTRU benches compared ordinary Vec-backed keys and guaranteed cache-aligned ABox keys, before and after the fixed-workspace migration. Both variants borrowed the same kind of ciphertext slice and used identical deterministic coefficients. Tests covered N=1024, u32/u64, specialized NTT, RustFFT and TFHE-FFT, with default features and SIMD on the same nightly compiler. The NTT moduli were 132120577 and 1125899906826241; radix bits were 9 with 3/5 levels. Fourier used native moduli with 3/7 levels. Setup and conversion were outside timing: one iteration was one external product, 15 samples, 200 ms warmup and 1 s measurement.

Ordinary versus aligned key differences were small (roughly 0–2% in the initial runs) and did not establish a consistent benefit across configurations. The ordinary allocator may itself return aligned addresses; this was a container comparison, not a controlled misalignment study. Workspace-container changes also produced small improvements and regressions. These results support neither a general key migration nor a speedup claim for boxed storage. Temporary benchmark variants were removed.

The complete [lookup pipeline fixture](../../crates/primus_tfhe_ntru_lut/IMPLEMENTATION.md#benchmark-fixture) measures retained requested heap and asserts zero online allocation. Its u64/N=1024/n=64/M=4/c=7/d=5/o=3 parameters and key generation were unchanged.

| Backend | Lookup workspace before → after | Retained reduction | Pinned complete lookup before → after |
| --- | --- | --- | --- |
| NTT | 731152 → 705552 bytes | 25 KiB | 7.084 → 7.053 ms |
| RustFFT | 903184 → 861200 bytes | 41 KiB | 7.985 → 8.169 ms |
| TFHE-FFT | 903184 → 861200 bytes | 41 KiB | 6.289 → 6.256 ms |

The pinned comparison used logical CPU 0, SIMD, 20 samples, 500 ms warmup and 2 s measurement, running the new executable first to reverse the earlier unpinned comparison's order. Entries are Criterion mean estimates. Server-key retained heap stayed at 5462856 bytes for NTT and 6749368 for Fourier. Heap counts exclude stack, allocator metadata and shared context/tables. Existing setup checked known outputs, phase errors and zero online allocations.

Memory reduction is established; latency is a tradeoff. RustFFT was about 2.3% slower in that pinned run. A subsequent isolation run retained AVec in the NTRU external-product workspace while keeping shared lookup buffers: 8.091 ms versus 8.148 ms with boxed workspace buffers. Container layout accounts for part, not all, of the observed difference. The current choice preserves fixed-length ownership and the smaller retained workspace, without claiming improved throughput. Revisit this choice when parameters, compiler or backend change.

Reproduce the complete-workload comparison with the existing pipeline target, on an available fixed CPU, using separate baseline names for each revision:

```sh
taskset -c 0 cargo +nightly bench -p primus_tfhe_ntru_lut --bench pipeline --features simd -- '/complete$' --sample-size 20 --warm-up-time 0.5 --measurement-time 2 --noplot --save-baseline workspace-current
```

Construction heap and online allocation are measured by that harness; key-generation latency and Vec-to-aligned-key conversion latency were not claimed or optimized. The lattice comparisons can be repeated with `ntru_ntt` and `ntru_fourier`, filtering `n1024.*external_product_coeff`, and preparing a second key with `AVec::from_iter(CACHELINE_ALIGN, key.as_ref().iter().copied()).into_boxed_slice()` before timing. Borrow it through the same NGSW slice view as the ordinary key.
