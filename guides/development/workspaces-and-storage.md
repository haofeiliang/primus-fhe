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

A fixed-length container is an ownership choice, not a speed claim. The migrated arrays are initialized at their final length. With aligned-vec 0.6.4, `into_boxed_slice` transfers a full-capacity allocation; its shrink path runs only when capacity exceeds length. No extra online conversion or allocation is needed. `primus_data` continues to support aligned `Data`/`DataMut`, with explicit alignment during construction rather than an implicit `DataOwned` allocation policy.

A cache-aligned base pointer does not align every subview. Polynomial strides in the measured N=1024 workload preserve alignment; an LWE entry has n+1 coefficients and generally does not. Public arithmetic still accepts normally aligned slices, including offset inputs. Keys or workspaces must not add padding without a separate layout design.

## NTRU parameter sharing

`NtruParameters` and `NlevParameters` share an `Arc<NtruParametersInner>` containing N, q and prepared secret/noise samplers. The ordinary codec and each gadget basis remain independently owned. Separate key-noise roles construct separate inner states. This shares distribution tables, never secret coefficients, RNG state or mutable workspace buffers; online operations borrow the inner state without cloning an Arc.

Measured on 2026-10-03 against `d8eedf4f`, on AMD Ryzen 9 9955HX3D, x86_64 Linux, rustc 1.98.1 (48a229cea, LLVM 22.1.8), default features and the repository's `target-cpu=native`. Construction and retained-memory measurements used the existing `primus_test_allocations::CountingAllocator`, not timing or RSS. The three measured stages retained all returned values: create `NtruParameters::new(1024, 16u64, NativeModulus::new(), distr, 3.2)`, derive `NlevParameters::with_ntru_params(&ordinary, base_log=8, levels=Some(3))`, then clone that NLev. Run `measure` separately for each stage; all three parameter objects remain alive until after the measurements.

| Secret distribution | Stage | Allocation count before → after | Allocated bytes before → after | Released bytes before → after |
| --- | --- | --- | --- | --- |
| Sparse ternary | Ordinary construction | 2 → 3 | 632 → 1096 | 312 → 312 |
| Sparse ternary | Gadget derivation | 3 → 2 | 392 → 72 | 0 → 0 |
| Sparse ternary | Gadget clone | 3 → 2 | 392 → 72 | 0 → 0 |
| Gaussian, sigma=3.2 | Ordinary construction | 4 → 5 | 1264 → 1728 | 624 → 624 |
| Gaussian, sigma=3.2 | Gadget derivation | 4 → 2 | 712 → 72 | 0 → 0 |
| Gaussian, sigma=3.2 | Gadget clone | 4 → 2 | 712 → 72 | 0 → 0 |

For these three live parameter objects, `sum(size_of_val)` fell from 1856 to 408 bytes. Total retained requested heap (`sum(allocated_bytes - released_bytes)`) fell from 1104 to 928 bytes for sparse ternary and from 2064 to 1248 bytes for Gaussian secrets. Inline plus retained heap therefore fell from **2960 to 1336 bytes**, or **3920 to 1656 bytes**, respectively. This estimate excludes allocator overhead and stack placement. The tradeoff is one additional 464-byte allocation at initial construction; the inner state was previously inline, so heap bytes alone do not express its total memory cost. Each gadget still allocates its own basis arrays. The temporary measurement harness was removed after recording these results.

Online encryption was measured separately using the existing [encryption benchmark](../../crates/primus_ntru/benches/encryption.rs), with one `encrypt_to` per iteration. Setup, keys, tables and output allocation were excluded. N=1024, u64, t=16, sparse ternary secret, noise sigma=3.2; NTT used q=1125899906826241 and Fourier used the native modulus. Commands on the baseline and changed tree, respectively:

```sh
cargo bench -p primus_ntru --bench encryption -- 'n1024/encrypt_to' --sample-size 20 --warm-up-time 0.2 --measurement-time 1 --save-baseline before-3b
cargo bench -p primus_ntru --bench encryption -- 'n1024/encrypt_to' --sample-size 20 --warm-up-time 0.2 --measurement-time 1 --baseline before-3b
```

| Backend | Before, µs (95% CI) | After, µs (95% CI) |
| --- | --- | --- |
| NTT | 10.679–10.688 | 10.452–10.640 |
| RustFFT | 6.8924–6.9093 | 6.9015–6.9046 |
| TFHE-FFT | 6.8672–6.8726 | 6.8720–6.8969 |

This short local comparison found no regression; Fourier changes were not statistically significant, and NTT was slightly faster. The reason for sharing is reduced parameter duplication, not a general claim of faster encryption. SIMD was checked functionally, not benchmarked in this comparison. The ordinary encoding, RNG draw order, inverse filtering and gadget arithmetic are unchanged.

## RNS base sharing

`RNSBase` owns an `Arc` to its immutable ordered moduli, numeric modulus cache, Q, punctured products and inverse factors. Cloning a base shares these buffers; independent construction or extension creates a new table. `BfvRnsCodec`, its internal converter and derived `CrtGlevParameters` therefore retain handles to the same Q precomputation. Sampling remains in its existing shared state. BFV scaling, gadget reconstruction weights and conversion matrices keep their separate ownership. The unused ordinary `delta_mod_q` vector was removed; encryption already uses the codec's Shoup factors.

Measured on 2026-10-03, on AMD Ryzen 9 9955HX3D, x86_64 Linux, rustc 1.98.1 (48a229cea, LLVM 22.1.8), default features and repository compiler flags. As in the NTRU comparison above, the existing `CountingAllocator` measured requested allocation traffic while retaining returned objects. The fixture used u64 Barrett moduli `[1125899906826241, 1125899906629633]`, k=1, N=1024, t=2, gamma=2305843009213554689, sparse ternary secrets, sigma=3.2 and a full gadget basis with logB=20. Measure ordinary construction, `CrtGlevParameters::with_glwe_params`, and gadget clone separately.

| Stage | Allocation count before → after | Allocated bytes before → after | Released bytes before → after |
| --- | --- | --- | --- |
| Base construction alone | 6 → 7 | 176 → 312 | 48 → 32 |
| Base clone | 4 → 0 | 128 → 0 | 0 → 0 |
| Ordinary construction | 35 → 31 | 2080 → 2192 | 576 → 544 |
| Gadget derivation | 12 → 7 | 488 → 344 | 0 → 0 |
| Gadget clone | 12 → 7 | 488 → 344 | 0 → 0 |

For the ordinary parameter, derived gadget and gadget clone together, inline storage plus retained requested heap fell from **3888 to 3208 bytes** (about 17.5%). This excludes allocator overhead and is not RSS. Creating an unshared base now costs an extra Arc allocation and retains the numeric cache; the benefit comes from sharing the repeated bases. No global interning is performed. BFV encode and decode with prepared buffers made zero measured allocations. The temporary allocation probe was removed after measurement.

Online screening used the existing `decompose`, `bfv_rns` and `key_switching` benchmarks, with setup outside measurement. Old and new executables ran sequentially on CPU 2; no compilation ran concurrently. Use these commands on each tree, with `--save-baseline rns-owned` before and `--baseline rns-owned` after:

```sh
taskset -c 2 cargo bench -p primus_rns --bench decompose -- --warm-up-time 0.5 --measurement-time 1.5 --sample-size 20 --noplot
taskset -c 2 cargo bench -p primus_encoding --features rns --bench bfv_rns -- --warm-up-time 0.5 --measurement-time 1.5 --sample-size 20 --noplot
taskset -c 2 cargo bench -p primus_glwe_rns --bench key_switching -- 'N=1024' --warm-up-time 0.5 --measurement-time 1.5 --sample-size 20 --noplot
```

The key-switch group fixes its sample count to 10. An initial roughly 1.7% fast-conversion regression was removed by copying the small destination arithmetic context before its coefficient loop. Alternating old/new runs then measured 3-to-2 conversion at 36.22–36.42 µs before and 36.02–36.18 µs after (point estimates, N=4096, 20 samples, 1.5 s). This is a check against regression, not a general speedup claim. SIMD is checked functionally; these timings use default features.

Final N=4096 BFV point estimates were 16.54 → 16.53 µs (single-limb decode), 2.33 → 2.31 µs (two-limb unsigned accumulation), 6.20 → 6.24 µs (centered accumulation), and 43.65 → 43.75 µs (two-limb decode). N=1024 full key switches measured 24.52 → 24.38 µs (CRT), 36.15 → 36.11 µs (grouped hybrid), and 36.73 → 36.57 µs (singleton hybrid). These local results are within about 1%; they do not establish a universal performance bound.

## Batched NTRU-to-LWE return

`NtruLweKeySwitchingBatchWorkspace` keeps one canonical Q→q polynomial and fixed
tiles for extracted and switched LWEs. Eight samples feed the existing LWE batch
key-switch kernel; a bounded copy delivers each output tile to the caller's
separate ciphertext objects. The allocation is `N + 8*(N+1) + 8*(n+1)` elements
for ring length N and target dimension n, independent of total output count.
No online allocation or output-count-sized intermediate buffer is needed.

NTT/Fourier PBS evaluators retain this workspace alongside the small scalar
return workspace. Interleaved ManyLUT shares the conversion across outputs,
including sparse PBS; ordinary and single-output interleaved PBS keep the direct
path. At N1024/n728, the extra requested heap is 60,224 bytes for u32 or 120,448
bytes for u64, excluding object/allocator overhead. Conversion from a complete
PBS to CBS/MVB retains these buffers. Standalone CBS/one-hot omits ordinary-return buffers and allocates them only when explicitly
converted into a complete PBS; see the ownership table below.
The [return benchmark](../../crates/primus_ntru/benches/lwe_return.rs) measures
conversion, extraction, key switching and tile-copy costs together; the backend
`mvb` benchmarks measure complete interleaved and factorized requests.

Factorized MVB submits each different product through its bound PBS
evaluator's private `LweReturnEvaluator` binding and `LweReturnBatchWorkspace`.
The binding borrows the key and q; the workspace owns bounded storage and the
stream protocol. Internally the binding uses
`modulus_switch_extract_at_to` into `extracted_slot_mut(slot)`, followed by
`key_switch_extracted_batch_to` on the filled output prefix. Each polynomial
gets its own Q→q conversion, but only extracted LWEs survive until a tile is
returned. The existing batch workspace is reused, adding no retained heap.
A singleton tile key-switches directly to the caller output, avoiding the
intermediate output copy. Samples retain their order and equal scalar returns.

## Serial reuse in high-precision lookup

The public high-precision LUT owns a boxed pool of unique encoded polynomials,
one descriptor per output: a single polynomial reference for direct lifting,
or an owned prefix-index array for table selection.
Construction hash buckets are temporary. Equal prefixes allow a BR-basis lift
followed by the usual low-chunk rotations; when all outputs qualify, the evaluator
omits table selectors and candidates as well as high-chunk CBS. Mixed tables
keep those shared buffers. Embedded one-hot scratch is retained. See the
[table layout](../../crates/primus_tfhe_ntru_lut/IMPLEMENTATION.md#public-table-storage-and-compiled-choices).

One-hot CBS reuses its BR external-product workspace for BR, trace and scheme switching. Table selection and encrypted rotation now borrow that same workspace between one-hot calls. The NTT entry point is `OneHotCircuitBootstrapEvaluator::external_product_workspace`; Fourier's `external_product_workspaces` returns the FFT engine and external-product buffers together. Borrowers retain polynomial lengths and the FFT table identity. Every subsequent one-hot call overwrites its scratch before reading it.

The high-precision evaluator therefore owns no second external-product workspace or FFT engine. Each evaluator still has independent mutable state, and borrowing excludes concurrent mutation. Existing one-hot/PBS conversion and recovery retain their ownership contracts.

The family `LweReturnEvaluator` binds only the coefficient-domain return key
and q, without allocating or carrying a transform-table generic. Callers prepare
scalar scratch with `new_scalar_workspace()` and/or batch scratch with
`new_batch_workspace()`, then pass the needed workspace explicitly. Both
backends use the same concrete implementation. Shared-input interleaved returns
reuse one Q→q conversion; streams independently round each source and retain
only its extracted LWE. This does not unify the NTT/Fourier numerical kernels.

Custom streams use `batch.begin_batch()` → ordered `append_at(..., &mut batch)`
→ `return_batch_to(..., &mut batch)` on the return binding. Submission consumes exactly the current prefix, including an
empty or partial tile, then invalidates it. `discard_batch` cancels it; restart
invalidates the old prefix. Input/index and output-count/dimension rejection
leave that prefix intact. Shared-prefix calls reject an active batch; separate scalar scratch remains usable.
All appends and submission in one stream must use the same actual secrets and
Q/q; the workspace tracks initialized slots, not key identity.
One-hot, table products and separately owned ordinary PBS may run between
appends because they do not own those return buffers. These state checks belong
to the stream boundary, not coefficient kernels.

Each lookup evaluator explicitly owns standalone one-hot and a return binding.
NTT allocates only scalar scratch; Fourier allocates only batch scratch and keeps
its bounded streamed schedule. Standalone one-hot has no ordinary-return buffers. Both NTRU factorized MVB backends still retain complete
PBS and use its private return evaluator. Arithmetic, tile size and scheduling
are unchanged; no new latency claim is made.

## Input, blind rotation and return ownership

Every concrete backend's private `BlindRotationEngine` binds the context, key,
selected BR scratch and coefficient accumulator; Fourier also owns its FFT
engine there. GLWE input preparation is direct for BR→KS, or owns the required
input KS and compact small LWE for KS→BR. The latter cannot be omitted by CBS.
Ordinary `Evaluator` adds its complete return stage: output KS for GLWE BR→KS,
direct extraction for GLWE KS→BR, or the NTRU return evaluator. It has no optional
missing essential workspace. GLWE BR→KS no longer allocates an unused input LWE.

A private two-state CBS resource enum contains either standalone BR/input
resources or the full retained PBS. Standalone GLWE KS→BR already has a complete
PBS, since its return is direct extraction. `bootstrapper_mut` exposes only PBS
operations, preventing replacement of the key-bound evaluator.

| CBS construction | Ordinary PBS borrow | Recovery allocation |
| --- | --- | --- |
| Standalone GLWE BR→KS | `None` | Allocate output KS |
| Standalone GLWE KS→BR | `Some` | None |
| Standalone NTRU CBS/one-hot | `None` | Allocate scalar/batch returns |
| GLWE CBS from complete PBS | `Some` | None |
| NTRU CBS/one-hot from complete PBS | `Some` | None for any compatible return key |

GLWE engines borrow the selected BR key directly. Each active KS stage binds
its own ring KS key alongside the existing scratch. Independent BR→KS CBS can
omit the KS owner entirely; KS→BR requires it at construction, with a structured
error for missing material. `try_from_bootstrapper(pbs, circuit_key, input_codec)`
retains complete PBS. `try_into_bootstrapper(glwe_ks_key)` validates the explicit
KS key and reuses an existing stage's buffers, including for another compatible
key from the same paired secrets/transform. Only standalone BR→KS allocates
missing output KS scratch. These conversions do not change numerical kernels
or workspace layouts.

NTRU BR, return and CBS material have independent owners. Standalone CBS/one-hot
borrows only BR and CBS keys; its resources retain no return-key dependency.
`try_from_bootstrapper(pbs, circuit_key, input_codec)` keeps a complete PBS for
alternation. `try_into_bootstrapper(return_key)` checks the supplied return
material and reuses retained buffers for any compatible key, discarding pending
samples from the previous binding. Only standalone CBS prepares missing return
buffers while retaining BR/FFT storage. All allocation is
explicit at construction or conversion; online operations do not allocate.

Existing size/domain boundaries and semantic polynomial/ciphertext iterators describe batches. Table groups contain M polynomials; ciphertext iterators traverse one complete object at a time. Candidate compaction remains indexed because a group must be consumed before its result overwrites the prefix. No additional generic batch abstraction is needed.

Partial reverse trace with r>1 retains r equally spaced coefficients; CBS needs separate constant projections of gadget entries. It cannot replace those projections. The real serial consumer already uses `project_prefix_coefficients_with_scratch_to`. Standalone partial-trace callers have their own trace workspace, so an additional partial-trace scratch API currently has no independent consumer.

## NTRU resource ownership

This table records the concrete serial consumers; it does not introduce a common
resource trait. NTT and Fourier keep distinct numerical representations.

| Resource | Owner | Lifetime and serial reuse |
| --- | --- | --- |
| Coefficient accumulator/current and BR temporary polynomial | `BlindRotationEngine::workspace` | BR overwrites both; CBS projects/rotates the result; factorized MVB reuses current for each recovered product |
| BR CMux/sparse scratch and external-product workspace | Selected `RotationState` | Selected at construction; classic EP scratch is reused by CBS trace/scheme switch, then borrowed by LUT selection/rotation |
| FFT plan borrow and backend workspace | Fourier `BlindRotationEngine::fft` | One engine for BR, projection, scheme switch and LUT products; NTT uses the context table directly |
| Reverse-trace scratch and projected NLEV | CBS/one-hot evaluator | One projected selector at a time; buffers are overwritten before the next selector |
| Common rotation and factor product in transform representation | `FactorizedEvaluator` | Common rotation survives across outputs; product is reused after conversion/extraction |
| Public/encrypted selectors, aggregate rotation controls, compiled selection slots | LUT evaluator | Needed selectors survive one request; selection slots follow the compiled graph's last uses |
| Rotation factors and current/product polynomials | LUT evaluator | Factors are prepared once; current/product ping-pong during encrypted rotation |
| Return key and target q | `LweReturnEvaluator` | Read-only, allocation-free binding; no scratch or transform dependency |
| Scalar intermediate LWE, N+1 elements | `NtruLweKeySwitchingWorkspace` | Complete PBS and NTT LUT; overwritten for each return |
| Converted polynomial and extracted/switched LWE tiles | `LweReturnBatchWorkspace` | Complete PBS and Fourier LUT; one conversion for a shared source, independent conversion per streamed source; only the prepared prefix may be submitted |

Complete PBS prepares both return workspaces, and factorized MVB retains them to
permit ordinary PBS alternation. Standalone CBS/one-hot prepares neither. Resource
enums and evaluator nesting still retain the existing PBS/CBS ownership pattern;
this separation does not redesign BR/projection storage.

## Independent NTRU return workspace measurement

Measured on 2026-10-03 against `a0d5716e`, AMD Ryzen 9 9955HX3D, x86_64 Linux,
rustc 1.98.1 (48a229cea, LLVM 22.1.8), default features and the repository's
`target-cpu=native`. Old and new executables ran sequentially on logical CPU 2,
without concurrent compilation. These are the existing functional benchmark
profiles, not security recommendations.

The public LUT fixture is unchanged: n800/N1024, eight two-bit input/output
chunks, d=5, seed 42, `x*x+3*x+7`. The allocator measures complete evaluator
construction, excluding context, keys, compiled public LUT and caller output.
Retained requested heap is `allocated_bytes - released_bytes`, excluding allocator
metadata and RSS. Inline sizes are reported separately.

| LUT backend / word | Allocations before → after | Retained requested bytes before → after | Inline bytes before → after | Constructor median before → after |
| --- | --- | --- | --- | --- |
| NTT / u32 | 22 → 19 | 571460 → 508932 | 744 → 672 | 37.32 → 29.92 µs |
| NTT / u64 | 22 → 19 | 912520 → 787464 | 744 → 672 | 7.63 → 6.35 µs |
| RustFFT / u32 | 27 → 26 | 1120324 → 1116224 | 816 → 800 | 16.38 → 15.90 µs |
| RustFFT / u64 | 27 → 26 | 1068168 → 1059968 | 816 → 800 | 15.71 → 16.06 µs |
| TFHE-FFT / u32 | 27 → 26 | 1120324 → 1116224 | 824 → 808 | 14.86 → 14.44 µs |
| TFHE-FFT / u64 | 27 → 26 | 1068168 → 1059968 | 824 → 808 | 14.52 → 14.31 µs |

The NTT saving is exactly its unused batch storage,
`(N + 8*(N+1) + 8*(n+1))*size_of::<T>()`; Fourier removes the unused scalar
`(N+1)*size_of::<T>()`. Complete PBS and factorized MVB retain both allocations;
standalone CBS still has neither. Binding `LweReturnEvaluator` itself allocates
nothing. A compatible return-key rebind now retains existing PBS scratch, even
when the supplied key is a different object; existing recovery tests also decrypt
an ordinary PBS result after that rebind.

Constructor timing used a temporary probe in the existing pipeline fixture:
101 separate `try_new(context, server, table)` calls, each timed with `Instant`
from immediately before construction to its return; `black_box(&evaluator)` and
destruction follow the timer. The median excludes key/LUT preparation and drops.
`measure(|| try_new(...))` and `size_of_val(&evaluator)` provide the memory columns.
The probe was removed afterward. These short cached-allocator observations do
not imply a general constructor speedup.

Full LUT request point estimates (20 samples, 0.5 s warmup, 1.5 s measurement)
were 66.65 → 65.72 ms (NTT/u32), 50.12 → 49.25 ms (NTT/u64),
109.64 → 104.84 ms (RustFFT/u32), 57.34 → 56.42 ms (RustFFT/u64),
87.03 → 86.77 ms (TFHE-FFT/u32), and 46.45 → 45.36 ms (TFHE-FFT/u64).
Every fixture verified its decrypted outputs and measured zero online allocations.
The established benefit is smaller retained storage; these timings do not claim
an algorithmic speedup. SIMD is verified functionally, not timed here.

Complete u64 requests were also screened with the existing PBS and MVB fixtures
(30 samples, 0.5 s warmup, 3 s measurement on CPU 2):

| Backend | Ordinary PBS before → after | Shared-input ManyLUT before → after | Streamed factorized MVB before → after |
| --- | --- | --- | --- |
| NTT | 5.986 → 5.982 ms | 6.041 → 6.113 ms | 6.143 → 6.194 ms |
| RustFFT | 7.150 → 7.159 ms | 7.375 → 7.306 ms | 7.353 → 7.320 ms |
| TFHE-FFT | 5.941 → 5.981 ms | 6.171 → 6.168 ms | 6.161 → 6.175 ms |

NTT ManyLUT showed an approximately 1.2% increase on CPU 2, so it was rerun in
new/old/new/old order on CPU 4, with 1 s warmup and 3 s measurement. New versus old
estimates were 6.117/6.195 ms and 6.146/6.133 ms: the direction did not persist
across cores/runs. Ordinary PBS rechecks also varied in direction. This screening
does not establish a consistent latency regression or improvement; it leaves
roughly percent-level platform/code-layout variation unresolved. No alignment
padding or numerical-kernel change was added to tune these samples.

Reproduce online measurements with the same tree-specific toolchain, features and
profiles. Use `--save-baseline ntru-returns` before and `--baseline ntru-returns`
after; compile both versions before running their benchmark executables when
alternating them:

```sh
taskset -c 2 cargo bench -p primus_tfhe_ntru_lut --bench pipeline -- 'u(32|64)/n800_N1024/c8_d5_o8/evaluate' --warm-up-time 0.5 --measurement-time 1.5 --sample-size 20 --noplot
taskset -c 2 cargo bench -p primus_tfhe_ntru_ntt --bench pbs -- 'u64/binary/boolean/.*/complete' --warm-up-time 0.5 --measurement-time 3 --sample-size 30 --noplot
taskset -c 2 cargo bench -p primus_tfhe_ntru_ntt --bench mvb -- 'u64/mvb/classic/.*/D8_k3/(interleaved|factorized)' --warm-up-time 0.5 --measurement-time 3 --sample-size 30 --noplot
```

Use `primus_tfhe_ntru_fourier` for the corresponding PBS/MVB commands; both FFT
engines are selected. Ordinary PBS uses n800/N1024 and MVB uses n728/N1024,
D8/k3. The shared-input and streamed return schedules, Q→q-before-sign order,
transform kernels and fixed tile size are unchanged.

## Historical fixed-workspace comparison

Measured on 2026-09-28 with AMD Ryzen 9 9955HX3D, x86_64 Linux, rustc 1.100.0-nightly (bff8e12ff5, LLVM 23.1.0), and the repository's `target-cpu=native` configuration. The comparison baseline is `85ea4cf` plus the naming-only changes. These are functional fixtures, not security recommendations.

Temporary variants of the existing lattice NTRU benches compared ordinary Vec-backed keys and guaranteed cache-aligned ABox keys, before and after the fixed-workspace migration. Both variants borrowed the same kind of ciphertext slice and used identical deterministic coefficients. Tests covered N=1024, u32/u64, specialized NTT, RustFFT and TFHE-FFT, with default features and SIMD on the same nightly compiler. The NTT moduli were 132120577 and 1125899906826241; radix bits were 9 with 3/5 levels. Fourier used native moduli with 3/7 levels. Setup and conversion were outside timing: one iteration was one external product, 15 samples, 200 ms warmup and 1 s measurement.

Ordinary versus aligned key differences were small (roughly 0–2% in the initial runs) and did not establish a consistent benefit across configurations. The ordinary allocator may itself return aligned addresses; this was a container comparison, not a controlled misalignment study. Workspace-container changes also produced small improvements and regressions. These results support neither a general key migration nor a speedup claim for boxed storage. Temporary benchmark variants were removed.

The historical lookup fixture in `e55ec2e` measured retained requested heap and zero online allocation. Its u64/N=1024/n=64/M=4/c=7/d=5/o=3 parameters and key generation were held fixed for the following comparison. The [current fixture](../../crates/primus_tfhe_ntru_lut/IMPLEMENTATION.md#benchmark-fixture) uses n800/c8/d5/o8; its latency cannot be compared directly with this table.

| Backend | Lookup workspace before → after | Retained reduction | Pinned complete lookup before → after |
| --- | --- | --- | --- |
| NTT | 731152 → 705552 bytes | 25 KiB | 7.084 → 7.053 ms |
| RustFFT | 903184 → 861200 bytes | 41 KiB | 7.985 → 8.169 ms |
| TFHE-FFT | 903184 → 861200 bytes | 41 KiB | 6.289 → 6.256 ms |

The pinned comparison used logical CPU 0, SIMD, 20 samples, 500 ms warmup and 2 s measurement, running the new executable first to reverse the earlier unpinned comparison's order. Entries are Criterion mean estimates. Server-key retained heap stayed at 5462856 bytes for NTT and 6749368 for Fourier. Heap counts exclude stack, allocator metadata and shared context/tables. Existing setup checked known outputs, phase errors and zero online allocations.

Memory reduction is established; latency is a tradeoff. RustFFT was about 2.3% slower in that pinned run. A subsequent isolation run retained AVec in the NTRU external-product workspace while keeping shared lookup buffers: 8.091 ms versus 8.148 ms with boxed workspace buffers. Container layout accounts for part, not all, of the observed difference. The current choice preserves fixed-length ownership and the smaller retained workspace, without claiming improved throughput. Revisit this choice when parameters, compiler or backend change.

For future comparisons, use the pipeline target on an available fixed CPU and separate baseline names for each revision. The command below measures the current geometry; reproducing the historical numbers requires the old fixture from `e55ec2e` and its comparison revision:

```sh
taskset -c 0 cargo +nightly bench -p primus_tfhe_ntru_lut --bench pipeline --features simd -- '/evaluate$' --sample-size 20 --warm-up-time 0.5 --measurement-time 2 --noplot --save-baseline workspace-current
```

Construction heap and online allocation are measured by that harness; key-generation latency and Vec-to-aligned-key conversion latency were not claimed or optimized. The lattice comparisons can be repeated with `ntru_ntt` and `ntru_fourier`, filtering `n1024.*external_product_coeff`, and preparing a second key with `AVec::from_iter(CACHELINE_ALIGN, key.as_ref().iter().copied()).into_boxed_slice()` before timing. Borrow it through the same NGSW slice view as the ordinary key.

## Representative-parameter recheck

The [current benchmark report](tfhe-benchmarks.md#aligned-key-recheck) repeats the key-alignment comparison with N1024, Q30/Q50/native, u32 base2 and u64 base8 at full internal levels. It separates container alignment from changes in decomposition work and complete-lookup geometry. The comparison keeps fixed workspace storage and semantic ciphertext views; it does not turn key alignment into a permanent dimension of every benchmark.
