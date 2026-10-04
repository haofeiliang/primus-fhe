# Workspaces, storage and serial reuse

Use the [library guide](README.md#distinguish-environment-from-workspace) for API navigation. This note records the ownership choices and measurements behind the workspace APIs.

## Names and binding

A `Workspace` owns reusable temporary buffers and their shape. NTT/Fourier external products, CMux, encryption, decryption, key switching, automorphisms, trace, RNS conversion and expansion use this name. Borrowed groups use `WorkspaceRefMut`. The lattice entry point is `primus_lattice::workspace`; scheme crates expose standalone workspaces or keep them private inside a bound evaluator.

FFT backends implement `FftTable::Workspace` and `new_workspace`. `FftEngine::from_workspace`, `zeroize_workspace` and `into_parts` support explicit reuse. Built-in FFT workspaces retain their allocation and length when erased. Local temporary slices and third-party `PodBuffer`/`PodStack` remain scratch; they are not new wrapper types.

`TfheContext` retains validated parameters and a transform table. `RingContext` and `FieldContext` describe arithmetic capabilities. An `Evaluator` or `FftEngine` binds resources and runs operations. The private NTRU `RotationState` couples a borrowed control-key variant with its required workspace. These roles are distinct from a buffer group.

Workspace lengths do not establish key identity, a decomposition basis, a modulus, or an FFT table's evaluation order. Read each operation's representation requirements. GLWE external-product `rebind` changes decomposition metadata without allocation when the GLWE shape is unchanged; `with_rebound` restores the original layout on unwind. Resizing to another GLWE shape may allocate.

## RNS automorphism bindings

CRT/DCRT automorphism, trace, reverse trace and coefficient expansion use concrete
owning evaluators, following the RNS key-switch API. Each borrows a key and
`DcrtGadgetDomain`, checks N, dimension, ordered Q, radix and retained levels at
construction, then creates scratch from that domain. Ordered Q fixes the product
modulus and fixed-width integer representation already checked by gadget
parameter construction. Secret identity and NTT representation identity remain
caller contracts; equal numerical values do not prove either.

A standalone auto key or complete trace/expansion key set stores one metadata
record. Private entries contain only encrypted key data and the coefficient/NTT
permutation. All entries are generated from one domain; there is no public entry
replacement or way to combine entries from different domains. Bound trace and
expansion kernels call the private auto kernel without rebuilding an evaluator
or repeating numerical compatibility checks.

Serial expansion owns one workspace. Parallel expansion owns a preallocated
pool sized explicitly for its Rayon worker demand, and requires `&mut self` for
each request. Per-task guards return scratch on completion or unwind; neither
path creates workspaces online. An undersized pool can panic after partial
output writes. This does not make a failed output valid. Full/partial expansion
and ordinary/normalized reverse trace retain separate mathematical contracts;
see the [RNS API workflow](../../crates/primus_glwe_rns/README.md#evaluation-resources).

### Binding migration measurements

Compared with `9564b7b5` on 2026-10-04, AMD Ryzen 9 9955HX3D,
rustc 1.98.1, release/default features and the repository's `target-cpu=native`.
Both versions used the existing u64/N1024/k2 fixtures, two approximately 50-bit
Q limbs, base_log=20 and seed=42. Executables were built in the same checkout,
saved, and run sequentially on CPUs 0/1; expansion used two Rayon workers.
Setup, binding and output allocation stayed outside each single-operation
iteration. Initial median timings in milliseconds:

| Operation | Before | After |
| --- | ---: | ---: |
| CRT trace | 0.572 | 0.573 |
| DCRT trace | 0.582 | 0.590 |
| Normalized reverse trace | 0.574 | 0.600 |
| CRT serial expansion | 67.406 | 68.349 |
| DCRT serial expansion | 69.601 | 67.742 |
| CRT parallel expansion | 35.321 | 34.747 |
| DCRT parallel expansion | 34.952 | 39.468 |

Automorphisms covered identity, N+1 and degree 5, taking roughly 50–54 us;
initial changes ranged from -0.1% to +5.4%. The larger differences prompted an
after/before/before/after recheck of the saved executables (two runs per version):

| Rechecked operation | Before medians, min–max | After medians, min–max |
| --- | ---: | ---: |
| CRT auto, degree N+1 (us) | 51.41–53.71 | 53.49–53.70 |
| DCRT auto, degree N+1 (us) | 50.90–53.48 | 53.43–54.05 |
| CRT trace (us) | 568.5–593.9 | 572.3–604.1 |
| DCRT trace (us) | 581.7–583.4 | 586.2–589.7 |
| Reverse trace (us) | 588.0–589.6 | 579.5–596.7 |
| DCRT parallel expansion (ms) | 40.01–40.17 | 37.63–37.79 |

The initial 13% parallel-expansion increase reversed; latency also varied within
the same binary. DCRT trace retained a small increase in this sample. These
results do not establish a general speedup or exact parity on other machines.
No arithmetic, scheduling or inlining adjustment was retained to tune this sample.
Reproduce with the crate's `automorphism`, `trace` and `expand_coeff` benches,
filtering `N=1024/|N=1024$`, with `RAYON_NUM_THREADS=2` and `taskset -c 0,1`.
Initial runs used 0.3 s warmup, 1 s measurement and 20 samples; rechecks used
0.5 s, 2 s and 30 samples. Expansion retains its fixture's 10-sample setting.

A temporary process-wide allocator probe checked the first and repeated online
calls for all three automorphism degrees, CRT/DCRT trace, reverse trace and both
expansion modes. With a two-worker Rayon pool initialized before measurement,
all reported zero allocations, including worker threads. An incompatible-radix
parallel binding was also rejected with zero allocations. The probe was removed;
ordinary tests retain domain rejection, dirty-buffer reuse and guard unwind
coverage. Other sizes, u32 timing and SIMD timing were not measured.

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

The constructor calls below describe the measured revision. Current composition APIs and TFHE codec ownership are documented in the [parameter guide](tfhe-parameters-and-boundaries.md#ntru-普通与-gadget-参数组合).

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
cargo bench -p primus_ntru --bench encryption --features ntt,rustfft,tfhe-fft -- 'n1024/encrypt_to' --sample-size 20 --warm-up-time 0.2 --measurement-time 1 --save-baseline before-3b
cargo bench -p primus_ntru --bench encryption --features ntt,rustfft,tfhe-fft -- 'n1024/encrypt_to' --sample-size 20 --warm-up-time 0.2 --measurement-time 1 --baseline before-3b
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
bytes for u64, excluding object/allocator overhead. Both NTRU backends lend these resources to CBS/MVB per call. Standalone CBS/one-hot omits ordinary-return buffers and allocates them only when explicitly
combined with a complete PBS; see the ownership table below.
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
keep those shared buffers. One-hot projection scratch is retained. See the
[table layout](../../crates/primus_tfhe_ntru_lut/IMPLEMENTATION.md#public-table-storage-and-compiled-choices).

One-hot CBS reuses its BR external-product workspace for BR, trace and scheme switching. Table selection and encrypted rotation now borrow that same workspace between one-hot calls. The NTT entry point is `BootstrapResources::external_product_workspace`; Fourier's `BootstrapResources::external_product_workspaces` returns the FFT engine and external-product buffers together. Borrowers retain polynomial lengths and the FFT table identity. Every subsequent one-hot call overwrites its scratch before reading it.

The high-precision evaluator therefore owns no second external-product workspace or FFT engine. Each evaluator still has independent mutable state, and borrowing excludes concurrent mutation. Both backends borrow common resources per operation; neither embeds PBS inside one-hot.

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

Each lookup evaluator explicitly owns common resources, one-hot state and a return binding.
NTT allocates only scalar scratch; Fourier allocates only batch scratch and keeps
its bounded streamed schedule. Standalone one-hot has no ordinary-return buffers. Both factorized MVB backends borrow complete PBS per request and use its private
return evaluator. Arithmetic, tile size and scheduling
are unchanged; no new latency claim is made.

## Input, blind rotation and return ownership

Each of the four backends exposes its own `BootstrapResources`, binding the context, key,
selected BR scratch and coefficient accumulator; Fourier also owns its FFT
engine there. GLWE input preparation is direct for BR→KS, or owns the required
input KS and compact small LWE for KS→BR. The latter cannot be omitted by CBS.
Ordinary `Evaluator` adds its complete return stage: output KS for GLWE BR→KS,
direct extraction for GLWE KS→BR, or the NTRU return evaluator. It has no optional
missing essential workspace. GLWE BR→KS no longer allocates an unused input LWE.

Both GLWE backends borrow the selected BR key directly. Each active KS stage binds
its own ring KS key alongside the existing scratch. Independent BR→KS CBS can
omit the KS owner entirely; KS→BR requires it at construction, with a structured
error for missing material. CBS/MVB borrow resources per call and do not own a
nested PBS. See the [GLWE resource table](#glwe-resource-ownership).

Each NTRU backend's ordinary `Evaluator` owns `BootstrapResources` and both return buffers.
CBS/one-hot retains a compiled LUT, trace scratch and projected NLEV, then borrows
common resources for each call. `FactorizedEvaluator::new(&pbs)` prepares one
extra NTT polynomial, or two Fourier polynomials, and borrows `&mut pbs` per request. No evaluator nesting or
recovery protocol is needed. The short-borrow boundary checks the same context
before any writes. Prepared state does not retain BR controls: classic/sparse
resources can share it when both actual secrets match. Context identity does not
prove the secret identity of independently generated material.
When borrowing resources from PBS, preserve its context/BR key binding: the retained
return material and buffers were prepared for it. The mutable accessor does not rebind PBS.
`Evaluator::try_from_resources(resources, return_key)` adds return buffers to
standalone resources. `try_rebind_return_key` reuses them with compatible material;
success discards pending samples, failure leaves the binding intact. A valid new
interleaved/MVB request also supersedes partial samples from an interrupted
request; scalar PBS uses its independent scratch and does not touch batch state.

Fourier's common resource owner additionally retains its FFT engine; the shared
engine/EP borrow preserves table identity and polynomial lengths. Integer factor
transforms, torus gadget transforms, native trace halving, Q→q-before-sign return
and streamed tiles retain their numerical order. No generic backend/resource
trait conceals these differences. All allocation is explicit at construction or
resource assembly; online operations do not allocate.

Existing size/domain boundaries and semantic polynomial/ciphertext iterators describe batches. Table groups contain M polynomials; ciphertext iterators traverse one complete object at a time. Candidate compaction remains indexed because a group must be consumed before its result overwrites the prefix. No additional generic batch abstraction is needed.

Partial reverse trace with r>1 retains r equally spaced coefficients; CBS needs separate constant projections of gadget entries. It cannot replace those projections. The real serial consumer already uses `project_prefix_coefficients_with_scratch_to`. Standalone partial-trace callers have their own trace workspace, so an additional partial-trace scratch API currently has no independent consumer.

## GLWE resource ownership

CBS retains its programmed LUT, trace scratch and projected GLev; MVB retains
one extra transform-domain GLWE for the shared rotation. Fourier MVB also keeps
one component-sized Fourier product, then inverse-transforms into the common
coefficient accumulator. They borrow common resources or
complete PBS per call, without a nested evaluator or recovery protocol.

| Resource | BR→KS | KS→BR | Serial reuse |
| --- | --- | --- | --- |
| Input KS scratch and switched GLWE | Absent | `BootstrapResources::input` | Overwritten before BR on every request |
| Compact small LWE | Absent | Same input stage | Extracted from the switched GLWE before BR |
| Selected classic/sparse BR scratch and EP buffers | `BootstrapResources` | `BootstrapResources` | BR, CBS scheme switch and CMux; only the selected algorithm is allocated |
| Coefficient accumulator | `BootstrapResources` | `BootstrapResources` | BR result, CBS projection source and MVB product; KS→BR first uses it for inverse extraction |
| Output KS scratch and switched GLWE | Ordinary `Evaluator` | Absent | One KS for ordinary/ManyLUT, one per factorized output |
| Output extraction | Compact small LWE after KS | Direct accumulator LWE | Writes caller buffers, no owned intermediate LWE |
| Trace scratch and projected GLev | CBS state | CBS state | Overwritten for each gadget result |
| Shared transform-domain rotation | MVB state | MVB state | Preserved until every factor output has returned |
| Fourier component product | MVB state | MVB state | Overwritten and inverse-transformed for each component |
| FFT engine and table-bound scratch (Fourier only) | `BootstrapResources` | `BootstrapResources` | Input/output KS, BR, trace, scheme switch, CMux and MVB |

`context.bootstrap_resources(br, input_ks)` checks material before allocation;
only KS→BR requires `Some(ks)`. `Evaluator::try_from_resources(resources, ks)`
adds output KS for BR→KS or rebinds the existing input KS for KS→BR.
`try_rebind_key_switching_key` validates and reuses either active stage's buffers;
failure preserves its prior binding. PBS resource borrows must preserve the
context and paired-secret binding needed by the retained return stage.

GLWE CBS/MVB state does not cache BR controls. Its public borrowing boundary
checks the same context, allowing independently prepared classic/sparse resources
with that context; key generation and callers must still pair actual secrets.
There is no extra identity token or general backend trait. CBS accepts independent
compatible output parameters because its scheme-switch key binds output layout.
EP buffers use existing `with_rebound` to change decomposition levels while
preserving GLWE geometry, then restore their layout on return or unwind. No
allocation, extra transform or coefficient-loop validation was added. Fourier
retains the same FFT table/engine throughout: factors use integer transforms,
GLWE/gadget values use torus transforms, and native trace halving retains its
rounding contract.

## NTRU resource ownership

This table records the concrete serial consumers; it does not introduce a common
resource trait. NTT and Fourier keep distinct numerical representations.

| Resource | Owner | Lifetime and serial reuse |
| --- | --- | --- |
| Coefficient accumulator/current and BR temporary polynomial | Each backend's `BootstrapResources::workspace` | BR overwrites both; CBS projects/rotates the result; factorized MVB reuses current for each recovered product |
| BR CMux/sparse scratch and external-product workspace | Selected `RotationState` | Selected at construction; classic EP scratch is reused by CBS trace/scheme switch, then borrowed by LUT selection/rotation |
| FFT plan borrow and backend workspace | Fourier `BootstrapResources::fft` | One engine for BR, projection, scheme switch and LUT products; NTT uses the context table directly |
| Reverse-trace scratch and projected NLEV | CBS/one-hot evaluator | One projected selector at a time; buffers are overwritten before the next selector |
| Common rotation in transform representation | `FactorizedEvaluator` | Survives across every factor output; NTT reuses the common coefficient accumulator for each product, while Fourier owns a separate transformed product |
| Public/encrypted selectors, aggregate rotation controls, compiled selection slots | LUT evaluator | Needed selectors survive one request; selection slots follow the compiled graph's last uses |
| Rotation factors and current/product polynomials | LUT evaluator | Factors are prepared once; current/product ping-pong during encrypted rotation |
| Return key and target q | `LweReturnEvaluator` | Read-only, allocation-free binding; no scratch or transform dependency |
| Scalar intermediate LWE, N+1 elements | `NtruLweKeySwitchingWorkspace` | Complete PBS and NTT LUT; overwritten for each return |
| Converted polynomial and extracted/switched LWE tiles | `LweReturnBatchWorkspace` | Complete PBS and Fourier LUT; one conversion for a shared source, independent conversion per streamed source; only the prepared prefix may be submitted |

Complete PBS prepares both return workspaces, which factorized MVB borrows for a
request. Standalone CBS/one-hot prepares neither. Each LUT owns common resources
separately from one-hot state and reuses them for table selection and rotation;
NTT returns scalar outputs, Fourier uses streamed tiles. No generic resource
trait hides backend differences.

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
taskset -c 2 cargo bench -p primus_tfhe_ntru_lut --bench pipeline --features ntt,rustfft,tfhe-fft -- 'u(32|64)/n800_N1024/c8_d5_o8/evaluate' --warm-up-time 0.5 --measurement-time 1.5 --sample-size 20 --noplot
taskset -c 2 cargo bench -p primus_tfhe_ntru_ntt --bench pbs -- 'u64/binary/boolean/.*/complete' --warm-up-time 0.5 --measurement-time 3 --sample-size 30 --noplot
taskset -c 2 cargo bench -p primus_tfhe_ntru_ntt --bench mvb -- 'u64/mvb/classic/.*/D8_k3/(interleaved|factorized)' --warm-up-time 0.5 --measurement-time 3 --sample-size 30 --noplot
```

Use `primus_tfhe_ntru_fourier` for the corresponding PBS/MVB commands; both FFT
engines are selected. Ordinary PBS uses n800/N1024 and MVB uses n728/N1024,
D8/k3. The shared-input and streamed return schedules, Q→q-before-sign order,
transform kernels and fixed tile size are unchanged.

## NTT borrowed-resource measurement

Compared with `c6fbb13d` on 2026-10-03 using the machine/toolchain above,
default features, logical CPU 2, sequential executables and no concurrent builds.
Common resources and operation state were measured together, so moving storage
out of an evaluator is not counted as a memory saving. Keys, context, input and
public programs were prepared outside measurement.

A temporary Criterion probe used the existing `ntru::circuit` u64 binary profile
(n800/N1024), seed 42, and `ntru::cbs` material. Each iteration constructed and
dropped one PBS, standalone CBS (t=4), standalone one-hot (t=8), or complete
PBS+factorized MVB resource set. Warmup was 0.5 s, measurement 1.5 s, 20 samples.
The counting allocator measured one retained construction separately; requested
heap excludes allocator metadata. The probe was removed after measurement.

| Resource set | Allocations, unchanged | Retained heap bytes, unchanged | Inline bytes before → after | Construction + drop, µs before → after |
| --- | --- | --- | --- | --- |
| Ordinary PBS | 11 | 224392 | 328 → 328 | 3.351 → 3.311 |
| Standalone CBS | 11 | 140288 | 528 → 440 | 1.092 → 1.115 |
| Standalone one-hot | 10 | 140288 | 496 → 408 | 1.119 → 1.116 |
| PBS + factorized MVB | 12 | 232584 | 352 → 368 | 1.416 → 1.433 |

Removing the CBS ownership enum saves inline space; MVB now keeps two binding
references alongside its separately owned PBS. Allocation count and retained
heap are unchanged. These short timings depend on allocator reuse and do not
establish a constructor speedup. The NTT public LUT fixture also retained the
same heap: 508932 bytes (u32), 787464 bytes (u64), with zero online allocations.

Initial full-request screening used 20 samples, 0.5 s warmup and 1.5 s
measurement; pipeline measures all eight output chunks in one iteration.

| Request | Before → after, ms |
| --- | --- |
| u64 binary PBS, n800/N1024 | 6.169 → 6.043 |
| u64 fixed-weight classic PBS, n728/h32/N1024 | 5.289 → 5.426 |
| u64 sparse PBS, same shape | 5.575 → 5.447 |
| u64 interleaved / factorized MVB, D8/k3 | 6.187 → 6.200 / 6.232 → 6.193 |
| u64 CBS / full one-hot / nonzero one-hot, n800/N1024 | 4.721 → 4.594 / 5.232 → 5.259 / 5.092 → 5.064 |
| NTT LUT, u32 / u64, c8/d5/o8 | 66.307 → 66.986 / 49.553 → 49.036 |

The initial fixed-weight classic result was rerun in before/after/after/before
order. Its increase shrank from about 3% on CPU 2 to about 1% on CPU 4; the
normalized BR disassembly was unchanged. Scalar PBS was then simplified to leave
independent batch state untouched. The final CPU 4 comparison (2 s measurement)
was 5.218/5.255 ms before versus 5.214/5.211 ms after for fixed-weight classic,
and 6.047/6.035 versus 6.066/6.099 ms for binary PBS. The earlier larger increase
did not persist. The u32 LUT recheck on CPU 2 was 65.691/65.566 ms before versus
66.040/65.953 ms after. Sub-percent differences and code-layout/platform effects
remain unresolved; these measurements support resource reuse, not a speedup or
an exact latency guarantee.

Reproduce with `pbs`, `sparse_pbs`, `mvb`, `circuit_bootstrap` targets in
`primus_tfhe_ntru_ntt`, and `pipeline` in `primus_tfhe_ntru_lut`. Select the IDs
above, build each revision separately, then run the saved executables in
sequence with `taskset -c 2`, `--bench`, `--sample-size 20`,
`--warm-up-time 0.5 --measurement-time 1.5 --noplot`. Do not share a Cargo target
directory between simultaneous revision builds. Default and nightly SIMD tests
cover semantics and online allocation; SIMD timing is not claimed here.

## Fourier borrowed-resource measurement

Compared with `77704a36` on 2026-10-03 using the machine/toolchain above,
default features and repository compiler flags. Saved executables ran sequentially
on logical CPU 4, without concurrent builds. One Criterion iteration measured one
complete request or one construction-and-drop. Warmup was 0.5 s, measurement 2 s,
20 samples. Keys, context, input, public programs and online output buffers were
prepared outside timing. These are functional fixtures, not security profiles.

The temporary constructor probe used the u64 `ntru::circuit` binary profile
(n800/N1024, native Q, external q=2^24), seed 42 and `ntru::cbs` material.
Standalone CBS used t=4 and one-hot t=8. Both revisions measured the entire
resource set, including separately owned common resources or PBS. The counting
allocator separately measured a construction while retaining its result; heap
bytes exclude allocator metadata and inline storage. The probe was removed.

| Engine / resource set | Allocations, unchanged | Retained heap bytes, unchanged | Inline bytes before → after | Construction + drop, µs before → after |
| --- | --- | --- | --- | --- |
| RustFFT PBS | 13 | 257160 | 368 → 368 | 3.734 → 3.797 |
| RustFFT CBS | 13 | 173056 | 568 → 480 | 1.514 → 1.536 |
| RustFFT one-hot | 12 | 173056 | 536 → 448 | 1.513 → 1.526 |
| RustFFT PBS + MVB | 15 | 273544 | 416 → 432 | 1.830 → 1.825 |
| TFHE-FFT PBS | 13 | 257160 | 376 → 376 | 2.440 → 2.437 |
| TFHE-FFT CBS | 13 | 173056 | 576 → 488 | 2.224 → 2.235 |
| TFHE-FFT one-hot | 12 | 173056 | 544 → 456 | 2.229 → 2.237 |
| TFHE-FFT PBS + MVB | 15 | 273544 | 424 → 440 | 2.575 → 2.572 |

Removing the CBS ownership enum saves 88 inline bytes; MVB adds 16 bytes of
binding references. No extra FFT engine, allocation or retained heap is added.
The constructor timings include deallocation and allocator reuse, so they do
not establish a speedup. LUT retained heap was unchanged for both engines:
1,116,224 bytes for u32 and 1,059,968 bytes for u64. Online allocation remained zero.

Initial full-request point estimates follow. The LUT request includes all eight
output chunks; factorized MVB and Fourier LUT keep their streamed return tiles.

| Request | RustFFT before → after, ms | TFHE-FFT before → after, ms |
| --- | --- | --- |
| u64 binary PBS, n800/N1024 | 7.136 → 7.267 | 6.067 → 5.949 |
| u64 fixed-weight classic PBS, n728/h32/N1024 | 6.544 → 6.415 | 5.390 → 5.222 |
| u64 sparse PBS, same shape | 7.020 → 6.975 | 6.890 → 6.999 |
| u64 interleaved MVB, D8/k3 | 7.312 → 7.414 | 6.277 → 6.082 |
| u64 factorized MVB, D8/k3 | 7.322 → 7.385 | 6.227 → 6.203 |
| u64 CBS, n800/N1024 | 5.757 → 5.714 | 4.406 → 4.432 |
| u64 full one-hot, M=4 | 6.444 → 6.371 | 4.845 → 4.942 |
| u64 nonzero one-hot, M=4 | 6.213 → 6.158 | 4.650 → 4.776 |
| LUT u32, c8/d5/o8 | 106.160 → 106.050 | 87.652 → 88.018 |
| LUT u64, c8/d5/o8 | 56.658 → 58.037 | 45.568 → 45.913 |

Rechecks alternated executables rather than tuning code for a single run. On CPU 2
(after/before/before/after, 3 s measurement), RustFFT u64 LUT measured
57.095/57.108 ms after versus 57.522/57.678 before, reversing the initial increase.
TFHE-FFT full one-hot measured 4.887/4.959 after versus 4.932/5.038 before;
nonzero one-hot measured 4.819/4.826 versus 4.767/4.962. RustFFT PBS measured
7.329/7.255 after versus 7.132/7.246 before. TFHE-FFT sparse PBS measured
6.895/7.677 after versus 6.961/6.965 before, including one much slower new run.

The final PBS recheck on CPU 4 used before/after/after/before order, 1 s warmup,
4 s measurement and 30 samples. RustFFT PBS measured 7.184/7.367 ms before versus
7.300/7.391 after; TFHE-FFT sparse PBS measured 6.945/7.151 before versus
6.963/6.996 after. The earlier larger increases did not persist consistently,
but percent-level platform/code-layout drift remains unresolved. These results
support resource reuse without a speedup claim or an exact latency guarantee.

Reproduce using `pbs`, `sparse_pbs`, `mvb`, `circuit_bootstrap` in
`primus_tfhe_ntru_fourier`, and `pipeline` in `primus_tfhe_ntru_lut`, with the
parameter IDs above. Build each revision separately, then run its saved
executable with `taskset -c 4`, `--bench`, `--sample-size 20`,
`--warm-up-time 0.5 --measurement-time 2 --noplot`. Pipeline filters are
`lookup/(rustfft|tfhe_fft)/u(32|64)/n800_N1024/c8_d5_o8/evaluate`.
Default and nightly SIMD tests cover both FFT engines, operation alternation,
short return tiles and zero online allocation. SIMD latency was not measured.

## GLWE NTT borrowed-resource measurement

Compared with `d566a73a` on 2026-10-03, AMD Ryzen 9 9955HX3D, x86_64 Linux,
rustc 1.98.1 (48a229cea, LLVM 22.1.8), default features and the repository's
`target-cpu=native`. Saved executables ran sequentially without concurrent builds.
These are functional profiles, not security recommendations.

A temporary constructor probe used u64, N1024, `ntt_circuit_modulus`, seed 42,
`glwe::cbs` and t=4. Classic used the n800 binary `glwe::circuit` profile;
sparse used `glwe::diagnostic`, n728/h32, three copies and 64 buckets.
Each iteration constructed and dropped the entire PBS, standalone CBS, or
PBS+MVB resource set. Separate counting-allocator measurements retained the
returned values. Moving common resources out of CBS/MVB was not counted as a
heap saving. Timings below used CPU 4, 0.5 s warmup, 2 s measurement and 20 samples.

| Order / key / set | Allocations, unchanged | Retained heap bytes, unchanged | Inline bytes before → after | Construction + drop, µs before → after |
| --- | --- | --- | --- | --- |
| BR→KS / classic / PBS | 11 | 116736 | 544 → 544 | 0.762 → 0.777 |
| BR→KS / classic / CBS | 16 | 182272 | 832 → 712 | 1.334 → 1.327 |
| BR→KS / classic / PBS+MVB | 12 | 133120 | 568 → 576 | 0.880 → 0.882 |
| BR→KS / sparse / PBS | 13 | 319168 | 544 → 544 | 1.571 → 1.572 |
| BR→KS / sparse / CBS | 18 | 384704 | 832 → 712 | 2.101 → 2.100 |
| BR→KS / sparse / PBS+MVB | 14 | 335552 | 568 → 576 | 1.667 → 1.659 |
| KS→BR / classic / PBS | 12 | 123144 | 544 → 544 | 0.892 → 0.888 |
| KS→BR / classic / CBS | 22 | 238856 | 832 → 712 | 1.800 → 1.738 |
| KS→BR / classic / PBS+MVB | 13 | 139528 | 568 → 576 | 0.990 → 0.981 |
| KS→BR / sparse / PBS | 14 | 325000 | 544 → 544 | 1.599 → 1.612 |
| KS→BR / sparse / CBS | 24 | 440712 | 832 → 712 | 2.489 → 2.470 |
| KS→BR / sparse / PBS+MVB | 15 | 341384 | 568 → 576 | 1.704 → 1.707 |

The CBS ownership enum removal saves 120 inline bytes in the combined resource
set; MVB adds one 8-byte context reference. Heap and allocation counts are
unchanged, excluding allocator metadata. Constructor timing includes allocator
reuse and does not establish a speedup. The temporary probe was removed.
Existing tests keep online allocation at zero across PBS, CBS/CMux and MVB;
assembling standalone resources into PBS allocates output KS only for BR→KS,
and rebinding compatible KS material does not allocate.

Each iteration evaluates one complete request with keys, input, LUT, outputs and
workspaces prepared outside timing. MVB includes all three output ciphertexts.
Initial CPU 4 point estimates in milliseconds, using the same sampling settings:

| u64 request | BR→KS before → after | KS→BR before → after |
| --- | --- | --- |
| Binary PBS, n800/N1024 | 3.121 → 3.114 | 3.200 → 3.198 |
| Fixed-weight classic PBS, n728/h32/N1024 | 12.831 → 12.819 | 12.595 → 12.606 |
| Sparse PBS, same fixed-weight profile | 16.533 → 16.463 | 16.647 → 16.442 |
| Classic interleaved MVB, D8/k3 | 12.501 → 12.582 | 12.662 → 12.829 |
| Classic factorized MVB, D8/k3 | 12.500 → 12.897 | 12.693 → 12.625 |
| Sparse interleaved MVB, D8/k3 | 17.094 → 16.523 | 16.638 → 16.544 |
| Sparse factorized MVB, D8/k3 | 16.801 → 16.769 | 17.026 → 16.732 |
| Classic CBS, n800/N1024 | 15.096 → 14.664 | 14.775 → 14.142 |
| Sparse CBS, n728/h32/N1024 | 16.683 → 17.428 | 16.718 → 17.372 |

Alternating runs checked the MVB and sparse CBS increases. With 0.5 s warmup,
3 s measurement and 20 samples, classic factorized MVB on CPU 4 measured
12.692/12.689 ms before versus 12.661/12.870 ms after for BR→KS, and
12.733/12.757 versus 12.732/12.700 ms for KS→BR. Its initial increase did not
persist consistently. Sparse CBS did remain slower in that recheck:

| CPU 4 sparse CBS | Before, two runs (ms) | After, two runs (ms) |
| --- | --- | --- |
| BR→KS | 16.640 / 16.730 | 17.037 / 17.316 |
| KS→BR | 16.682 / 16.733 | 17.255 / 17.328 |

Disassembly showed changed inlining/register allocation despite unchanged
arithmetic, but this does not establish the cause of the slowdown. An experiment
removed the common BR stage's `#[inline]` hint: the benchmark's u64 CBS entry
shrank from 2736 to 513 machine-code bytes (baseline: 942). Sparse CBS on CPU 8
then approached baseline, while classic BR→KS CBS became about 2% slower in
alternating runs. This did not establish a general benefit, so the experiment
was reverted. No forced inlining, alignment or numerical specialization remains.

The retained implementation, with the original hint, was also compared on CPU 8.
Both revisions used that same CPU, with after/before/before/after run order,
0.5 s warmup, 2 s measurement and 20 samples:

| CPU 8 CBS | Before, two runs (ms) | After, two runs (ms) |
| --- | --- | --- |
| Classic BR→KS | 14.301 / 14.277 | 14.423 / 14.146 |
| Sparse BR→KS | 17.208 / 17.242 | 17.224 / 17.196 |
| Classic KS→BR | 14.446 / 15.832 | 15.553 / 14.559 |
| Sparse KS→BR | 17.266 / 17.157 | 17.200 / 17.163 |

CPU 8 does not reproduce the sparse CBS increase; it does not invalidate the
CPU 4 result. Other CPU 2/4 runs varied substantially for both revisions.
Zero extra allocation and unchanged retained heap are established, but the
CPU-dependent sparse CBS latency difference remains unresolved. Its analysis and
sparse PBS optimization are deferred; no resolution is claimed here. Do not claim
an online speedup or unconditional performance parity from these measurements.

Reproduce with `pbs`, `sparse_pbs`, `mvb`, and `circuit_bootstrap` in
`primus_tfhe_glwe_ntt`, selecting the parameter IDs above. Build each revision
separately, then run saved executables with `taskset -c 4` (or 8), `--bench`,
`--warm-up-time 0.5 --measurement-time 2 --sample-size 20 --noplot`.
The MVB filter is `u64/mvb/.*/D8_k3/(interleaved|factorized)`; CBS uses `u64/cbs/`.
SIMD and u32 are validated functionally, not timed.

## GLWE Fourier borrowed-resource measurement

Compared with `07c3117e` on 2026-10-03, AMD Ryzen 9 9955HX3D, x86_64 Linux,
rustc 1.98.1 (48a229cea, LLVM 22.1.8), default features and the repository's
`target-cpu=native`. Each revision was built in the same checkout and its
executables saved; timing ran sequentially on CPU 8 without concurrent builds.
The fixtures are arithmetic profiles, not security recommendations.

The temporary constructor probe used u64/Native/N1024, seed 42, t=4 and
`glwe::cbs`. Classic used n800 binary `glwe::circuit`; sparse used n728/h32
`glwe::diagnostic`, three copies and 64 buckets. The probe retained the complete
PBS, standalone CBS or PBS+MVB resource set, including the owners moved out of
CBS/MVB. Requested allocation counts and retained heap (allocated minus released
bytes, excluding allocator metadata) are unchanged for both FFT engines:

| Order / key | PBS count / heap bytes | CBS count / heap bytes | PBS+MVB count / heap bytes |
| --- | --- | --- | --- |
| BR→KS / classic | 13 / 133120 | 18 / 198656 | 15 / 157696 |
| BR→KS / sparse | 16 / 663232 | 21 / 728768 | 18 / 687808 |
| KS→BR / classic | 14 / 139528 | 24 / 255240 | 16 / 164104 |
| KS→BR / sparse | 17 / 669064 | 27 / 784776 | 19 / 693640 |

For either order/key, RustFFT inline sizes are PBS 544 → 544, CBS 800 → 712,
and PBS+MVB 592 → 600 bytes. TFHE-FFT adds 8 bytes to each size on both revisions.
The removed CBS ownership enum saves 88 inline bytes; MVB adds one context
reference. The probe has been removed, and constructor latency was not measured.
Tests cover zero online allocation from the first call and after alternating
CBS/CMux/external product/PBS or MVB/PBS. Moving resources into ordinary PBS
allocates output KS only for BR→KS; compatible KS rebinding does not allocate.

One timed iteration evaluates one complete request, excluding setup, keys,
input, LUT, outputs and workspace allocation. Classic PBS/CBS use n800/N1024;
classic MVB uses n728/h32/N1024, D8/k3 and returns all three ciphertexts.
Sparse online latency was deliberately not measured: sparse CBS analysis and
sparse PBS optimization are deferred. Initial u64 point estimates in ms,
with 0.5 s warmup, 2 s measurement and 20 samples:

| Engine / request | BR→KS before → after | KS→BR before → after |
| --- | --- | --- |
| RustFFT binary PBS | 3.164 → 3.158 | 3.194 → 3.182 |
| TFHE-FFT binary PBS | 2.769 → 2.803 | 2.807 → 2.721 |
| RustFFT classic CBS | 16.266 → 16.316 | 16.144 → 16.314 |
| TFHE-FFT classic CBS | 15.012 → 14.514 | 14.907 → 15.651 |
| RustFFT interleaved MVB | 16.086 → 15.950 | 16.164 → 16.335 |
| RustFFT factorized MVB | 15.736 → 15.828 | 15.968 → 16.035 |
| TFHE-FFT interleaved MVB | 14.105 → 13.445 | 13.986 → 14.254 |
| TFHE-FFT factorized MVB | 13.850 → 13.378 | 13.899 → 13.365 |

The initial TFHE-FFT KS→BR CBS increase prompted an after/before/before/after
recheck on CPU 8, with 0.5 s warmup, 3 s measurement and 20 samples. It also
rechecked classic CBS on RustFFT, TFHE-FFT PBS and the slower interleaved MVB case:

| Rechecked request | Before, two runs (ms) | After, two runs (ms) |
| --- | --- | --- |
| RustFFT CBS BR→KS | 16.411 / 16.138 | 16.285 / 16.248 |
| RustFFT CBS KS→BR | 16.294 / 18.021 | 16.272 / 16.388 |
| TFHE-FFT CBS BR→KS | 15.708 / 14.453 | 15.197 / 14.444 |
| TFHE-FFT CBS KS→BR | 15.919 / 16.044 | 15.268 / 14.436 |
| TFHE-FFT PBS BR→KS | 2.729 / 2.740 | 2.729 / 2.727 |
| TFHE-FFT PBS KS→BR | 2.730 / 2.753 | 2.731 / 2.790 |
| TFHE-FFT interleaved MVB KS→BR | 12.916 / 12.984 | 13.228 / 12.921 |

The initial increases did not persist consistently; baseline latency also
varied. The retained implementation keeps the original arithmetic, transform
schedule and inline hints. These measurements establish neither a general
speedup nor exact latency parity across environments. Sparse online performance
remains outside this comparison.

Reproduce with `pbs`, `circuit_bootstrap`, and `mvb` in
`primus_tfhe_glwe_fourier`. Build each revision separately, then run its saved
executable with `taskset -c 8`, `--bench`, `--warm-up-time 0.5`,
`--measurement-time 2 --sample-size 20 --noplot`. Filters are
`u64/binary/boolean/.*/complete`, `u64/cbs/classic/`, and
`u64/mvb/classic/.*/D8_k3/(interleaved|factorized)` respectively.
SIMD and u32 are checked functionally, not timed.

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
taskset -c 0 cargo +nightly bench -p primus_tfhe_ntru_lut --bench pipeline --features ntt,simd,rustfft,tfhe-fft -- '/evaluate$' --sample-size 20 --warm-up-time 0.5 --measurement-time 2 --noplot --save-baseline workspace-current
```

Construction heap and online allocation are measured by that harness; key-generation latency and Vec-to-aligned-key conversion latency were not claimed or optimized. The lattice comparisons can be repeated with `ntru_ntt` and `ntru_fourier`, filtering `n1024.*external_product_coeff`, and preparing a second key with `AVec::from_iter(CACHELINE_ALIGN, key.as_ref().iter().copied()).into_boxed_slice()` before timing. Borrow it through the same NGSW slice view as the ordinary key.

## Representative-parameter recheck

The [current benchmark report](tfhe-benchmarks.md#aligned-key-recheck) repeats the key-alignment comparison with N1024, Q30/Q50/native, u32 base2 and u64 base8 at full internal levels. It separates container alignment from changes in decomposition work and complete-lookup geometry. The comparison keeps fixed workspace storage and semantic ciphertext views; it does not turn key alignment into a permanent dimension of every benchmark.
