# Workspaces, storage and serial reuse

Use the [library guide](README.md#distinguish-environment-from-workspace) for API navigation. This note records current ownership and storage contracts. Historical measurements are in the [performance report](../performance/workspace-measurements.md).

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

The [binding measurements](../performance/workspace-measurements.md#binding-migration-measurements) record the migration cost and allocation checks.

## Storage decisions

| Consumer | Storage and reason |
| --- | --- |
| NTRU external products; GLWE Fourier key switching | Existing aligned numeric arrays use `ABox`; ordinary carries/digits use `Box`. Their lengths are fixed, and views remain ordinary slices. |
| NTRU CMux; GLWE ternary CMux; DCRT GLev decomposition; exact RNS conversion; NTRU-to-LWE return | Ordinary `Box` expresses the bound geometry. No stronger alignment requirement is introduced. |
| High-precision LUT selectors, factors, candidates and ciphertext temporaries | Ordinary `Box`; binding determines every length. Public output allocation still returns the existing owned ciphertext types. |
| Resizable GLWE external products, BR and gadget-generation workspaces | Keep `Vec`/`AVec`, including capacity reuse and existing resize/rebind semantics. |
| FFT tables and workspaces | Keep existing aligned boxed buffers and backend-specific `PodBuffer`, including their erase/drop behavior. |
| Secret keys and private encryption/decryption intermediates | Keep existing storage and erasure. Secret-key zeroization may invalidate a key by clearing its length; workspace zeroization may instead preserve its shape. |
| Public, BR, sparse, KS, trace and scheme-switch keys | Keep existing coefficient storage. The [alignment measurements](../performance/tfhe-baseline.md#aligned-key-recheck) do not justify a general migration. Object-vector alignment would not align each object's separate allocation. |
| Modulus tables, RNS bases, metadata and public owned-output aliases | Keep their current representations; a buffer cleanup does not change mathematical tables or introduce an allocator framework. |

A fixed-length container is an ownership choice, not a speed claim. The migrated arrays are initialized at their final length. With aligned-vec 0.6.4, `into_boxed_slice` transfers a full-capacity allocation; its shrink path runs only when capacity exceeds length. No extra online conversion or allocation is needed. `primus_data` continues to support aligned `Data`/`DataMut`, with explicit alignment during construction rather than an implicit `DataOwned` allocation policy.

A cache-aligned base pointer does not align every subview. Polynomial strides in the measured N=1024 workload preserve alignment; an LWE entry has n+1 coefficients and generally does not. Public arithmetic still accepts normally aligned slices, including offset inputs. Keys or workspaces must not add padding without a separate layout design.

## NTRU parameter sharing

`NtruParameters` and `NlevParameters` share an `Arc<NtruEncryptionParameters>` containing N, q and prepared secret/noise samplers. The ordinary codec and each gadget basis remain independently owned. Separate key-noise roles construct separate encryption states. This shares distribution tables, never secret coefficients, RNG state or mutable workspace buffers; online operations borrow the encryption state without cloning an Arc.

The [construction and evaluation measurements](../performance/workspace-measurements.md#ntru-parameter-sharing-measurements) record the storage tradeoff; current APIs are described in the [parameter guide](tfhe-parameters-and-boundaries.md).

## RNS base sharing

`RNSBase` owns an `Arc` to its immutable ordered moduli, numeric modulus cache, Q, punctured products and inverse factors. Cloning a base shares these buffers; independent construction or extension creates a new table. `BfvRnsCodec`, its internal converter and derived `CrtGlevParameters` therefore retain handles to the same Q precomputation. Sampling remains in its existing shared state. BFV scaling, gadget reconstruction weights and conversion matrices keep their separate ownership. The unused ordinary `delta_mod_q` vector was removed; encryption already uses the codec's Shoup factors.

The [construction and evaluation measurements](../performance/workspace-measurements.md#rns-base-sharing-measurements) record the storage tradeoff; current APIs are described in the [parameter guide](tfhe-parameters-and-boundaries.md).

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
bytes for u64, excluding object/allocator overhead. MVB retains these buffers
in its owned PBS state; CBS/one-hot borrows only the common BR/EP resources.
Standalone CBS/one-hot omits ordinary-return buffers and allocates them only when explicitly
combined with a complete PBS; see the ownership table below.
The [return benchmark](../../crates/primus_ntru/benches/lwe_return.rs) measures
conversion, extraction, key switching and tile-copy costs together.

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

The public high-precision LUT owns all encoded polynomials contiguously in
`[output][prefix][coefficient]` order. Each output executes the complete M-ary
selection tree. Depth-first traversal keeps M ciphertexts per encrypted layer,
reusing those slots after their parent consumes them; h=c-d gives
`M*max(h-1,0)` intermediate NTRUs. For h=0, the sole public polynomial is lifted
with NLEV[1] before low-chunk rotations. Selectors and rotation controls are
shared across outputs, but intermediate tree results are not. See the
[table layout](../../crates/primus_tfhe_ntru_lut/IMPLEMENTATION.md#public-table-storage-and-complete-choices).

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
its bounded streamed schedule. Standalone one-hot has no ordinary-return buffers.
Both factorized MVB backends own complete PBS state and use its private
return evaluator. Arithmetic, tile size and scheduling
are unchanged; no new latency claim is made.

## Input, blind rotation and return ownership

Each backend exposes `bootstrap::BootstrapResources`, binding the context, key,
selected BR scratch and coefficient accumulator; Fourier also owns its FFT
engine there. GLWE input preparation is direct for BR→KS, or owns the required
input KS and compact small LWE for KS→BR. The latter cannot be omitted by CBS.
Ordinary `Evaluator` adds its complete return stage: output KS for GLWE BR→KS,
direct extraction for GLWE KS→BR, or the NTRU return evaluator. It has no optional
missing essential workspace. GLWE BR→KS no longer allocates an unused input LWE.

Both GLWE backends borrow the selected BR key directly. Each active KS stage binds
its own ring KS key alongside the existing scratch. Independent BR→KS CBS can
omit the KS owner entirely; KS→BR requires it at construction, with a structured
error for missing material. Low-level CBS borrows resources per call; MVB owns
complete PBS state. See the [GLWE resource table](#glwe-resource-ownership).

Each NTRU backend's ordinary `Evaluator` owns `BootstrapResources` and both return buffers.
CBS/one-hot retains a compiled LUT, trace scratch and projected NLEV, then borrows
common resources for each call. MVB uses `context.mvb_evaluator(&server_key)`
to own its PBS state and one extra NTT polynomial, or two Fourier polynomials.
Online calls take only input, program and outputs. Advanced material composition
can move an existing evaluator into `FactorizedEvaluator::new(pbs)`: context and
keys remain borrowed, and existing buffers move without copying or rebuilding.
The compiled program must use the same context, checked before any writes.
Low-level CBS/one-hot state does not retain BR controls: classic/sparse resources
can share it when both actual secrets match. Context identity does not prove the
secret identity of independently generated material.
When borrowing resources from PBS, preserve its context/BR key binding: the retained
return material and buffers were prepared for it. The mutable accessor does not rebind PBS.
`Evaluator::try_from_resources(resources, key_switching, return_key)` binds checked
return material and adds return buffers to standalone resources. A valid new
interleaved/MVB request supersedes partial samples from an interrupted
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
coefficient accumulator. Low-level CBS borrows common resources per call; the owning MVB evaluator
retains complete PBS state without a recovery protocol.

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

`context.bootstrap_resources_from_server_key(&server)` selects the required
input KS from a complete bundle without preparing ordinary return scratch.
Independent material uses `context.bootstrap_resources(br, input_ks)`;
only KS→BR requires `Some(ks)`. Both check material before allocation. `Evaluator::try_from_resources(resources, key_switching, ks)`
checks independent return material, then adds output KS for BR→KS or binds the
existing input KS for KS→BR. PBS resource borrows must preserve the
context and paired-secret binding needed by the retained return stage.

GLWE low-level CBS state does not cache BR controls. Its public borrowing boundary
checks the same context, allowing independently prepared classic/sparse resources
with that context; key generation and callers must still pair actual secrets.
There is no extra identity token or general backend trait. CBS accepts independent
compatible output parameters through `CircuitBootstrapEvaluator::try_with_parameters`
because its scheme-switch key binds output layout. The default `try_new` uses
the circuit key's parameters, including when borrowing an existing PBS evaluator's resources.
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

Complete PBS prepares both return workspaces; factorized MVB retains them in its
owned PBS state. Standalone CBS/one-hot prepares neither. Each LUT owns common resources
separately from one-hot state and reuses them for table selection and rotation;
NTT returns scalar outputs, Fourier uses streamed tiles. No generic resource
trait hides backend differences.
