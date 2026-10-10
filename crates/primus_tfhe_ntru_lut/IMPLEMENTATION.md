# NTRU lookup stages and storage

User-facing encoding and evaluation contracts are in the [README](README.md). This document records the internal storage and evaluation stages shared by the [NTT evaluator](src/ntt.rs) and [Fourier evaluator](src/fourier.rs).

## Compilation and evaluator features

The default build retains public compilation and polynomial inspection, including
the complete backend-neutral selection plan. Compilation accepts `PolyLength`, accumulator Q, a Rounded input codec at q
and chunk geometry; its normal dependency tree contains no encryption/key or
TFHE crate and no NTT/FFT implementation. `ntt` / `fourier` enable the corresponding evaluator module,
its binding errors and the shared ciphertext-access helpers in `evaluation.rs`.
Concrete FFT engine flags also enable `fourier`; SIMD weakly propagates to selected
backends. Neither feature selection nor compiler-only use changes graph interning,
slot scheduling, callback order or stored coefficients.

Scheduling fields remain part of the compiled artifact even when no evaluator is
selected. The three internal metadata structs explicitly permit unread fields in
that configuration; execution-only accessors are gated with their consumers.

The [`statistics` module](src/lookup_table/statistics.rs) reads the immutable
plan for operation counts. It also owns the direct buffer-length calculations
shared by both evaluator constructors and `estimate_workspace`. NTT counts T
entries; Fourier counts N/2 complex pairs per transformed polynomial plus its
coefficient conversion and gadget-one buffers. This describes storage only and
does not merge numerical kernels. Bootstrap/CBS/one-hot resources (including
the extra sparse input state), return buffers, transform engines, keys, public compilation storage, caller buffers, allocator
overhead and construction temporaries are excluded. This partial estimate must
not be treated as complete retained heap or peak memory.

## Public table storage and compiled choices

[`lookup_table.rs`](src/lookup_table.rs) owns validated logical geometry and
immutable table access. Its private [`compile` module](src/lookup_table/compile.rs)
enumerates every callback pair in the documented order and interns encoded,
zero-padded polynomials. Hashes narrow the search; complete coefficient equality
establishes identity. Construction checks worst-case storage before callbacks;
sharing never skips a callback or changes its error position.

For radices up to 256, compilation precomputes the M unsigned rounded digit
encodings with `RoundedCodec::encode_slice_assign`, then reuses them while
filling coefficients. A single M-entry output keeps direct encoding because
the preparation pass would be as large as the entire coefficient fill. Larger
radices also keep direct encoding, bounding the temporary cache to 2 KiB at u64.
Each callback result is checked against M before indexing the cache; callbacks
still run once per logical pair, including repeated polynomials. The cache is
construction scratch and is discarded with the codec, not retained by the LUT
or its evaluators. Both paths use the same rounded encoding and zero padding.

The table retains a flat boxed coefficient pool and a
[`selection plan`](src/lookup_table/selection.rs). Its private
[`graph compiler`](src/lookup_table/selection/compile.rs) groups M branches
in ascending input-chunk order, removing a choice when every branch has the same
source. Remaining operations have three distinct forms:

| Operation | Operand domain | Control and basis |
| --- | --- | --- |
| `Lift` | One public polynomial | Bound NLEV[1], its own generation basis |
| `SelectPublic` | M public polynomials | Full NLEV one-hot, CBS output basis |
| `SelectEncrypted` | M coefficient-form NTRUs under f | Nonzero NGSW one-hot, CBS output basis |

`needs_public_lift()` scans the compiled reachable nodes for `Lift`; public choices
already lift through their one-hot NLEV selectors. Evaluator binding requires
NLEV[1] and its `NlevParameters` only when that scan succeeds, validating the
ring and exact transformed length once. `try_new` borrows the classic initializer
and BR parameters when needed; `try_with_public_lift` supplies explicit material.
The advanced `try_from_parts` accepts an optional lift with the same classic fallback.
All entries share this binding implementation. Sparse plans with a lift require
explicit material; plans without a lift ignore surplus material.
Online `Lift` reads this binding directly, without querying one-hot BR controls.
The backend `KeyGenerator::try_generate_public_lift_key` encrypts one independently
under the supplied accumulator secret and `NlevParameters`; no bucket-derived
noise or BR/CBS/return material is introduced. Call it only after
`needs_public_lift()` reports a requirement. No additional ciphertext owner or
online workspace is introduced. A raw view cannot prove its secret, encoded one,
basis or transform identity.

An operation's identity includes its form, input chunk, ordered polynomial/child
IDs and the table's ring/encoding contract. Identical operations share a node
across outputs. Removing a first or middle layer can move a public choice to a
higher chunk. A group containing any encrypted source lifts its remaining public
leaves before using NGSW; NLEV never selects encrypted operands.
`polynomial(j,p)` traverses the reduced choices using the digits of prefix p and
returns a borrowed polynomial. No additional full prefix map is retained.
Construction hash maps, source arrays and liveness counters do not survive.
`PolynomialId` names an entry in the unique polynomial pool; `TableNodeId`
names an interned operation. Both are opaque internal wrappers over `usize`,
distinct from logical table prefixes, chunk positions and reusable result slots.
The pool's `PolynomialHashValue(u64)` only selects a candidate bucket; full
coefficient comparison still establishes equality. No integer `Deref` or blanket
conversion erases these distinctions.
The immutable plan contains only operations, execution order, output actions,
selector batches and result slots. [`evaluation.rs`](src/evaluation.rs) owns
completed-LWE copying and borrowed ciphertext views; the plan does not mutate
ciphertexts or know backend representations.

## Stage and buffer layout

Let M be the per-chunk value count (the radix), c the input chunk count, d the coefficient chunk count, o the
output count and h=c-d. There are P=M^h logical polynomials per output, with
K=M^d meaningful entries in N coefficients. L is the CBS output gadget level
count; transformed row length R is N for NTT and N/2 for Fourier.

```text
try_new / try_with_public_lift -> try_from_parts
  choose required lift; validate binding and lengths; allocate compiled workspace
  prepare_rotation_constants
evaluate_to
  validate all input/output shapes before writes
  prepare_selectors: low d chunks, then surviving high-chunk choices
    sparse: BR in pairs, then project and consume each chunk in order
    classic or odd tail: BR/project/consume one chunk
  for each output in ascending order
    if its root matches an earlier output: copy that completed LWE
    otherwise execute its newly needed selection nodes in compiled order
    copy the selected root to current
    rotate_selected_table
    NTT: lwe_return.return_at_to
    Fourier: lwe_return.append_at (begin and submit once per bounded tile)
```

Selector requirements are the union of surviving public/encrypted choices.
Each high chunk needs full NLEV, nonzero NGSW, both, or no CBS. Both representations
share one BR and coefficient projection per branch; zero is projected for NLEV but not scheme-switched. Each selector
batch is generated once and reused by every node needing that chunk. Fourier
uses one reusable coefficient NLEV batch before storing transformed batches.
`SelectorBatches::{Unused,Nlev,Ngsw,Both}` makes those four cases explicit.
NLEV and NGSW batch indices belong to independent packed buffers; global input
chunk indices are converted by the table's `selector_batches_for_chunk` accessor. Each
backend retains its concrete coefficient-to-NTT/Fourier transformation.

| Buffer | Element count | Role |
| --- | --- | --- |
| `public_table_selectors` | A*M*L*R | A high chunks needing full NLEV |
| `encrypted_table_selectors` | B*(M-1)*L*R | B high chunks needing nonzero NGSW |
| `rotation_controls` | d*L*R | One aggregate per low chunk |
| `rotation_factors` | d*(M-1)*R | Integer-scale monomial differences |
| `selected_tables` | S*N | S compiled live-result slots, coefficient domain |

A and B may overlap in chunk identity. These counts exclude the embedded one-hot
and shared BR/CBS/return workspaces, current/product ciphertexts and
Fourier gadget constants. `nonzero_selectors` is one scratch batch when d>0.

The compiler schedules children before parents using depth-first traversal in
output order. A shared node executes once. Reference counts include every branch
occurrence and output root; a slot is reusable only after its last consumer.
A parent may reuse a dying child's slot because the kernel reads every branch
into separate `current`/external-product scratch before copying its result to
the destination. Runtime evaluation performs no reference counting, hashing or
allocation. `node_order` contains each node once; each output's `node_range`
selects the nodes first needed there. `result_slot` names its coefficient buffer
destination, independently of node ID or execution order. Every call replays
the complete schedule.

`OutputAction::Evaluate` still rotates and returns a root when its node range is
empty: an earlier output may have computed that root as a child. Only
`CopyFrom(previous)` reuses an already completed output LWE. Fourier's
`evaluation_tile` bounds a consecutive Evaluate range by return capacity and
stops before CopyFrom, so the source LWE is complete before copying it.

Public choices compute `sum_k T_k odot NLEV[delta_k]`, including k=0. Encrypted
choices compute `c_0 + sum_{k>0}(c_k-c_0) otimes NGSW[delta_k]`. Semantic polynomial
and ciphertext view iterators consume the ordered branches, which can occupy
noncontiguous pool slots. Each choice sums products in the transform domain and
inverse-transforms once. CMux uses `current` for differences; no separate
coefficient difference buffer is needed.

Every distinct output root copies its unrotated result to `current`, leaving shared results
intact, and applies all d rotations. A repeated root copies the earlier completed LWE,
because encoding, rotation controls and return key are identical in one binding. Low chunk i supplies
`C_i=G+sum_{k>0}(X^(-k*M^i)-1)*NGSW[delta_k]`, targeting `NGSW[X^(-m_i*M^i)]`.
Monomial factors are prepared at binding; Fourier factors use integer transforms
and G uses torus scale. `product` is the rotation ping-pong buffer.

Shared nodes reuse exactly the same ciphertext and error. Consumers therefore
have correlated errors, and identical roots followed by identical operations can
reuse the complete output ciphertext. Pruning changes the error path: budget BR-
basis lifts, CBS-basis public products, subsequent encrypted choices, rotations
and returns for the surviving path. Fewer operations alone do not certify a
noise bound. Fourier transform-domain summation can differ in rounding from
separately converted products; NTT summation is exact.

Both evaluators explicitly compose one-hot CBS and a coefficient-domain
`LweReturnEvaluator` binding. Each separately owns its backend's
`BootstrapResources`; one-hot operation state borrows that owner per CBS call,
and table products borrow its external-product scratch between calls. Fourier
also reuses that owner's single FFT engine for integer factors, torus gadget
rows, BR, projection and products. NTT allocates only scalar return scratch. Fourier allocates
only `LweReturnBatchWorkspace` and groups
selection, rotation and extraction in `prepare_output_returns`, then key-switches
consecutive newly evaluated outputs up to its fixed tile capacity (eight LWEs),
including a partial last tile. Tiles stop before a repeated output, which takes
no return slot and copies its earlier completed LWE. The LUT owns and binds
that return evaluator independently of one-hot/BR resources. Each tile starts empty and appends a consecutive valid
prefix; submission consumes exactly that prefix and invalidates it. Selection
and rotation preserve prepared samples; conversion and extraction remain
independent for each source polynomial.
Q→q still precedes extraction signs. A singleton tile writes directly to output;
larger tiles copy switched LWEs from scratch. Neither LUT carries the other return schedule's unused scratch; standalone one-hot
also omits ordinary return resources. See [workspaces and storage](../../guides/development/workspaces-and-storage.md).

## Fixed sparse input pairs

The LUT alone decides which chunks require one-hot CBS. Their count is
`d + active high chunks`, independent of the output count. No index list is
allocated online: an iterator visits low chunks then unpruned high chunks.
Sparse resources process two consecutive surviving inputs together; an odd
last input uses the ordinary single-input operation. Classic evaluation remains
serial, and plans with fewer than two BRs allocate no extra pair state.

The backend's `SparseBlindRotationPairWorkspace` retains only one extra
coefficient aggregate, current NTRU and exponent vector. For BR level count
`L_BR`, ring length N, external dimension n and coefficient T, its requested heap
is `(L_BR+1)*N*sizeof(T) + n*sizeof(usize)`. The two aggregates are filled in
`bucket -> source-control group -> input` order. NTT keeps its existing pairs;
Fourier u64 keeps four-way groups and its pair/single tail. Each input's selector
order and arithmetic remain unchanged. All buckets, encrypted zero controls and
zero exponents still contribute.

After both aggregates are ready, transform and external product run serially.
Three N-coefficient buffers suffice: each input's current and the existing shared
scratch. Swapping owners after each product preserves both current results.
Fourier also shares its single transformed aggregate and FFT engine. There is
no second evaluator, full input batch, queue or worker thread. This schedule
can improve source-key locality, but logical per-input key reads and arithmetic
counts are unchanged; it does not establish a cache-counter explanation or a
single-request PBS speedup.

`with_sparse_pair` lends each completed BR through a scoped `OneHotProjection`.
The callback cannot replace the BR resources and cannot retain the prepared
state. Borrowed `SelectorBuffers` choose the chunk's output forms and consume them
before the next callback: low chunks aggregate a rotation control; high chunks
retain their required selectors. Mixed NLEV/NGSW roles still share projection,
and branch zero is not scheme-switched. Fourier projection lends the existing
FFT engine to convert its one reusable coefficient batch immediately. Pairing
adds no selector scratch and no online allocation.

Measured complete-evaluation results and requested retained/peak memory are in
the [sparse pair report](../../guides/performance/sparse-layout-and-batching.md#ntru-lut-paired-blind-rotation).

## Historical measurements

The [complete lookup workflow report](../../guides/performance/tfhe-baseline.md#complete-high-precision-lookup-workflow-2026-10-09)
compares manually assembled and context-bound evaluation. The
[sparse lookup report](../../guides/performance/sparse-baseline.md#ntru-high-precision-lookup)
records fixed-weight classic/sparse measurements, and the
[sparse pair report](../../guides/performance/sparse-layout-and-batching.md#ntru-lut-paired-blind-rotation)
records the locality tradeoff and additional retained workspace of paired input preparation.
These reports describe their measured revisions and parameters; they are not
current benchmark commands or performance guarantees.

Public table compilation and online evaluation are separate costs. Polynomial
sharing and choice pruning reduce storage and arithmetic according to the function;
dense and repetitive functions can have very different costs at the same chunk
geometry. Fewer selector products alone do not imply a proportional speedup.
Compare complete evaluations with the same function, parameters, backend and
input geometry, accounting for retained workspace as well as latency.
