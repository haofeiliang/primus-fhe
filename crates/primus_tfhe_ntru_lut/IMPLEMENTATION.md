# NTRU lookup stages, storage and benchmarks

User-facing encoding and evaluation contracts are in the [README](README.md). This document records the internal storage and measurement boundaries shared by the [NTT evaluator](src/ntt.rs) and [Fourier evaluator](src/fourier.rs).

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
Compiler tests still exercise shared-node identity and slot lifetimes without a
transform implementation. Evaluation tests select individual available backends;
the comparative `pipeline` benchmark deliberately requires all of them.

The [`statistics` module](src/lookup_table/statistics.rs) reads the immutable
plan for operation counts. It also owns the direct buffer-length calculations
shared by both evaluator constructors and `estimate_workspace`. NTT counts T
entries; Fourier counts N/2 complex pairs per transformed polynomial plus its
coefficient conversion and gadget-one buffers. This describes storage only and
does not merge numerical kernels. Nested bootstrap/CBS/one-hot/return resources,
transform engines, keys, public compilation storage, caller buffers, allocator
overhead and construction temporaries are excluded. The benchmark's retained-heap
measurement includes resources beyond this partial estimate; the two numbers
must not be treated as the same metric.

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
ring and exact transformed length once. Both `try_new` and `try_from_parts` accept
optional independent lift material. If omitted, `try_new` can borrow the classic
initializer and BR parameters. Sparse plans with a lift require explicit material.
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
try_new
  validate binding and lengths; allocate compiled workspace
  prepare_rotation_constants
evaluate_to
  validate all input/output shapes before writes
  prepare_rotation_controls for low d chunks
  prepare_table_selectors for surviving high-chunk choices
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
use `one_hot_nlev_and_nonzero_ngsw_to`, sharing one BR and coefficient projection
per branch; zero is projected for NLEV but not scheme-switched. Each selector
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
workspace (including its return resources), current/product ciphertexts and
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

## Benchmark fixture

The [pipeline benchmark](benches/pipeline.rs) calls the public evaluators.
[Support](benches/support/mod.rs) holds only the public layout, cleartext function,
creation timing and heap reporting; its NTT/Fourier modules keep concrete
backend types. It neither includes production source files nor exposes scratch.

| Parameter | Value |
| --- | --- |
| Words / N / external n | u32 and u64 / 1024 / 800 |
| External q / plaintext t | PowOf2 2^24 / 8; M=4 |
| Ring Q | NTT Q30=998244353 (u32), Q50=1125899906826241 (u64); Fourier Native32/64 |
| Secrets | Fixed-weight binary external LWE (h32) and independent SparseTernary ring secret |
| BR algorithms | Paired classic/sparse; sparse r3/B64 |
| Bases / noise | Shared [NTRU circuit profile](../../guides/development/tfhe-parameters.md#ntru-pbs-cbs-and-lookup), including independent q-domain return KS |
| Layout | c8/d5/o8: 65536 inputs, 64 polynomials per output, K=N=1024 |
| Public function / input / seeds | `(x*x+3*x+7) mod 65536` / 43981 / client 42, input 43 |
| Public lift | Sparse generates independent NLEV[1] only when needed, using BR basis and sigma 0.7; classic borrows its initializer |

IDs include `/classic/` or `/sparse/` and `n800_h32_N1024` to separate them from
the former uniform-binary classic fixture. IDs without a workload suffix retain
this polynomial function. IDs containing
`/dense_seed42/` use the low 16 bits of a fixed SplitMix64 output mixer applied
to `x + 42 + 0x9e3779b97f4a7c15` with wrapping u64 arithmetic; the exact mapping
is in `Workload::digit` in the benchmark support module. It is independent of
the key-generation RNG and identical across word widths and backends. All workloads retain the same geometry, keys, input and measurement boundaries.
Within each classic/sparse pair the client coefficients and encrypted input are
identical; server-key generation consumes different randomness.
The polynomial's distinct public-polynomial counts per output are
`1,1,1,1,1,4,16,64`; the dense mapping has 64 distinct polynomials in each output.
The polynomial fixture stores 89 unique polynomials instead of 512, reducing
retained coefficient storage by about 83%; compiled plan metadata adds a small overhead. The dense fixture
still stores 512 polynomials plus compiled node/branch metadata.
Hashing and deduplication add construction work; creation (including plan compilation) and online evaluation
are measured separately, and fewer products do not imply proportional speedup.
The polynomial fixture bypasses selection for its first five outputs. Its
remaining outputs require 1, 5 and 21 choices instead of 21 each: 27 choice nodes
instead of 63, and 102 selector products instead of 237. Five initializer lifts
remain. The dense fixture requires 168 choices and 632 selector products. Both
fixtures still need all three high-chunk CBS calls and all low rotations.
Depth-first scheduling requires ten result slots instead of the old sixteen
candidates in these fixtures. This pair distinguishes
gains from repeated subtables from general evaluation costs. Creation includes
computing the selected public function, hashing, deduplication and selection-plan compilation.

The `/shared_middle_chunk/` diagnostic mapping returns `(m_0+m_6) mod 4` in every
output. Four polynomials, one public choice on chunk 6 and one result slot suffice;
chunks 5 and 7 require no CBS. All eight outputs share the complete result, so
only one set of low rotations and one return remain. This deliberately repetitive
function isolates cross-output sharing and a moved public layer. Its oracle and
zero-allocation checks run outside timing like those of the other fixtures.

For these mixed/dense fixtures, one `evaluate` iteration generates selectors for eight input chunks, selects or lifts,
rotates and returns all eight output ciphertexts. Keys, public LUT compilation,
encryption, correctness checks and reusable workspace allocation are outside timing.
The shape checks inside `evaluate_to` remain timed.
Throughput counts eight output ciphertexts, not eight independent requests.
The separate `create_lut_and_drop` IDs include allocation, filling and destruction
of one deduplicated public high-precision LUT; only classic IDs register creation,
and Fourier registers it once per word width because neither BR choice nor the
FFT engine affects coefficient compilation.

The selected evaluation fixture reports retained requested heap for combined
client/server keys, independent public-lift material, the public LUT, evaluator
workspace and caller outputs.
Context/tables, allocator metadata, stack and peak transient generation storage
are excluded. An untimed evaluation asserts zero online allocations and checks
every decoded output digit, then reports maximum circular q-domain phase error
over the output chunks (q=2^24, t=8, decoding half-gap 2^20). Counting and phase
checks are disabled during latency sampling.
These are finite functional observations, not a failure-probability estimate.

Ordinary CBS and full/nonzero one-hot costs now belong to their NTRU backend's
`circuit_bootstrap` benchmark. Private selection/rotation states, fused lift,
and reverse trace are no longer duplicated in this target. Their mathematical
contracts remain covered by library tests and lower-level primitive benchmarks.

## Reproducing measurements

```sh
cargo bench -p primus_tfhe_ntru_lut --bench pipeline --features ntt,rustfft,tfhe-fft -- --list
cargo bench -p primus_tfhe_ntru_lut --bench pipeline --features ntt,rustfft,tfhe-fft -- --test
taskset -c 0 cargo bench -p primus_tfhe_ntru_lut --bench pipeline --features ntt,rustfft,tfhe-fft -- \
  '/create_lut_and_drop$' --sample-size 20 --warm-up-time 0.5 --measurement-time 2 --noplot
taskset -c 0 cargo bench -p primus_tfhe_ntru_lut --bench pipeline --features ntt,rustfft,tfhe-fft -- \
  '/evaluate$' --sample-size 20 --warm-up-time 0.5 --measurement-time 2 --noplot
# SIMD configuration; use the same nightly compiler for both sides of a feature comparison.
taskset -c 0 cargo +nightly bench -p primus_tfhe_ntru_lut --bench pipeline --features ntt,simd,rustfft,tfhe-fft -- \
  '/evaluate$' --sample-size 20 --warm-up-time 0.5 --measurement-time 2 --noplot
```

Criterion defaults apply unless the command overrides them. `--list` performs
no key generation; filters initialize only matching fixtures. Build before
measurement, fix affinity and avoid concurrent benchmark/compiler work.
Record exact IDs and compiler/features. The [earlier measurements](../../guides/development/tfhe-benchmarks.md) use the
same public polynomial but uniform-binary classic keys and a different input RNG.
The fixed-weight classic/sparse measurements are in the
[sparse report](../../guides/development/sparse-bootstrap-measurements.md#ntru-high-precision-lookup).
Historical c7/d5/o3, n64, all-sigma0.7 results in Git also have different table
sizes and key work and are not latency comparison baselines.
