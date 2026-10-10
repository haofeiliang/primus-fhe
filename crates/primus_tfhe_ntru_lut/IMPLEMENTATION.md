# NTRU lookup stages and storage

User-facing encoding and evaluation contracts are in the [README](README.md). This document records the storage and stages shared by the [NTT evaluator](src/ntt.rs) and [Fourier evaluator](src/fourier.rs).

## Compilation and evaluator features

The compiler-only build (`--no-default-features`) retains public compilation and
polynomial inspection. It accepts `PolyLength`, accumulator Q, a Rounded input
codec at q and chunk geometry; it requires no encryption/key material or
NTT/FFT implementation. `ntt` / `fourier` enable the corresponding evaluator;
concrete FFT flags also enable `fourier`. Features do not change callback order,
encoding or table layout.

The backend-only [`buffer_lengths` module](src/lookup_table/buffer_lengths.rs)
checks each direct LUT allocation in its actual element type. NTT stores N ring
elements per transformed row; Fourier stores N/2 complex values, with separate
coefficient conversion and gadget-one buffers. These checks run at binding,
not in selection kernels. BR/CBS/return resources, transforms, keys and caller
buffers have their own storage contracts.

## Public table storage and complete choices

Let M=2^tau be the chunk radix, c the input chunk count, d the coefficient chunk
count, o the independent output count and h=c-d. Each output has P=M^h public
polynomials, with K=M^d meaningful entries in each N-coefficient polynomial.

[`lookup_table.rs`](src/lookup_table.rs) owns geometry and a flat boxed array in
`[output][prefix][coefficient]` order. For `x=p*K+z`, output j stores
`E_Q(F(x,j))` at coefficient z of polynomial p, and zero at coefficients K..N.
`polynomial(j,p)` directly borrows its N coefficients. Every logical polynomial
is stored, including equal polynomials and repeated outputs. There are no
content hashes, polynomial IDs, shared nodes or data-dependent schedules.

The private [compiler](src/lookup_table/compile.rs) checks the complete `o*P*N`
element count and byte size before allocation/callbacks. It then enumerates
output j first and ascending x within each output, stopping at the first invalid
digit. Radices up to 256 use a temporary cache of M unsigned Rounded encodings,
except for a single M-entry output, where direct encoding avoids a redundant
preparation pass. Larger radices also encode directly. The cache is bounded by
2 KiB at u64 (128 bytes at M=16) and is not retained by the table.

`needs_public_lift()` is exactly h=0. With no selection layer, the sole public
polynomial still needs an NLEV[1] product before rotations. Binding borrows the
classic initializer unless explicit lift material is supplied; sparse requires
independent material for this case. Its ring and transformed length are checked
once, and its own basis is used. With h>0, the first public selection lifts via
one-hot NLEV, so no separate LUT lift is retained. This rule is independent of
the function and does not alter blind rotation's own initialization.

The complete context's `try_generate_keys(rng)` uses that geometry directly;
no compiled function is passed to key generation. It returns the family
`KeyGenerationError`. Table layout/encoding compatibility is checked when
binding an evaluator. An explicitly imported lift takes precedence over the
classic initializer for h=0, even if its metadata is invalid; invalid material
is rejected, not silently replaced. With h>0 surplus lift material is ignored,
including its metadata. These checks establish N/Q/storage compatibility,
not actual secret, encoded-one, basis or transform identity. The caller retains
those numerical contracts for independently assembled keys.

## Stage and buffer layout

```text
try_new / try_with_public_lift -> try_from_parts
  choose lift for h=0; validate binding and allocation lengths
  allocate workspace and prepare rotation constants
evaluate_to
  validate every input/output shape before writes
  prepare_selectors for all c chunks
    sparse: prepare pairs, then project/consume each chunk in order
    classic or odd tail: prepare/project/consume one chunk
  for every output
    select_table: complete depth-first tree, or lift for h=0
    rotate_selected_table
    NTT: return_at_to immediately
    Fourier: append_at, then return_batch_to per bounded tile
```

Every input chunk has one fixed selector role:

| Input chunks | Retained form |
| --- | --- |
| 0..d | One NGSW monomial control per chunk; nonzero selectors are temporary |
| d, when h>0 | All M NLEV selectors, including delta_0 |
| d+1..c | M-1 NGSW selectors per chunk, omitting delta_0 |

Selectors and rotation controls are prepared once per request and shared across
outputs. A chunk never needs both forms. NTT converts the first high chunk's
coefficient NLEVs in place; Fourier converts that one batch using its existing
FFT engine and keeps torus-scaled Fourier rows. There is no content-dependent
chunk omission or representation choice.

For CBS output level count L and transformed row length R (N for NTT, N/2 for
Fourier), the principal buffers are:

| Buffer | Element count | Role |
| --- | --- | --- |
| `public_table_selectors` | M*L*R if h>0, else 0 | First high chunk's full NLEVs |
| `encrypted_table_selectors` | max(h-1,0)*(M-1)*L*R | Later high chunks' nonzero NGSWs |
| `rotation_controls` | d*L*R | One aggregate per low chunk |
| `nonzero_selectors` | (M-1)*L*R if d>0, else 0 | Reused while building low controls |
| `rotation_factors` | d*(M-1)*R | Integer-scale monomial differences |
| `selected_tables` | max(h-1,0)*M*N | M coefficient NTRUs per encrypted layer |
| `current`, `product` | N each | Current result and rotation ping-pong buffer |

Fourier additionally retains M*L*N coefficient values for the first NLEV batch
when h>0, and L*R values for the public gadget one when d>0. The table above does
not include embedded BR/CBS/return workspaces, transforms, keys or caller outputs.

`select_subtree` receives M^height consecutive polynomials. At height one it
performs the public selection. Higher levels split the range into M equal
subtrees, visit each child, and copy its result from `current` to the corresponding
slot for that encrypted layer. Descendants only use lower layers, so completed
siblings remain intact. Once all M children are present, a fused CMux consumes
the read-only slots and leaves the parent in `current`. Slots can then be reused.
The root already occupies `current`; it needs no extra copy before rotation.
Recursion depth is bounded by the validated input width, below usize::BITS.
No node metadata, reference counting or allocation is needed online.

The first high chunk computes
`sum_r P_r odot NLEV[delta_r]`, including r=0, for every public group. All
later groups compute `C_0 + sum_{r>0}(C_r-C_0) otimes NGSW[delta_r]`.
Semantic polynomial/ciphertext iterators traverse each contiguous group. Each
kernel accumulates in the transform domain and inverse-transforms once; CMux
uses `current` for differences while retaining the default unchanged.
Constant groups and repeated outputs execute the same operations.

For h>0, each output performs P public products and P/M-1 encrypted products:
`P+P/M-1` selection products, followed by d rotations. The number of selection
groups (and inverse transforms) is `(P-1)/(M-1)`. For M=16, d=3, c=4/5/6, the
selection-product counts are 16/271/4351. The first-layer lift is included;
counting only P-1 products would omit part of this implementation's work.
For h=0, there is one bound NLEV[1] product instead of selection groups.

Low chunk i supplies
`C_i=G+sum_{r>0}(X^(-r*M^i)-1)*NGSW[delta_r]`, targeting
`NGSW[X^(-m_i*M^i)]`. G is the public gadget encoding of one, not an NLEV lift.
The selected polynomial uses positive coefficient indices; all rotations are
negative, so coefficient zero recovers its entry at z. Fourier monomial
factors use integer transforms and G uses torus scale. Every output executes all
d products, swapping `current` and `product` after each one.

Selectors are reused, so output errors need not be independent. The first public
selection's decomposition residual is `-epsilon(P_selected)`; a later encrypted
selection adds `-f*epsilon(C_selected-C_0)` under NTRU secret f. Existing child
error follows the selected branch. Here `epsilon(U)=U-sum_l g_l*D_l(U)`
is the residual of the applicable gadget decomposition. Row errors, decomposition residuals, rotations
and return errors all need a joint budget. Fourier also adds FFT rounding;
fused inversion can differ from separately converting each product. NTT modular
summation is exact. Shape checks and operation counts do not certify that budget.

Both evaluators own backend `BootstrapResources` and borrow its external-product
scratch between one-hot calls. Fourier reuses that owner's FFT engine. NTT keeps
only scalar return scratch. Fourier keeps `LweReturnBatchWorkspace`, extracting
one polynomial at a time and key-switching up to eight LWEs per tile, including
a partial final tile. Every output is computed even if another has the same table.
The return binding independently performs coefficient-wise Q→q, signed extraction
and LWE key switching at q. Filled return slots survive selection/rotation of
later outputs; each submitted batch consumes exactly the appended prefix.
See [workspaces and storage](../../guides/development/workspaces-and-storage.md).

## Fixed sparse input pairs

The recommended configurations use classic BR. Explicit sparse selection retains
its paired schedule: consecutive input chunks are prepared two at a time on one
thread, with an ordinary single-input tail for odd c. The BR count is always c,
independent of function contents and output count. Classic, or c=1, retains no
extra pair state.

`SparseBlindRotationPairWorkspace` adds one coefficient aggregate, current NTRU
and exponent vector: `(L_BR+1)*N*sizeof(T) + n*sizeof(usize)` requested bytes.
Aggregate preparation shares source-key traversal, then transforms and external
products run serially with the existing scratch. No extra evaluator, full input
batch, queue or worker thread is introduced. Logical arithmetic counts do not
change.

`with_sparse_pair` lends each result through a scoped projection. Borrowed
`SelectorBuffers` consume it before the next callback: aggregate a low rotation
control, retain the first high chunk's NLEVs, or retain a later NGSW batch. Fourier
projection lends the same FFT engine for the coefficient conversion. The
[historical pair report](../../guides/performance/sparse-layout-and-batching.md#ntru-lut-paired-blind-rotation)
measures the old workload; it is not performance evidence for new parameters.

## Historical measurements

The [workflow report](../../guides/performance/tfhe-baseline.md#complete-high-precision-lookup-workflow-2026-10-09),
[sparse lookup report](../../guides/performance/sparse-baseline.md#ntru-high-precision-lookup)
and [sparse pair report](../../guides/performance/sparse-layout-and-batching.md#ntru-lut-paired-blind-rotation)
describe their measured revisions and parameters. Those versions used
content-dependent sharing/pruning; they are not current benchmark commands or
fixed-tree performance guarantees. Compare complete evaluations at the same
parameters, backend and geometry, accounting for retained storage and latency.
Table creation and online evaluation are separate costs.
