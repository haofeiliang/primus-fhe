# NTRU lookup stages, storage and benchmarks

User-facing encoding and evaluation contracts are in the [README](README.md). This document records the internal storage and measurement boundaries shared by the [NTT evaluator](src/ntt.rs) and [Fourier evaluator](src/fourier.rs).

## Public table storage

[`lookup_table.rs`](src/lookup_table.rs) owns logical geometry and immutable table
access. Its private [`compile` module](src/lookup_table/compile.rs) enumerates every
callback pair in the documented order, encodes one N-coefficient scratch
polynomial at a time, and interns it. The construction-only pool owns the fixed
polynomial stride, hashing and full coefficient comparisons. Hash matches alone
never establish identity.

The table stores a flat boxed coefficient pool and one `OutputTable` per output:
`Direct(id)` refers to one polynomial for every high-chunk prefix, while
`Select(ids)` owns P prefix-ordered references. Direct outputs retain no repeated
prefix array. `polynomial(j,p)` resolves logical entries without exposing IDs or
pool order. `polynomial_groups` gives evaluators M-polynomial groups as exact-size
view iterators, so backend code never handles IDs or gathers copied polynomials.
Construction still validates worst-case dense storage before callbacks without
reserving that size. No construction hash map or scratch survives compilation.

A direct output uses the initializer's **BR basis** to
lift its polynomial. Equality of prefixes does not imply a constant polynomial:
all d low-chunk rotations remain necessary. This covers h=0 as well. Mixed tables
retain every high-chunk selector for unresolved outputs; if all outputs bypass
selection, both backends omit high-chunk CBS, public/encrypted table-selector
buffers and candidates. Embedded one-hot scratch and the binding's CBS key
requirements remain unchanged. No partial subtree sharing is performed.

## Stage and buffer layout

Let M be the chunk radix, c the input chunk count, d the coefficient chunk count, o the output chunk count and h=c-d the table chunk count. Each output has P=M^h logical public polynomials, each storing K=M^d entries in N coefficients. L is the CBS output gadget level count. One transformed polynomial has R=N elements for NTT and R=N/2 complex elements for Fourier.

```text
try_new
  validate binding and lengths; allocate workspace
  prepare_rotation_constants
evaluate_to
  validate every input/output shape before writing
  prepare_selectors
    prepare_rotation_controls: low d chunks
    prepare_table_selectors: high h chunks, only if some output needs selection
  for each output chunk
    select_table
      direct output (including h=0): lift_public_polynomial with the BR basis
      otherwise: select_public_table_groups, then select_encrypted_table_layer
    rotate_selected_table
    NTT: key_switch_to (independent Q -> q, extraction and LWE key switch)
    Fourier: modulus_switch_extract_at_to (independent Q -> q, extraction into a tile slot)
      key_switch_extracted_batch_to when eight slots or the last output are ready
```

The Fourier evaluator groups selection, rotation and extraction for one tile in `prepare_output_returns`; `evaluate_to` validates the full request, prepares selectors, then prepares and key-switches each tile. The helper leaves completed LWE slots intact while reusing polynomial scratch for later outputs.

The logical high-chunk count h always means c-d. `needs_table_selection()` is a
separate decision derived from the output variants: it is true when any output
is `Select`. Every table-selection buffer is zero-length when it is false; the
following selection-buffer counts apply only when it is true.
Lengths below count array elements, not bytes or ciphertexts. Transformed storage uses T for NTT and Complex64 for Fourier; candidates always use coefficient-domain T values.

| Quantity | Element count | Role |
| --- | --- | --- |
| `selector_len` | L*R | One NLEV/NGSW selector or aggregated rotation control |
| `one_hot_len` | M*L*R | Complete selector batch for one input chunk |
| `nonzero_one_hot_len` | (M-1)*L*R | Nonzero selectors; slot r-1 corresponds to branch r |
| `encrypted_table_selectors_len` | max(h-1,0)*(M-1)*L*R | Nonzero NGSWs for all later table layers |
| `rotation_controls_len` | d*L*R | One aggregate for each low chunk |
| `rotation_factors_len` | d*(M-1)*R | Public monomial differences, without gadget levels |
| `candidates_len` | (P/M)*N | First-layer results and subsequent in-place compaction |

`public_table_selectors` holds one complete batch only when table selection is needed. Fourier additionally retains its coefficient form in `public_selector_coefficients`. `nonzero_selectors` holds one reusable scratch batch only when d>0. These counts exclude the embedded one-hot evaluator (including shared external-product, FFT and return workspaces), the NTT evaluator's separate scalar return buffer, current/product ciphertexts and Fourier gadget constants; they are not a total heap estimate.

The public first layer computes `sum_k T_k odot NLEV[delta_k]`, including k=0. Later encrypted layers compute `c_0 + sum_{k>0}(c_k-c_0) otimes NGSW[delta_k]`. For an output with equal prefixes, the server's BR-basis `NLEV[1]` lifts the shared public polynomial, even when h>0.

Each group sums all products in the transform domain and inverse-transforms once. The public layer uses `NLEV.external_product_sum_to`; encrypted layers use `NGSW.cmux_k_to` with semantic candidate/control iterators. CMux uses `current` for each difference and the shared workspace for the sum, keeping `c_0` unchanged. A separate coefficient difference buffer is unnecessary; `product` remains the ping-pong buffer for rotations.

Each low chunk i produces `C_i=G+sum_{k>0}(X^(-k*M^i)-1)*NGSW[delta_k]`, targeting `NGSW[X^(-m_i*M^i)]`. The factors are prepared at construction. Fourier factors use integer transforms, while G and ciphertexts use torus transforms. Only C_i is retained for that chunk; the next chunk overwrites the scratch selectors. All table selectors and rotation controls are reused across o outputs, with only one output's candidate tree live at a time.

Each encrypted layer consumes consecutive groups of M candidates. Group g starts at coefficient g*M*N; its result is written at g*N only after the whole group has been read. Writes therefore stay within consumed storage, leaving unread groups intact. The active candidate count is divided by M after each layer. Explicit group indices express this in-place dependency; polynomial and ciphertext iterators traverse the individual mathematical objects within each group.

If any output needs selection, each call projects M+(c-1)*(M-1) selectors. Otherwise it projects d*(M-1). Each unresolved output uses P+P/M-1 table-selection external products; each direct output uses one public lift. All outputs still add d rotation products and one return operation.

For each unresolved output, selection performs `(P-1)/(M-1)` inverse transforms per output: 21 for M=4/P=64, versus 79 separately inverted products. NTT summation is exact; Fourier sums before torus conversion, so its rounding can differ from separately converted products. These are operation counts, not runtime or noise estimates. CBS, approximate decomposition, selector errors, Fourier rounding and the return path still require a decoding budget.

Table products borrow one-hot CBS's external-product workspace; Fourier transforms also borrow its FFT engine. These stages execute serially and overwrite scratch before reuse. NTT returns each completed polynomial through its scalar return buffer. Fourier immediately converts and extracts it into the embedded PBS return workspace. Selection and rotation leave the filled LWE slots intact; at most eight samples are retained before key switching, including a partial last tile. The outer Fourier evaluator needs no separate return buffer. A singleton tile writes directly to the caller output; larger tiles copy their switched LWEs from scratch into the separate output objects. This regrouping preserves each scalar return exactly, including Q→q rounding before extraction signs. Storage choices and the measured memory/latency tradeoff are recorded in [workspaces and storage](../../guides/development/workspaces-and-storage.md).

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
| Secrets | Independent UniformBinary external LWE and SparseTernary ring secret |
| Bases / noise | Shared [NTRU circuit profile](../../guides/development/tfhe-parameters.md#ntru-pbs-cbs-and-lookup), including independent q-domain return KS |
| Layout | c8/d5/o8: 65536 inputs, 64 polynomials per output, K=N=1024 |
| Public function / input / seed | `(x*x+3*x+7) mod 65536` / 43981 / 42 |

IDs without a workload suffix retain this polynomial function. IDs containing
`/dense_seed42/` use the low 16 bits of a fixed SplitMix64 output mixer applied
to `x + 42 + 0x9e3779b97f4a7c15` with wrapping u64 arithmetic; the exact mapping
is in `Workload::digit` in the benchmark support module. It is independent of
the key-generation RNG and identical across word widths and backends. Both
workloads retain the same geometry, keys, input and measurement boundaries.
The polynomial's distinct public-polynomial counts per output are
`1,1,1,1,1,4,16,64`; the dense mapping has 64 distinct polynomials in each output.
The polynomial fixture stores 89 unique polynomials instead of 512, reducing
retained LUT heap by about 82% (including logical indices). The dense fixture
still stores 512 polynomials and pays only the additional index/metadata storage.
Hashing and deduplication add construction work; creation and online evaluation
are measured separately, and fewer products do not imply proportional speedup.
The polynomial fixture therefore bypasses selection for its first five outputs,
while retaining all high-chunk CBS for the remaining three. This pair distinguishes
gains from repeated subtables from general evaluation costs. Creation includes
computing the selected public function, hashing and deduplication.

For these mixed/dense fixtures, one `evaluate` iteration generates selectors for eight input chunks, selects or lifts,
rotates and returns all eight output ciphertexts. Keys, public LUT compilation,
encryption, correctness checks and reusable workspace allocation are outside timing.
The shape checks inside `evaluate_to` remain timed.
Throughput counts eight output ciphertexts, not eight independent requests.
The separate `create_lut_and_drop` IDs include allocation, filling and destruction
of one deduplicated public high-precision LUT; Fourier registers this once per word width
because the two FFT engines do not affect coefficient compilation.

The selected evaluation fixture reports retained requested heap for combined
client/server keys, the public LUT, evaluator workspace and caller outputs.
Context/tables, allocator metadata, stack and peak transient generation storage
are excluded. An untimed evaluation asserts zero online allocations and checks
every decoded output digit; counting is disabled during latency sampling.
These are finite functional observations, not a failure-probability estimate.

Ordinary CBS and full/nonzero one-hot costs now belong to their NTRU backend's
`circuit_bootstrap` benchmark. Private selection/rotation states, fused lift,
and reverse trace are no longer duplicated in this target. Their mathematical
contracts remain covered by library tests and lower-level primitive benchmarks.

## Reproducing measurements

```sh
cargo bench -p primus_tfhe_ntru_lut --bench pipeline -- --list
cargo bench -p primus_tfhe_ntru_lut --bench pipeline -- --test
taskset -c 0 cargo bench -p primus_tfhe_ntru_lut --bench pipeline -- \
  '/create_lut_and_drop$' --sample-size 20 --warm-up-time 0.5 --measurement-time 2 --noplot
taskset -c 0 cargo bench -p primus_tfhe_ntru_lut --bench pipeline -- \
  '/evaluate$' --sample-size 20 --warm-up-time 0.5 --measurement-time 2 --noplot
# SIMD configuration; use the same nightly compiler for both sides of a feature comparison.
taskset -c 0 cargo +nightly bench -p primus_tfhe_ntru_lut --bench pipeline --features simd -- \
  '/evaluate$' --sample-size 20 --warm-up-time 0.5 --measurement-time 2 --noplot
```

Criterion defaults apply unless the command overrides them. `--list` performs
no key generation; filters initialize only matching fixtures. Build before
measurement, fix affinity and avoid concurrent benchmark/compiler work.
Record exact IDs and compiler/features. The [current baseline](../../guides/development/tfhe-benchmarks.md)
uses this workload; historical c7/d5/o3, n64, all-sigma0.7 results in Git have
different table sizes and key work and are not latency comparison baselines.
