# NTRU lookup stages, storage and benchmarks

User-facing encoding and evaluation contracts are in the [README](README.md). This document records the internal storage and measurement boundaries shared by the [NTT evaluator](src/ntt.rs) and [Fourier evaluator](src/fourier.rs).

## Stage and buffer layout

Let M be the chunk radix, c the input chunk count, d the coefficient chunk count, o the output chunk count and h=c-d the table chunk count. Each output has P=M^h public polynomials, each storing K=M^d entries in N coefficients. L is the CBS output gadget level count. One transformed polynomial has R=N elements for NTT and R=N/2 complex elements for Fourier.

```text
try_new
  validate binding and lengths; allocate workspace
  prepare_rotation_constants
evaluate_to
  validate every input/output shape before writing
  prepare_selectors
    prepare_rotation_controls: low d chunks
    prepare_table_selectors: high h chunks
  for each output chunk
    select_table
      h=0: lift the sole public polynomial
      h>0: select_public_table_groups, then select_encrypted_table_layer
    rotate_selected_table
    key_switch_to: coefficient-wise Q -> q, extraction, external LWE switch
```

Lengths below count array elements, not bytes or ciphertexts. Transformed storage uses T for NTT and Complex64 for Fourier; candidates always use coefficient-domain T values.

| Quantity | Element count | Role |
| --- | --- | --- |
| `selector_len` | L*R | One NLEV/NGSW selector or aggregated rotation control |
| `one_hot_len` | M*L*R | Complete selector batch for one input chunk |
| `nonzero_one_hot_len` | (M-1)*L*R | Nonzero selectors; slot r-1 corresponds to branch r |
| `encrypted_table_selectors_len` | max(h-1,0)*(M-1)*L*R | Nonzero NGSWs for all later table layers |
| `rotation_controls_len` | d*L*R | One aggregate for each low chunk |
| `rotation_factors_len` | d*(M-1)*R | Public monomial differences, without gadget levels |
| `candidates_len` | (P/M)*N if h>0; otherwise 0 | First-layer results and subsequent in-place compaction |

`public_table_selectors` holds one complete batch only when h>0. Fourier additionally retains its coefficient form in `public_selector_coefficients`. `nonzero_selectors` holds one reusable scratch batch only when d>0. These counts exclude the embedded one-hot evaluator (including shared external-product and FFT workspaces), the return workspace, current/product/difference ciphertexts and Fourier gadget constants; they are not a total heap estimate.

The public first layer computes `sum_k T_k odot NLEV[delta_k]`, including k=0. Later encrypted layers compute `c_0 + sum_{k>0}(c_k-c_0) otimes NGSW[delta_k]`. With no table layer, the server's BR-basis `NLEV[1]` lifts the single public polynomial.

Each low chunk i produces `C_i=G+sum_{k>0}(X^(-k*M^i)-1)*NGSW[delta_k]`, targeting `NGSW[X^(-m_i*M^i)]`. The factors are prepared at construction. Fourier factors use integer transforms, while G and ciphertexts use torus transforms. Only C_i is retained for that chunk; the next chunk overwrites the scratch selectors. All table selectors and rotation controls are reused across o outputs, with only one output's candidate tree live at a time.

Each encrypted layer consumes consecutive groups of M candidates. Group g starts at coefficient g*M*N; its result is written at g*N only after the whole group has been read. Writes therefore stay within consumed storage, leaving unread groups intact. The active candidate count is divided by M after each layer. Explicit group indices express this in-place dependency; polynomial and ciphertext iterators traverse the individual mathematical objects within each group.

For h>0, each call projects M+(c-1)*(M-1) selectors, and each output uses P+P/M-1 table-selection external products. For h=0, each call projects c*(M-1) selectors and each output uses one public lift. Both cases add d rotation products and one return operation per output. These are operation counts, not runtime or noise estimates. CBS, approximate decomposition, selector errors, Fourier rounding and the return path still require a decoding budget.

Table products borrow one-hot CBS's external-product workspace; Fourier transforms also borrow its FFT engine. These stages execute serially and overwrite scratch before reuse. Storage choices and the measured memory/latency tradeoff are recorded in [workspaces and storage](../../guides/development/workspaces-and-storage.md).

## Benchmark fixture

The [pipeline benchmark](benches/pipeline.rs) calls the public evaluators.
[Support](benches/support/mod.rs) holds only the public layout, cleartext function,
compilation timing and heap reporting; its NTT/Fourier modules keep concrete
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

One `complete` iteration generates selectors for eight input chunks, selects,
rotates and returns all eight output ciphertexts. Keys, public LUT compilation,
encryption, validation and reusable workspace allocation are outside timing.
Throughput counts eight output ciphertexts, not eight independent requests.
The separate `compile_and_drop` IDs include allocation, filling and destruction
of one public LUT; Fourier registers this once per word width because the two
FFT engines do not affect coefficient compilation.

The selected complete fixture reports retained requested heap for combined
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
  '/complete$' --sample-size 20 --warm-up-time 0.5 --measurement-time 2 --noplot
# SIMD configuration; use the same nightly compiler for both sides of a feature comparison.
taskset -c 0 cargo +nightly bench -p primus_tfhe_ntru_lut --bench pipeline --features simd -- \
  '/complete$' --sample-size 20 --warm-up-time 0.5 --measurement-time 2 --noplot
```

Criterion defaults apply unless the command overrides them. `--list` performs
no key generation; filters initialize only matching fixtures. Build before
measurement, fix affinity and avoid concurrent benchmark/compiler work.
Record exact IDs and compiler/features. The [current baseline](../../guides/development/tfhe-benchmarks.md)
uses this workload; historical c7/d5/o3, n64, all-sigma0.7 results in Git have
different table sizes and key work and are not latency comparison baselines.
