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

`public_table_selectors` holds one complete batch only when h>0. Fourier additionally retains its coefficient form in `public_selector_coefficients`. `nonzero_selectors` holds one reusable scratch batch only when d>0. These counts exclude the embedded one-hot evaluator, external-product and return workspaces, current/product/difference ciphertexts and Fourier gadget constants; they are not a total heap estimate.

The public first layer computes `sum_k T_k odot NLEV[delta_k]`, including k=0. Later encrypted layers compute `c_0 + sum_{k>0}(c_k-c_0) otimes NGSW[delta_k]`. With no table layer, the server's BR-basis `NLEV[1]` lifts the single public polynomial.

Each low chunk i produces `C_i=G+sum_{k>0}(X^(-k*M^i)-1)*NGSW[delta_k]`, targeting `NGSW[X^(-m_i*M^i)]`. The factors are prepared at construction. Fourier factors use integer transforms, while G and ciphertexts use torus transforms. Only C_i is retained for that chunk; the next chunk overwrites the scratch selectors. All table selectors and rotation controls are reused across o outputs, with only one output's candidate tree live at a time.

Each encrypted layer consumes consecutive groups of M candidates. Group g starts at coefficient g*M*N; its result is written at g*N only after the whole group has been read. Writes therefore stay within consumed storage, leaving unread groups intact. The active candidate count is divided by M after each layer. Explicit group indices express this in-place dependency; polynomial and ciphertext iterators traverse the individual mathematical objects within each group.

For h>0, each call projects M+(c-1)*(M-1) selectors, and each output uses P+P/M-1 table-selection external products. For h=0, each call projects c*(M-1) selectors and each output uses one public lift. Both cases add d rotation products and one return operation per output. These are operation counts, not runtime or noise estimates. CBS, approximate decomposition, selector errors, Fourier rounding and the return path still require a decoding budget.

## Benchmark fixture

The [pipeline benchmark](benches/pipeline.rs) compiles the evaluator sources with `include!`/`#[path]` to access private stages. It does not add production API hooks or copy the selection algorithms. Parameters are defined in [support/mod.rs](benches/support/mod.rs); backend measurements are in [support/ntt.rs](benches/support/ntt.rs) and [support/fourier.rs](benches/support/fourier.rs).

| Parameter | Value |
| --- | --- |
| Word width / ring length / external LWE dimension | u64 / N=1024 / n=64 |
| External q / plaintext t | `PowOf2Modulus(2^24)` / 8; M=4 |
| Ring Q | NTT: `BarrettModulus(1125899906826241)`; Fourier: native 2^64 |
| Secrets | Independent external UniformBinary and ring SparseTernary |
| BR, trace, scheme-switch decomposition | log_basis=8, maximum level count |
| Return KS / CBS output decomposition | log_basis=8, 3 levels |
| Noise standard deviations | 0.7 in each role's coefficient-domain units |
| Layout | c=7, d=5, o=3; K=1024, P=16, 16384 possible inputs |
| Function | `(x*x + 3*x + x/17 + x/257 + 7) mod 64`, three base-4 output digits |
| Seed / timed input | `0x0053_5445_5039` / x=0x1234 |

The maximum 8-bit decomposition has six levels and drops two low bits for the 50-bit NTT Q; native u64 has eight levels and drops none. The fixture measures functional workloads. Its small external dimension and noise do not define production security parameters or equal-security backends. Changing modulus implementations, dimensions or decompositions requires a new timing baseline.

## Measurement boundaries

Each Criterion iteration performs one named operation. Key generation, public LUT compilation, input encryption, validation, allocation probes and decryption occur outside timing.

| Measurement | Timed work |
| --- | --- |
| `complete` | Selectors for seven chunks, then selection, rotation and return for all three outputs |
| `table_selection/prepared_selectors` | One output: 16 public candidates, two selection layers, 19 external products |
| `rotation_selection/prepared_controls` | Five aggregated controls on one selected ciphertext; includes two state swaps |
| `return_Q_to_q_then_KS` | One already rotated ciphertext returned to external LWE |
| `one_hot/full_ngsw`, `one_hot/nonzero_ngsw` | One input through BR, projection and scheme switch; four or three outputs respectively |
| `ordinary_cbs` | One binary input through ordinary CBS |
| `first_lift/binary` | Fused public lift for selector 1 and exponent N/3, excluding key generation and the rest of BR |
| `reverse_trace/retained1`, `reverse_trace/retained4` | Full or partial normalized trace, retaining one or four coefficient positions |

Rotation uses `iter_batched_ref` to clone the initial selected ciphertext outside timing; repeated samples do not accumulate rotations or noise. The two swaps needed to use the in-place evaluator are timed. Stage measurements reuse prepared states, and full NGSW one-hot differs from the public layer's NLEV output, so summing these timings does not predict complete lookup latency.

The harness prints retained requested heap (`allocated_bytes-released_bytes`), online allocation counts and maximum q-domain phase error against known function outputs. Retained heap excludes temporary allocations, allocator metadata, stack and RSS; workspace measurements exclude the shared context and transform tables. A returned key's coefficient storage is part of the server key, and standalone stage workspaces overlap the complete evaluator's responsibilities, so these rows must not be summed blindly.

Setup validates x=0, 0x1234 and 16383 (nine output phases per backend), compact selectors against full selectors, ordinary CBS through CMux, fused lifting through a known monomial rotation, and trace projection including discarded positions. Online operations assert zero allocation. These checks and a few fixed-seed phase observations are functional diagnostics, not failure-probability estimates or complete correctness coverage; ordinary [tests](tests) remain independent validation.

## Reproducing measurements

```sh
# Run setup and assertions once per benchmark target, without latency sampling.
cargo bench -p primus_tfhe_ntru_lut --bench pipeline -- --test

# Measure the default fixture.
cargo bench -p primus_tfhe_ntru_lut --bench pipeline

# Compare sequentially on the same available logical CPU and nightly toolchain.
taskset -c 4 cargo +nightly bench -p primus_tfhe_ntru_lut --bench pipeline -- --save-baseline default
taskset -c 4 cargo +nightly bench -p primus_tfhe_ntru_lut --bench pipeline --features simd -- --save-baseline simd
```

The harness uses 20 samples, 300 ms warmup and a one-second target measurement time. Record CPU, affinity, toolchain, feature set, parameters and machine load with results. Keep compilation and other measurements out of the timed run. The default feature set does not imply that FFT dependencies avoid SIMD. Criterion results live under `target/criterion`; compare equivalent workloads and use confidence intervals rather than interpreting small single-run differences as stable improvements.
