# Lattice test coverage

> [!WARNING]
> Part of the experimental [Primus FHE](../../../README.md) workspace; APIs and numerical contracts may change incompatibly.

Tests here protect raw ciphertext layouts and low-level operation contracts. They use deterministic inputs and check coefficient order, signs, normalization, output overwrite, accumulation, and storage/workspace reuse. Encryption noise, key generation, and decryptability belong to the higher-level scheme crates.

| File | Contract |
| --- | --- |
| `serde.rs` | Optional raw `Lwe`/`MultiMsgLwe` serialization for borrowed and owned storage; mask/body order and full-width coefficients (`serde`) |
| `layout.rs` | Checked sizes, ABox/offset-slice storage reuse, workspace rebind rejection/unwind restoration, and RNS layout/limb-width compatibility |
| `arithmetic.rs` | Shared flat arithmetic through borrowed LWE storage, offset-output sentinels, scalar/factor overwrite and accumulation |
| `rns_arithmetic.rs` | CRT add/sub/neg and DCRT scalar/factor arithmetic across GGSW rows, levels, components and moduli (`rns`) |
| `fourier.rs` | Borrowed complex arithmetic; GGSW polynomial scaling and monomial subtraction against coefficient oracles with both FFT backends |
| `polynomial_products.rs` | Single-polynomial NTRU and multi-polynomial GGSW monomial oracles, including NTT product overwrite/accumulation; CRT monomials and DCRT products (`rns`) |
| `extraction.rs` | GLWE/NTRU sample order and phase signs, compact padding, packed extraction and allocation reuse |
| `plaintext_and_gadget.rs` | Body-only plaintext updates, trivial ciphertext clearing, selected gadget diagonals; one representative per shared macro |
| `external_product.rs` | Gadget product oracles, coefficient/borrowed transform outputs, independent NLev/control levels, dirty-output clearing, NTT coefficient/Fourier transform output-length rejection before writes and workspace reuse |
| `external_product_sum.rs` | NTT/Fourier batch sums against independent polynomial oracles and separate products, u32/u64 and both FFT backends, empty-sum clearing, fixed-buffer/pair-length rejection and recovery after partial accumulation |
| `cmux_k.rs` | NGSW multi-way CMux count/default/output checks, validation of each pair before its difference, recovery after late failures and empty-batch copying; N=32 noiseless f=1 fixture |
| `ternary_cmux.rs` | GGSW NTT/Fourier and NGSW NTT ternary rotation against an independent negacyclic oracle, sign/wrap boundary exponents, decomposition/rounding error and scratch reuse |

Shared flat-operation macros are checked through one representative wrapper, using borrowed storage and a length that exercises SIMD tails. GGSW fixtures cover multi-row, multi-level polynomial traversal; NTRU monomial tests retain its separate single-polynomial implementation. Do not repeat the same operation over every wrapper solely to instantiate generated methods. Native, explicit-modulus, Fourier, and RNS cases remain separate where their numerical contracts differ. Checked layout fixtures use N=32/64; raw arithmetic retains smaller buffers where useful; the flat scalar/factor test retains 65 coefficients for vector/tail traversal. Fourier CMUX retains u32/u64 and both FFT backends, including exact and truncated decomposition.

Monomial and CMUX tests select zero, positive/negative half-ring, interior and wrap-boundary exponents. Zero runs last to expose stale scratch. Paired monomial coefficient arithmetic is exhaustively checked in [`primus_poly/tests/monomial.rs`](../../primus_poly/tests/monomial.rs); the ciphertext method only forwards slices, so this suite does not repeat that Cartesian product. The four-coefficient CRT test still exhausts its eight exponents to check modulus-block traversal.

Nonzero gadget products validate NLev/NGSW conversion, level order and normalization. The same fixtures then run zero products through reused outputs and scratch, checking exact zero in transformed storage as well as coefficient results. This covers representation boundaries without separate iterator-count or transform-roundtrip tests.

`layout.rs` checks the GLWE layout range and derived dimensions; [`primus_poly/tests/poly_length.rs`](../../primus_poly/tests/poly_length.rs) owns the shared power-of-two geometry boundary. It then separates workspace/owning-storage contracts from numerical kernels. Its pointer checks establish consuming allocation reuse, not a general allocation count. Online allocation counters remain with the real consumers: [`primus_ntru/tests/phase_contracts.rs`](../../primus_ntru/tests/phase_contracts.rs) covers fused initialization, while the TFHE PBS/CBS/lookup tests cover their complete evaluation paths. Do not add a counter around every lattice numerical sample.

Do not add tests for raw constructors, standard slice forwarding, or every malformed buffer. Most raw-layout preconditions are deliberately unchecked here. Panic tests cover documented owning boundaries, and must also pass in release. A plain transform roundtrip is unnecessary when a retained nonzero convolution already checks the same conversion path and its scale.

CMUX selection and encrypted GLWE/RNS gadget products also have end-to-end coverage in `primus_glwe/tests/cmux.rs`, `primus_glwe/tests/gadget_generation.rs`, `primus_ntru/tests/{gadget_generation,ternary_cmux}.rs`, and `primus_glwe_rns/tests/{glev,ext_prod}.rs`. Do not duplicate their encryption fixtures in this crate.

NGSW k-CMux length/empty-batch checks live here; `primus_ntru` keeps the real-key
selection and separate-product differential, including the noise from encrypted
zero controls. Those numerical checks are independent of the raw shape tests.

Targets declare their NTT/Fourier capabilities and concrete engines. Mixed comparisons require `ntt,rustfft,tfhe-fft`; missing requirements skip the entire target. Layout and plaintext tests retain coefficient cases without a backend, and gate only their representation-specific cases. Use the commands below for full coverage; workspace `just` selects NTT and both FFT engines.

Run from the workspace root:

```sh
cargo nextest run -p primus_lattice --lib --tests --features serde
cargo nextest run -p primus_lattice --lib --tests --features ntt,rustfft,tfhe-fft
cargo nextest run -p primus_lattice --lib --tests --features rns,rustfft,tfhe-fft
cargo nextest run -p primus_lattice --lib --tests --release --features rns,rustfft,tfhe-fft
cargo clippy -p primus_lattice --all-targets --features rns,rustfft,tfhe-fft -- -D warnings
cargo +nightly nextest run -p primus_lattice --lib --tests --all-features
cargo test -p primus_lattice --doc --features rns,rustfft,tfhe-fft
```
