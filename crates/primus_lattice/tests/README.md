# Lattice test coverage

Tests here protect raw ciphertext layouts and low-level operation contracts.
They use deterministic inputs and check coefficient order, signs, normalization,
output overwrite, accumulation, and storage/workspace reuse. Encryption noise,
key generation, and decryptability belong to the higher-level scheme crates.

| File | Contract |
| --- | --- |
| `layout.rs` | Checked size boundaries, gadget level preservation across representations, RNS workspace compatibility |
| `arithmetic.rs` | Borrowed/owned single-modulus arithmetic, scalar/factor products and fused accumulation |
| `rns_arithmetic.rs` | Component/modulus order and per-modulus scalar/factor arithmetic (`rns`) |
| `fourier.rs` | Complex arithmetic and integer-polynomial/torus-ciphertext scaling with both FFT backends |
| `polynomial_products.rs` | Negacyclic monomial signs and NTT/DCRT polynomial overwrite/accumulation |
| `extraction.rs` | GLWE/RLWE/NTRU sample order and phase signs, compact padding, packed extraction and allocation reuse |
| `plaintext_and_gadget.rs` | Body-only plaintext updates, trivial ciphertext clearing, selected gadget diagonals |
| `external_product.rs` | Gadget decomposition/product semantics and dirty workspace reuse |

Keep one focused oracle or differential test per independent contract. Local
macros exercise the ciphertext type matrix without copying test bodies; these
invocations also detect missing generated APIs. Keep native, explicit-modulus,
Fourier, and RNS cases distinct when their numerical contracts differ.

Do not add tests for raw constructors, standard slice forwarding, or every
malformed buffer. Most raw-layout preconditions are deliberately unchecked here.
Panic tests cover documented owning boundaries, and must also pass in release.
A plain transform roundtrip is unnecessary when a retained nonzero convolution
already checks the same conversion path and its scale.

CMUX selection and encrypted GLWE/RNS gadget products also have end-to-end
coverage in `primus_glwe/tests/cmux.rs`, `primus_glwe/tests/gadget_generation.rs`,
`primus_ntru/tests/gadget_generation.rs`, and `primus_glwe_rns/tests/{glev,ext_prod}.rs`.
Do not duplicate their encryption fixtures in this crate.

Run from the workspace root:

```sh
cargo test -p primus_lattice
cargo test -p primus_lattice --features rns
cargo test -p primus_lattice --release --features rns
cargo clippy -p primus_lattice --all-targets --features rns -- -D warnings
cargo +nightly test -p primus_lattice --features rns,simd
```
