# primus_glwe_rns

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

GLWE encryption and evaluation over an ordered RNS basis, with CRT coefficient and DCRT NTT representations. This crate supplies BFV-scaled coefficient encryption, gadget products, automorphism, trace, expansion and key switching. It is a building block, not a complete BFV/BGV/CKKS scheme.

## Recommended workflow

1. Choose ordered, pairwise-coprime NTT primes and construct one `DcrtTable`. Each prime must satisfy the [NTT constraints](../primus_ntt/README.md#construction-constraints).
2. Construct `CrtGlweParameters` with dimension k, polynomial length N, plaintext modulus t, auxiliary decoding modulus gamma, ordered ciphertext moduli, secret distribution and noise. Its [`BfvRnsCodec`](../primus_encoding/README.md#encoding-contracts) supplies scaling and recovery checks.
3. Generate a signed coefficient `GlweSecretKey` and convert it with `DcrtGlweSecretKey::from_coeff_secret_key`. Keep that table and modulus order for subsequent operations.
4. Allocate ciphertexts through parameter length accessors. Reuse encryption output and `DcrtGlweDecryptWorkspace`; `decrypt_inplace` also reuses caller plaintext output.

The small parameters below demonstrate coefficient encryption and storage reuse, not security. The snippet requires `primus_glwe_rns`, `primus_modulus`, `primus_ntt`, `primus_poly` and `rand` as direct dependencies:

```rust
use primus_glwe_rns::{
    CrtGlweParameters, DcrtGlweCiphertext, DcrtGlweDecryptWorkspace,
    DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr,
};
use primus_modulus::BarrettModulus;
use primus_ntt::UintDcrtTable;
use primus_poly::Polynomial;

let moduli = [998_244_353u32, 1_004_535_809].map(BarrettModulus::new);
let table = UintDcrtTable::new(5, &moduli).unwrap();
let parameters = CrtGlweParameters::new(
    2, 32, BarrettModulus::new(17), BarrettModulus::new(65_537),
    &moduli, SecretKeyDistr::UniformBinary, 3.2,
);
let mut rng = rand::rng();
let coefficient_key = GlweSecretKey::generate(
    parameters.size().glwe_size(), parameters.secret_key_sampler(), &mut rng,
);
let key = DcrtGlweSecretKey::from_coeff_secret_key(&coefficient_key, &table);
let mut ciphertext = DcrtGlweCiphertext::<Vec<u32>>::zero(parameters.rns_glwe_len());
let mut workspace = DcrtGlweDecryptWorkspace::new(parameters.size());
let message = Polynomial::new(vec![3u32; parameters.poly_length()]);

key.encrypt_plaintext_inplace(&message, &mut ciphertext, &parameters, &table, &mut rng);
let decoded = key.decrypt(&ciphertext, &parameters, &table, &mut workspace);
assert_eq!(decoded.as_ref(), message.as_ref());
```

## Encoding and representation

`encrypt_plaintext_inplace` uses unsigned BFV scaling, and `encrypt_centered_plaintext_inplace` uses centered lifting; messages contain N canonical values in `[0,t)`. `encrypt_inplace` accepts already encoded CRT coefficients and does not apply plaintext scaling. Both produce DCRT ciphertexts. `phase_inplace` returns a DCRT phase; decryption performs coefficient recovery and decoding. `DcrtGlwePublicKey` supports public encryption; its noise budget includes the additional public-key terms.

For m moduli, ordinary storage contains `(k+1)*m*N` elements in `[component][modulus][coefficient/evaluation]` order. Gadget storage adds outer row/level dimensions. Use `RnsGlweSize` / `RnsGadgetSize` and polynomial/ciphertext iterators rather than inferring chunk sizes. CRT and DCRT have the same shape but different arithmetic; see [ciphertext layouts](../primus_lattice/README.md#storage-and-layout).

## Evaluation resources

`CrtGlevParameters::try_with_glwe_params` prepares gadget decomposition over the product Q. `DcrtGadgetDomain::try_new` binds parameters and a table, checking polynomial length and ordered moduli. Ordinary DCRT key switching uses this domain. Hybrid switching instead binds the complete Q/P basis with `HybridRnsKeySwitchDomain::try_new`; partitioning and ModUp/ModDown contracts live in [`primus_rns`](../primus_rns/README.md#hybrid-rns).

The client generates evaluation keys from its secrets and supplies them to the server. Reuse the operation's `*Workspace` with the bound layout; shape and modulus checks do not prove actual secret identity, canonical residues or a noise margin. CRT and DCRT trace/expansion APIs retain their own input/output and normalization contracts in rustdoc.

## Features and further reading

Default features are empty. `simd` forwards nightly SIMD support to arithmetic dependencies. This crate enables the RNS features it needs without a separate `rns` switch.

[Public API sources](src/lib.rs) · [RNS bases and conversion](../primus_rns/README.md) · [Library usage guide](../../guides/development/README.md) · [Validation coverage](../../guides/development/testing.md)
