# primus_glwe_rns

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

GLWE encryption and evaluation over an ordered RNS basis, with CRT coefficient and DCRT NTT representations. This crate supplies BFV-scaled coefficient encryption, gadget products, automorphism, trace, expansion and key switching. It is a building block, not a complete BFV/BGV/CKKS scheme.

## Recommended workflow

1. Choose ordered, pairwise-coprime NTT primes and construct one `DcrtTable`. Each prime must satisfy the [NTT constraints](../primus_ntt/README.md#construction-constraints).
2. Construct `CrtGlweParameters` with dimension k, polynomial length N, plaintext modulus t, auxiliary decoding modulus gamma, ordered ciphertext moduli, secret distribution and noise. Use `try_new` to handle invalid parameters or `new` for known valid configurations. Its [`BfvRnsCodec`](../primus_encoding/README.md#encoding-contracts) supplies scaling and recovery checks.
3. Generate a signed coefficient `GlweSecretKey` and convert it with `DcrtGlweSecretKey::from_coeff_secret_key`. Bind it with `try_bind(&parameters, &table)` once, then encrypt and decrypt through the returned `DcrtGlweSecretKeyContext`.
4. Allocate ciphertexts through parameter length accessors. Reuse encryption output and `DcrtGlweDecryptWorkspace`; `decrypt_to` also reuses caller plaintext output.

The small parameters below demonstrate coefficient encryption and storage reuse, not security. The snippet requires `primus_glwe_rns`, `primus_lattice`, `primus_modulus`, `primus_ntt`, `primus_poly` and `rand` as direct dependencies:

```rust
use primus_glwe_rns::{
    CrtGlweParameters, DcrtGlweCiphertext, DcrtGlweDecryptWorkspace,
    DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr,
};
use primus_modulus::BarrettModulus;
use primus_ntt::UintDcrtTable;
use primus_poly::{PolyLength, Polynomial};

let moduli = [998_244_353u32, 1_004_535_809].map(BarrettModulus::new);
let table = UintDcrtTable::new(PolyLength::new(32), &moduli).unwrap();
let parameters = CrtGlweParameters::new(
    primus_lattice::GlweDimension::new(2), 32, BarrettModulus::new(17), BarrettModulus::new(65_537),
    &moduli, SecretKeyDistr::UniformBinary, 3.2,
);
let mut rng = rand::rng();
let coefficient_key = GlweSecretKey::generate(
    parameters.size().glwe_size(), parameters.secret_key_sampler(), &mut rng,
);
let key = DcrtGlweSecretKey::from_coeff_secret_key(&coefficient_key, &table);
let mut ciphertext = DcrtGlweCiphertext::<Vec<u32>>::zero(parameters.rns_glwe_len());
let mut workspace = DcrtGlweDecryptWorkspace::new(parameters.size());
let message = Polynomial::new(vec![3u32; parameters.poly_length().get()]);

let context = key.try_bind(&parameters, &table).unwrap();
context.encrypt_to(&message, &mut ciphertext, &mut rng);
let decoded = context.decrypt(&ciphertext, &mut workspace);
assert_eq!(decoded.as_ref(), message.as_ref());
```

## Encoding and representation

`encrypt_to` uses unsigned BFV scaling, and `encrypt_centered_to` uses centered lifting; messages contain N canonical values in `[0,t)`. `encrypt_crt_to` accepts unscaled plaintext lifts reduced into each CRT modulus and applies `floor(Q/t)` scaling; do not pass the already-scaled output of the codec. These methods overwrite DCRT ciphertext output. `encrypt_zeros_to` encrypts zero. `phase_to` writes a DCRT phase; `decrypt` allocates plaintext output, while `decrypt_to` reuses it. Decryption performs coefficient recovery and decoding. `DcrtGlwePublicKey` supports public encryption; its noise budget includes the additional public-key terms.

For m moduli, ordinary storage contains `(k+1)*m*N` elements in `[component][modulus][coefficient/evaluation]` order. Gadget storage adds outer row/level dimensions. Use `RnsGlweSize` / `RnsGadgetSize` and polynomial/ciphertext iterators rather than inferring chunk sizes. CRT and DCRT have the same shape but different arithmetic; see [ciphertext layouts](../primus_lattice/README.md#storage-and-layout).

## Parameter composition

`CrtGlweParameters` takes `GlweDimension`, and gadget construction takes `DecompositionBaseLog` and `Option<DecompositionLevelCount>`. Parameter accessors return these checked units; use `.get()` at raw storage or numerical boundaries.

The ordinary constructor above prepares all parts. For gadget-only encryption or independently chosen encoding, prepare and combine them explicitly:

- `CrtGlweParametersInner::try_new(size, &base_q, secret_distribution, noise)` prepares layout and samplers without t or gamma. Fixed secret weights apply to the complete kN signed key, before replication across moduli; secret and noise support must fit below every q_i. Wrap the result in `Arc` to share those precomputations.
- `CrtGlevParameters::try_from_parts(shared_inner, base_q, basis)` moves the ordered `RNSBase` and `BigUintApproxSignedBasis` into gadget parameters. It checks the sampler's ordered moduli, the basis's exact product modulus and limb width, radix < every q_i, and composed gadget lengths before caching level weights. It needs no BFV codec.
- `CrtGlweParameters::try_from_parts(shared_inner, codec)` binds ordinary BFV encoding, checking the codec's ordered moduli and fresh private-key recovery margin. The codec owns its RNS base and conversion data; the shared sampling state stores no additional base or converter.

`CrtGlweParameters::try_new` and `try_from_parts` report errors through `CrtGlweParametersError<T>`, preserving their causes. `CrtGlevParameters::try_with_glwe_params` remains the convenient way to derive gadget parameters from existing ordinary parameters and shares their samplers. Gadget construction reports `CrtGlevParametersError`; its `Layout` variant reports length overflow. Distinct noise roles require independently prepared sampling states.

Derived gadget parameters also share the ordinary codec's immutable `RNSBase` tables and numeric modulus cache; the codec's internal converter shares that base too. BFV's `floor(Q/t)` factors and the gadget's per-level reconstruction residues serve different roles and remain separate. Parameter clones share samplers and base tables, but still copy codec-specific or gadget-specific weights. Ordinary encryption uses `delta_factor_mod_q()` directly, without an additional raw delta-residue cache.

Ordinary parameter construction passes the noise sampler's maximum magnitude to `BfvRnsCodec::validate_noise_bound` with unsigned lifting, covering both plaintext embeddings for fresh private-key encryption. An insufficient margin returns `CrtGlweParametersError::Encoding`. Public-key encryption and homomorphic evaluation require bounds on their complete phase noise; parameter construction does not cover those additional contributions.

## Evaluation resources

Both parameter types expose their sampling state through `inner()`. Public-key generation takes `DcrtGlwePublicKey::new(&secret, parameters.inner(), parameters.base_q(), &table, rng)`; zero encryption needs no codec. DCRT and hybrid key-switch generation likewise accept `input_parameters.inner()` rather than ordinary BFV parameters. These setup calls validate ordered bases before consuming randomness. Hybrid generation also checks the input sampling state's key noise against the auxiliary P limbs.

`DcrtGadgetDomain::try_new` binds gadget parameters and a table, checking polynomial length and ordered moduli. Ordinary DCRT key switching uses this domain. Hybrid switching instead binds the complete Q/P basis with `HybridRnsKeySwitchDomain::try_new`; partitioning and ModUp/ModDown contracts live in [`primus_rns`](../primus_rns/README.md#hybrid-rns).

`try_bind` checks ordinary parameter/table/key layouts and ordered moduli, returning `RnsDomainError`; the public key has the same binding workflow. For gadget encryption, `try_bind_gadget(&domain)` returns `DcrtGlevEncryptor` for a secret key or `DcrtGgswEncryptor` for a public key. The GLev encryptor accepts coefficient messages through `encrypt_crt_to` and NTT messages through `encrypt_dcrt_to`; these apply gadget weights without BFV plaintext scaling. The GGSW encryptor provides `encrypt_monomial_ggsw` / `encrypt_monomial_ggsw_to` for allocated / reused output. Reuse these bindings across messages and key rows.

Construct `DcrtGlweKeySwitchEvaluator::try_new(&key, &domain)` or `HybridRnsGlweKeySwitchEvaluator::try_new(&key, &domain)` once. Each evaluator borrows its key/domain and owns scratch; online calls take only `key_switch_to(&input, &mut output)`. Classic binding checks the gadget layout, ordered Q and decomposition radix; hybrid binding checks N, ordered QP, the Q/P boundary and actual partition width. No complete parameters, tables or converters are copied into keys.

The client generates evaluation keys from its secrets and supplies them to the server. Reuse the operation's `*Workspace` with the bound layout; shape and modulus checks do not prove actual secret identity, canonical residues or a noise margin. CRT and DCRT trace/expansion APIs retain their own input/output and normalization contracts in rustdoc.

Both representations provide `expand_coefficients_to` and `expand_partial_coefficients_to` with a reusable serial workspace. Their parallel variants end in `_parallel_to` and reuse a preallocated `CrtGlweExpandCoeffSyncPool` or `DcrtGlweExpandCoeffSyncPool`.

## Features and further reading

Default features are empty. `simd` forwards nightly SIMD support to arithmetic dependencies. This crate enables the RNS features it needs without a separate `rns` switch.

[Public API sources](src/lib.rs) · [RNS bases and conversion](../primus_rns/README.md) · [Library usage guide](../../guides/development/README.md) · [Validation coverage](../../guides/development/testing.md)
