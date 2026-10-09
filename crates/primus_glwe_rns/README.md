# primus_glwe_rns

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

GLWE encryption and evaluation over an ordered RNS basis, with CRT coefficient and DCRT NTT representations. This crate supplies BFV-scaled coefficient encryption, gadget products, automorphism, trace, expansion and key switching. It is a building block, not a complete BFV/BGV/CKKS scheme.

`CrtGlweParameters::new` / `try_new` takes `primus_poly::PolyLength`. Construct it once with `PolyLength::try_new(n)?` (or `new` for known constants) and reuse it for parameters, sizes and transform tables. Invalid integers are reported by `PolyLengthError`; parameter construction retains its combined-layout, modulus and sampler checks.

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
let poly_length = PolyLength::new(32);
let table = UintDcrtTable::new(poly_length, &moduli).unwrap();
let parameters = CrtGlweParameters::new(
    primus_lattice::GlweDimension::new(2), poly_length, BarrettModulus::new(17), BarrettModulus::new(65_537),
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

`encrypt_to` uses unsigned BFV scaling, and `encrypt_centered_to` uses centered lifting; messages contain N canonical values in `[0,t)`. `encrypt_plaintext_crt_to` accepts unscaled plaintext lifts reduced into each CRT modulus and applies `floor(Q/t)` scaling; do not pass the already-scaled output of the codec. These methods overwrite DCRT ciphertext output. `encrypt_zeros_to` encrypts zero. `phase_to` writes a DCRT phase; `decrypt` allocates plaintext output, while `decrypt_to` reuses it. Decryption performs coefficient recovery and decoding. `DcrtGlwePublicKeyContext::encrypt_plaintext_crt` allocates public encryption of the same unscaled CRT lifts; its noise budget includes the additional public-key terms.

For m moduli, ordinary storage contains `(k+1)*m*N` elements in `[component][modulus][coefficient/evaluation]` order. Gadget storage adds outer row/level dimensions. Use `RnsGlweSize` / `RnsGadgetSize` and polynomial/ciphertext iterators rather than inferring chunk sizes. CRT and DCRT have the same shape but different arithmetic; see [ciphertext layouts](../primus_lattice/README.md#storage-and-layout).

## Parameter composition

`CrtGlweParameters` takes `GlweDimension` and `PolyLength`, and gadget construction takes `DecompositionBaseLog` and `Option<DecompositionLevelCount>`. Parameter accessors return these checked units; use `.get()` at raw storage or numerical boundaries.

The ordinary constructor above prepares all parts. For gadget-only encryption or independently chosen encoding, prepare and combine them explicitly:

- `CrtGlweEncryptionParameters::try_new(size, &base_q, secret_distribution, noise)` prepares layout and samplers without t or gamma. Fixed secret weights apply to the complete kN signed key, before replication across moduli; secret and noise support must fit below every q_i. Wrap the result in `Arc` to share those precomputations.
- `CrtGlevParameters::try_from_parts(shared_encryption, base_q, basis)` moves the ordered `RNSBase` and `BigUintApproxSignedBasis` into gadget parameters. It checks the sampler's ordered moduli, the basis's exact product modulus and limb width, radix < every q_i, and composed gadget lengths before caching level weights. It needs no BFV codec.
- `CrtGlweParameters::try_from_parts(shared_encryption, codec)` binds ordinary BFV encoding, checking the codec's ordered moduli and fresh private-key recovery margin. The codec owns its RNS base and conversion data; the shared sampling state stores no additional base or converter.

`CrtGlweParameters::try_new` and `try_from_parts` report errors through `CrtGlweParametersError<T>`, preserving their causes. `try_new` creates the codec and samplers from the same ordered base, so their pairing is not compared again; fresh BFV recovery is still checked. `CrtGlevParameters::try_with_glwe_params` derives gadget parameters using that validated sampler/base pairing and builds the basis in the same product modulus and limb representation. It checks the new radix against every q_i and the new gadget layout before preparing weights. Gadget construction reports `CrtGlevParametersError`; its `Layout` variant reports length overflow. Distinct noise roles require independently prepared sampling states.

Derived gadget parameters also share the ordinary codec's immutable `RNSBase` tables and numeric modulus cache; the codec's internal converter shares that base too. BFV's `floor(Q/t)` factors and the gadget's per-level reconstruction residues serve different roles and remain separate. Parameter clones share samplers and base tables, but still copy codec-specific or gadget-specific weights. Ordinary encryption uses `delta_factor_mod_q()` directly, without an additional raw delta-residue cache.

Ordinary parameter construction passes the noise sampler's maximum magnitude to `BfvRnsCodec::validate_noise_bound` with unsigned lifting, covering both plaintext embeddings for fresh private-key encryption. An insufficient margin returns `CrtGlweParametersError::Encoding`. Public-key encryption and homomorphic evaluation require bounds on their complete phase noise; parameter construction does not cover those additional contributions.

## Evaluation resources

Both parameter types expose their sampling state through `encryption_parameters()`. Public-key generation takes `DcrtGlwePublicKey::new(&secret, parameters.encryption_parameters(), parameters.base_q(), &table, rng)`; zero encryption needs no codec. DCRT and hybrid key-switch generation likewise accept `input_parameters.encryption_parameters()` rather than ordinary BFV parameters. These setup calls validate ordered bases before consuming randomness. Hybrid generation also checks the input sampling state's key noise against the auxiliary P limbs.

`DcrtGadgetDomain::try_new` binds gadget parameters and a table, checking polynomial length and ordered moduli. Ordinary DCRT key switching uses this domain. Hybrid switching instead binds the complete Q/P basis with `HybridRnsKeySwitchDomain::try_new`; partitioning and ModUp/ModDown contracts live in [`primus_rns`](../primus_rns/README.md#hybrid-rns).

`try_bind` checks ordinary parameter/table/key layouts and ordered moduli, returning `RnsDomainError`; the public key has the same binding workflow. For gadget encryption, `try_bind_gadget(&domain)` returns `DcrtGlevEncryptor` for a secret key or `DcrtGgswEncryptor` for a public key. The GLev encryptor accepts coefficient messages through `encrypt_crt_to` and NTT messages through `encrypt_dcrt_to`; these apply gadget weights without BFV plaintext scaling. The GGSW encryptor provides `encrypt_monomial_ggsw` / `encrypt_monomial_ggsw_to` for allocated / reused output. Reuse these bindings across messages and key rows.

Construct `DcrtGlweKeySwitchEvaluator::try_new(&key, &domain)` or `HybridRnsGlweKeySwitchEvaluator::try_new(&key, &domain)` once. Each evaluator borrows its key/domain and owns scratch; online calls take only `key_switch_to(&input, &mut output)`. Classic binding checks the gadget layout, ordered Q and decomposition radix; hybrid binding checks N, ordered QP, the Q/P boundary and actual partition width. No complete parameters, tables or converters are copied into keys.

The client generates evaluation keys from its secrets and supplies them to the server. Automorphism, trace, reverse trace and expansion each use a concrete evaluator with `new` / `try_new`. It borrows the key and `DcrtGadgetDomain`, validates N, dimension, ordered Q, radix and retained levels once, then allocates its own scratch. A complete key set stores one metadata record; individual automorphism entries do not copy parameters or tables. Equal numerical domains do not prove secret identity, canonical residues, matching NTT roots/order or a sufficient noise margin.

For example, continuing the encryption workflow above (also add `primus_decompose` as a dependency):

```rust
use primus_decompose::DecompositionBaseLog;
use primus_glwe_rns::{CrtGlevParameters, DcrtGadgetDomain, DcrtGlweAutoEvaluator, DcrtGlweAutoKey};

let gadget = CrtGlevParameters::with_glwe_params(&parameters, DecompositionBaseLog::new(8), None);
let domain = DcrtGadgetDomain::try_new(&gadget, &table).unwrap();
let auto_key = DcrtGlweAutoKey::new(&domain, 3, &key, &mut rng);
let mut evaluator = DcrtGlweAutoEvaluator::try_new(&auto_key, &domain).unwrap();
let mut output = DcrtGlweCiphertext::<Vec<u32>>::zero(parameters.rns_glwe_len());
evaluator.automorphism_to(&ciphertext, &mut output);
```

`CrtGlweAutoEvaluator` uses coefficient ciphertexts; `DcrtGlweAutoEvaluator` uses NTT ciphertexts. Their kernels share the respective `CoeffAutomorphismPermutation` and `NttAutomorphismPermutation` across modulus components and key rows. Trace and expansion call these kernels under their existing binding, without rechecking or allocating per automorphism.

Trace, reverse-trace and expansion key generation bind the secret to the gadget
domain once per key set and reuse local `Zeroizing` scratch across degrees.
CRT generation permutes the signed secret then encodes it into each modulus;
DCRT generation permutes the existing NTT secret. Degree, row and gadget-level
sampling order is preserved. Scratch is erased on return or unwind and is not
added to online evaluators. Standalone automorphism generation retains its own
binding and layout checks.

`CrtGlweTraceEvaluator` / `DcrtGlweTraceEvaluator` expose `trace_to(&input, &mut output)` and return the ordinary ring trace, whose plaintext is `N*m[0]`. `DcrtGlweRevTraceEvaluator` exposes the same method but reverses the automorphism order and multiplies by `2^-1 mod q_i` at each step, retaining normalized output `m[0]`. Inputs remain unchanged; output and internal scratch are overwritten.

Reverse trace keeps the same Q basis; modular `inv2` is not modulus switching or
rounded halving. The full sequence projects the input message and input error
onto their constant coefficients. Each automorphism/key-switch error undergoes
only the remaining projections, so late errors can survive at nonconstant
positions. Budget these errors for the chosen secret, basis and message scale;
the native-torus variance bound does not follow from the absence of rounding.
See the [phase and error contract](src/dcrt/rev_trace.rs) and the corresponding
[single-modulus contract](../primus_glwe/src/trace/ntt_operations.rs).

For either CRT or DCRT, construct `*GlweExpandCoeffEvaluator::new(&key, &domain)` for serial use or `*GlweExpandCoeffParallelEvaluator::new(&key, &domain, worker_count)` for a preallocated parallel pool. Both offer `expand_coefficients_to` (exactly N outputs) and `expand_partial_coefficients_to` (a power-of-two output count in 1..=N). Output j encrypts coefficient m[j], with no extra count factor. For partial expansion, omitted plaintext coefficients must be zero to obtain constant-polynomial outputs.

Parallel calls use Rayon; initialize its worker pool before evaluation, and set `worker_count` to cover its maximum simultaneous workers. Each call borrows the evaluator mutably, preventing concurrent calls from competing for the same pool. Guards return scratch on completion or worker unwind; an undersized pool can panic after partial output writes. Serial evaluators allocate only one workspace. Repeated evaluations reuse all arithmetic scratch; neither path creates replacement workspaces online.

## Features and further reading

Default features are empty. `simd` forwards nightly SIMD support to arithmetic dependencies. This crate enables the RNS features it needs without a separate `rns` switch.

[Public API sources](src/lib.rs) · [RNS bases and conversion](../primus_rns/README.md) · [Library usage guide](../../guides/development/README.md) · [Validation coverage](../../guides/development/testing.md)
