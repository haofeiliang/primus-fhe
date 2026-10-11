# primus_tfhe_ntru_lut

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

Evaluate a finite function on independently encrypted NTRU-TFHE chunks. One-hot CBS selects a public table, encrypted rotations select its coefficient, and the result returns to the external LWE secret. Recommended configs use classic binary BR; classic ternary and explicitly selected sparse fixed-weight binary BR are also supported.

## Quick start

```sh
cargo run --release -p primus_tfhe_ntru_lut --example ntt_lookup
cargo run --release -p primus_tfhe_ntru_lut --example fourier_lookup
```

The [NTT](examples/ntt_lookup.rs) and [Fourier](examples/fourier_lookup.rs) examples compute a piecewise fee from 16 input bits to 16 output bits. They separate client/server stages, reuse keys, table, evaluator and buffers, and check requests at breakpoints and domain boundaries. Both use u64 coefficients; the library also supports u32.

## Experimental paired parameters

Start from `experimental::NTT_CLASSIC_LOOKUP_U64` or `FOURIER_CLASSIC_LOOKUP_U64`. Each combines n800/h32/N1024 one-hot CBS and required return KS with eight input/eight output two-bit chunks. `coefficient_chunk_count: None` selects d=5; `Some(d)` overrides the partition. Input/output counts are independent. These are arithmetic teaching configurations with **unassessed security and failure probability**; see the [parameter guide](../../guides/development/tfhe-parameters.md#scope-of-paired-parameter-entries).

`NttHighPrecLutContext::try_from_config` / `FourierHighPrecLutContext::try_from_config` prepare the operation's parameters, encodings and transform table. Keys, public function compilation and mutable evaluator state are prepared separately:

```rust,no_run
use primus_ntt::U64NttTable;
use primus_tfhe_ntru_lut::{NttHighPrecLutContext, experimental};
use rand::{SeedableRng, rngs::StdRng};

let context = NttHighPrecLutContext::<u64, U64NttTable, _>::try_from_config(
    experimental::NTT_CLASSIC_LOOKUP_U64,
)?;
let fee = |x: u64| {
    if x < 16_384 {
        x / 4
    } else if x < 49_152 {
        4_096 + (x - 16_384) / 2
    } else {
        20_480 + (x - 49_152)
    }
};
let table = context.compile_fn(fee)?; // Public, offline; no secrets.

// Client: only paired setup needs both secrets; online clients borrow external s.
let mut rng = StdRng::seed_from_u64(42);
let (client, server) = context.try_generate_keys(&mut rng)?;
let encryptor = context.encryptor(&client)?;
let decryptor = context.decryptor(&client)?;
let mut input = encryptor.allocate_input();

// Server: receives public context/table, evaluation material and encrypted chunks.
let mut evaluator = context.evaluator(&server, &table)?;
let mut output = evaluator.allocate_output();
for (value, expected) in [(16_383u64, 4_095u64), (49_152, 20_480)] {
    encryptor.encrypt_to(value, &mut input, &mut rng)?;
    evaluator.evaluate_to(&input, &mut output);
    let result: u64 = decryptor.decrypt(&output)?;
    assert_eq!(result, expected);
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

For Fourier, use `FourierHighPrecLutContext<u64, RustFftTable, _>` and the matching experimental constant. Client factories need no LUT or manual codec: input/returned chunks use q, while table coefficients use Q. The API handles chunk extraction, padded encryption and joining; it does not homomorphically split a single high-precision LWE.

`compile_fn(|x: W| -> W)` accepts a cleartext integer type W independent of coefficient type T. Both complete widths must fit W and the result must fit the output domain; excess bits are rejected. Compilation calls the pure function again for each output chunk. For output wider than one word, use `compile_chunks_fn(|x, output| digit)`, `encrypt_chunks_to` and `decrypt_chunks_to`. Raw chunk slices are least-significant first. A failed chunk decode may leave a written prefix; discard that result. See the [client contracts](src/client.rs).

## Encoding and table partition

Let `M=2^tau>=2`; chunks use plaintext modulus `t=2*M` and unsigned digits in `0..M`. Input and output share tau but have independent positive counts. `ChunkFormat` provides `split_to`, `join` and `chunk` for cleartext conversion; `context.chunk_format()` returns the prepared format. Bit counts use u32; counts and indices use usize.

| Quantity | Meaning |
| --- | --- |
| `input_chunk_count` = c | Input chunks in `x=sum_i m_i*M^i` |
| `output_chunk_count` = o | Independently selected output width in chunks |
| `coefficient_chunk_count` = d | Low chunks selecting a coefficient; `0<=d<=c` |
| `entries_per_polynomial()` = K = M^d | Used coefficients per polynomial; K<=N |
| `polynomials_per_output()` = P = M^(c-d) | Stored polynomials per output chunk |
| `input_value_count()` = M^c | Entire input domain enumerated at compilation |

Write `x=p*K+z`. For output chunk j, polynomial p stores `E_Q(F(x,j))` at coefficient z and zeros at K..N, with `E_Q(v)=round(Q*v/(2*M))`. `F(x,j)` must be in `0..M`. Compilation visits output j first and x in ascending order, once per pair. Any finite mapping that fits these value/storage limits is allowed; signed or fixed-point interpretation belongs to the chosen digit mapping.

`polynomial(j,p)` borrows N coefficients. All `o*P*N` coefficients are stored contiguously in `[output][prefix][coefficient]` order, including equal polynomials and repeated outputs. For M=4, c=3, d=1 and N=64, each output has 16 polynomials with four entries and 60 zeros each; input 6 selects polynomial 1, coefficient 2.

The full-domain size must fit usize, so `tau*c < usize::BITS`. This is an implementation enumeration limit, not a paper constraint. Compilation checks total bit widths, element counts and byte sizes before allocation or callbacks; it cannot guarantee available physical memory. Public table storage is exponential in c-d: `o*P*N*sizeof(T)` bytes.

### Choosing the coefficient chunk count

For fixed N, M and c, start with `d=min(c, floor(log2(N)/tau))`, making M^d close to N. Increasing d by one divides public storage by M and adds one rotation product per output while reducing selection work. Choose using complete evaluation time and noise margin.

For `h=c-d>0`, each output performs `P+P/M-1` selection products in `(P-1)/(M-1)` groups, then d rotation products. The first layer lifts through all M NLEV selectors; later layers use M-1 NGSW selectors. With h=0, one NLEV[1] lifts the sole public polynomial before d rotations. All outputs execute the complete tree, including constant/repeated tables. Derivations and shared-error conditions are in the [numerical guide](../../guides/development/bootstrapping-contracts.md#fixed-complete-high-precision-lookup).

## Evaluation and workspace

Generate the complete bundle with `context.try_generate_keys(rng)`, without passing a function. Bind it and a compiled table with `context.evaluator(&server, &table)`, allocate output once, then reuse `evaluate_to`. The evaluator borrows these owners and allocates its buffers at construction; online evaluation has no extra allocation. Concurrent evaluators need separate mutable state.

The context supplies lifting material when c=d: classic uses its initializer; sparse receives independent NLEV[1] with the BR basis/noise. For c>d the first public selection already lifts. The supplied configurations have fixed-weight secrets, so sparse can be selected before context construction:

```rust,ignore
use primus_tfhe::BlindRotationMethod;

let mut config = experimental::NTT_CLASSIC_LOOKUP_U64;
config.one_hot.pbs.algorithm =
    BlindRotationMethod::Sparse { copy_count: 3, bucket_count: 64 };
let context = NttHighPrecLutContext::<u64, U64NttTable, _>::try_from_config(config)?;
```

The key bundle can serve other tables with compatible geometry, encodings and material; function values do not change lift requirements. Resources must match N/q/Q and actual key identity, and Fourier requires the same FFT table instance. Input/output shapes are checked before writes. Return performs coefficient-wise Q→q, extraction and KS to the external secret.

For explicit composition, use `backend_context()` and the low-level [NTT](src/ntt.rs) / [Fourier](src/fourier.rs) evaluators. Public lift views pair NLEV[1] with its generation parameters. With c=d, an explicit lift takes precedence over the classic initializer and must validate; c>d ignores surplus lift. It can have a different basis/noise, but must encode one under the matching ring secret and transform. Metadata does not prove these facts or sufficient decomposition precision.

## Numerical limits

The data table stores one value per logical input/output chunk. Input-error tolerance comes from the preceding [one-hot guard](../primus_tfhe_ntru/README.md#one-hot-cbs), not repeated data entries. Budget encryption/coordinate-rounding error for that guard, then CBS, selection, rotations and Q→q/KS error for final decoding. Fourier adds trace halving and FFT/conversion error; fused summation need not match separately converted ciphertext coefficients. Shared selectors correlate output errors. Shape checks and example success do not establish a failure probability; see the [numerical guide](../../guides/development/bootstrapping-contracts.md).

## Features

Default features are `ntt,rustfft`. Features preserve callback order, coefficient encoding and complete table layout.

| Feature | Enables |
| --- | --- |
| `--no-default-features` | Public compiler and inspection without keys, transforms or evaluator |
| `ntt` | NTT context, server bundle and evaluator |
| `fourier` | Generic Fourier workflow without a concrete FFT engine |
| `rustfft` / `tfhe-fft` | `fourier` plus the chosen FFT implementation |
| `simd` | Nightly SIMD in active dependencies; no evaluator/engine selection |

Compiler-only use starts with `HighPrecisionLookupTable::try_new(poly_length, ring_modulus, input_codec, config, function)`: N/Q, Rounded input q/t and chunk geometry suffice. With a backend enabled, `HighPrecLutParameters::try_from_config` can compile before constructing a transform, then move into its context.

Use `--no-default-features --features ntt` for NTT alone, or `--no-default-features --features tfhe-fft` for TFHE-FFT alone. The Fourier example imports `RustFftTable` and requires `rustfft`; to switch it, change both the table import and its target's `required-features` in [Cargo.toml](Cargo.toml). Adding `--features tfhe-fft` alone enables another engine without switching that example.

## Benchmarks

```sh
cargo bench -p primus_tfhe_ntru_lut --bench lookup_create -- 'c4_'
cargo bench -p primus_tfhe_ntru_lut --bench lookup_evaluate -- 'c4_'
```

`lookup_create` measures the complete public table, **including allocation and drop**, with the random mapping prepared outside timing. `lookup_evaluate` measures one complete homomorphic request with prebuilt keys, table, input and buffers. It uses classic BR and defaults to NTT/RustFFT; `--features tfhe-fft` also measures TFHE-FFT.

Both use M=16, d=3, N=4096 and four output chunks. Filters `c4_`, `c5_` and `c6_` select 16-, 20- and 24-bit inputs; output stays 16 bits and public storage is 2/32/512 MiB. Criterion filters timing only: other cases' untimed preparation and checks still run. See [benchmark commands and costs](../../guides/development/testing.md#high-precision-lut-benchmarks) and the [experimental numerical profile](../../guides/development/tfhe-parameters.md#random-high-precision-lut-benchmark).
