# primus_tfhe_ntru_lut

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

High-precision lookup over already encrypted NTRU-TFHE chunks, using one-hot CBS, public and encrypted table selection, negative rotation and return to an independent LWE secret.

## Experimental paired parameters

`experimental::NTT_CLASSIC_LOOKUP_U64` / `FOURIER_CLASSIC_LOOKUP_U64` combine n800/h32/N1024 one-hot CBS and its required return KS with eight input/eight output two-bit chunks. `coefficient_chunk_count: None` resolves to d=5; `Some(d)` explicitly selects another partition. Input/output counts remain independent. These arithmetic teaching configurations have no assessed security or failure-probability guarantee; see the [parameter guide](../../guides/development/tfhe-parameters.md#scope-of-paired-parameter-entries).

`NttHighPrecLutContext::try_from_config` / `FourierHighPrecLutContext::try_from_config` prepare the complete operation, its q/Q encodings and one transform table. They create no keys or evaluator workspace. To compile before constructing transforms, use `HighPrecLutParameters::try_from_config` and its compilation methods, then move that owner into the selected Context. The single CBS/BR/return owner and samplers are moved, without cloning or another Arc.

## Workflow

Both backends support classic binary/ternary and sparse fixed-weight binary lookup. The recommended workflow uses a pure integer function and complete integer inputs/outputs; the library handles chunk extraction, padded encryption and joining:

```rust,no_run
use primus_ntt::U64NttTable;
use primus_tfhe_ntru_lut::{NttHighPrecLutContext, experimental};
use rand::{SeedableRng, rngs::StdRng};

let context = NttHighPrecLutContext::<u64, U64NttTable, _>::try_from_config(
    experimental::NTT_CLASSIC_LOOKUP_U64,
)?;
let function = |x: u64| (x*x + 3*x + 7) & 0xffff;
let table = context.compile_fn(function)?; // Public, offline; no secrets.

// Client: only paired setup needs both secrets; online clients borrow external s.
let mut rng = StdRng::seed_from_u64(42);
let (client, server) = context.try_generate_keys(&table, &mut rng)?;
let encryptor = context.encryptor(&client)?;
let decryptor = context.decryptor(&client)?;
let mut input = encryptor.allocate_input();

// Server: receives public context/table, evaluation material and encrypted chunks.
let mut evaluator = context.evaluator(&server, &table)?;
let mut output = evaluator.allocate_output();
for value in [43981u64, 0] {
    encryptor.encrypt_to(value, &mut input, &mut rng)?;
    evaluator.evaluate_to(&input, &mut output);
    let result: u64 = decryptor.decrypt(&output)?;
    assert_eq!(result, function(value));
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

For Fourier, select `FourierHighPrecLutContext<u64, RustFftTable, _>` and the matching experimental constant. Complete runnable workflows are [ntt_lookup.rs](examples/ntt_lookup.rs) and [fourier_lookup.rs](examples/fourier_lookup.rs), using 16-bit input/output and reusing the same evaluator and ciphertexts for two requests. Five low chunks fill N=1024 coefficients; three high chunks select among 64 polynomials. Examples fix u64 coefficients; the library and tests retain u32.

`compile_fn(|x: W| -> W)` separates the cleartext integer type W from coefficient type T. Both complete widths must fit W; results outside the output domain are rejected, without truncation. Compilation remains output-major: the pure function is evaluated again for each output chunk. It does not retain a full-domain cleartext cache. Expensive functions can explicitly prepare their values. `compile_chunks_fn(|x, output| digit)` retains the digit callback and supports outputs wider than one integer. Clients similarly provide `encrypt_chunks_to` and `decrypt_chunks_to` for caller-owned digit slices.

Encryptor/decryptor factories do not receive the table or function. They derive encoding from the operation: input and returned chunks at q, table coefficients at Q. Integer encryption and decoding allocate no digit buffer; input allocation is explicit. Count, dimension, capacity and value checks precede encryption writes/RNG use. Decoding rejects digits in the unused padded half rather than masking them. A chunk decoding failure may leave a prefix written by `decrypt_chunks_to`; discard that partial result. Ciphertexts still carry no key/encoding metadata.

```sh
cargo run --release -p primus_tfhe_ntru_lut --example ntt_lookup --features ntt
cargo run --release -p primus_tfhe_ntru_lut --example fourier_lookup --features rustfft
```

## Encoding and table partition

The plaintext modulus must be `t=2*M`, with `M=2^tau>=2`. All input and output chunks share tau; their counts are independent and positive. Both ciphertext slices are least-significant first: `x=sum_i m_i*M^i`. Inputs are separate encrypted chunks; the API does not homomorphically split one high-precision LWE.

`ChunkFormat::new(tau)` is the single source for `bits()`, `radix()`, `mask()` and `plaintext_modulus()`; use the latter when constructing the Rounded codec. `bit_count(count)` returns either combined width as u32, rejecting overflow. The compiler derives the same format from the codec, available as `table.chunk_format()`, so callers do not supply a second width to compilation. This format owns no buffers or codec. `table.chunk_bits()` and `LookupTableStats::input_bits/output_bits` also use `u32`; compilation rejects a combined width above `u32::MAX` before allocation or callbacks. Chunk counts, table sizes and indices remain `usize`.

For cleartext words, `chunks.split_to(value, &mut digits)` overwrites a reusable least-significant-first slice, and `chunks.join(&digits)` reconstructs the word. These helpers reject oversized capacity, truncation or invalid digits; exact word capacity is allowed. `chunks.chunk(value, index)` extracts one digit with zero extension beyond the word, useful in a table callback. Word conversion is optional: the callback may instead supply output digits whose combined width exceeds u64 or any other one word. The LUT retains its separate full-input enumeration/storage limits.

Let `c=input_chunk_count`, `d=coefficient_chunk_count` and `o=output_chunk_count`. Require `0<=d<=c` and `M^d<=N`. The low d chunks select a coefficient; the remaining high chunks select a polynomial. The layout quantities are:

| Quantity | Meaning |
| --- | --- |
| `chunk_bits()` = tau | Common bit width of each input/output chunk |
| `input_value_count()` = M^c | Number of possible complete input values |
| `entries_per_polynomial()` = K = M^d | Number of LUT entries occupying coefficients in each polynomial |
| `polynomials_per_output()` = P = M^(c-d) | Logical polynomial count per output chunk, before storage sharing |
| `unique_polynomial_count()` = U | Physically stored polynomials, shared across outputs |
| N | Allocated coefficient count of every polynomial, including zero padding |

Split an input as `x=p*K+z`. For output chunk j, polynomial p has coefficient `E_Q(F(x,j))` at z; coefficients `K..N` are zero. Here `E_Q(v)=round(Q*v/(2*M))`, with multiplication before rounding. `F(x,j)` returns chunk j of the desired function result, and must lie in `0..M`. Compilation enumerates every `(x,j)` once, in output-major order and then ascending x. Any finite mapping can be compiled within the domain/storage limits; integer, signed or fixed-point interpretation is determined by the caller's chunk encoding and callback.

For example, `M=4, c=3, d=1, N=64` gives 64 inputs, 16 polynomials per output and 4 entries per polynomial. Polynomial 0 stores inputs 0..3, polynomial 1 stores inputs 4..7, and so on. Input 6 selects polynomial 1, coefficient 2. Each polynomial's remaining 60 coefficients are zero.

`polynomial(j,p)` returns the N coefficients for logical output j and prefix p. Identical encoded polynomials share storage across all outputs; `unique_polynomial_count()` reports their physical count. Storage uses U*N coefficients plus a compiled selection plan. Equal branches are removed; identical ordered choices for the same input chunk share a node across outputs. Physical pool order and node indices are internal details.

The input value count itself must fit in `usize`, requiring `tau*c < usize::BITS`; this is an indexing limit of full enumeration, not a paper constraint. Construction still checks worst-case `o*P*N` storage and index lengths before invoking the callback, but allocates the pool incrementally. These checks do not guarantee enough physical memory for an exponential table.

### Choosing the coefficient chunk count

For fixed N, M and c, start with `d=min(c, floor(log2(N)/tau))`, making M^d as close to N as possible. Increasing d by one divides worst-case public table storage by M and adds one rotation product per output. The best choice still depends on measured time and noise margins; the formulas are in the [stage guide](IMPLEMENTATION.md#stage-and-buffer-layout).

After compiling each candidate d, `table.stats()` reports input/output bits, logical/unique polynomials, required one-hot chunks, NLEV/NGSW selector counts, selection nodes, public lifts and live result slots. Counts reflect pruning and sharing across outputs; they do not predict latency or noise. `public_lift_count > 0` is equivalent to `needs_public_lift()`.

`table.estimate_workspace(output_levels)?` takes the proposed CBS output `DecompositionLevelCount` and returns `ntt_bytes` and `fourier_bytes`, using the same buffer lengths as evaluator construction. This **partial** estimate counts only direct LUT buffers: selectors, rotation controls/factors, result slots, current/product and Fourier conversion/gadget-one buffers. It excludes BR/CBS/one-hot workspaces (including the extra sparse input state), LWE-return workspaces, transform engines, keys, the public table/plan, caller inputs/outputs, allocator overhead and temporary construction storage. Comparing d therefore still requires measured total memory and time.

## Evaluation and workspace

`context.try_generate_keys(&table, rng)` generates one BR/CBS/return bundle and only the lift required by the compiled plan. Classic borrows its existing initializer. Sparse generates independent `NLEV[1]` with BR's configured basis/noise only when `table.needs_public_lift()` is true. Its accepted ring transform/inverse are shared across BR, CBS and lift generation; there is no second BR or table. Ordinary sparse PBS/CBS/one-hot remains unaffected.

To choose sparse lookup, modify the one-hot PBS algorithm before constructing the lookup Context:

```rust,ignore
config.one_hot.pbs.algorithm =
    BlindRotationMethod::Sparse { copy_count: 3, bucket_count: 64 };
let context = NttHighPrecLutContext::<u64, Table, _>::try_from_config(config)?;
let table = context.compile_fn(function)?;
let (client, server) = context.try_generate_keys(&table, rng)?;
let mut evaluator = context.evaluator(&server, &table)?;
```

The server bundle may serve another table with the same operation layout/encoding and compatible material. A sparse bundle generated without lift rejects a later table needing it; it does not generate material online. A bundle containing lift can also bind plans needing none. Actual secrets and transform identity must still match; metadata does not establish them.

For explicit composition, `backend_context()` borrows the original NTRU environment, and `server.into_parts()` moves out the complete `CircuitBootstrapServerKey` and optional owned lift pair. `NttPublicLiftKey` / `FourierPublicLiftKey` pair owned transformed NLEV with its `NlevParameters`; `NttPublicLift` / `FourierPublicLift` are their borrowed views. The explicit `NttLookupTableEvaluator` / `FourierLookupTableEvaluator` constructors and `try_from_parts` remain available. An independently supplied lift may select another basis/noise; the default workflow does not silently regenerate or reinterpret it.

Raw public compilation remains `HighPrecisionLookupTable::try_new(poly_length, ring_modulus, input_codec, config, function)`, requiring only N/Q and input q/t. With a backend enabled, `try_from_parameters` uses existing PBS parameters. Both compile without keys or transforms. Raw evaluator binding checks N/q/Q and one-hot geometry; the complete Context additionally requires its own chunk counts/partition and t. An explicit lift takes precedence over the classic initializer when needed. A plan without Lift ignores surplus lift material. These checks establish shapes/domains, not secret identity, the lift's encoded one or a complete noise margin.

Each call performs one-hot CBS for the low chunks and only for high chunks used by the compiled selection plan. Equal branches omit a choice, and repeated subtrees are computed once. A public choice uses full NLEV selectors and lifts the polynomial; an encrypted choice uses nonzero NGSW selectors. A chunk requiring both representations shares its BR and projections. An output independent of all high chunks uses the bound NLEV[1] lift; mixed public/encrypted choices can also require it. Thus fully pruned tables and c=d still need this material. Each distinct root still requires low-chunk rotations and return; repeated roots copy the earlier completed output because these subsequent operations are identical in one bound evaluator.

Sparse evaluation groups those surviving input chunks in pairs on one thread, then projects and consumes each result in order. A lone input or odd tail uses the ordinary path. With at least two required chunks, construction retains one extra BR aggregate, accumulator and exponent vector: `(L_BR+1)*N*sizeof(T) + n*sizeof(usize)` bytes. Transform, external-product and projection scratch remain shared. This changes traversal order without reducing the number of BRs or storing another selector batch; the public evaluation API is unchanged.

Shared nodes reuse the same ciphertext and error across consumers; output errors are correlated, and identical roots reuse the complete output ciphertext when subsequent operations match. Pruning preserves the cleartext mapping but changes the error path. Full selection, rotation and return formulas are in the [implementation notes](IMPLEMENTATION.md#stage-and-buffer-layout).

Each selection group accumulates products in the transform domain before one inverse transform. Fourier rounding can therefore differ from evaluating and converting each product separately; the encoded function is unchanged, and results still require an adequate decoding margin.

The data LUT encodes one function value per logical input/output chunk, with identical polynomials sharing storage. Repeated guards that tolerate input phase error belong to the preceding one-hot CBS test polynomial. Subsequent selection and rotation introduce additive ciphertext error, which still needs a decoding margin.

The evaluator borrows its context, server key and table and allocates all buffers at construction. Reuse the result of `allocate_output()` with `evaluate_to` for allocation-free online evaluation. All chunk counts and LWE dimensions are checked before writes. Resources must match N/q/Q and actual key identity; the table’s t determines one-hot geometry; Fourier also requires the exact FFT table instance. Each concurrent evaluator owns independent mutable workspace.

The return path performs coefficient-wise Q→q and phase extraction independently for each polynomial, then switches to the external LWE secret. NTT returns each output immediately and allocates only scalar return scratch. Fourier allocates only `LweReturnBatchWorkspace` and batches key switching through an independent `LweReturnEvaluator`, retaining only a small tile of intermediate LWEs; the polynomial buffer can be overwritten after each extraction. Outputs approximate the q-domain chunk encoding; budget double-rounding and return errors.

## Numerical limits and further reading

Inputs must satisfy the [one-hot guard](../primus_tfhe_ntru/README.md#one-hot-cbs), including encryption, encoding and per-coordinate quantization error. CBS and every selection/rotation external product add error; Fourier also includes native trace halving and FFT rounding. Public-lift decomposition must resolve the LUT scale. Shape checks and functional tests do not certify security, production parameters or failure probability.

The [parameter guide](../../guides/development/tfhe-parameters.md) records example choices and validation scope, the [testing guide](../../guides/development/testing.md) maps independent contracts, and the [implementation notes](IMPLEMENTATION.md) describe the algorithm and internal buffers.

## Features

With `--no-default-features`: `ChunkFormat`, public table compilation and inspection, `LookupTableConfig` and their errors need no transform or evaluator. `HighPrecisionLookupTable::try_new` takes `PolyLength`, accumulator Q, an input codec and chunk configuration; its normal dependencies include no LWE/GLWE/NTRU/TFHE material or transform crate. Statistics and both workspace estimates are available without a backend. Compilation retains the complete immutable selection plan. Features do not change callback order, coefficient encoding or table layout.

| Feature | Enables |
| --- | --- |
| `ntt` | NTT Context, public server bundle and evaluator, without a concrete FFT engine |
| `fourier` | Fourier Context, public server bundle and evaluator, without a concrete FFT engine |
| `rustfft` / `tfhe-fft` | `fourier` and the selected FFT implementation |
| `simd` | Nightly SIMD in active arithmetic dependencies, without activating an evaluator or FFT engine |

The defaults are `ntt,fourier`; no concrete FFT engine is selected. All features are additive. `LookupTableError::OneHot` / `Evaluation` are available only with `ntt` or `fourier`.

The NTT example requires `ntt`; the Fourier example requires its chosen engine. Evaluation tests run for each selected NTT/FFT implementation, retaining the existing cases at both word widths. `high_precision_lut` compares u64 NTT and the primary Fourier engine (RustFFT when enabled). Enable any of `ntt`, `rustfft` or `tfhe-fft` independently; combining NTT and one FFT engine registers all 18 workloads. With no applicable backend, the target prints a feature hint and registers no IDs. Use `just tfhe` for complete validation, or run compiler-only and individual backends separately:

```sh
cargo test -p primus_tfhe_ntru_lut
cargo test -p primus_tfhe_ntru_lut --no-default-features --features ntt
cargo test -p primus_tfhe_ntru_lut --no-default-features --features rustfft
cargo test -p primus_tfhe_ntru_lut --no-default-features --features tfhe-fft
```

## Benchmarks

```sh
# Create and drop one public high-precision LUT.
cargo bench -p primus_tfhe_benchmarks --bench high_precision_lut --features lut,ntru-ntt,ntru-fourier,rustfft -- '/create_lut_and_drop/'
# Homomorphically evaluate all output chunks using a prepared LUT and workspace.
cargo bench -p primus_tfhe_benchmarks --bench high_precision_lut --features lut,ntru-ntt,ntru-fourier,rustfft -- '/evaluate/'
```

The 18 workloads retain polynomial, dense and shared tables, paired classic/sparse evaluation, and separate creation for Q50/Native64. Creation includes allocation, coefficient filling and destruction. Evaluation excludes key generation, public LUT creation, input encryption and workspace allocation. Set `PRIMUS_LUT_DIAGNOSTICS=1` and use `--test` for an explicit phase-error report from the same fixture; ordinary timing keeps only result checks. See the [benchmark fixture](IMPLEMENTATION.md#benchmark-fixture) for details.

Original IDs use the polynomial example; IDs containing `/dense_seed42/` use a fixed dense mapping with the same parameters. Filter by `dense_seed42` to run only that workload, or by `c8_d5_o8/evaluate/` to evaluate only the polynomial example.

The `/shared_middle_chunk/` diagnostic mapping sets every output digit to `(m_0+m_6) mod 4`. It isolates a public choice moved past chunk 5, omission of high-chunk CBS for chunks 5 and 7, and reuse of the identical final outputs. It deliberately differs from a full-width arithmetic function.
