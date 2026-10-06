# primus_tfhe_ntru_lut

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

High-precision lookup over already encrypted NTRU-TFHE chunks, using one-hot CBS, public and encrypted table selection, negative rotation and return to an independent LWE secret.

## Workflow

Both [NTT](../primus_tfhe_ntru_ntt/README.md) and [Fourier](../primus_tfhe_ntru_fourier/README.md) support classic binary/ternary and sparse fixed-weight binary lookup. Generate evaluation material with `generator.try_generate_server_key(&client, blind_rotation, Some(cbs_config), rng)`, choosing `BlindRotationConfig::Classic` or `Sparse { copy_count, bucket_count }`. CBS material is required. Generate and encrypt input chunks on the client with `encrypt_padded`. The basic examples fix classic BR and keep one eight-chunk workflow. Sparse/public-lift setup is shown below under [Evaluation and workspace](#evaluation-and-workspace).

`HighPrecisionLookupTable::try_new(poly_length, ring_modulus, &input_codec, config, function)` compiles the public table using only N, Q and the codec’s q/t, without TFHE parameters, secrets or transforms. The callback receives `(full_input_index, output_chunk_index)` and returns one digit. Bind `NttLookupTableEvaluator::try_new(context, server_key, None, table)` or `FourierLookupTableEvaluator::try_new(context, server_key, None, table)`, call `allocate_output()` once, then reuse `evaluate_to(input_chunks, output_chunks)`. Decode each result with `context.decryptor(client.external_lwe_secret_key(), &input_codec)`. The table owns its chunk encoding; keys are independent of t. The evaluator borrows its context, server key and table; no client secret is needed for evaluation.

For a u32 context with `t=8` and `N=1024`, eight two-bit chunks represent a 16-bit input. This fragment evaluates `(x*x+3*x+7) mod 65536` and returns eight chunks:

```rust,ignore
use primus_tfhe_ntru_lut::{
    HighPrecisionLookupTable, LookupTableConfig, NttLookupTableEvaluator,
};

let input_codec = primus_encoding::RoundedCodec::new(8u64, context.parameters().external_lwe().cipher_modulus());
let table = HighPrecisionLookupTable::try_new(
    context.parameters().poly_length(),
    context.parameters().accumulator_ntru().cipher_modulus(),
    &input_codec,
    LookupTableConfig {
        input_chunk_count: 8,
        output_chunk_count: 8,
        coefficient_chunk_count: 5,
    },
    |x, output| {
        let x = x as u64; // The cleartext intermediate can exceed u32.
        let value = (x * x + 3 * x + 7) % 65536;
        (value >> (2 * output)) & 3
    },
)?;
let mut evaluator = NttLookupTableEvaluator::try_new(&context, &server, None, &table)?;
let mut output = evaluator.allocate_output();
evaluator.evaluate_to(&encrypted_chunks, &mut output);
```

Complete runnable workflows are in [ntt_lookup.rs](examples/ntt_lookup.rs) and [fourier_lookup.rs](examples/fourier_lookup.rs). They use n=800/N=1024 and eight two-bit chunks for both the 16-bit input and 16-bit result. Five low input chunks select coefficients; three high chunks select one of 64 candidate polynomials. The output chunk count remains independently configurable. Input `0b10_10_10_11_11_00_11_01` returns `0b10_00_01_01_10_01_01_11`, then zero returns 7, reusing the same evaluator and buffers.

Both examples use `Word = u64`; NTT uses `U64NttTable`. Each workflow keeps one explicit parameter set; library tests and diagnostics retain u32 coverage. The Fourier example selects RustFFT; use `TfheFftTable as Table` for TFHE-FFT. When switching FFT engines, also update the example target’s `required-features` and use `--features tfhe-fft`. Each file explicitly builds `TfheConfig` and `CircuitBootstrapConfig` in local `parameters()` and `circuit_config()` functions, showing dimensions, noise, u64 decomposition bases, prime/native ring modulus and independent PowOf2 q=2^24; see the [arithmetic profiles](../../guides/development/tfhe-parameters.md).

```sh
cargo run --release -p primus_tfhe_ntru_lut --example ntt_lookup --features ntt
cargo run --release -p primus_tfhe_ntru_lut --example fourier_lookup --features rustfft
```

## Encoding and table partition

The plaintext modulus must be `t=2*M`, with `M=2^tau>=2`. All input and output chunks share tau; their counts are independent and positive. Both ciphertext slices are least-significant first: `x=sum_i m_i*M^i`. Inputs are separate encrypted chunks; the API does not homomorphically split one high-precision LWE.

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

Each evaluator owns its backend's common `BootstrapResources` separately from one-hot operation state. Selection, rotation and CBS borrow the same external-product workspace in sequence; Fourier also reuses the same FFT engine inside those resources. The return binding is independent of one-hot: NTT allocates only scalar return scratch, Fourier only batch return scratch.

Both evaluators accept a complete `ServerKey` through `try_new(context, server_key, public_lift, lookup_table)`, or borrow independent material with `try_from_parts(context, blind_rotation_key, return_key, circuit_key, public_lift, lookup_table)`. Components can come from `ServerKey::into_parts()` without copying ciphertext buffers. Unlike standalone CBS/one-hot, this workflow always requires the Q→q, f→s return key for its LWE outputs. Components are checked when binding; actual shared secrets and transform identity remain caller contracts.

`table.needs_public_lift()` reports whether the pruned selection plan contains an explicit `Lift`. If so, `try_from_parts` requires `public_lift=Some((nlev_view, &nlev_parameters))`: an NTT/Fourier NLEV encryption of one and the `NlevParameters` used to generate it. `NttPublicLift` / `FourierPublicLift` name these borrowed tuples; they add no owner or constructor. The evaluator checks N, Q and transformed length, then uses that material's basis, which may differ from BR/CBS. The material must use the same accumulator secret and transform representation (the same table instance for Fourier); its claimed plaintext/basis and noise budget remain caller contracts. Without `Lift`, pass `None`; unused material is ignored and not retained.

With `public_lift=None`, `try_new` borrows the classic initializer and its BR parameters when needed. Explicit material takes precedence, allowing a separate lift basis/noise even with classic BR. A sparse plan with `Lift` returns `MissingPublicLiftKey` unless independent material is supplied; plans without `Lift` require none. One-hot evaluators do not expose BR controls.

For sparse setup, use a fixed-weight binary external secret and matched CBS parameters, as in the lookup examples (n=800, h=32, N=1024, q24). The caller compiles the public table and encrypts its chunks with the same context/encoding. This typed NTT snippet takes those prepared inputs rather than duplicating the full parameter fixture. Client setup produces keys and, only when required by the table, NLEV[1]; the server block binds them and returns ciphertexts:

```rust,no_run
use primus_modulus::PowOf2Modulus;
use primus_ntt::U64NttTable as Table;
use primus_tfhe::{BlindRotationConfig, CircuitBootstrapConfig, LweCiphertext};
use primus_tfhe_ntru::ClientKey;
use primus_tfhe_ntru_ntt::{KeyGenerator, TfheContext};
use primus_tfhe_ntru_lut::{HighPrecisionLookupTable, NttLookupTableEvaluator as LookupEvaluator};
use rand::rngs::StdRng;

// Complete setup and one encrypted request; keep the final server block alive
// to reuse its evaluator/output for further requests.
fn sparse_setup_and_request(
    context: &TfheContext<u64, Table, PowOf2Modulus<u64>>,
    client: &ClientKey<u64>,
    cbs_config: CircuitBootstrapConfig,
    table: &HighPrecisionLookupTable<u64>,
    inputs: &[LweCiphertext<u64>],
    rng: &mut StdRng,
) -> Vec<LweCiphertext<u64>> {
    // Client: generate evaluation material for its fixed-weight binary LWE secret.
    let mut generator = KeyGenerator::new(context);
    let server_key = generator.try_generate_server_key(
        client,
        BlindRotationConfig::Sparse { copy_count: 3, bucket_count: 64 },
        Some(cbs_config),
        rng,
    ).unwrap();
    // BR's basis and row noise are used here (sigma=0.7 in the lookup examples).
    // A separate NlevParameters can select another lift basis/noise budget.
    let lift_parameters = context.parameters().blind_rotation();
    let lift = table.needs_public_lift().then(|| {
        generator.try_generate_public_lift_key(
            client.accumulator_ntru_secret_key(), lift_parameters, rng,
        ).unwrap()
    });

    // Server: receive the keys/lift, public parameters/table and encrypted chunks.
    let mut evaluator = LookupEvaluator::try_new(
        context, &server_key,
        lift.as_ref().map(|key| (key.as_view(), lift_parameters)), table,
    ).unwrap();
    let mut outputs = evaluator.allocate_output();
    evaluator.evaluate_to(inputs, &mut outputs);
    // Further requests reuse this evaluator and overwrite the same output buffer.
    outputs // Only result ciphertexts return to the client for decryption.
}
```

For Fourier, the same flow uses `primus_fft::RustFftTable as Table`, `primus_tfhe_ntru_fourier::{KeyGenerator, TfheContext}` and `FourierLookupTableEvaluator as LookupEvaluator`. Use its Native64 ring parameters, keep external `PowOf2Modulus<u64>`, and generate all material with the same FFT table instance. Keep key/lift owners alive while the evaluator borrows them; do not call the whole setup function for every request.

This is an independent encryption of one under the same accumulator secret. It does not sum the first sparse bucket, whose error would have a different distribution. Generation checks the ring and secret before sampling; Fourier uses the context's FFT table. Ordinary sparse PBS/CBS/one-hot pays no lift-generation or storage cost.

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

Default features are empty: public table compilation, inspection, `LookupTableConfig` and compilation errors need no transform or evaluator. `HighPrecisionLookupTable::try_new` takes `PolyLength`, accumulator Q, an input codec and chunk configuration; its normal dependencies include no LWE/GLWE/NTRU/TFHE material or transform crate. Statistics and both workspace estimates are available without a backend. Compilation retains the complete immutable selection plan. Features do not change callback order, coefficient encoding or table layout.

| Feature | Enables |
| --- | --- |
| `ntt` | `NttLookupTableEvaluator` and NTT dependencies, without FFT |
| `fourier` | `FourierLookupTableEvaluator` and generic FFT interfaces, without NTT or a concrete FFT engine |
| `rustfft` / `tfhe-fft` | `fourier` and the selected FFT implementation |
| `simd` | Nightly SIMD in active arithmetic dependencies, without activating an evaluator or FFT engine |

All features are additive. `LookupTableError::OneHot` / `Evaluation` are available only with `ntt` or `fourier`.

The NTT example requires `ntt`; the Fourier example requires its chosen engine. Evaluation tests run for each selected NTT/FFT implementation, retaining the existing cases at both word widths. `pipeline` compares u64 NTT and the primary Fourier engine (RustFFT when enabled). Enable any of `ntt`, `rustfft` or `tfhe-fft` independently; combining NTT and one FFT engine registers all 18 workloads. With no applicable backend, the target prints a feature hint and registers no IDs. Use `just tfhe` for complete validation, or run compiler-only and individual backends separately:

```sh
cargo test -p primus_tfhe_ntru_lut
cargo test -p primus_tfhe_ntru_lut --features ntt
cargo test -p primus_tfhe_ntru_lut --features rustfft
cargo test -p primus_tfhe_ntru_lut --features tfhe-fft
```

## Benchmarks

```sh
# Create and drop one public high-precision LUT.
cargo bench -p primus_tfhe_ntru_lut --bench pipeline --features ntt,rustfft -- '/create_lut_and_drop$'
# Homomorphically evaluate all output chunks using a prepared LUT and workspace.
cargo bench -p primus_tfhe_ntru_lut --bench pipeline --features ntt,rustfft -- '/evaluate$'
```

The 18 workloads retain polynomial, dense and shared tables, paired classic/sparse evaluation, and separate creation for Q50/Native64. Creation includes allocation, coefficient filling and destruction. Evaluation excludes key generation, public LUT creation, input encryption and workspace allocation. Set `PRIMUS_LUT_DIAGNOSTICS=1` and use `--test` for an explicit heap/allocation/phase report from the same fixture; ordinary timing keeps only result checks. See the [benchmark fixture](IMPLEMENTATION.md#benchmark-fixture) for details.

Original IDs use the polynomial example; IDs containing `/dense_seed42/` use a fixed dense mapping with the same parameters. Filter by `dense_seed42` to run only that workload, or by `c8_d5_o8/evaluate$` to evaluate only the polynomial example.

The `/shared_middle_chunk/` diagnostic mapping sets every output digit to `(m_0+m_6) mod 4`. It isolates a public choice moved past chunk 5, omission of high-chunk CBS for chunks 5 and 7, and reuse of the identical final outputs. It deliberately differs from a full-width arithmetic function.
