# primus_tfhe

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

Shared LUT compilation, encoding metadata, PBS traits and Boolean gate evaluation for the GLWE and NTRU families. Boolean evaluators own gate LUTs and LWE workspace; client keys, transform tables and ring evaluation workspace remain in their owning layers. Start with a backend example below for an end-to-end workflow.

## Choosing an operation

Choose the function and encoding first, then the GLWE/NTRU family, NTT/Fourier representation and secret distribution. “Ordinary key” below means the server's PBS/KS material. All `_to` operations reuse caller outputs and evaluator workspace.

| Task | Input domain and encoding | Output | Evaluation material | Execution and reuse |
| --- | --- | --- | --- | --- |
| Unary function | Unsigned Rounded front half `0..ceil(t/2)` | One Rounded LWE at the chosen output codec | Ordinary key | `LookupTable` + `Evaluator` |
| Odd full domain | Unsigned Rounded `0..t`, odd `t>=3` | One Rounded LWE | Ordinary key | Same LUT/evaluator, narrower input margin |
| Interleaved outputs (ManyLUT) | One front-half input; `ceil(t/2)<=N/next_power_of_two(k)` | k Rounded LWEs sharing the output codec | Ordinary key | `InterleavedLookupTable`, ordinary evaluator |
| Factorized MVB | Rounded front-half prefix | k unsigned Scaled LWEs | Ordinary key | Prepared program + `FactorizedEvaluator`; one BR, per-output products |
| Bounded two-input function | Same secret/codec, `x<B,y<R`, `B*R<=ceil(t/2)` | One Rounded LWE | Ordinary key | `BivariateLookupTable` and one reusable packed LWE |
| Boolean gates | Rounded 0/1 with `t=4` | Same Boolean LWE encoding, ready for chaining | Ordinary key | `BooleanEvaluator` owns gate LUTs and temporary ciphertexts |
| CBS → CMUX | Rounded front half; a CMUX control requires input 0/1 | Accumulator-secret GGSW/NGSW gadget control, then a selected ring ciphertext | Ordinary key + trace/SS | `CircuitBootstrapEvaluator`; separate `AccumulatorClient` for ring clients |

ManyLUT and MVB evaluate **several functions of one input**, not independent inputs. MVB keeps step-one resolution but its factors amplify noise; interleaving trades rotation resolution for output count. Scaled numeric flags, Boolean LWEs and CBS gadget controls are not interchangeable. Start with a backend basic example; the sections below and rustdoc give each operation's domain and noise contracts.

## Crate map and capabilities

| Family | NTT backend | Fourier backend |
| --- | --- | --- |
| [GLWE parameters and clients](../primus_tfhe_glwe/README.md) | [GLWE NTT](../primus_tfhe_glwe_ntt/README.md) | [GLWE Fourier](../primus_tfhe_glwe_fourier/README.md) |
| [NTRU parameters and clients](../primus_tfhe_ntru/README.md) | [NTRU NTT](../primus_tfhe_ntru_ntt/README.md) | [NTRU Fourier](../primus_tfhe_ntru_fourier/README.md) |

All four backends support secret-key and LWE public-key clients. Fourier backends support RustFFT and TfheFFT. Example and benchmark fixtures are not production security or failure-probability recommendations.

Classic GLWE and NTRU PBS, CBS and MVB support binary/ternary input secrets in both backends. NTRU client secrets must also pass the backend's invertibility screening.

Both GLWE backends support experimental sparse PBS for fixed-weight binary small secrets, with both orders and ordinary/interleaved/factorized LUTs. [NTT](../primus_tfhe_glwe_ntt/README.md#experimental-sparse-pbs) and [Fourier](../primus_tfhe_glwe_fourier/README.md#experimental-sparse-pbs) retain their respective exact-transform and native coefficient-aggregation paths. Both support sparse CBS; sparse ternary remains unsupported.

NTRU [NTT](../primus_tfhe_ntru_ntt/README.md#experimental-sparse-pbs) and [Fourier](../primus_tfhe_ntru_fourier/README.md#experimental-sparse-pbs) sparse PBS support ordinary/interleaved LUTs for fixed-weight binary clients. Fourier requires odd weight and a stable inverse. Both reject sparse CBS/MVB.

## Client and server roles

The client generates paired keys, keeps `ClientKey` and encryption/decryption helpers, and gives `ServerKey` to the server. The server needs only public context, evaluation keys, LUTs/programs and input ciphertexts; it returns encrypted results to the client. Examples show these stages in one process, with parameter construction kept separate. Input and output encodings are public agreements between the two sides.

Ordinary buffer allocation needs no secret: all four backends provide `context.allocate_lwe_ciphertext()` for the external LWE mask/body and `context.allocate_accumulator_ciphertext()` for coefficient-domain GLWE/NTRU storage. Both allocate zeros without encrypting. CBS controls also depend on output decomposition and transform representation, so use `cbs.allocate_output()`. Each side prepares and reuses its own workspace and result buffers.

## Error boundaries

Errors are named by operation and re-exported at crate roots. Handle the error type returned by the operation you call.

| Operation | Error |
| --- | --- |
| LUT compilation / ordinary, Boolean or CBS evaluator binding | Shared `LookupTableError` / `TfheEvaluationError` |
| TFHE / CBS parameter preparation | Family `TfheParameterError` / `CircuitBootstrapParameterError` |
| Client-key compatibility / client operations | Family `TfheKeyError` / `TfheClientError` |
| Boolean client construction, encryption and decryption | Family `BooleanError`; `Client` retains underlying client failures |
| Ordinary/sparse server, sparse BSK, or standalone CBS key generation | Family `KeyGenerationError`; NTRU sampling/conversion enters `Ntru` directly; sparse failures enter `SparseBootstrapping` |
| NTRU accumulator client construction | Family `TfheClientError`; `Ntru` retains secret-conversion failures |
| Automatic table creation or explicit table binding | Backend `TfheContextError`; `TransformTable` retains the underlying FFT/NTT error |

`KeyGenerationError::ClientKey` reports client incompatibility directly; sparse errors retain mapping causes through `BucketMap`.

## Boolean gates

For parameters with `t=4`, all four contexts provide `boolean_encryptor(key)`, `boolean_decryptor(client)` and `boolean_evaluator(server)`. The encryptor accepts private or LWE public keys; the decryptor requires the client secret. They use raw `LweCiphertext<T>` with unsigned rounded 0/1 encoding and reject non-Boolean decoded values. Boolean evaluation uses ordinary PBS keys, without CBS material.

```rust,ignore
let encryptor = context.boolean_encryptor(&client)?;
let decryptor = context.boolean_decryptor(&client)?;
let mut gates = context.boolean_evaluator(&server)?;
let lhs = encryptor.encrypt(true, &mut rng)?;
let rhs = encryptor.encrypt(false, &mut rng)?;
let mut output = context.allocate_lwe_ciphertext();
let mut next = context.allocate_lwe_ciphertext();
gates.evaluate_binary_to(BooleanGate::Nand, &lhs, &rhs, &mut output);
assert!(decryptor.decrypt(&output)?);
gates.mux_to(&output, &rhs, &lhs, &mut next);
core::mem::swap(&mut output, &mut next);
assert!(!decryptor.decrypt(&output)?);
```

`BooleanEvaluator` shares affine preprocessing, signed modulus-8 LUTs and the restoring output shift between families. Binary gates use one PBS; NOT uses none, and MUX uses two. Reuse `evaluate_binary_to`, `not_to` and `mux_to` with existing outputs. Outputs keep the external Boolean encoding and can feed subsequent gates directly. Client dimension errors return `BooleanError::Client`; gate dimension mismatches panic. Raw ciphertexts do not carry key identity or encoding metadata; those remain caller contracts.

`BooleanEvaluator::try_new(dimension, poly_length, input_codec, coefficient_modulus, bootstrapper)` is the custom-backend boundary: the caller must bind those arguments to the backend and preserve LUT output scales. It returns `TfheEvaluationError`, including `InvalidBooleanEncoding` for input modulus other than 4 or explicit ciphertext moduli at most 8.

## CBS output and consumption

All four backends bind CBS output layout and consumption to the same evaluator:

```rust,ignore
// Client: encrypt the two candidate messages.
let mut ring_client = context.accumulator_client(&client_key)?;
let lhs = ring_client.encrypt(&lhs_message, &mut rng);
let rhs = ring_client.encrypt(&rhs_message, &mut rng);
let mut decoded = vec![0; lhs_message.len()];

// Server: receive the encrypted input bit and candidates, then return selected.
let mut cbs = context.circuit_bootstrap_evaluator(&server_key)?;
let mut control = cbs.allocate_output();
let mut selected = context.allocate_accumulator_ciphertext();
cbs.circuit_bootstrap_to(&input_bit, &mut control);
cbs.cmux_to(&control, &lhs, &rhs, &mut selected);

// Client: decrypt the response.
ring_client.decrypt_to(&selected, &mut decoded);
```

`allocate_output` returns the backend's raw GGSW/NGSW, and ring ciphertexts remain coefficient-domain GLWE/NTRU values. `cmux_to` selects `lhs` for zero and `rhs` for one; `external_product_to(control, input, output)` also accepts non-bit gadget controls. Controls must use this evaluator's output basis, accumulator secret and transform representation. Candidates must use that secret/modulus and a common encoding. These identities and the noise margin remain caller contracts; every ciphertext length is checked before output writes.

`AccumulatorClient` owns the prepared accumulator secret and reusable conversion buffers, borrowing its context. It encrypts/decrypts N unsigned coefficients using the accumulator codec; this ring domain is separate from external LWE clients. Invalid shapes panic before writes or RNG consumption; invalid plaintext values may consume randomness. NTRU preparation returns `TfheClientError` for key validation or secret conversion failures; GLWE preparation returns `TfheKeyError`.

Construct once and reuse `_to` calls and output buffers for allocation-free evaluation.

## Reusing evaluators

A context owns immutable parameters/tables; the server key owns evaluation material; an evaluator owns mutable workspace. Keep compiled LUTs/programs and use `_to` with preallocated output ciphertexts.

When alternating PBS and MVB/CBS, consume an existing evaluator to retain one PBS workspace:

- GLWE MVB: `FactorizedEvaluator::from_bootstrapper(pbs)`; NTRU MVB uses fallible `try_from_bootstrapper`.
- CBS: `CircuitBootstrapEvaluator::try_from_bootstrapper(pbs)` gets CBS material from the bound server key.
- `bootstrapper_mut()` borrows PBS operations. Import `ProgrammableBootstrap` / `ProgrammableBootstrapInterleaved` to call their `_to` methods; the borrow cannot replace the bound evaluator.
- `into_bootstrapper()` releases dedicated buffers and recovers ordinary workspace. Recovery allocates nothing when MVB/CBS was constructed from an ordinary evaluator.

For one capability alone, use `context.factorized_evaluator` or `context.circuit_bootstrap_evaluator`. Standalone GLWE BR→KS CBS has no return-KS workspace: its PBS borrow is `None`, and recovery explicitly allocates that workspace. Consume ordinary PBS instead when frequently alternating. Other GLWE CBS constructors return `Some`; NTRU CBS/MVB provide a direct borrow but reject sparse keys. Construction may allocate; online evaluation and borrowing never allocate implicitly. Boolean accepts PBS ownership through `try_new` and recovers it through `into_bootstrapper`.

## LUTs and resource lifetime

Backends accept named `TfheConfig` choices and derive shared ring parameters; `TfheContext::try_from_parameters` creates the selected transform table. This crate re-exports `DecompositionConfig` (radix and retained levels) from [`primus_decompose`](../primus_decompose/README.md), and defines `CircuitBootstrapConfig` (independent output/trace/scheme-switch choices). Backends bind these choices to their own modulus, layout and representation. `Option<CircuitBootstrapConfig>` selects optional CBS during paired key generation; the server key owns its parameters and material, while each evaluator owns only its own workspace.

1. A family parameter set describes the external LWE and accumulator ring.
2. A backend context binds those parameters to an NTT/FFT table and generates paired client/server keys.
3. Compile `LookupTable` or `InterleavedLookupTable` through the family parameters. Create an evaluator once; its scratch is reused by online `_to` calls.
4. Allocate caller outputs once, then encrypt and evaluate into the same storage.

The front-half unary function or slice compiler programs `0..ceil(t_in/2)` with outputs in `0..t_out`, as selected by the output codec. Its remaining inputs are not independently programmed. Odd full-domain compilation is a separate entry point described below. For an interleaved LUT (ManyLUT), the effective output count `k` is positive and the padded output count is `s = next_power_of_two(k)`, with `ceil(t/2) <= N/s`. The callback receives `(input, output_index)` once per effective pair, in input-major order; slices contain `D*k` values in the same order. With `k=3`, three outputs occupy four slots: the compiler zeros the fourth slot without calling the callback, and the evaluator returns exactly three ciphertexts. All outputs share one blind rotation (BR) and key switch, then use separate extraction. More outputs reduce rotation resolution and the available input-noise margin. This is one input evaluated by multiple functions, not batching independent ciphertexts.

For direct shared-layer use, `LookupTable` / `InterleavedLookupTable` provide `try_from_fn` and `try_from_slice`, taking the input codec, accumulator modulus and output codec for unsigned Rounded encoding and validation. Odd full domains use `LookupTable::try_from_odd_full_domain_fn` / `_slice`; family compilation methods use these shared constructors.

Raw constructors `LookupTable::try_new` / `InterleavedLookupTable::try_new` accept an explicit prefix length `D` and encoded outputs. `input_ciphertext_modulus` describes input quantization; `coefficient_modulus` is the LUT/accumulator modulus, and raw outputs must be canonical under it. Neither `k` nor the plaintext modulus must be a power of two; padded count `s` must fit capacity, distinct centers and noise margins. Failed construction returns no partial table. See the [rotation geometry](IMPLEMENTATION.md#rotation-geometry) for output lanes, repeated intervals and rounding.

## Encoding and key contracts

| Interface | Input / output meaning |
| --- | --- |
| Ordinary `encrypt` | Unsigned message in `0..t` |
| `encrypt_padded` | Same unsigned scale, restricted to `0..ceil(t/2)` for front-half LUT input |
| `encrypt_centered` | Modular representative in `0..t`; upper-half values represent negatives, e.g. `3` means `-1` for `t=4` |
| Boolean (both families) | External `false/true` is `0/1` modulo 4; internal LUTs use signed values at the rounded modulus-8 scale, followed by a restoring shift |
| CBS | Ordinary unsigned LWE input becomes GGSW/NGSW at the selected gadget scales, under the accumulator secret; a `0/1` input yields a CMUX control |

Client `decrypt` uses the parameter codec and returns a canonical representative in `0..t`. Centered encryption is not a replacement for the unsigned input contract of ordinary LUTs. PBS preserves the LUT's output scale; it does not automatically convert Boolean or gadget outputs to ordinary messages.

Raw `LweCiphertext` does not track its secret, encoding or noise. Callers must use paired keys, canonical explicit-modulus coefficients and an adequate noise margin. LUT and dimension checks happen before output writes; they cannot verify secret identity. Fourier keys and evaluators must use the same FFT table instance.

The minimal traits are `ProgrammableBootstrap` and `ProgrammableBootstrapInterleaved`. Ordinary applications use parameter compilation methods, which validate and encode plaintext outputs. `LookupTable::try_new` and `InterleavedLookupTable::try_new` accept already encoded outputs and an explicit programmed prefix length; Boolean and CBS paths use these constructors for their distinct output scales. Compatibility checks bind polynomial length and encoding moduli; callers remain responsible for keeping the input within the table's programmed prefix. `rotation` owns the quantization contract shared by LUT compilation and blind rotation.

### Choosing the output encoding

Ordinary, interleaved and odd full-domain parameter compilers have two forms:

| Output encoding | Function / slice entry points | Decoding |
| --- | --- | --- |
| Default: `input_plaintext_codec()` | `compile_lookup_table_fn(function)` / `compile_lookup_table_slice(values)` | `decryptor.decrypt(output)` |
| Explicit output codec | `compile_lookup_table_with_codec_fn(codec, function)` / `compile_lookup_table_with_codec_slice(codec, values)` | Decode `decrypt_phase(output)` with that codec |

Interleaved and odd full-domain compilers follow the same naming rule. Default compilation borrows the prepared parameter codec; it does not construct another codec. The function's output range can be smaller than the plaintext modulus: `x % 4` can still use `t=16` encoding. Basic examples use this default workflow.

Explicit variants take `&RoundedCodec<T, M>` first. Input parameters still determine rotation centers and the input domain; the output codec sets `t_out`, validates `0..t_out` values and encodes them unsigned. Interleaved columns share one codec. Only that LUT's output encoding changes; parameters/context remain unchanged. The codec's ciphertext modulus must match the accumulator or compilation returns `OutputModulusMismatch`. Complete PBS chains require `q_in = q_acc = q_out`. MVB continues to require an explicit unsigned `ScaledCodec`.

For an NTRU context with `t_in=16`, compute `x % 4` at output modulus `t_out=4`:

```rust
use primus_encoding::RoundedCodec;

let output_codec = RoundedCodec::new(4u32, context.parameters().external_lwe().cipher_modulus());
let lut = context.parameters().compile_lookup_table_with_codec_fn(&output_codec, |x| (x % 4) as u32).unwrap();
let input = encryptor.encrypt_padded(7u32, &mut rng).unwrap();
let output = evaluator.apply_lookup_table(&input, &lut);
let message = output_codec.decode_value(decryptor.decrypt_phase(&output).unwrap());
assert_eq!(message, 3);
```

For GLWE use `context.parameters().accumulator_glwe().cipher_modulus()` to construct the output codec. Independent output encoding requires no additional evaluation keys; keep that codec to decode the resulting ciphertext.

`decrypt_phase` returns a canonical noisy residue under the external LWE secret; the caller retains the output codec for decoding. LUT compatibility metadata continues to describe the input and accumulator, without equating `t_out` to `t_in`. Chaining another PBS requires its input encoding and LUT geometry to match the previous output encoding; a context does not infer that change from raw ciphertexts. Custom encodings, per-column scales and Boolean/CBS gadget outputs use the raw constructors and retain their own decoding contracts.

## Odd full-domain PBS

Use `compile_odd_full_domain_lookup_table_fn(function)` or its `_slice` form; choose the `*_with_codec_*` variant for a different output encoding. These methods program **all of `0..t_in`**, with odd `t_in >= 3` and `t_in <= N`. Slices contain exactly `t_in` outputs in input order. Encrypt with ordinary `encrypt`, then use the existing `apply_lookup_table_to`. Decode with `decrypt` for the default encoding, or with the explicit output codec. For example, in a context configured with `t_in=15` and an output codec for `t_out=8`:

```rust,ignore
let lut = context.parameters().compile_odd_full_domain_lookup_table_with_codec_fn(
    &output_codec, |x| ((x * x + 3) % 8) as u32,
).unwrap();
let input = encryptor.encrypt(14u32, &mut rng).unwrap();
evaluator.apply_lookup_table_to(&input, &lut, &mut output);
let message = output_codec.decode_value(decryptor.decrypt_phase(&output).unwrap());
assert_eq!(message, 7);
```

Raw encoded outputs use `LookupTable::try_new_odd_full_domain`. The compiler folds negacyclic rotation centers and restores output signs; colliding folded centers return `RotationCenterCollision`. Callback order and interval details are specified in rustdoc.

Typical spacing is `N/t_in`, so the noise margin is about half that of front-half compilation. Capacity and collision checks establish LUT geometry, not a PBS failure probability. Account for input error and per-coefficient modulus switching. This entry supports single-output odd domains; interleaved and bivariate compilers retain their front-half contracts. No extra key or online evaluator is needed. The [rotation geometry notes](IMPLEMENTATION.md#rotation-geometry) explain the signed folding and its limits.

## Bounded two-input PBS

`BivariateLookupTable::try_new(B, R, N, input_codec, output_codec, function)` compiles `f(x,y)` for `0 <= x < B`, `0 <= y < R` using `z = x + B*y`. `B` and `R` must be positive and `D = B*R <= ceil(t_in/2)`; the ordinary LUT capacity and rotation-center checks also apply. Only the prefix `0..D` is compiled, with `x` varying fastest. `B` need not be a power of two. The output codec selects `t_out` independently but must use the same ciphertext modulus. The shared type works with all four backends and owns no keys or scratch.

For an NTRU context with `t_in=16`, reuse the existing client and evaluator:

```rust
use primus_tfhe::BivariateLookupTable;

let compare = BivariateLookupTable::try_new(
    3, 2, context.parameters().poly_length(),
    context.parameters().input_plaintext_codec(),
    &output_codec, |x, y| u32::from(x > y),
).unwrap();
let lhs = encryptor.encrypt_padded(2u32, &mut rng).unwrap();
let rhs = encryptor.encrypt_padded(1u32, &mut rng).unwrap();
compare.pack_to(&lhs, &rhs, &mut packed);
evaluator.apply_lookup_table_to(&packed, compare.lookup_table(), &mut output);
assert_eq!(output_codec.decode_value(decryptor.decrypt_phase(&output).unwrap()), 1);
```

Allocate `packed` and `output` once with the external LWE dimension. `pack_to` writes `lhs + B*rhs` in one modular multiply-add pass, without allocation; it rejects unequal lengths or missing bodies before writing. Inputs must share an actual secret, ciphertext modulus and the supplied unsigned input codec, with canonical coefficients and messages inside the stated bounds. These semantic conditions cannot be checked from raw ciphertexts. GLWE uses its order-dependent external dimension and `input_plaintext_codec()`; no extra key material is needed.

Packing amplifies the second input's noise by B and can add an encoding-rounding discrepancy when `t_in` does not divide q. Budget both before PBS; the capacity check alone does not prove sufficient noise margin. See `BivariateLookupTable` rustdoc for the bound. This is a bounded single-output workflow, not general integer arithmetic or LWE-to-ring packing.

## Fixed-scale factorized MVB

`FactorizedLookupTable::try_new(D, N, output_count, input_codec, output_codec, function)` compiles a nonempty front-half prefix using Rounded input and unsigned Scaled output. The coefficient modulus may be explicit and odd, or Native with an even Scaled output scale. Explicit even moduli are unsupported. The callback receives `(input, output_index)` once per pair, with **output index outermost**. Signed integer factor norms determine noise amplification; the algebra is documented on `FactorizedLookupTable` and in the [MVB design](IMPLEMENTATION.md#factorized-mvb).

All outputs share one BR at step one and then apply separate public polynomial products. Positive output count is unpadded and does not reduce input capacity; each output instead amplifies BR error by its factor. Input geometry alone is not a sufficient noise budget. The Scaled codec must be retained for phase decoding; chaining into Rounded-input PBS must account for differing centers.

Both [GLWE NTT](../primus_tfhe_glwe_ntt/README.md#fixed-scale-factorized-mvb) and [NTRU NTT](../primus_tfhe_ntru_ntt/README.md#fixed-scale-factorized-mvb) support this program. GLWE NTT supports classic/sparse keys and both orders; NTRU NTT shares its encrypted initialization and BR, then key-switches each product. [GLWE Fourier](../primus_tfhe_glwe_fourier/README.md#fixed-scale-factorized-mvb) supports classic binary/ternary and sparse binary keys in both orders with u32/u64 and an even Native scale; it transforms factors as signed integers and also requires an FFT error budget. [NTRU Fourier](../primus_tfhe_ntru_fourier/README.md#fixed-scale-factorized-mvb) supports the same widths and Native scales with binary/ternary keys; its factors amplify both encrypted initialization and BR noise before per-output key switching. `t_out` need not be a power of two: check the actual scale. Each prepared program borrows one context and its separate evaluator reuses scratch. Odd full-domain MVB and CBS outputs remain outside this implementation. Algebra and noise conditions are detailed in the [MVB design](IMPLEMENTATION.md#factorized-mvb).

The [GLWE](../primus_tfhe_glwe_ntt/examples/mvb_thresholds.rs) and [NTRU](../primus_tfhe_ntru_ntt/examples/ntru_ntt_mvb_thresholds.rs) threshold examples turn one encrypted score into 17 flags beyond interleaved capacity. Prefer ManyLUT when capacity and rotation margins suffice; consider MVB for more outputs with small integer factor norms, and measure complete costs on the actual backend and parameters.

## Typed rotation quantization

Raw LUT compilation accepts independent typed input and coefficient moduli. `rotation::RotationQuantizer::new(input_modulus, two_n, rotation_step)` prepares a fixed modulus-pair conversion; `exponent(value)` reuses it without allocation. The rotation domain `two_n = 2N` must be representable by the input coefficient type; the target `two_n/rotation_step` is an explicit power of two, even for Native input. Interleaved rotation rounds in `two_n/rotation_step` positions before multiplying by `rotation_step`, which equals the LUT padded output count. See the [rotation geometry](IMPLEMENTATION.md#rotation-geometry) for full geometry and preparation details.

## Further reading

[Implementation notes](IMPLEMENTATION.md) · [Benchmarks and performance decisions](IMPLEMENTATION.md#performance-decisions-and-reproducibility)
