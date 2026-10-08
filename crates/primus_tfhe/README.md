# primus_tfhe

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

Shared external LWE clients, LUT compilation, encoding metadata, PBS traits and Boolean gate evaluation for the GLWE and NTRU families. Boolean evaluators own gate LUTs and LWE workspace; client keys, transform tables and ring evaluation workspace remain in their owning layers. Start with a backend example below for an end-to-end workflow.

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
| CBS → CMUX | Rounded front half; a CMUX control requires input 0/1 | Accumulator-secret GGSW/NGSW gadget control, then a selected ring ciphertext | BR + trace/SS; input KS for GLWE KS→BR | `CircuitBootstrapEvaluator`; separate `AccumulatorClient` for ring clients |
| One-hot CBS | One padded chunk, t=2M | NLEV/NGSW selectors for δ_r(m) | NTRU CBS material | [One-hot API](../primus_tfhe_ntru/README.md#one-hot-cbs) |
| High-precision lookup | Separately encrypted chunks of uniform width | Independently chosen output chunk count | NTRU CBS and return keys; public lift when required | [High-precision lookup](../primus_tfhe_ntru_lut/README.md) |

ManyLUT and MVB evaluate **several functions of one input**, not independent inputs. MVB keeps step-one resolution but its factors amplify noise; interleaving trades rotation resolution for output count. Scaled numeric flags, Boolean LWEs and CBS gadget controls are not interchangeable. Start with a backend basic example; the sections below and rustdoc give each operation's domain and noise contracts.

## Crate map and capabilities

| Family | NTT backend | Fourier backend |
| --- | --- | --- |
| [GLWE parameters and clients](../primus_tfhe_glwe/README.md) | [GLWE NTT](../primus_tfhe_glwe_ntt/README.md) | [GLWE Fourier](../primus_tfhe_glwe_fourier/README.md) |
| [NTRU parameters and clients](../primus_tfhe_ntru/README.md) | [NTRU NTT](../primus_tfhe_ntru_ntt/README.md) | [NTRU Fourier](../primus_tfhe_ntru_fourier/README.md) |

All four backends provide secret-key and LWE public-key clients. Fourier supports RustFFT and TFHE-FFT with Native ring moduli only. Example parameters are not production security or failure-probability recommendations.

| Key mode | Ordinary / ManyLUT PBS | CBS | Factorized MVB | One-hot / high-precision lookup |
| --- | --- | --- | --- | --- |
| GLWE classic binary/ternary | Both PBS orders | Yes | Yes | Not provided |
| GLWE sparse fixed-weight binary | Both PBS orders | Yes | Yes | Not provided |
| NTRU classic binary/ternary | Yes | Yes | Yes | Yes |
| NTRU sparse fixed-weight binary | Yes | Yes | Yes | Supported |

Sparse mode requires explicit key generation; sparse ternary is unsupported. NTRU's external LWE secret is independent of its ring secret. Only the ring secret undergoes invertibility and Fourier inverse-stability screening; external fixed weights may be even.

## Selecting blind rotation

All four backends re-export `BlindRotationConfig`. Select the algorithm independently of the secret distribution and optional CBS material:

```rust,ignore
let blind_rotation = BlindRotationConfig::Sparse { copy_count: 3, bucket_count: 64 };
// Use BlindRotationConfig::Classic for per-coordinate CMux controls.
let (client, server) = context.try_generate_keys(blind_rotation, None, rng)?;
```

`Classic` supports binary and ternary distributions, including fixed-weight ones. `Sparse` requires fixed-weight binary with `0<h<n`; it retries only the public bucket map and returns an error if matching fails. It never changes the client secret or falls back to classic. Paired generation reuses transformed secrets; `generator.try_generate(blind_rotation, cbs, rng)` offers the same choice with reusable setup scratch. To retain an existing client, use `generator.try_generate_server_key(&client, blind_rotation, cbs, rng)`.

CBS and sparse configuration errors precede secret sampling. Existing clients are validated at the generation boundary; fresh keys rely on the sampler guarantees. NTRU additionally checks the accepted ring secret against return q when its sampler bound cannot establish that condition. Ring-only BR/CBS does not need this return bound.

`None` for CBS generates BR and ordinary return material; `Some(config)` adds trace/scheme-switch keys. Independent BR, CBS and return generation remains available, and NTRU public lift is requested separately when a lookup needs it. Each backend's `BlindRotationKey` owns only BR material; `ServerKey` combines materials. GLWE ring KS and NTRU LWE return keep distinct APIs because their domains differ.

For ring-output CBS or NTRU one-hot, use the dedicated paired entry:

```rust,ignore
let (client, server) = context.try_generate_circuit_bootstrap_keys(blind_rotation, cbs_config, rng)?;
let mut resources = server.bootstrap_resources(&context)?;
let mut cbs = CircuitBootstrapEvaluator::try_new(
    &resources, server.circuit_bootstrap_key(), &input_codec,
)?;
```

This returns `CircuitBootstrapServerKey`, with BR and required CBS material. GLWE adds input KS only for KS→BR; GLWE BR→KS and NTRU generate no ordinary return key. NTRU one-hot uses `OneHotCircuitBootstrapEvaluator` with the same bundle. The generator variant has the same method name and reuses setup scratch. For mixed PBS/CBS or high-precision lookup, keep `try_generate_keys(..., Some(cbs_config), ...)` and its complete `ServerKey`. Components can be borrowed or moved out with `into_parts()` for advanced composition; no ciphertext buffers are copied.

## Client and server roles

`Encryptor`, `Decryptor` and their Boolean wrappers share encoding, range checks and allocation-free `*_to` operations. `LweClientParameters::new(&lwe_parameters)` borrows a validated LWE domain, including its dimension, rounded codec and noise, and derives the mask sampler from the codec modulus. Its fields are private and available through accessors. Family constructors validate their keys and select the active LWE secret and noise once; Both families use `LweClientParameters::try_from_parts(dimension, &codec, &noise)` to bind a selected message encoding: GLWE BR→KS uses small-LWE noise and dimension, while KS→BR uses the extracted dimension and accumulator noise; NTRU uses its independent external LWE parameters. Codec/key and codec/noise moduli are checked at binding. These checks do not establish a noise or security budget.

The shared layer accepts `LweSecretKeyRef` or `&LwePublicKey`; its only client trait, `EncryptionKey<T, M>`, selects the encryption kernel without family parameter or error types. Raw operations return `ClientError`; Boolean operations return `BooleanError`.

Family factories check the owning LWE secret's recorded modulus before taking a raw view; mismatches return `TfheKeyError::LweSecretKeyModulusMismatch`. Direct shared-layer constructors taking `LweSecretKeyRef` cannot do this check: their caller must establish the secret's modulus compatibility first. The bound client keeps a view and does not repeat the owning-key check for each message.

Allocating encryption methods return `LweCiphertext<T>`. Client writes take `Lwe<&mut [T]>` and reads take `Lwe<&[T]>` by value: use `encryptor.encrypt_padded_to(message, output.as_mut_view(), rng)` and `decryptor.decrypt(output.as_view())`. These views borrow the coefficients without copying or allocating. For caller-owned slices, wrap them with `primus_tfhe::Lwe::new`; the same API supports boxed, aligned and stack storage. Boolean clients use the same borrowing convention.

Evaluation uses the same views for single LWE operands: `evaluator.apply_lookup_table_to(input.as_view(), &lut, output.as_mut_view())`. Boolean gates and bivariate packing borrow their operands; CBS, one-hot and MVB borrow their LWE input. Allocating methods still return owned ciphertexts. ManyLUT/MVB output batches and high-precision input/output batches borrow slices of preallocated `LweCiphertext<T>` values. Allocate one complete LWE per effective output; LUT padding does not require extra ciphertexts. Each LWE keeps its own coefficient buffer, so pass the existing slice directly without packing coefficients or collecting views. Counts and every ciphertext dimension are checked before output writes.

The client generates paired keys, keeps the setup bundle `ClientKey` (or separates its owners with `into_parts()`) and encryption/decryption helpers, and gives `ServerKey` to the server. The server needs only public context, evaluation keys, LUTs/programs and input ciphertexts; it returns encrypted results to the client. Examples show these stages directly in `main`, with comments identifying each side. Server setup uses public context, codecs and evaluation keys; encryption and decryption use the client secret. CBS also sends client-encrypted ring candidates; sparse high-precision plans may need a client-generated NLEV[1] public-lift ciphertext. The public LUT may be compiled by the server. Each side allocates and reuses its own buffers. This demonstrates material flow without a transport layer; input/output encodings are public agreements.

Ordinary buffer allocation needs no secret: all four backends provide `context.allocate_lwe_ciphertext()` for the external LWE mask/body and `context.allocate_accumulator_ciphertext()` for coefficient-domain GLWE/NTRU storage. Both allocate zeros without encrypting. CBS controls also depend on output decomposition and transform representation, so use `cbs.allocate_output()`. Each side prepares and reuses its own workspace and result buffers.

## Error boundaries

Prefer `try_*` configuration and binding constructors and handle the error returned by that operation. `LookupTableError` covers LUT compilation and `TfheEvaluationError` covers evaluator resource binding. Families/backends provide parameter, key-generation, client and transform-table errors. Ordinary client operations return `ClientError`; Boolean operations return `BooleanError`. Underlying causes remain accessible through `std::error::Error::source()`; consult the public API's rustdoc for individual cases.

## Boolean gates

Boolean clients require `t=4`. All context factories take an explicit Rounded codec, as shown below; use the family’s external LWE modulus when constructing it. They use raw `LweCiphertext<T>` with unsigned rounded 0/1 encoding and reject non-Boolean decoded values. Direct Boolean construction wraps a prepared client with `BooleanEncryptor::try_new(encryptor)` or `BooleanDecryptor::try_new(decryptor)`. Boolean evaluation uses ordinary PBS keys, without CBS material.

```rust,ignore
let codec = primus_encoding::RoundedCodec::new(4, context.parameters().cipher_modulus());
let external_secret = client.external_lwe_secret_key();
let encryptor = context.boolean_encryptor(external_secret, &codec)?;
let decryptor = context.boolean_decryptor(external_secret, &codec)?;
let mut gates = context.boolean_evaluator(&server, &codec)?;
let lhs = encryptor.encrypt(true, &mut rng)?;
let rhs = encryptor.encrypt(false, &mut rng)?;
let mut output = context.allocate_lwe_ciphertext();
let mut next = context.allocate_lwe_ciphertext();
gates.evaluate_binary_to(
    BooleanGate::Nand, lhs.as_view(), rhs.as_view(), output.as_mut_view(),
);
assert!(decryptor.decrypt(output.as_view())?);
gates.mux_to(output.as_view(), rhs.as_view(), lhs.as_view(), next.as_mut_view());
core::mem::swap(&mut output, &mut next);
assert!(!decryptor.decrypt(output.as_view())?);
```

`BooleanEvaluator` shares affine preprocessing, signed modulus-8 LUTs and the restoring output shift between families. Binary gates use one PBS; NOT uses none, and MUX uses two. Reuse `evaluate_binary_to`, `not_to` and `mux_to` with existing outputs. Outputs keep the external Boolean encoding and can feed subsequent gates directly. Client dimension errors return `BooleanError::Client`; gate dimension mismatches panic. Raw ciphertexts do not carry key identity or encoding metadata; those remain caller contracts.

## CBS output and consumption

All four backends bind CBS output layout and consumption to the same evaluator. This GLWE example selects a Rounded input codec and an independent Scaled accumulator codec. NTRU uses `client_key.accumulator_ntru_secret_key()` instead of the GLWE accessor and takes the same codec arguments, with the input codec at external q and the ring codec at accumulator Q:

```rust,ignore
// Client: encrypt the two candidate messages.
let input_codec = primus_encoding::RoundedCodec::new(4, context.parameters().cipher_modulus());
let ring_codec = primus_encoding::ScaledCodec::new(8, context.parameters().cipher_modulus());
let mut ring_client = context.accumulator_client(client_key.glwe_secret_key(), ring_codec)?;
let lhs = ring_client.encrypt(&lhs_message, &mut rng);
let rhs = ring_client.encrypt(&rhs_message, &mut rng);
let mut decoded = vec![0; lhs_message.len()];

// Server: receive the encrypted input bit and candidates, then return selected.
let mut pbs = context.evaluator(&server_key)?;
let key = server_key.circuit_bootstrap_key().unwrap();
let mut cbs = CircuitBootstrapEvaluator::try_new(
    pbs.bootstrap_resources(), key, &input_codec,
)?;
let mut control = cbs.allocate_output();
let mut selected = context.allocate_accumulator_ciphertext();
cbs.circuit_bootstrap_to(input_bit.as_view(), &mut control, pbs.bootstrap_resources_mut());
cbs.cmux_to(&control, &lhs, &rhs, &mut selected, pbs.bootstrap_resources_mut());

// Client: decrypt the response.
ring_client.decrypt_to(&selected, &mut decoded);
```

All four backends borrow common resources and take the default CBS output parameters from the circuit key; see resource reuse below.

`allocate_output` returns the backend's raw GGSW/NGSW, and ring ciphertexts remain coefficient-domain GLWE/NTRU values. `cmux_to` selects `lhs` for zero and `rhs` for one; `external_product_to` also accepts non-bit gadget controls. Controls must use this evaluator's output basis, accumulator secret and transform representation. Candidates must use that secret/modulus and a common encoding. These identities and the noise margin remain caller contracts; every ciphertext length is checked before output writes.

`AccumulatorClient` owns the prepared accumulator secret and reusable conversion buffers, borrowing its context. It encrypts/decrypts N unsigned coefficients using the accumulator codec; this ring domain is separate from external LWE clients. Invalid shapes panic before writes or RNG consumption; invalid plaintext values may consume randomness. Preparation returns `TfheClientError`: both families check keys and the supplied Scaled codec modulus; NTRU also checks secret conversion.

Construct once and reuse `_to` calls and output buffers for allocation-free evaluation.

## Reusing evaluators

A context owns immutable parameters/tables; the server key owns evaluation material; an evaluator owns mutable workspace. Keep compiled LUTs/programs and use `_to` with preallocated output ciphertexts.

Both NTRU backends compose short borrows: ordinary PBS owns common BR/EP (including FFT for Fourier) and return buffers, while CBS/one-hot prepares only LUT/projection state. Construct with `try_new(pbs.bootstrap_resources(), circuit_key, &input_codec)` and pass `pbs.bootstrap_resources_mut()` as the final execution argument. Construct factorized MVB with `FactorizedEvaluator::new(&pbs)` and pass `&mut pbs` for execution. CBS-only callers can prepare common resources independently with `context.bootstrap_resources(br)`. See [NTT resource reuse](../primus_tfhe_ntru_ntt/README.md#reusing-evaluators) and [Fourier resource reuse](../primus_tfhe_ntru_fourier/README.md#reusing-evaluators).

Both GLWE backends use short borrows too. Standalone CBS can prepare resources with `context.bootstrap_resources_from_server_key(&server)`; the factory selects the required input KS. Use `CircuitBootstrapEvaluator::try_with_parameters` for an alternate output basis; MVB uses infallible `FactorizedEvaluator::new(&pbs)`, supporting classic and sparse keys. Common resources keep input KS for KS→BR; standalone BR→KS omits output KS. Fourier reuses the same FFT engine throughout. See [GLWE NTT resource reuse](../primus_tfhe_glwe_ntt/README.md#reusing-evaluators) and [GLWE Fourier resource reuse](../primus_tfhe_glwe_fourier/README.md#reusing-evaluators).

All backends prepare storage at construction; online `_to` operations never allocate implicitly. Boolean accepts PBS ownership through `try_new` and recovers it with `into_bootstrapper`.

## LUTs and resource lifetime

Backends accept named `TfheConfig` choices and derive shared ring parameters; `TfheContext::try_from_parameters` creates the selected transform table. This crate re-exports `DecompositionConfig` (radix and retained levels) from [`primus_decompose`](../primus_decompose/README.md). `GadgetEncryptionConfig { decomposition, noise_standard_deviation }` groups the independent choices for blind rotation or PBS key switching. `CircuitBootstrapConfig` contains three `DecompositionConfig` choices: `output`, `trace` and `scheme_switch`. Trace and scheme-switch rows inherit the accumulator encryption noise and share its immutable sampler state; their bases and random draws remain independent. Backends bind these choices to their own modulus, layout and representation. `Option<CircuitBootstrapConfig>` selects optional CBS during paired key generation; the server key owns its parameters and material, while each evaluator owns only its own workspace.

`GadgetEncryptionConfig<D = DecompositionConfig>` defaults to decomposition choices; the direct GLWE constructor instead accepts a prepared `ApproxSignedBasis<T>` as `D` and moves it without rebuilding it. Noise is in coefficient units at the key's modulus: common q for GLWE BR/KS, accumulator Q for NTRU BR and CBS trace/scheme switching, and external q for NTRU return KS. The config itself is unchecked; existing parameter constructors validate it. The noise in `TfheConfig::blind_rotation` also serves accumulator encryption and, for GLWE KS→BR, fresh external LWE encryption. KS noise remains independently configurable; CBS trace/scheme-switch rows inherit accumulator noise.

1. A family parameter set describes the external LWE and accumulator ring.
2. A backend context binds those parameters to an NTT/FFT table and generates paired client/server keys.
3. Compile `LookupTable` or `InterleavedLookupTable` through the family parameters. Create an evaluator once; its scratch is reused by online `_to` calls.
4. Allocate caller outputs once, then encrypt and evaluate into the same storage.

The front-half unary function or slice compiler programs `0..ceil(t_in/2)` with outputs in `0..t_out`, as selected by the output codec. Its remaining inputs are not independently programmed. Odd full-domain compilation is a separate entry point described below. For an interleaved LUT (ManyLUT), the effective output count `k` is positive and the padded output count is `s = next_power_of_two(k)`, with `ceil(t/2) <= N/s`. The callback receives `(input, output_index)` once per effective pair, in input-major order; slices contain `D*k` values in the same order. With `k=3`, three outputs occupy four slots: the compiler zeros the fourth slot without calling the callback, and the evaluator returns exactly three ciphertexts. All outputs share one blind rotation (BR). GLWE shares a ring key switch with separate extraction; NTRU returns and LWE-key-switches each output separately. More outputs reduce rotation resolution and the available input-noise margin. This is one input evaluated by multiple functions, not batching independent ciphertexts.

Create a reusable `LookupTableCompiler` with `parameters.lookup_table_compiler(&codecs)?` in either family. TFHE parameters contain key domains and sampling state without a message modulus; clients and programs choose their codecs independently. For direct shared-layer use, `LookupTableCompiler::try_new(poly_length, &input_codec, accumulator_modulus, &output_codec)` binds the same encoding environment. It copies only the needed encoding state, without allocation or a borrow of the parameters/context. Its methods are:

| Program | Function input | Slice input |
| --- | --- | --- |
| Front-half, one output | `compile_fn(function)` | `compile_slice(values)` |
| Front-half, multiple outputs | `compile_interleaved_fn(k, function)` | `compile_interleaved_slice(k, values)` |
| Odd full domain, one output | `compile_odd_full_domain_fn(function)` | `compile_odd_full_domain_slice(values)` |

Compiler construction checks the output codec's modulus; the GLWE factory also checks the input codec against the key modulus. Compilation checks each program's capacity and slice length before filling, preserving callback order and stopping at the first invalid output or colliding center.

All shared LUT constructors and `BooleanEvaluator::try_new` take `PolyLength`, re-exported from `primus_poly`. Pass the checked length from the ring parameters, or construct it once with `PolyLength::try_new(N)`. The type centrally checks the power-of-two range `32..=2^17`; compilation still checks rotation-domain representability in the coefficient word, encoding, output capacity and values.

Raw constructors `LookupTable::try_new` / `InterleavedLookupTable::try_new` accept an explicit prefix length `D` and encoded outputs. `input_ciphertext_modulus` describes input quantization; `coefficient_modulus` is the LUT/accumulator modulus, and raw outputs must be canonical under it. Neither `k` nor the plaintext modulus must be a power of two; padded count `s` must fit capacity, distinct centers and noise margins. Failed construction returns no partial table. See the [rotation geometry](IMPLEMENTATION.md#rotation-geometry) for output lanes, repeated intervals and rounding.

## Encoding and key contracts

| Interface | Input / output meaning |
| --- | --- |
| Ordinary `encrypt` | Unsigned message in `0..t` |
| `encrypt_padded` | Same unsigned scale, restricted to `0..ceil(t/2)` for front-half LUT input |
| `encrypt_centered` | Modular representative in `0..t`; upper-half values represent negatives, e.g. `3` means `-1` for `t=4` |
| Boolean (both families) | External `false/true` is `0/1` modulo 4; internal LUTs use signed values at the rounded modulus-8 scale, followed by a restoring shift |
| CBS | Ordinary unsigned LWE input becomes GGSW/NGSW at the selected gadget scales, under the accumulator secret; a `0/1` input yields a CMUX control |

Client `decrypt` uses its bound codec and returns a canonical representative in `0..t`. Centered encryption is not a replacement for the unsigned input contract of ordinary LUTs. PBS preserves the LUT's output scale; it does not automatically convert Boolean or gadget outputs to ordinary messages.

Raw `LweCiphertext` does not track its secret, encoding or noise. Callers must use paired keys, canonical explicit-modulus coefficients and an adequate noise margin. LUT and dimension checks happen before output writes; they cannot verify secret identity. Fourier keys and evaluators must use the same FFT table instance.

The minimal traits are `ProgrammableBootstrap` and `ProgrammableBootstrapInterleaved`. Ordinary applications use the compiler returned by the parameters, which validates and encodes plaintext outputs. `LookupTable::try_new` and `InterleavedLookupTable::try_new` accept already encoded outputs and an explicit programmed prefix length; Boolean and CBS paths use these constructors for their distinct output scales. Compatibility checks bind polynomial length and encoding moduli; callers remain responsible for keeping the input within the table's programmed prefix. `rotation::RotationModulusSwitch` prepares the coefficient modulus switching shared by LUT compilation and blind rotation, including the rotation-step alignment used by ManyLUT and CBS.

### Choosing the output encoding

Describe message domains once with `PbsMessageConfig::new(t_in)`. It defaults to `t_out=t_in`; `.with_output_modulus(t_out)` explicitly changes the output domain without changing input encoding or keys. All ManyLUT lanes and MVB outputs share this output modulus. Odd plaintext moduli remain supported where the operation permits them.

Prepare the codecs from either family's parameters; all four backends re-export the configuration:

| Factory | `input_codec()` at q | `lut_output_codec()` at Q | `output_codec()` at q |
| --- | --- | --- | --- |
| `parameters.pbs_codecs(messages)?` | Rounded | Rounded | Rounded |
| `parameters.factorized_pbs_codecs(messages)?` | Rounded | Scaled | Scaled |

For example, ordinary PBS or ManyLUT with `t_in=16` and `t_out=4`:

```rust,ignore
use primus_tfhe::PbsMessageConfig;

let codecs = context.parameters().pbs_codecs(
    PbsMessageConfig::new(16).with_output_modulus(4),
)?;
let encryptor = context.encryptor(external_secret, codecs.input_codec())?;
let decryptor = context.decryptor(external_secret, codecs.output_codec())?;
let compiler = context.parameters().lookup_table_compiler(&codecs)?;
let lut = compiler.compile_fn(|x| (x % 4) as u64)?;
let input = encryptor.encrypt_padded(7, &mut rng)?;
let output = evaluator.apply_lookup_table(input.as_view(), &lut);
assert_eq!(decryptor.decrypt(output.as_view())?, 3);
```

Omit `.with_output_modulus(4)` for equal message moduli. Preparation validates the selected input/output codecs, allocates nothing, and retains no key or context borrow. The output choice is applied before codec validation, so an invalid default is not silently substituted. Program geometry, factorization-specific scale conditions and noise budgets are still checked or required by the chosen operation.

GLWE uses a common ciphertext modulus for all three roles. NTRU derives both output codecs from the same `t_out`, with Q for LUT coefficients and q for returned ciphertexts. The return path rescales an existing phase; it does not recreate the exact q-encoding center. Budget Q→q rounding and key-switch noise. Preparing a Scaled codec at q additionally checks that codec's own scale-recovery condition.

For MVB, use `factorized_pbs_codecs` and pass `&codecs` directly to `context.compile_factorized_lookup_table_fn`. Bind `context.decryptor(external_secret, codecs.output_codec())?`, then call `decryptor.decrypt(output.as_view())?`, just as for ordinary PBS or ManyLUT. Factorized outputs keep Scaled encoding even when `t_out=t_in`.

The decryptor copies the codec’s prepared `MessageDecoder` and borrows only the secret. Rounded and Scaled codecs share q→t decoding, while retaining their distinct encoding centers and recovery bounds. Input encryption and output decryption may use different message moduli. Keep `decrypt_phase` for noise diagnostics or advanced composition; it does not decode a message.

Explicit `RoundedCodec`/`ScaledCodec` construction and raw LUT constructors remain available for advanced composition. `LookupTableCompiler::try_new` accepts explicitly paired input and LUT-output codecs without first preparing a default output. `try_with_output_codec` changes only the compiler's output codec, checks its ciphertext modulus, and leaves input geometry unchanged. Callers using these explicit interfaces must retain the corresponding output decoder themselves. Odd full-domain methods and raw Boolean/CBS output scales keep their existing contracts.

A returned value belongs to `0..t_out`; front-half input accepts only `0..ceil(t_in/2)`. Equal message moduli alone do not make an output suitable for another PBS: its encoding, domain and noise margin must also match that next program.

## Odd full-domain PBS

Use `compiler.compile_odd_full_domain_fn(function)` or its `_slice` form; select a different output message modulus with `PbsMessageConfig::with_output_modulus` before preparing codecs when needed. These methods program **all of `0..t_in`**, with odd `t_in >= 3` and `t_in <= N`. Slices contain exactly `t_in` outputs in input order. Encrypt with ordinary `encrypt`, then use the existing `apply_lookup_table_to`. Bind the output codec to the decryptor and call `decrypt`, for either default or explicit output encoding. For example, with a common input/accumulator modulus, `t_in=15` and an output codec for `t_out=8`:

```rust,ignore
let codecs = context.parameters().pbs_codecs(
    primus_tfhe::PbsMessageConfig::new(15).with_output_modulus(8),
)?;
let encryptor = context.encryptor(external_secret, codecs.input_codec())?;
let compiler = context.parameters().lookup_table_compiler(&codecs)?;
let lut = compiler.compile_odd_full_domain_fn(|x| ((x * x + 3) % 8) as u32).unwrap();
let input = encryptor.encrypt(14u32, &mut rng).unwrap();
evaluator.apply_lookup_table_to(input.as_view(), &lut, output.as_mut_view());
let decryptor = context.decryptor(external_secret, codecs.output_codec())?;
let message = decryptor.decrypt(output.as_view())?;
assert_eq!(message, 7);
```

Raw encoded outputs use `LookupTable::try_new_odd_full_domain`. The compiler folds negacyclic rotation centers and restores output signs; colliding folded centers return `RotationCenterCollision`. Callback order and interval details are specified in rustdoc.

Typical spacing is `N/t_in`, so the noise margin is about half that of front-half compilation. Capacity and collision checks establish LUT geometry, not a PBS failure probability. Account for input error and per-coefficient modulus switching. This entry supports single-output odd domains; interleaved and bivariate compilers retain their front-half contracts. No extra key or online evaluator is needed. The [rotation geometry notes](IMPLEMENTATION.md#rotation-geometry) explain the signed folding and its limits.

## Bounded two-input PBS

`BivariateLookupTable::try_new(B, R, poly_length, input_codec, output_codec, function)` compiles `f(x,y)` for `0 <= x < B`, `0 <= y < R` using `z = x + B*y`. `B` and `R` must be positive and `D = B*R <= ceil(t_in/2)`; the ordinary LUT capacity and rotation-center checks also apply. Only the prefix `0..D` is compiled, with `x` varying fastest. `B` need not be a power of two. The output codec selects `t_out` independently but must use the same ciphertext modulus. The type owns no keys or scratch.

Allocate `packed` and `output` once with the external LWE dimension. `pack_to` writes `lhs + B*rhs` in one modular multiply-add pass, without allocation; it rejects unequal lengths or missing bodies before writing. Inputs must share an actual secret, ciphertext modulus and the supplied unsigned input codec, with canonical coefficients and messages inside the stated bounds. These semantic conditions cannot be checked from raw ciphertexts. GLWE uses its order-dependent external dimension and an explicitly chosen input codec; no extra key material is needed.

Packing amplifies the second input's noise by B and can add an encoding-rounding discrepancy when `t_in` does not divide q. Budget both before PBS; the capacity check alone does not prove sufficient noise margin. See `BivariateLookupTable` rustdoc for the bound. This is a bounded single-output workflow, not general integer arithmetic or LWE-to-ring packing.

The current constructor has one ciphertext modulus shared by both codecs. It supports GLWE and NTRU configurations with q=Q; NTRU bivariate lookup with q≠Q is unsupported. Ordinary NTRU LUT support for Q→q does not remove this restriction.

## Fixed-scale factorized MVB

`FactorizedLookupTable::try_new(D, poly_length, output_count, input_codec, output_codec, function)` compiles a nonempty front-half prefix using Rounded input and unsigned Scaled output. The coefficient modulus may be explicit and odd, or Native with an even Scaled output scale. Explicit even moduli are unsupported. The callback receives `(input, output_index)` once per pair, with **output index outermost**. Signed integer factor norms determine noise amplification; the algebra is documented on `FactorizedLookupTable` and in the [MVB design](IMPLEMENTATION.md#factorized-mvb).

All outputs share one BR at step one and then apply separate public polynomial products. Positive output count is unpadded and does not reduce input capacity; each output instead amplifies BR error by its factor. Input geometry alone is not a sufficient noise budget. The Scaled codec must be retained for phase decoding; chaining into Rounded-input PBS must account for differing centers.

Both [GLWE NTT](../primus_tfhe_glwe_ntt/README.md#fixed-scale-factorized-mvb) and [NTRU NTT](../primus_tfhe_ntru_ntt/README.md#fixed-scale-factorized-mvb) support this program. GLWE NTT supports classic/sparse keys and both orders; NTRU NTT supports classic binary/ternary and sparse binary keys, sharing its public lift and BR before returning each product. [GLWE Fourier](../primus_tfhe_glwe_fourier/README.md#fixed-scale-factorized-mvb) supports classic binary/ternary and sparse binary keys in both orders with u32/u64 and an even Native scale; it transforms factors as signed integers and also requires an FFT error budget. [NTRU Fourier](../primus_tfhe_ntru_fourier/README.md#fixed-scale-factorized-mvb) supports the same widths and Native scales with classic binary/ternary and sparse binary keys; its factors amplify both encrypted initialization and BR noise before per-output key switching. `t_out` need not be a power of two: check the actual scale. Each prepared program borrows one context and its separate evaluator reuses scratch. Odd full-domain MVB and CBS outputs remain outside this implementation. Algebra and noise conditions are detailed in the [MVB design](IMPLEMENTATION.md#factorized-mvb).

The [GLWE](../primus_tfhe_glwe_ntt/examples/mvb_thresholds.rs) and [NTRU](../primus_tfhe_ntru_ntt/examples/ntru_ntt_mvb_thresholds.rs) threshold examples turn one encrypted score into 17 flags beyond interleaved capacity. Prefer ManyLUT when capacity and rotation margins suffice; consider MVB for more outputs with small integer factor norms, and measure complete costs on the actual backend and parameters.

## Further reading

[Implementation notes](IMPLEMENTATION.md) · [Common PBS benchmark parameters](../../benchmarks/tfhe/BENCHMARKS.md) · [Performance decisions](IMPLEMENTATION.md#performance-decisions-and-reproducibility)
