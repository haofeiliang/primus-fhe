# primus_fft

English | [简体中文](README.zh_CN.md)

`primus_fft` provides negacyclic Fourier transforms for polynomials in `Z[X] / (X^N + 1)`. It exposes a common table-and-workspace API over RustFFT and `tfhe-fft`, together with the torus conversions used by the Fourier FHE paths in [Primus FHE](../../README.md).

> [!WARNING]
> This crate is part of the experimental Primus FHE workspace. Its API, Fourier representation, and numerical contracts are unstable and may change incompatibly at any time.

## Core types

| Type | Role |
| --- | --- |
| `FftTable` | Backend-independent negacyclic transform contract for one polynomial length |
| `RustFftTable` | `FftTable` implementation backed by RustFFT |
| `TfheFftTable` | `FftTable` implementation backed by the unordered `tfhe-fft` plan |
| `FftEngine<'a, Table>` | A reference to one immutable table plus one reusable mutable workspace |
| `TorusFftValue` | Conversion between unsigned `u16`, `u32`, or `u64` torus bit patterns and `f64` |

For `N = 2^log_n`, each table transforms `N` coefficients into `N / 2` complex values. The table owns the backend plan and twist factors; the engine owns the temporary memory used by each transform.

## Example

```rust
use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable};

let table = RustFftTable::new(3).unwrap(); // N = 8
let mut fft = FftEngine::new(&table);
let input: Vec<u32> = (0..fft.poly_length()).map(|value| value as u32).collect();
let mut fourier = vec![Complex64::default(); fft.fourier_length()];
let mut output = vec![0u32; fft.poly_length()];

fft.forward_as_torus(&input, &mut fourier);
fft.backward_as_torus(&fourier, &mut output);

assert_eq!(output, input);
```

## Transform variants

- `forward_as_torus` reinterprets each unsigned word as its signed bit pattern, then scales it by `2^-BITS`. For example, `u32::MAX` represents `-1 / 2^32`.
- `forward_as_integer` performs the same signed-bit-pattern interpretation without torus scaling. It is intended for small integer polynomials such as secret keys and decomposition digits.
- `forward_integer_f64` accepts integer-valued `f64` coefficients without an additional representation conversion.
- `backward_as_torus` applies the inverse transform, torus scaling, rounding, and wrapping conversion back to the selected unsigned word type.

A negacyclic convolution uses `forward_as_torus` for a torus polynomial, `forward_as_integer` for an integer polynomial, point-wise complex multiplication, and then `backward_as_torus`.

## Table and workspace contract

Construct one table in the context that owns a Fourier representation and reuse it. Fourier values and scratch memory are bound to that exact table instance. Do not mix values or scratch from independently constructed tables, even when the backend and polynomial length are the same: backend ordering, planning, and workspace compatibility are private properties of the table and are not part of a cross-table compatibility guarantee.

Tables are immutable and implement `Send + Sync`, so a table may be shared across threads. Each concurrent worker must create its own `FftEngine` (or its own scratch through `new_scratch`); mutable workspace is never shared between transform calls.

The built-in tables use cache-line-aligned storage for their twist factors and transform workspace. Caller-owned inputs and outputs still accept ordinary slices, including subslices; no additional alignment is required.

The built-in scratch types securely erase their full buffers on drop. After processing secret data, `fft.zeroize_scratch()` erases the workspace while keeping it reusable. Ordinary transforms do not erase scratch on every call. Caller-owned inputs and outputs have their own lifetimes; this heap-buffer guarantee does not cover registers or compiler-created stack copies. Custom backends define their own scratch erasure behavior.

Input and output lengths are exact:

- coefficient slices contain `poly_length()` values;
- Fourier slices contain `fourier_length() == poly_length() / 2` values;
- scratch passed directly to `FftTable` methods must have been allocated by that table instance.

Incorrect lengths or incompatible workspace cause a panic.

`FftTable::automorphism_map(degree)` allocates the Fourier map for `X -> X^degree`, where `degree` is odd and in `[1, 2N)`. Entry `j` gives `(source, conjugate)` for output `j`.

Build and cache the map during evaluation-key construction, and reuse the originating table instance. Custom `FftTable` implementations must provide the map for their own storage order. Applying the map alone does not perform cryptographic key switching.

## Length and precision

`FftTable::new(log_n)` accepts `2 <= log_n <= usize::BITS - 1`, so the minimum supported polynomial length is four. Table construction performs backend planning and allocation; it should stay outside repeated transform paths.

The transform uses `f64` and is approximate. Whether a Fourier computation can be rounded back to the intended torus value depends on the accumulated floating-point error and the magnitude of the integer operands; higher-level algorithms are responsible for maintaining a suitable precision budget.

## Testing and benchmarks

```text
cargo test -p primus_fft
cargo bench -p primus_fft --bench fft
```

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) or the [MIT License](../../LICENSE-MIT), at your option.
