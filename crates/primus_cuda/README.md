# primus_cuda

[简体中文](README.zh_CN.md)

`primus_cuda` provides CUDA plans for exact `u32` and `u64` pointwise modular arithmetic, negacyclic NTT, and multiplication by a negacyclic monomial. Create a `CudaNttPlan32` or `CudaNttPlan64` with a `cudarc` stream and the corresponding CPU NTT table. The plan uploads that table's roots once and reuses its device buffers across batches.

## Build and test

Enable the `cuda` feature to build the kernels. The build uses `nvcc` on `PATH` or at `PRIMUS_CUDA_NVCC`. `PRIMUS_CUDA_ARCH` sets the virtual architecture for the embedded PTX and defaults to `compute_80`. The NVIDIA driver must support the target architecture and the PTX version produced by the toolkit. The device tests were verified with `compute_120`, CUDA Toolkit 13.2, and an RTX 5080 Laptop GPU.

```sh
cargo run -p primus_cuda --features cuda --example cuda_smoke
cargo test -p primus_cuda --features cuda --tests
```

The CUDA Toolkit and driver are optional for CPU workspace builds. See the [smoke example](examples/cuda_smoke.rs) and [device tests](tests/device.rs) for transfer, plan setup, and arithmetic calls.

## Device data

- Each transform view contains contiguous, complete polynomials of a fixed power-of-two length from 32 through 2048. Forward NTT maps ascending coefficient order to bit-reversed evaluation order. Inverse NTT includes normalization by `N^-1`.
- All arithmetic takes canonical residues. `mul_assign` and `add_mul_assign` use equal-length views for pointwise multiplication and multiply-accumulation in either representation.
- `mul_monomial_to` multiplies each coefficient-domain polynomial in a batch by the same `X^degree` modulo `X^N + 1`. It reduces the exponent modulo `2N` and writes a separate output view.
- Allocate device buffers on the plan's stream using `plan.stream()`. Create the stream with `new_stream()` or `default_stream()`. Arithmetic submits to that stream and leaves the results in device memory. Synchronize the stream to check completion, or copy to pageable host memory and check `CudaContext::check_err()` for deferred copy errors.

## GLWE evaluation

- `CudaExternalProductWorkspace32` and `CudaExternalProductWorkspace64` bind a gadget size, signed basis and batch capacity. `external_product_to` consumes one NTT GGSW and one coefficient-domain GLWE per lane. It writes a coefficient-domain GLWE to each output lane and reuses device scratch.
- `CudaBlockBlindRotationWorkspace32` and `CudaBlockBlindRotationWorkspace64` upload a coefficient-domain Block key once. `blind_rotate_lookup_table_to` evaluates an ordinary LUT for a batch of mask-then-body LWEs with a power-of-two input modulus. It quantizes the input, rotates the LUT by each negative body exponent, and applies all the key blocks in order. Each lane has its own accumulator and shares the read-only key and LUT. `apply_block_to` is available for cases with already initialized accumulators and quantized block exponents.
- `CudaGlweKeySwitchingWorkspace32` and `CudaGlweKeySwitchingWorkspace64` use one resident NTT key for a batch of coefficient-domain GLWEs. `CudaReverseTraceWorkspace64` applies the CPU key's ordered reverse trace, halving coefficients in the field before each automorphism and key switch.
- `CudaOmrBridge32` sums groups of four rank-one GLWEs, extracts the active LWE mask prefix after key switching, and switches compact coefficients to the `q=4096` u64 BR2 representation.

## Packed LWE extraction

`CudaPackedLweExtraction32` expands records with one shared mask and four bodies into four ordinary LWEs in clue and body order. It supports binary LWE moduli and optional body centering for equal ExactlyOne blocks. Its output layout goes directly into the u32 blind-rotation workspace.

## Digest accumulation

`CudaDigestPacking64::pack_to` expands compact F257 index coefficients, payload digits and row weights into centered coefficient-domain public polynomials. Rows can span physical polynomials. Only the final physical polynomial has padding.

`CudaDigestAccumulation64::accumulate_assign` transforms coefficient-domain flags and already packed public polynomials in place, then adds their full products to caller-initialized device NTT sums. A batch contains one public polynomial per physical ciphertext for each flag. Reuse the sums across batches and apply the plan's inverse transform once when coefficient form is needed.
