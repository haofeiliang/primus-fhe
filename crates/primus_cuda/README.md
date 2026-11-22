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
