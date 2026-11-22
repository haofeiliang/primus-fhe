# primus_cuda

[English](README.md)

`primus_cuda` 提供精确的 `u32`、`u64` CUDA 逐点模运算、负循环 NTT 和负循环单项式乘法。用 `cudarc` stream 和对应的 CPU NTT 表创建 `CudaNttPlan32` 或 `CudaNttPlan64`。plan 将表中的根上传一次，并在各批次间复用设备缓冲区。

## 构建与测试

启用 `cuda` feature 构建内核。构建会从 `PATH` 或 `PRIMUS_CUDA_NVCC` 查找 `nvcc`。`PRIMUS_CUDA_ARCH` 指定嵌入 PTX 的虚拟架构，默认 `compute_80`。NVIDIA 驱动须支持目标架构和工具链生成的 PTX 版本。设备测试已在 RTX 5080 Laptop GPU 上使用 CUDA Toolkit 13.2 和 `compute_120` 验证。

```sh
cargo run -p primus_cuda --features cuda --example cuda_smoke
cargo test -p primus_cuda --features cuda --tests
```

CPU workspace 构建可在没有 CUDA Toolkit 和驱动的环境中运行。[smoke 示例](examples/cuda_smoke.rs)和[设备测试](tests/device.rs)展示传输、plan 初始化与算子调用。

## 设备数据

- 每个变换视图包含连续、完整的多项式，固定长度为 32 到 2048 的二次幂。正向 NTT 将升幂系数序变换为 bit-reversed 求值序。逆向 NTT 包含乘以 `N^-1` 的归一化。
- 算术使用规范残基。`mul_assign` 和 `add_mul_assign` 分别对等长视图做逐点模乘和模乘累加，可用于两种表示。
- `mul_monomial_to` 将批次中每个系数域多项式乘以同一个 `X^degree`，按 `X^N + 1` 约简。指数按 `2N` 取模，结果写入独立的输出视图。
- 使用 `plan.stream()` 分配设备缓冲区。可用 `new_stream()` 或 `default_stream()` 创建 plan 的 stream。算术提交到该 stream，结果留在设备显存。同步 stream 可检查执行是否完成。复制到 pageable host memory 后，用 `CudaContext::check_err()` 检查延迟报告的复制错误。
