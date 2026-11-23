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

## GLWE 求值

- `CudaExternalProductWorkspace32` 和 `CudaExternalProductWorkspace64` 绑定 gadget 尺寸、有符号分解基和批容量。`external_product_to` 为各 lane 接收一个 NTT GGSW 和一个系数域 GLWE，写出系数域 GLWE，并复用设备工作区。
- `CudaBlockBlindRotationWorkspace32` 和 `CudaBlockBlindRotationWorkspace64` 将系数域 Block key 上传一次。`blind_rotate_lookup_table_to` 对批量 LWE 求值同一张普通 LUT，输入按 mask、body 顺序排列，模数为二次幂。设备量化输入，按各条 LWE 的负 body 指数旋转 LUT，并依次应用全部 key block。每条 LWE 使用独立 accumulator，共享只读 key 和 LUT。已有 accumulator 和量化块指数时，可以用 `apply_block_to` 单独更新一块。
- `CudaGlweKeySwitchingWorkspace32` 和 `CudaGlweKeySwitchingWorkspace64` 为一批系数域 GLWE 复用同一份常驻 NTT 密钥。`CudaReverseTraceWorkspace64` 依照 CPU 密钥的顺序执行 reverse trace，在每层自同构和 key switch 前在域内乘以 `inv2`。
- `CudaOmrBridge32` 对每组四个 rank-one GLWE 求和，在 key switch 后紧凑提取活跃 LWE 前缀，并把系数模切到 BR2 使用的 `q=4096` u64 表示。

## Packed LWE 提取

`CudaPackedLweExtraction32` 将一份共享 mask 和四个 body 按 clue、body 顺序展开为四条普通 LWE。支持二次幂 LWE 模数，以及等宽 ExactlyOne 块的可选 body 居中。输出布局可以直接交给 u32 盲旋转工作区。

## Digest 累加

`CudaDigestPacking64::pack_to` 将紧凑 F257 索引系数、载荷数字和行权重展开为中心提升后的系数域公开多项式。载荷行可以跨越物理多项式。仅最后一个物理多项式含补零位置。

`CudaDigestAccumulation64::accumulate_assign` 原地变换系数域 flag 和已打包的公开多项式，将完整乘积加到由调用方初始化的设备 NTT sums。批内每条 flag 对每个物理密文有一个对应的公开多项式。跨批次复用 sums，在需要系数形式时用 plan 逆变换一次。
