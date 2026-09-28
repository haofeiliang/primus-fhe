# primus_decompose 验证与基准

[English](README.md) | 简体中文

> [!WARNING]
> [Primus FHE](../../../README.zh_CN.md) 是实验性项目；其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

## 测量范围

```text
cargo test -p primus_decompose
cargo bench -p primus_decompose --bench decompose
cargo +nightly test -p primus_decompose --features simd
```

基准分别测量 basis 构造和在线分解。通用 primitive 与 BigUint 批量案例每次处理 4096 个系数，包含初始化与所有保留层。Primitive 覆盖 scalar 以及零复制/adjusted 批量路径；BigUint 覆盖紧凑输出的固定步长与通用 fallback，并保留一组相同参数的全宽输出对照。

`decompose/pbs/` 组保留代表性的 external-product 分解配置；当前完整 TFHE 工作负载另见 [TFHE 基准](../../primus_tfhe/BENCHMARKS.md)，覆盖 GLWE/NTRU × NTT/Fourier、u32/u64、N=1024/2048。`init` 测初始化，`levels` 在计时外克隆初始 carry 后测所有保留层，`full` 测两者合计。每次迭代分解一个多项式，不是整个 external product 或 PBS。固定输入在计时前与标量初始化、每层标量 digit/carry 核对。分阶段耗时用于诊断，其和不等同于实测 `full`。

Criterion 使用 20 个样本、预热 1 秒、测量 5 秒。SIMD 基准命令放在 bench 源文件中。Workspace 已通过 [`.cargo/config.toml`](../../../.cargo/config.toml) 设置 `target-cpu=native`。
