# primus_glwe 验证与基准

[English](README.md) | 简体中文

> [!WARNING]
> [Primus FHE](../../../README.zh_CN.md) 是实验性项目；其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

## 源码与测试

[私钥](../src/secret_key)、[公钥](../src/public_key)、[key switching](../src/key_switch)、[自同构](../src/automorphism)、[trace/packing](../src/trace)、[packing key switching](../src/packing_key_switch) 和 [scheme switching](../src/scheme_switch) 中维护公开契约与实现细节。

测试按操作分组：普通密钥工作流、gadget phase 与 external product、常数批次等价性、CMUX、key switching、自同构、scheme switching，以及 trace/展开/packing。`tests/common` 保存求值测试共用的小规模朴素 phase oracle。边界拒绝和容量擦除使用独立测试文件。Fourier 常数批次、自同构、trace、packing key switching 和 scheme switching 测试覆盖 RustFFT 和 tfhe-fft。

```sh
cargo test -p primus_glwe
cargo clippy -p primus_glwe --all-targets -- -D warnings
cargo +nightly test -p primus_glwe --features simd
```

## 基准

```sh
cargo bench -p primus_glwe --bench encryption
cargo bench -p primus_glwe --bench primitives
cargo bench -p primus_glwe --bench key_conversion
# 执行全部 case，不收集计时样本：
cargo bench -p primus_glwe -- --test
```

所有基准均使用 `(k, N) = (1, 1024)` 和 `(2, 4096)`。每次迭代执行一次操作，复用输出和工作区；密钥、变换表构造与分配在计时外。参数和固定 seed 记录在基准源码中。这些工作负载用于跟踪回归，不用于比较相同安全级别，也不作为安全参数建议。

| 基准 | 测量内容 |
| --- | --- |
| [encryption](encryption.rs) | 私钥/公钥加密、私钥解密（含 NTT 系数域路径）、GLev/GGSW 生成及 8 个常数 GGSW 的批量加密；包含采样、编解码及必要变换 |
| [primitives](primitives.rs) | 普通/反向 trace；8 和 `N/8` 项的投影与部分展开；完整展开；1、8、`N` 条 LWE packing；两种 FFT 后端的直接 Fourier 自同构 |
| [key_conversion](key_conversion.rs) | 独立私钥下 1、8、`N` 条 LWE packing（输入维数 512；单条用例覆盖基数 `2^3` 和 `2^10`）；NTT/Fourier GLev-to-GGSW scheme switching |

普通和反向 trace 分别按各自 API 的明文尺度测量。投影与部分展开使用同一份明文高位为零的密文，throughput 按输出消息数量计算。编解码变体在 `primus_encoding` 中单独测量。
