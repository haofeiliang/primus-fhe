# primus_ntru 验证与基准

[English](README.md) | 简体中文

> [!WARNING]
> [Primus FHE](../../../README.zh_CN.md) 是实验性项目；其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

## 测试与基准

```sh
cargo test -p primus_ntru --features rustfft,tfhe-fft
cargo clippy -p primus_ntru --all-targets --features rustfft,tfhe-fft -- -D warnings
cargo +nightly test -p primus_ntru --features simd,rustfft,tfhe-fft
cargo bench -p primus_ntru --bench encryption --features rustfft,tfhe-fft
cargo bench -p primus_ntru --bench lwe_return
cargo bench -p primus_ntru --bench primitives --features rustfft,tfhe-fft -- 'ntt/n4096/logb3'
cargo bench -p primus_ntru --bench constant_gadget --features rustfft
cargo bench -p primus_ntru --bench ternary_cmux --features rustfft,tfhe-fft
```

`encryption` 测量普通加密和未解码相位提取。`primitives` 测量 key switching、 自同构、trace/reverse trace、三个系数投影、八系数前缀展开及 scheme switching （输出 B=2^8、L=3），覆盖 `N = 1024/4096/8192`、`B = 2^3/2^10` 和分解基支持的最大层数。两者使用 `u64`、稀疏三元私钥及 sigma 3.2；NTT 使用 `q = 1_125_899_906_826_241`，Fourier 覆盖两个 FFT 后端。`constant_gadget` 保留常数 NLev 和八控制位 NGSW 生成基准。 设置、table、密钥生成及分配位于计时 closure 外。附加 `-- --test` 可执行 fixture 冒烟检查；该检查不测量性能，也不能证明可解密性。

`lwe_return` 单独测量同一 NTRU 多项式多个系数的 Q→q、提取和 LWE key switch，对比逐项返回与共享转换后的分块返回。使用 N1024/n728、q=2^24、logB=3，覆盖 u32/u64 的 NTT 显式源模数和 native 源模数；k=1、3、17 分别检查单输出、ManyLUT 常见批次和跨块尾部。输入为固定 seed 的规范系数，密钥及工作区只为选中的 ID 在计时外准备。

`ternary_cmux` 使用真实加密控制，在 `N=1024` 下比较融合旋转和两次 binary CMUX， 覆盖 NTT 与两种 FFT 的 u32/u64 并复用工作区；Fourier 在计时外用独立系数卷积报告相位误差。

NTT 标量产品复用已有 CPU dispatch 与依赖的可选 SIMD 支持，NTRU 公开 API 不新增 ISA 选择参数。仅比较匹配工作负载的耗时；这些后端参数并不具有相同的安全强度。
