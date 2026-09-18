# primus_tfhe_ntru_fourier

[English](README.md) | 简体中文

基于 NTRU 的 TFHE Fourier 后端。使用原生 wrapping 模数。所有变换域密钥、值与 evaluator 必须使用同一 FFT table
实例；仅长度相同不能证明 table 身份一致。
API 和参数仍处于实验阶段；示例和基准是功能工作负载，不是安全参数建议。

完整能力与编码约定见[公共指南](../primus_tfhe/README.zh_CN.md)，参数和秘密域见
[NTRU family](../primus_tfhe_ntru/README.zh_CN.md)。两路 NTRU 后端均支持 PBS、ManyLUT 和 CBS，
NTRU Boolean 适配器尚未实现。

## 普通 PBS 与 ManyLUT

先用 `TfheParameters::try_from_config(TfheConfig { .. })` 声明数学参数，再调用
`TfheContext::<_, RustFftTable>::try_from_parameters(parameters)` 自动创建匹配的变换表。
表类型仍由调用方选择，建表失败返回底层 FFT 错误；已有表可用 `try_new(parameters, table)` 显式注入。

`TfheContext` 绑定参数和变换 table。通过 `context.try_generate_keys` 生成配套密钥，
建立 encryptor、evaluator、decryptor，再通过 `context.parameters()` 编译 LUT。[message/carry 示例](examples/ntru_fourier_basic.rs)
展示多个输出共享一次 BR 和一次环密钥切换。普通 PBS 返回 client secret 下的 LWE；
BR 后的 NTRU 密钥切换将 f_acc 转为 f_client。

```sh
cargo run -p primus_tfhe_ntru_fourier --example ntru_fourier_basic
```

示例从一个输入计算 message、carry 和 parity（`x % 4`、`x / 4`、`x % 2`），
三个输出占用四个交错槽，不代表完整的加密整数系统。

LUT 编译的第一个参数为输出 `RoundedCodec`。示例采用 `t_in=16 → t_out=4`，
通过 `decrypt_phase` 与该 codec 解码；输入几何仍遵循参数编码。

输入域、输出 codec、奇数全域 PBS 和 ManyLUT 噪声余量见
[共享编码指南](../primus_tfhe/README.zh_CN.md#选择输出编码)与
[NTRU 客户端/LUT 契约](../primus_tfhe_ntru/README.zh_CN.md#客户端与-lut)。

## 公钥客户端

`client_key.try_generate_public_key(context.parameters(), &mut rng)` 生成外部
二进制前缀秘密下的 `LwePublicKey`；将其传入 `context.encryptor(&public_key)`
即可使用 `encrypt`、`encrypt_padded`、`encrypt_centered`。
三种加密均提供 `_to(message, output, rng)`，公钥和私钥客户端都可无分配地复用
密文存储。消息或维数错误不会改变输出及 RNG。

公钥噪声、存储和密钥身份要求集中于
[NTRU 客户端契约](../primus_tfhe_ntru/README.zh_CN.md#客户端与-lut)。

## 可选 circuit bootstrapping

使用 `CircuitBootstrapParameters::try_from_config(tfhe, config)`，通过
`CircuitBootstrapConfig` 独立选择 output/trace/scheme-switch 分解和 trace/SS 噪声；
长度、模数与 accumulator 秘密分布自动派生。`try_new` 仍可绑定已有 basis/NLev 参数。

`CircuitBootstrapParameters`、`CircuitBootstrapKey` 和 `CircuitBootstrapEvaluator`
提供可选 CBS 材料。使用 `context.try_generate_circuit_bootstrap_key` 和
`context.circuit_bootstrap_evaluator`；普通 server key 独立于这些材料。
Fourier CBS 输出 `FourierNgswCiphertext`，需预算原生系数除二和 FFT 误差，并始终使用
同一 FFT table 实例。
Gadget 尺度、accumulator 密钥身份及独立噪声/安全预算见
[共享 CBS 契约](../primus_tfhe_ntru/README.zh_CN.md#cbs-与示例)。

运行 [CBS → CMUX 示例](examples/ntru_fourier_circuit_bootstrap.rs)：

```sh
cargo run -p primus_tfhe_ntru_fourier --example ntru_fourier_circuit_bootstrap
```

示例创建配套的普通/CBS key，在 `f_acc` 下加密两个 NTRU 候选密文，再将外部 LWE bit
重复转换为 gadget 尺度的 NGSW 控制。CMUX 在输入 0 时选第一个候选，输入 1 时选第二个。
输入、control、选择结果和服务端 scratch 均复用，最后通过解密检查结果。

## 验证与性能

```sh
cargo test -p primus_tfhe_ntru_fourier
cargo clippy -p primus_tfhe_ntru_fourier --all-targets -- -D warnings
cargo +nightly test -p primus_tfhe_ntru_fourier --features simd
cargo bench -p primus_tfhe_ntru_fourier --bench pbs
cargo bench -p primus_tfhe_ntru_fourier --bench circuit_bootstrap
```

`pbs` 复用输出，测量完整 PBS，并比较 3/4 输出 ManyLUT 与独立 PBS 调用。
Fourier 用例同时覆盖 RustFFT 和 TfheFFT。

CBS 测试覆盖 LWE bit 到 NGSW、再消费为 CMUX 控制的完整路径、非二次幂层数、basis
和容量错误，以及 evaluator 从首次调用起零在线分配。`circuit_bootstrap` 复用输出
和工作区，覆盖 N=1024/4096、输入维数 N/16、BR/trace/SS 的 B=2^3/2^10，以及
B=2^8、两层的输出。基准报告新增 CBS key 和 evaluator 实际请求且仍持有的堆字节数，
不包括分配器开销、借用 table、普通 server key 和调用方输出。密钥生成和内存统计
位于计时 closure 外。附加 `-- --test` 可检查 fixture，但不能得出耗时或可解密性结论。
SIMD 复用现有依赖内核，不增加公开 ISA 选择接口。
