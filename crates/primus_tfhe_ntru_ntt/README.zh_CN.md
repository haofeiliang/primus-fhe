# primus_tfhe_ntru_ntt

[English](README.md) | 简体中文

基于 NTRU 的 TFHE NTT 后端。使用显式域模数和 context 的 NTT 表示。
API 和参数仍处于实验阶段；示例和基准是功能工作负载，不是安全参数建议。

完整能力与编码约定见[公共指南](../primus_tfhe/README.zh_CN.md)，参数和秘密域见
[NTRU family](../primus_tfhe_ntru/README.zh_CN.md)。两路 NTRU 后端均支持 PBS、ManyLUT 和 CBS，
NTRU Boolean 适配器尚未实现。

## 普通 PBS 与 ManyLUT

`TfheContext` 绑定参数和变换 table。生成 client/server key，建立 encryptor、
evaluator、decryptor，再通过 context 编译 LUT。[message/carry 示例](examples/ntru_ntt_basic.rs)
展示多个输出共享一次 BR 和一次环密钥切换。普通 PBS 返回 client secret 下的 LWE；
BR 后的 NTRU 密钥切换将 f_acc 转为 f_client。

```sh
cargo run -p primus_tfhe_ntru_ntt --example ntru_ntt_basic
```

示例从一个输入计算 message、carry 和 parity（`x % 4`、`x / 4`、`x % 2`），
三个输出占用四个交错槽，不代表完整的加密整数系统。

LUT 编译的第一个参数为输出 `RoundedCodec`。示例采用 `t_in=16 → t_out=4`，
通过 `decrypt_phase` 与该 codec 解码；输入几何仍遵循参数编码。

同一示例还用 `BivariateLookupTable` 比较 `0..3` 内的加密 `x` 与 `0..2` 内的加密 `y`，
打包 `x+3*y` 后调用一次普通 PBS，复用密钥、evaluator scratch 和输出缓冲区。
共同输入尺度和误差放大条件见[共享双输入契约](../primus_tfhe/README.zh_CN.md#有界双输入-pbs)。

公开 PBS 检查 LUT 的编码模数、环长度及全部输出维数。原始 LWE 输入必须
使用 context 的 external key、规范 residue 和 unsigned rounded 编码。
可独立编程的输入为 `0..ceil(t/2)`，另一半按负循环关系扩展。ManyLUT 输出数量
`k` 必须为正，步长 `s = next_power_of_two(k)` 须满足 `ceil(t/2) <= N/s`；
步长越大，旋转分辨率越低，输入噪声余量越小。
Boolean/CBS 输出尺度允许区别于普通明文编码。

## 公钥客户端

`client_key.try_generate_public_key(context.parameters(), &mut rng)` 生成外部
二进制前缀秘密下的 `LwePublicKey`；将其传入 `context.encryptor(&public_key)`
即可使用 `encrypt`、`encrypt_padded`、`encrypt_centered`。
三种加密均提供 `_to(message, output, rng)`，公钥和私钥客户端都可无分配地复用
密文存储。消息或维数错误不会改变输出及 RNG。

公钥生成及加密中的新鲜误差均使用 `external_lwe` 噪声采样器。总误差为
`e^T r + e2 - e1^T s`，不能把该采样器视为最终密文噪声分布。参数必须满足
[底层公钥契约](../primus_lwe/README.zh_CN.md#公钥加密)及 PBS/ManyLUT 输入余量。
公钥维数/模数检查不能验证实际秘密来源；使用配套的 client/server key。
公钥存储 `n * (n + 1)` 个系数，不包括 NTRU 秘密的零填充部分。

## 可选 circuit bootstrapping

`CircuitBootstrapParameters`、`CircuitBootstrapKey` 和 `CircuitBootstrapEvaluator`
提供 CBS，普通 server key 无需携带 trace/SS 材料：

```text
external LWE -> gadget-scaled ManyLUT -> f_acc 下的一次 BR
             -> reverse-trace 系数投影 -> NLev_f_acc[m]
             -> scheme switch -> NTT NGSW_f_acc[m]
```

CBS 保留 BR 的环 accumulator，不执行普通 PBS 后续的环密钥切换和 LWE 提取，
也不依赖 packing。一般 ManyLUT accumulator 不满足目标消息零尾前提，不能用
前缀展开替代所需的系数投影。

CBS 接收 output basis 和完整的 trace/scheme-switch 加密参数；BR 参数和输出环
由 TFHE context 提供。内部交错 LUT 保留请求的层数，仅以零槽补齐步长；
投影与 NGSW 都保留请求的层数。Scheme-switch key 绑定完整的 output basis。

运行 [CBS → CMUX 示例](examples/ntru_ntt_circuit_bootstrap.rs)：

```sh
cargo run -p primus_tfhe_ntru_ntt --example ntru_ntt_circuit_bootstrap
```

示例创建配套的普通/CBS key，在 `f_acc` 下加密两个 NTRU 候选密文，再将外部 LWE bit
重复转换为 gadget 尺度的 NGSW 控制。CMUX 在输入 0 时选第一个候选，输入 1 时选第二个。
输入、control、选择结果和服务端 scratch 均复用，最后通过解密检查结果。

包括 bit 在内，输入仍使用 unsigned rounded LWE 编码。CBS 输出使用指定的 gadget
scalar，并非普通编码的 NTRU 明文。仅输入消息为 0/1 时才可把输出用作 CMUX 控制。
两组求值密钥必须来自同一个 accumulator secret 和变换 table。

Trace、scheme switching 的误差预算不同于普通 PBS。Scheme switching 将输入误差
乘 f、分解误差乘 f²；其 `NGSW_f[f]` 求值密钥需要独立论证
key-dependent-message/circular-security 假设。模逆元/原生整数归一化与 Fourier
精度要求见 [NTRU 数值契约](../primus_ntru/README.zh_CN.md)。当前实现不提供安全证明、
失败概率估计或推荐 CBS 参数。

## 验证与性能

```sh
cargo test -p primus_tfhe_ntru_ntt
cargo clippy -p primus_tfhe_ntru_ntt --all-targets -- -D warnings
cargo +nightly test -p primus_tfhe_ntru_ntt --features simd
cargo bench -p primus_tfhe_ntru_ntt --bench pbs
cargo bench -p primus_tfhe_ntru_ntt --bench circuit_bootstrap
```

`pbs` 复用输出，测量完整 PBS，并比较 3/4 输出 ManyLUT 与独立 PBS 调用。
准备工作位于计时之外。

CBS 测试覆盖 LWE bit 到 NGSW、再消费为 CMUX 控制的完整路径、非二次幂层数、basis
和容量错误，以及 evaluator 从首次调用起零在线分配。`circuit_bootstrap` 复用输出
和工作区，覆盖 N=1024/4096、输入维数 N/16、BR/trace/SS 的 B=2^3/2^10，以及
B=2^8、两层的输出。基准报告新增 CBS key 和 evaluator 实际请求且仍持有的堆字节数，
不包括分配器开销、借用 table、普通 server key 和调用方输出。密钥生成和内存统计
位于计时 closure 外。附加 `-- --test` 可检查 fixture，但不能得出耗时或可解密性结论。
SIMD 复用现有依赖内核，不增加公开 ISA 选择接口。
