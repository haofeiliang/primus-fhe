# primus_tfhe_ntru

[English](README.md) | 简体中文

与后端无关的 NTRU-TFHE 参数和 LWE 客户端层。变换域 server key 与 evaluator
由 [NTT](../primus_tfhe_ntru_ntt/README.zh_CN.md) 或
[Fourier](../primus_tfhe_ntru_fourier/README.zh_CN.md) 后端提供。
完整能力与编码约定见[公共指南](../primus_tfhe/README.zh_CN.md)。

## 参数与密钥域

`NtruTfheParameters::try_new(external_lwe, bootstrapping, key_switching)` 将外部 LWE
绑定到 `f_client` 的二进制前缀，该 NTRU 秘密的其余系数为零。
`bootstrapping` 描述 `f_acc` 下的 accumulator，`key_switching` 描述返回 `f_client` 的切换。
环长度、明文模数与密文模数必须匹配，且 `1 <= external_lwe.dimension() <= N`。
构造时同时准备普通 PBS 量化，并要求 `log2(2N) <= T::BITS`。

普通 PBS 使用固定链：`f_acc` 下 BR → NTRU 密钥切换到 `f_client` → compact LWE extraction。
没有 order 选项。外部输出按 `external_lwe().dimension()` 分配；使用配套的 context/client/server key。

## 客户端与 LUT

Client 加密接受 `T`，解密返回 `Result<T, NtruClientError>`，消息是 `[0,t)` 内的
规范剩余类，消息类型转换由应用按需处理。

Context 提供 `encryptor`、`decryptor`；直接构造使用 `NtruEncryptor::try_new` 和
`NtruDecryptor::try_new`。加密接受 client key，或通过
`client_key.try_generate_public_key(parameters, rng)` 生成的 `LwePublicKey`。
这是二进制前缀秘密下的外部 LWE 公钥，不是 NTRU 环公钥。解密需要 client key。
噪声和秘密来源要求见 [LWE 公钥契约](../primus_lwe/README.zh_CN.md#公钥加密)。

`encrypt`、`encrypt_padded` 和 `encrypt_centered` 均提供
`*_to(message, output, rng)`。两类密钥都可复用输出存储，消息或维数错误先于采样和写入。
普通 family/context LUT 使用 padded unsigned 输入；centered 模消息有独立的编码契约。

ManyLUT 编译同一个输入的多个函数。后端 message/carry 示例将输入拆为 `x % 4` 与
`x / 4`，不代表已经实现完整的加密整数类型或算术系统。

## CBS 与示例

两后端均提供可选的 CBS 参数、密钥和 evaluator。CBS 从 BR 后分支，在 `f_acc` 下执行
系数投影、trace/scheme switching，跳过普通 PBS 的返回密钥切换与提取。
输出 NGSW 使用 gadget 尺度；输入为 `0/1` 时可控制 CMUX，其候选密文也必须使用 `f_acc`。
本 TFHE 层不提供 NTRU Boolean 适配器或 packing。

后端 README 链接到可运行的 PBS 和 CBS → CMUX 示例。Fixture 不构成生产噪声余量或
安全性论证；NTRU scheme switching 需要独立的秘密相关消息假设，见 [NTRU 契约](../primus_ntru/README.zh_CN.md)。

## 验证

```sh
cargo test -p primus_tfhe_ntru
cargo doc -p primus_tfhe_ntru --no-deps
```
