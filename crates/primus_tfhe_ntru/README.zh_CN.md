# primus_tfhe_ntru

[English](README.md) | 简体中文

与后端无关的 NTRU-TFHE 参数和 LWE 客户端层。变换域 server key 与 evaluator
由 [NTT](../primus_tfhe_ntru_ntt/README.zh_CN.md) 或
[Fourier](../primus_tfhe_ntru_fourier/README.zh_CN.md) 后端提供。
完整能力与编码约定见[公共指南](../primus_tfhe/README.zh_CN.md)。

## 参数与密钥域

推荐使用 `TfheParameters::try_from_config(TfheConfig { .. })`：`external_lwe` 提供
外部维数、秘密分布、`t/q` 与客户端加密噪声；具名字段选择公共环长度、accumulator
分布与噪声、两种 `DecompositionConfig { log_basis, level_count }` 和独立的
key-switch 噪声。客户端 NTRU 域自动复用外部秘密分布与公共环参数，无需重复构造。
`level_count: None` 保留完整分解。已持有 NLev 参数时也可使用下述直接入口。

`TfheParameters::try_new(external_lwe, blind_rotation, ntru_key_switching)` 将外部 LWE
绑定到 `f_client` 的二进制前缀，该 NTRU 秘密的其余系数为零。
`blind_rotation` 描述 `f_acc` 下的 accumulator，`ntru_key_switching` 描述返回 `f_client` 的切换。
环长度、明文模数与密文模数必须匹配，且 `1 <= external_lwe.dimension() <= N`。
构造时同时准备普通 PBS 量化，并要求旋转域 `2N` 能由 `T` 表示。

普通 PBS 使用固定链：`f_acc` 下 BR → NTRU 密钥切换到 `f_client` → compact LWE extraction。
没有 order 选项。外部输出按 `external_lwe_dimension()` 分配；使用配套的 context/client/server key。

客户端秘密通过后端 `KeyGenerator::try_generate_client_key` 生成：NTT 拒绝采样检查
可逆性，Fourier 还检查逆元稳定性。生成配套密钥时优先使用 `context.try_generate_keys(circuit_bootstrap, rng)`
或 `KeyGenerator::try_generate`，复用变换后的秘密。共享 `TfheKeyError` 表达结构不兼容，
`KeyGenerationError::Ntru` 保留底层 NTRU 生成/转换失败。`ClientKey::new` 导入系数秘密，
参数绑定检查二进制前缀与零填充，可逆性由后端转换检查。

## 客户端与 LUT

Client 加密接受 `T`，解密返回 `Result<T, TfheClientError>`，消息是 `[0,t)` 内的
规范剩余类，消息类型转换由应用按需处理。

Context 提供 `encryptor`、`decryptor`；直接构造使用 `Encryptor::try_new` 和
`Decryptor::try_new`。加密接受 client key，或通过
`client_key.try_generate_public_key(parameters, rng)` 生成的 `LwePublicKey`。
这是二进制前缀秘密下的外部 LWE 公钥，不是 NTRU 环公钥。解密需要 client key。
公钥生成和新鲜加密误差均使用 `external_lwe` 噪声采样器，但总误差为
`e^T r + e2 - e1^T s`。公钥存储 active prefix 对应的 `n * (n + 1)` 个系数。
维数/模数检查不能证明密钥身份；使用配套密钥，并为 PBS/ManyLUT 预算组合噪声。
噪声和秘密来源要求见 [LWE 公钥契约](../primus_lwe/README.zh_CN.md#公钥加密)。

`encrypt`、`encrypt_padded` 和 `encrypt_centered` 均提供
`*_to(message, output, rng)`。两类密钥都可复用输出存储，消息或维数错误先于采样和写入。
参数编译的前半区 LUT 使用 padded unsigned 输入；centered 模消息有独立的编码契约。

ManyLUT 编译同一个输入的多个函数。后端示例计算 `x % 4`、`x / 4` 和 `x % 2`，
不代表已经实现完整的加密整数类型或算术系统。

通过 `context.parameters().compile_*` 编译 LUT。第一个参数为显式输出 `RoundedCodec`。沿用输入尺度时传入
`parameters.input_plaintext_codec()`；也可用另一明文模数与相同密文模数构造 codec，
再用 `output_codec.decode_value(decryptor.decrypt_phase(&output)?)` 解码输出。
范围检查、raw 输出与后续 PBS 契约见[选择输出编码](../primus_tfhe/README.zh_CN.md#选择输出编码)。

奇数全域使用 `compile_odd_full_domain_lookup_table_fn` / `_slice`，输入改用普通
`encrypt`；输出 codec 与既有 PBS 求值入口相同。容量、折叠中心和噪声条件见
[奇数全域 PBS](../primus_tfhe/README.zh_CN.md#奇数全域-pbs)。

有界双输入函数使用共享 `BivariateLookupTable` 打包 `x+B*y`，再把其中的普通 LUT
交给现有 evaluator。范围、共同编码与误差放大条件见[有界双输入 PBS](../primus_tfhe/README.zh_CN.md#有界双输入-pbs)。

## Boolean 客户端与门

明文模数采用 4 时，通过后端 `boolean_encryptor(key)`、`boolean_decryptor(client)` 和
`boolean_evaluator(server)` 工厂构造。独立的 `BooleanEncryptor` / `BooleanDecryptor`
绑定 NTRU family 参数与密钥；加密支持私钥或 LWE 公钥，错误为本族 `BooleanError`，
其中原始 `TfheClientError` 通过 `#[from]` 进入 `Client`。求值器构造返回公共 `TfheEvaluationError`。
门预处理、正负 LUT 和输出修正与 GLWE 共用 `primus_tfhe::BooleanEvaluator`，
用法和编码约定见[公共 Boolean 契约](../primus_tfhe/README.zh_CN.md#boolean-门)。

## CBS 与示例

两后端均提供可选的 CBS 参数、密钥和 evaluator。CBS 从 BR 后分支，在 `f_acc` 下执行
系数投影、trace/scheme switching，跳过普通 PBS 的返回密钥切换与提取。
包括 bit 在内，输入使用 unsigned rounded LWE 编码。输出 NGSW 使用 gadget 尺度；输入为 `0/1` 时可控制 CMUX，其候选密文也必须使用 `f_acc`。
本 TFHE 层不提供 LWE 到环密文的 packing。

CBS 参数独立选择 output、trace 和 scheme-switch basis。内部 ManyLUT 仅在输出组中
补零，投影 NLev 和输出 NGSW 保留请求的层数；scheme-switch key 绑定完整 output basis。
一般 ManyLUT accumulator 不保证消息零尾，reverse-trace 系数投影不能用前缀展开替代。

普通与 CBS 密钥必须共享 accumulator secret 和变换 table。Scheme switching 将输入
误差乘 f、分解误差乘 f²；`NGSW_f[f]` 材料需要独立论证 key-dependent-message/
circular-security 假设，见 [NTRU 契约](../primus_ntru/README.zh_CN.md)。
NTT 使用模逆元归一化；Fourier 还引入原生整数除二和 FFT 误差。

后端 README 链接到可运行的 PBS 和 CBS → CMUX 示例。Fixture 不构成生产噪声余量或
安全性论证。

## 验证

```sh
cargo test -p primus_tfhe_ntru
cargo doc -p primus_tfhe_ntru --no-deps
```
