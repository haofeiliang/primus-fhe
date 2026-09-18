# primus_tfhe_glwe

[English](README.md) | 简体中文

与后端无关的 GLWE-TFHE 参数、客户端密钥、加解密及 Boolean 语义层。
变换 table、server key 和 evaluator scratch 由 [NTT](../primus_tfhe_glwe_ntt/README.zh_CN.md)
或 [Fourier](../primus_tfhe_glwe_fourier/README.zh_CN.md) 后端持有。
完整能力与编码约定见[公共指南](../primus_tfhe/README.zh_CN.md)。

公共层与两个后端使用相同的角色名称：`Encryptor`、`Decryptor`、`ClientKey`、
`EncryptionKey`、`PbsOrder` 和 `TfheParameters`。客户端密文为 `LweCiphertext`；
GLWE 表示 PBS 累加器所属的方案家族。

## 参数与外部密钥域

`TfheParameters::try_new(small_lwe, accumulator_glwe, blind_rotation_basis,
key_switching_basis, order)` 从 accumulator 派生 BSK 布局，从 small LWE 派生
补零的密钥切换目标。明文与密文模数必须匹配，small secret 支持 binary 或 ternary 家族，且 `n <= kN`。
旋转域 `2N` 必须能由输入系数类型 `T` 表示。
Ternary LWE 密钥按 `0/1/q-1` 保存；构造补零 GLWE 密钥时将 `q-1` 还原为 signed `-1`。
均匀、自定义概率及固定重量/正负计数分布复用同一流程，Gaussian small secret 不支持。

| `PbsOrder` | 完整 PBS 链 | 外部 LWE 秘密 / 维数 |
| --- | --- | --- |
| `BootstrapKeyswitch` | BR → 环密钥切换 → compact extraction | Small LWE / `n` |
| `KeyswitchBootstrap` | Inverse extraction → 环密钥切换 → compact extraction → BR → full extraction | GLWE 系数向量 / `kN` |

两种 order 均返回各自的外部秘密域。用 `external_lwe_dimension()` 分配输出，
用 `client_key.external_lwe_secret_key()` 借用对应秘密。
`accumulator_glwe()` 描述累加器域，`blind_rotation_ggsw()` 描述其中的 GGSW 控制项，
`glwe_key_switching()` 描述环密钥切换。
Basis/布局兼容不能证明实际秘密一致。

## 客户端与 LUT

`ClientKey::generate(&parameters, &mut rng)` 生成客户端秘密，无需变换表。
同时生成配套客户端/服务端密钥时使用 `context.generate_keys`，后端会在生成服务端密钥时
复用变换后的秘密。Context 也提供 `encryptor` / `decryptor` 工厂。
通用 client 加密接受 `T`，解密返回 `Result<T, TfheClientError>`，消息是 `[0,t)` 内的
规范剩余类，消息类型转换由应用处理。Boolean 加密接受 `bool`，解密返回
`Result<bool, BooleanError>`，并验证 Boolean 值。
直接使用 family 时，构造入口为 `Encryptor::try_new` 与 `Decryptor::try_new`。
加密接受 `ClientKey`，也接受通过
`client_key.try_generate_public_key(parameters, rng)` 生成的 `LwePublicKey`；解密需要 client key。
公钥遵循选定的外部秘密域，包括 signed `kN` 秘密。
噪声与秘密来源要求见 [LWE 公钥契约](../primus_lwe/README.zh_CN.md#公钥加密)。

`encrypt`、`encrypt_padded` 和 `encrypt_centered` 均提供
`*_to(message, output, rng)`，可复用输出存储；消息或维数错误不改变输出和 RNG。
前半区 LUT 输入使用 `encrypt_padded`。普通 LUT 通过
`context.parameters().compile_lookup_table_fn(...)` 及对应的 slice、交错或奇数全域方法编译。

LUT 编译的第一个参数为显式输出 `RoundedCodec`。沿用输入尺度时传入
`parameters.input_plaintext_codec()`；也可用另一明文模数与相同密文模数构造 codec，
再用 `output_codec.decode_value(decryptor.decrypt_phase(&output)?)` 解码输出。
范围检查、raw 输出与后续 PBS 契约见[选择输出编码](../primus_tfhe/README.zh_CN.md#选择输出编码)。

奇数全域使用 `compile_odd_full_domain_lookup_table_fn` / `_slice`，输入改用普通
`encrypt`；输出 codec 与既有 PBS 求值入口相同。容量、折叠中心和噪声条件见
[奇数全域 PBS](../primus_tfhe/README.zh_CN.md#奇数全域-pbs)。

有界双输入函数使用共享 `BivariateLookupTable` 打包 `x+B*y`，再把其中的普通 LUT
交给现有 evaluator。范围、共同编码与误差放大条件见[有界双输入 PBS](../primus_tfhe/README.zh_CN.md#有界双输入-pbs)。

## Boolean 与 CBS

Boolean 运算直接使用 `LweCiphertext<T>`，采用模 4 下 unsigned rounded `0/1` 编码。
`BooleanEncryptor` 接受私钥或公钥，提供 `encrypt` / `encrypt_to`；
`BooleanDecryptor` 使用客户端私钥，拒绝解码为 `0/1` 以外值的密文。
两种客户端均以 `try_new(parameters, key)` 构造，要求明文模数为 4。
后端 `boolean_encryptor`、`boolean_decryptor`、`boolean_evaluator` 工厂绑定同一参数。
通过 `evaluate_binary_to`、`not_to`、`mux_to` 复用输出；共享 evaluator 负责仿射预处理、
内部 LUT 尺度与修正。`BooleanEvaluator<T, M, E>::try_new` 也接受自定义 PBS 实现，
但传入的 family 参数必须匹配。求值器只保存所需模数、维数和编码常量，不借用这套参数。
Raw 输入必须采用 Boolean 编码及匹配的外部秘密，这些性质无法从 LWE 密文本身验证。

CBS 是两个后端的可选能力，提供独立的 output basis、trace/scheme-switch 参数及密钥，
支持两种 PBS order 和经典 binary/ternary small secret。CBS 输出留在 accumulator
secret 下，使用 gadget 尺度；稀疏 CBS 尚不支持。

## 示例与验证

后端 basic 示例展示两种 order、公钥输入、LUT 和复用输出的 Boolean 运算。
所有示例 fixture，包括 NTT 的 `boolean_parameters()`，均用于开发，不是生产参数建议。

```sh
cargo test -p primus_tfhe_glwe
cargo doc -p primus_tfhe_glwe --no-deps
```
