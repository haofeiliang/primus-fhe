# primus_tfhe_glwe

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

与后端无关的 GLWE-TFHE 参数、客户端密钥、加解密及 Boolean 语义层。 变换 table、server key 和 evaluator scratch 由 [NTT](../primus_tfhe_glwe_ntt/README.zh_CN.md) 或 [Fourier](../primus_tfhe_glwe_fourier/README.zh_CN.md) 后端持有。 完整能力与编码约定见[公共指南](../primus_tfhe/README.zh_CN.md)。

公共层与两个后端使用相同的角色名称：`Encryptor`、`Decryptor`、`ClientKey`、 `EncryptionKey`、`PbsOrder` 和 `TfheParameters`。客户端密文为 `LweCiphertext`； GLWE 表示 PBS 累加器所属的方案家族。

## 参数与外部密钥域

`TfheParameters<T, M>` 和客户端使用同一个密文模数类型 `M`；两后端的类型别名固定各自的模数实现。

推荐使用 `TfheParameters::try_from_config(TfheConfig { .. })`：只在 `small_lwe` 中指定一次 `t/q`，具名字段选择 accumulator 的维数、长度、秘密分布和噪声，以及 blind rotation、key switching 的 `DecompositionConfig { log_basis, level_count }` 和 PBS order。`level_count: None` 保留完整分解；各 basis 自动绑定同一模数。 GLWE evaluation key 沿用 accumulator 噪声。已持有环参数或预计算 basis 时，使用下述直接入口。

`TfheParameters::try_new(small_lwe, accumulator_glwe, blind_rotation_basis, key_switching_basis, order)` 从 accumulator 派生 BSK 布局，从 small LWE 派生 补零的密钥切换目标。明文与密文模数必须匹配，small secret 支持 binary 或 ternary 家族，且 `n <= kN`。 旋转域 `2N` 必须能由输入系数类型 `T` 表示。 Ternary LWE 密钥按 `0/1/q-1` 保存；构造补零 GLWE 密钥时将 `q-1` 还原为 signed `-1`。 均匀、自定义概率及固定重量/正负计数分布复用同一流程，Gaussian small secret 不支持。

| `PbsOrder` | 完整 PBS 链 | 外部 LWE 秘密 / 维数 |
| --- | --- | --- |
| `BootstrapKeyswitch` | BR → 环密钥切换 → compact extraction | Small LWE / `n` |
| `KeyswitchBootstrap` | Inverse extraction → 环密钥切换 → compact extraction → BR → full extraction | GLWE 系数向量 / `kN` |

两种 order 均返回各自的外部秘密域。后端 `context.allocate_lwe_ciphertext()` 根据 `external_lwe_dimension()` 分配输出， 用 `client_key.external_lwe_secret_key()` 借用对应秘密。 `accumulator_glwe()` 描述累加器域，`blind_rotation_ggsw()` 描述其中的 GGSW 控制项， `glwe_key_switching()` 描述环密钥切换。 Basis/布局兼容不能证明实际秘密一致。

`ClientKey::new` 导入系数秘密。参数绑定检查 small-LWE 的 binary/ternary 系数范围，无效值返回 `TfheKeyError::InvalidLweSecretKeyCoefficient`。Accumulator 仍支持 Gaussian 秘密，其幅值要求继续由后端契约规定。

## 客户端与 LUT

`Encryptor`、`Decryptor`、`BooleanEncryptor` 和 `BooleanDecryptor` 从 [`primus_tfhe`](../primus_tfhe/README.zh_CN.md#客户端与服务端边界) 重导出。家族构造入口验证客户端密钥，选择外部 LWE 秘密和噪声；公共客户端负责编码、范围检查及输出复用，借用 LWE 密钥视图，不再持有家族参数或客户端密钥类型。

`ClientKey::generate(&parameters, &mut rng)` 生成客户端秘密，无需变换表。配套客户端/服务端密钥使用 `context.try_generate_keys(circuit_bootstrap, rng)`，复用生成服务端密钥所需的变换秘密。参数和 context 都提供 `encryptor(&client)`、`public_encryptor(&public)`、`decryptor(&client)`。家族私钥客户端构造返回 `TfheClientError`，公钥构造和普通操作返回公共 `ClientError`。加密接受 `T`，解密返回 `[0,t)` 内的规范剩余类。通过 `client.try_generate_public_key(parameters, rng)` 生成公钥，它遵循选定的外部秘密域，包括 signed `kN` 秘密。噪声与秘密来源要求见 [LWE 公钥契约](../primus_lwe/README.zh_CN.md#公钥加密)。

`encrypt`、`encrypt_padded` 和 `encrypt_centered` 均提供 `*_to(message, output, rng)`，可复用输出存储；消息或维数错误不改变输出和 RNG。 前半区 LUT 输入使用 `encrypt_padded`。普通 LUT 通过 `context.parameters().compile_lookup_table_fn(...)` 及对应的 slice、交错或奇数全域方法编译。

LUT 编译默认使用 `parameters.input_plaintext_codec()` 编码输出，直接用 `decrypt` 解码。 `*_with_codec_fn` / `*_with_codec_slice` 变体以显式输出 `RoundedCodec` 为第一个参数， 支持另一明文模数与相同密文模数，再用 `output_codec.decode_value(decryptor.decrypt_phase(&output)?)` 解码输出。 范围检查、raw 输出与后续 PBS 契约见[选择输出编码](../primus_tfhe/README.zh_CN.md#选择输出编码)。

奇数全域使用 `compile_odd_full_domain_lookup_table_fn` / `_slice`，输入改用普通 `encrypt`；输出 codec 与既有 PBS 求值入口相同。容量、折叠中心和噪声条件见 [奇数全域 PBS](../primus_tfhe/README.zh_CN.md#奇数全域-pbs)。

有界双输入函数使用共享 `BivariateLookupTable` 打包 `x+B*y`，再把其中的普通 LUT 交给现有 evaluator。范围、共同编码与误差放大条件见[有界双输入 PBS](../primus_tfhe/README.zh_CN.md#有界双输入-pbs)。

## Boolean 与 CBS

明文模数采用 4 时，context 提供 `boolean_encryptor(&client)`、`boolean_public_encryptor(&public)`、`boolean_decryptor(&client)` 和 `boolean_evaluator(&server)`。直接构造使用已有普通客户端：`BooleanEncryptor::try_new(encryptor)` 和 `BooleanDecryptor::try_new(decryptor)`。加密接受 `bool`，解密拒绝 `0/1` 以外的值。操作返回公共 `BooleanError`，其 `Client` 分支包装 `ClientError`；家族私钥工厂用 `TfheClientError` 报告构造失败。求值器构造返回 `TfheEvaluationError`。门预处理、正负 LUT 和输出修正在 `primus_tfhe::BooleanEvaluator` 中共享。用法和编码约定见[公共 Boolean 契约](../primus_tfhe/README.zh_CN.md#boolean-门)。

CBS 是两个后端的可选能力，提供独立的 output basis、trace/scheme-switch 参数及密钥， 两种 PBS order 均支持经典 binary/ternary 和 sparse binary。CBS 输出留在 accumulator secret 下，使用 gadget 尺度。`CircuitBootstrapParameters<T, M>` 由公共层定义，后端提供具体模数别名； 同层数的不同输出 basis 可复用 scheme-switch key。噪声与变换要求见对应后端契约。

## 示例

后端 basic 示例展示两种 order、默认编码和普通 PBS 缓冲复用。 独立输出编码见共享指南。 MVB/CBS 使用专门示例，Boolean 用法见[共享指南](../primus_tfhe/README.zh_CN.md#boolean-门)。 所有示例 fixture 均用于开发，不是生产参数建议。

## 进一步阅读

[实现说明](../primus_tfhe/IMPLEMENTATION.md) · [基准入口与性能取舍](../primus_tfhe/IMPLEMENTATION.md#performance-decisions-and-reproducibility)
