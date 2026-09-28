# primus_tfhe_glwe

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

与后端无关的 GLWE-TFHE 参数、客户端密钥、加解密及 Boolean 语义层。 变换 table、server key 和 evaluator scratch 由 [NTT](../primus_tfhe_glwe_ntt/README.zh_CN.md) 或 [Fourier](../primus_tfhe_glwe_fourier/README.zh_CN.md) 后端持有。 完整能力与编码约定见[公共指南](../primus_tfhe/README.zh_CN.md)。

公共层与两个后端使用相同的角色名称：`Encryptor`、`Decryptor`、`ClientKey`、 `EncryptionKey`、`PbsOrder` 和 `TfheParameters`。客户端密文为 `LweCiphertext`； GLWE 表示 PBS 累加器所属的方案家族。

## 参数与外部密钥域

`TfheParameters<T, M>` 和客户端使用同一个密文模数类型 `M`；两后端的类型别名固定各自的模数实现。

推荐使用 `TfheParameters::try_from_config(TfheConfig { .. })`：只在 `small_lwe` 中指定一次 `t/q`，具名字段选择 accumulator 的维数、长度、秘密分布和噪声，以及 blind rotation、key switching 的 `DecompositionConfig { log_basis, level_count }` 和 PBS order。`level_count: None` 选择支持的最大层数，仍可能丢弃低位（见[分解精度](../primus_decompose/README.zh_CN.md)）；各 basis 自动绑定同一模数。 GLWE evaluation key 沿用 accumulator 噪声。已持有环参数或预计算 basis 时，使用下述直接入口。

`TfheParameters::try_new(small_lwe, accumulator_glwe, blind_rotation_basis, key_switching_basis, order)` 从 accumulator 派生 BSK 布局，从 small LWE 派生 补零的密钥切换目标。明文与密文模数必须匹配，small secret 支持 binary 或 ternary 家族，且 `n <= kN`。 旋转域 `2N` 必须能由输入系数类型 `T` 表示。 Ternary LWE 密钥按 `0/1/q-1` 保存；构造补零 GLWE 密钥时将 `q-1` 还原为 signed `-1`。 均匀、自定义概率及固定重量/正负计数分布复用同一流程，Gaussian small secret 不支持。

| `PbsOrder` | 完整 PBS 链 | 外部 LWE 秘密 / 维数 |
| --- | --- | --- |
| `BootstrapKeyswitch` | BR → 环密钥切换 → compact extraction | Small LWE / `n` |
| `KeyswitchBootstrap` | Inverse extraction → 环密钥切换 → compact extraction → BR → full extraction | GLWE 系数向量 / `kN` |

两种 order 均返回各自的外部秘密域。后端 `context.allocate_lwe_ciphertext()` 根据 `external_lwe_dimension()` 分配输出， 用 `client_key.external_lwe_secret_key()` 借用对应秘密。 `accumulator_glwe()` 描述累加器域，`blind_rotation_ggsw()` 描述其中的 GGSW 控制项， `glwe_key_switching()` 描述环密钥切换。 Basis/布局兼容不能证明实际秘密一致。

`ClientKey::new` 导入系数秘密。参数绑定检查 small-LWE 的 binary/ternary 系数范围，无效值返回 `TfheKeyError::InvalidLweSecretKeyCoefficient`。Accumulator 仍支持 Gaussian 秘密，其幅值要求继续由后端契约规定。

## 客户端与 LUT

优先通过 `context.try_generate_keys(circuit_bootstrap, rng)` 生成配套 client/server 密钥；仅需系数秘密时使用 `ClientKey::generate(&parameters, &mut rng)`。

通过 context 的 `encryptor(&client)`、`public_encryptor(&public)`、`decryptor(&client)` 绑定外部密钥；`client.try_generate_public_key(parameters, rng)` 生成对应的 LWE 公钥。两种 PBS 顺序使用各自的外部秘密与维数。公钥加密的总噪声要求见 [LWE 公钥契约](../primus_lwe/README.zh_CN.md#公钥加密)。

前半区 LUT 使用 `encrypt_padded`，奇数全域 LUT 使用普通 `encrypt`。`compile_lookup_table_fn` 默认保留参数的明文模数；改变输出明文模数时，传入同一密文模数下的 `RoundedCodec`，再用它解码 `decrypt_phase`。ManyLUT、Boolean、双输入和 MVB 的接口及编码要求见[公共指南](../primus_tfhe/README.zh_CN.md)。

## Boolean 与 CBS

明文模数 t=4 时，context 提供 `boolean_encryptor`、`boolean_public_encryptor`、`boolean_decryptor` 和 `boolean_evaluator`。这些接口使用普通 PBS 材料；调用与串联约定见[公共 Boolean 契约](../primus_tfhe/README.zh_CN.md#boolean-门)。

CBS 是两个后端的可选能力，提供独立的 output basis、trace/scheme-switch 参数及密钥， 两种 PBS order 均支持经典 binary/ternary 和 sparse binary。CBS 输出留在 accumulator secret 下，使用 gadget 尺度。`CircuitBootstrapParameters<T, M>` 由公共层定义，后端提供具体模数别名； 同层数的不同输出 basis 可复用 scheme-switch key。噪声与变换要求见对应后端契约。

## 示例

后端 basic 示例展示默认编码和普通 PBS 缓冲复用；通过 `ORDER` 常量选择 PBS 顺序。 独立输出编码见共享指南。 MVB/CBS 使用专门示例，Boolean 用法见[共享指南](../primus_tfhe/README.zh_CN.md#boolean-门)。 所有示例 fixture 均用于开发，不是生产参数建议。

## 进一步阅读

[实现说明](../primus_tfhe/IMPLEMENTATION.md) · [基准入口与性能取舍](../primus_tfhe/IMPLEMENTATION.md#performance-decisions-and-reproducibility)
