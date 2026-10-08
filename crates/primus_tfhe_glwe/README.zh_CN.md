# primus_tfhe_glwe

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

与后端无关的 GLWE-TFHE 参数、客户端密钥、加解密及 Boolean 语义层。 变换 table、server key 和 evaluator scratch 由 [NTT](../primus_tfhe_glwe_ntt/README.zh_CN.md) 或 [Fourier](../primus_tfhe_glwe_fourier/README.zh_CN.md) 后端持有。 完整能力与编码约定见[公共指南](../primus_tfhe/README.zh_CN.md)。

公共层与两个后端使用相同的角色名称：`Encryptor`、`Decryptor`、`ClientKey`、 `EncryptionKey`、`PbsOrder` 和 `TfheParameters`。客户端密文为 `LweCiphertext`； GLWE 表示 PBS 累加器所属的方案家族。

该 family 的默认依赖只使用系数类型、sparse 密钥存储、参数和客户端运算，不引入 NTT/FFT。需要同态求值时选择下述具体后端；其普通依赖会启用对应表示。

`TfheConfig::poly_length` 接收 `primus_poly::PolyLength`。用 `PolyLength::try_new(n)?`（已知常量可用 `new`）构造一次，供参数、尺寸与变换表复用。无效整数由 `PolyLengthError` 报告；参数构造仍负责组合布局、模数及采样器检查。

## 参数与外部密钥域

`TfheParameters<T, M>` 和客户端使用同一个密文模数类型 `M`；两后端的类型别名固定各自的模数实现。

推荐使用 `TfheParameters::try_from_config(TfheConfig { .. })`：在 `small_lwe` 中传入不含 codec 的 `LweEncryptionParameters`，只指定一次 `q`，具名字段选择 accumulator 的维数、长度和秘密分布，以及盲旋转、密钥切换配置和 PBS order。`blind_rotation` 和 `key_switching` 均使用 `GadgetEncryptionConfig { decomposition, noise_standard_deviation }`，其中 `decomposition` 为 `DecompositionConfig { log_basis, level_count }`。`level_count: None` 选择支持的最大层数，仍可能丢弃低位（见[分解精度](../primus_decompose/README.zh_CN.md)）；各 basis 自动绑定同一模数。`blind_rotation.noise_standard_deviation` 指定 BR 与累加环加密噪声；`key_switching.noise_standard_deviation` 独立选择环 KS 噪声。补零的 KS 目标直接由 GLWE 布局、采样状态和 basis 构造，无需消息 codec。CBS 的 `output`、`trace` 和 `scheme_switch` 各选择一组 `DecompositionConfig`，trace 与 scheme-switch 密钥行继承 BR/累加环加密噪声。已持有环参数或预计算 basis 时，使用下述直接入口。

调整 KS 噪声只影响环 KS 密钥生成，两种 PBS order 均如此。Accumulator 噪声也用于 KS→BR 的新鲜外部加密；新鲜 small-LWE 噪声仍独立配置，CBS trace/scheme-switch 密钥行继承 accumulator 噪声。所有标准差均以系数单位表示。非法 KS 采样参数在构造时返回 `TfheParameterError::KeySwitchingEncryption`。

维数选择使用 `LweDimension`，GLWE 另用 `GlweDimension`；分解选择使用 `DecompositionBaseLog` 和 `Option<DecompositionLevelCount>`。这些单位只构造一次，参数访问器返回的值直接传给工作区。在原始存储或内核边界用 `.get()` 提取整数；组合长度和 basis/模数兼容性仍由构造器检查。

`TfheParameters::try_new(small_lwe, blind_rotation_ggsw, key_switching, order)` 接收 small LWE 采样域、已构造的 GGSW 参数和 `GadgetEncryptionConfig<ApproxSignedBasis<T>>`，再派生补零的密钥切换目标。预计算 KS basis 直接移入参数，不重新构造。密文模数必须匹配，small secret 支持 binary 或 ternary 家族，且 `n <= kN`。旋转域 `2N` 必须能由输入系数类型 `T` 表示。Ternary LWE 密钥按 `0/1/q-1` 保存；构造补零 GLWE 密钥时将 `q-1` 还原为 signed `-1`。均匀、自定义概率及固定重量/正负计数分布复用同一流程，Gaussian small secret 不支持。

| `PbsOrder` | 完整 PBS 链 | 外部 LWE 秘密 / 维数 |
| --- | --- | --- |
| `BootstrapKeyswitch` | BR → 环密钥切换 → compact extraction | Small LWE / `n` |
| `KeyswitchBootstrap` | Inverse extraction → 环密钥切换 → compact extraction → BR → full extraction | GLWE 系数向量 / `kN` |

两种 order 均返回各自的外部秘密域。后端 `context.allocate_lwe_ciphertext()` 根据 `external_lwe_dimension()` 分配输出， 用 `client_key.external_lwe_secret_key()` 借用对应秘密。 `blind_rotation_ggsw()` 描述累加环域和 GGSW 控制项， `glwe_key_switching()` 描述环密钥切换。 Basis/布局兼容不能证明实际秘密一致。

`ClientKey::new` 导入系数秘密。完整 setup 检查与 BR→KS 外部绑定会核对拥有型 LWE 秘密记录的模数；即使 binary 系数相同，异模数也返回 `TfheKeyError::LweSecretKeyModulusMismatch`。这些边界也检查 small-LWE 的 binary/ternary 系数范围，无效值返回 `TfheKeyError::InvalidLweSecretKeyCoefficient`。Accumulator 仍支持 Gaussian 秘密，其幅值要求继续由后端契约规定。

## Sparse 系数密钥

`SparseGlweBootstrappingKey<T, M>` 统一持有系数 GGSW、公开 bucket map、布局、模数与 basis。NTT 后端使用 `M = BarrettModulus<T>`，Fourier 使用 `NativeModulus<T>`，均重导出家族类型。`bucket(i)` 借用递增的输入索引与 GGSW，每桶末尾额外包含一个 dummy。

通常通过后端 `KeyGenerator` 加密生成。`try_new(data, map, hamming_weight, &ggsw_parameters)` 导入已有系数控制密文并检查组合布局，不转换或复制密文；加密选择、实际秘密与噪声预算仍由生成方保证。Raw sparse BR 使用后端的 `SparseGlweBlindRotationWorkspace::blind_rotate_lookup_table_to(&key, input, lut, output, table_or_fft)`；普通 PBS/CBS 继续使用已有 evaluator。

## 客户端与 LUT

使用 `PbsMessageConfig::new(t_in)` 默认选择相同输入/输出消息模数，或通过 `.with_output_modulus(t_out)` 覆盖输出。`parameters.pbs_codecs(messages)?` 准备 Rounded codec；`parameters.factorized_pbs_codecs(messages)?` 为 MVB 准备 Rounded 输入和 Scaled 输出。两者通过 `input_codec()`、`lut_output_codec()`、`output_codec()` 区分角色，自动派生正确的密文模数，不复制密钥、不分配缓冲。编译与输出解码见[选择输出编码](../primus_tfhe/README.zh_CN.md#选择输出编码)。

`ClientKey` 保留为生成服务端密钥的完整 setup 组合。普通消息先取 `let external_secret = client.external_lwe_secret_key();`：BR→KS 借用 `ExternalLweSecretKey::SmallLwe(&small)`，KS→BR 借用 `ExternalLweSecretKey::ExtractedGlwe(&glwe)`。也可直接用这两个变体借用独立持有的秘密；`into_parts()` 无复制地移出两把密钥。消息客户端只检查该外部角色，setup 仍检查完整组合。环客户端只接收 `client.glwe_secret_key()`。

优先通过 `context.try_generate_keys(blind_rotation, circuit_bootstrap, rng)` 生成配套 client/server 密钥；仅需系数秘密时使用 `ClientKey::generate(&parameters, &mut rng)`。

独立于密钥生成选择 `RoundedCodec`。通过 context 的 `encryptor(external_secret, &codec)`、`public_encryptor(&public, &codec)`、`decryptor(external_secret, &codec)` 绑定外部密钥；`parameters.try_generate_public_key(external_secret, rng)` 生成对应的 LWE 公钥。两种 PBS 顺序使用各自的外部秘密与维数。公钥加密的总噪声要求见 [LWE 公钥契约](../primus_lwe/README.zh_CN.md#公钥加密)。

客户端读写接收 LWE 借用视图：向 `encrypt_to` 传入 `output.as_mut_view()`，向 `decrypt` 或 `decrypt_phase` 传入 `ciphertext.as_view()`。分配型加密方法仍返回 `LweCiphertext<T>`；Boolean 客户端遵循同样的约定。

解密 LUT 结果时，将返回输出 codec 传给 `decryptor(external_secret, &output_codec)`，再调用 `decrypt()`。Rounded 和 Scaled 均可绑定，包括消息模数与输入不同的 MVB 输出。已准备的解码状态按值复制，秘密保持借用；`decrypt_phase` 继续供诊断使用。

前半区 LUT 使用 `encrypt_padded`，奇数全域 LUT 使用普通 `encrypt`。用 `parameters.pbs_codecs(PbsMessageConfig::new(t_in))?` 准备编码，默认输出消息模数与输入相同；需要不同时，在准备前调用 `.with_output_modulus(t_out)`。`parameters.lookup_table_compiler(&codecs)?` 直接绑定选定的输入/输出编码，支持 `compile_fn` / `compile_slice` 及交错、奇数全域方法。输出 decryptor 绑定 `codecs.output_codec()`。输入、LUT 和返回密文使用同一密文模数。ManyLUT、Boolean、双输入和 MVB 的接口及编码要求见[公共指南](../primus_tfhe/README.zh_CN.md)。

## Boolean 与 CBS

两个后端均提供 `context.try_generate_circuit_bootstrap_keys(blind_rotation, cbs_config, rng)`，返回 client 和仅含环输出所需材料的 `CircuitBootstrapServerKey`。CBS 在该组合中始终存在，不生成普通返回材料。GLWE KS→BR 仍包含输入 KS。混合 PBS/CBS 仍使用完整 `ServerKey`，见[材料选择](../primus_tfhe/README.zh_CN.md#选择盲旋转算法)。

显式传入 t=4 的 `RoundedCodec` 时，context 提供 `boolean_encryptor`、`boolean_public_encryptor`、`boolean_decryptor` 和 `boolean_evaluator`。这些接口使用普通 PBS 材料；调用与串联约定见[公共 Boolean 契约](../primus_tfhe/README.zh_CN.md#boolean-门)。

输入编码与 ManyLUT 容量在 CBS 程序绑定时检查：两后端均使用 `CircuitBootstrapEvaluator::try_new(&resources, key, &input_codec)`。默认构造使用密钥自带参数，`try_with_parameters` 显式选择兼容的替代输出 basis。同一套密钥可服务多个明文模数，前提是各程序满足容量与噪声余量。`accumulator_client(client.glwe_secret_key(), scaled_codec)` 独立绑定普通环消息，其 `ScaledCodec` 不必采用输入 LWE 的明文模数。

CBS 是两个后端的可选能力，提供独立的 output basis、trace/scheme-switch 参数及密钥， 两种 PBS order 均支持经典 binary/ternary 和 sparse binary。CBS 输出留在 accumulator secret 下，使用 gadget 尺度。`CircuitBootstrapParameters<T, M>` 由公共层定义，后端提供具体模数别名； 同层数的不同输出 basis 可复用 scheme-switch key。噪声与变换要求见对应后端契约。

`CircuitBootstrapParameters::try_from_config` 从 BR 派生 trace 与 scheme-switch 参数，保持相同 GLWE 布局，通过 `Arc` 共享不可变的采样状态。分解 basis 和随机采样仍然独立。

后端可独立生成和持有 BR、环 KS 与 CBS 材料，也保留完整 `ServerKey` 的便捷生成。CBS 生成只接收累加器秘密；BR→KS 的独立 CBS 不需要环 KS，KS→BR 仍需用它处理输入。普通 PBS 在两种顺序下都需要 BR 和环 KS。接口及示例见对应后端说明。

## 示例

后端 basic 示例展示默认编码和普通 PBS 缓冲复用；basic 示例固定 BR→KS，MVB 示例固定 KS→BR。 独立输出编码见共享指南。 MVB/CBS 使用专门示例，Boolean 用法见[共享指南](../primus_tfhe/README.zh_CN.md#boolean-门)。 所有示例 fixture 均用于开发，不是生产参数建议。

## 进一步阅读

[实现说明](../primus_tfhe/IMPLEMENTATION.md) · [基准入口与性能取舍](../primus_tfhe/IMPLEMENTATION.md#performance-decisions-and-reproducibility)
