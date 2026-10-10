# primus_tfhe_glwe

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

与后端无关的 GLWE-TFHE 参数、客户端密钥、加解密及 Boolean 语义层。 变换 table、server key 和 evaluator scratch 由 [NTT](../primus_tfhe_glwe_ntt/README.zh_CN.md) 或 [Fourier](../primus_tfhe_glwe_fourier/README.zh_CN.md) 后端持有。 完整能力与编码约定见[公共指南](../primus_tfhe/README.zh_CN.md)。

公共层与两个后端使用相同的角色名称：`Encryptor`、`Decryptor`、`ClientKey`、 `EncryptionKey`、`PbsOrder` 和 `PbsParameters`。客户端密文为 `LweCiphertext`； GLWE 表示 PBS 累加器所属的方案家族。

该 family 的默认依赖只使用系数类型、sparse 密钥存储、参数和客户端运算，不引入 NTT/FFT。需要同态求值时选择下述具体后端；其普通依赖会启用对应表示。

`PbsConfig::bsk_poly_length` 接收 `primus_poly::PolyLength`。用 `PolyLength::try_new(n)?`（已知常量可用 `new`）构造一次，供参数、尺寸与变换表复用。无效整数由 `PolyLengthError` 报告；参数构造仍负责组合布局、模数及采样器检查。

## 实验配套参数

`PbsConfig` 直接描述 PBS/ManyLUT/MVB 的 LWE/环域、`bsk_gadget`、`method`、必需的 `key_switching` 与 `messages`。`CbsConfig { pbs, gadget }` 在同一域上补充 CBS 分解；selector 输入消息模数来自 `pbs.messages.input_modulus`。配置是可复制的数值描述，不含准备后的 sampler 或 codec。

`bsk_dimension` 和 `bsk_poly_length` 描述 accumulator/BSK 共用的环布局；`bsk_secret_distr` 描述加密 BSK 的环秘密，`bsk_gadget` 描述其分解与行噪声。BR 输出使用该环秘密；公开的 `(0, LUT * X^(-b))` 初始化不采样加密噪声。输入 LWE 秘密在 LWE 配置中单独描述。`method: BlindRotationMethod` 选择 classic 或 sparse 及其桶几何。

`PbsParameters::try_from_config(pbs_config)` 返回含必需 KS、算法和默认消息选择的 `PbsParameters`。`CbsParameters::try_from_config(cbs_config.pbs, cbs_config.gadget)` 将它与 `CbsGadgetParameters`、输入 codec 组合。后端 Context 用一个 Box 保存完整操作状态；`try_from_pbs_config` / `try_from_cbs_config` 移入准备后的参数。`parameters()` 始终借用完整 PBS 域；`cbs_parameters()` 查询额外的 CBS 能力。`try_with_circuit_bootstrap(gadget)` 添加 CBS 时复用同一份公共参数和变换表。

PBS 和 CBS 的 `key_switching` 都是必需的 `GadgetEncryptionConfig`，分解和噪声可独立于 BR 选择。CBS 当前阶段输出环/gadget 密文；后续消费结果返回 LWE 时复用同一份 KS。输入 LWE 与环秘密仍独立采样。 GLWE KS→BR 在输入准备时执行 KS，BR→KS 在返回阶段执行。

参数入口为 `PbsParameters::try_from_config(pbs_config)`、`CbsParameters::try_from_config(pbs_config, gadget_config)` 和 `CbsParameters::try_with_config(pbs_parameters, gadget_config)`；最后一种移动已有公共状态，不重建 sampler。已有参数按值移入 Context，BR、trace、scheme-switch 继续共享既有环 sampler Arc；显式 `clone()` 可能复制 LWE sampler 数据。

具体后端的 `experimental::*_U64` 提供 PBS、ManyLUT、MVB 和 CBS 等教学配置。`PbsMessageConfig::new(t)` 默认输入/输出消息模数相同，`.with_output_modulus(t_out)` 可单独修改输出。后端 PBS/ManyLUT 的客户端和编译器根据消息选择派生 Rounded 编码，MVB 通过专用工厂选择 Scaled 输出；CBS 保存输入 codec，候选环消息模数由消费方选择。这些配置没有安全性或失败概率评估，来源与操作条件见[参数指南](../../guides/development/tfhe-parameters.md#scope-of-paired-parameter-entries)。

## 参数与外部密钥域

`PbsParameters<T, M>` 和客户端使用同一个密文模数类型 `M`；两后端的类型别名固定各自的模数实现。

数值 PBS 配置的 `small_lwe` 描述不含 codec 的 small LWE 域，`bsk_dimension`、`bsk_poly_length`、`bsk_secret_distr`、`bsk_gadget` 描述 accumulator/BSK 的环状态。`key_switching` 独立选择环 KS 分解和噪声，`order` 选择 PBS 顺序。两组 gadget 均使用 `GadgetEncryptionConfig { decomposition, noise_standard_deviation }`，分解由 `DecompositionConfig { log_basis, level_count }` 描述。`level_count: None` 选择支持的最大层数，仍可能丢弃低位（见[分解精度](../primus_decompose/README.zh_CN.md)）。`CbsConfig` 补充 output/trace/scheme-switch 分解；其 PBS 部分可保留已有 KS，直接环输出入口可省略返回 KS。

调整 KS 噪声只影响环 KS 密钥生成，两种 PBS order 均如此。Accumulator 噪声也用于 KS→BR 的新鲜外部加密；新鲜 small-LWE 噪声仍独立配置，CBS trace/scheme-switch 密钥行继承 accumulator 噪声。所有标准差均以系数单位表示。非法 KS 采样参数在构造时返回 `TfheParameterError::KeySwitchingEncryption`。

维数选择使用 `LweDimension`，GLWE 另用 `GlweDimension`；分解选择使用 `DecompositionBaseLog` 和 `Option<DecompositionLevelCount>`。这些单位只构造一次，参数访问器返回的值直接传给工作区。在原始存储或内核边界用 `.get()` 提取整数；组合长度和 basis/模数兼容性仍由构造器检查。

`PbsParameters::try_from_config` 一次准备 LWE/环 sampler 与选定的分解，然后派生补零的 KS 目标。Small secret 支持 binary 或 ternary 家族，要求 `n <= kN`，旋转域 `2N` 必须能由输入系数类型 `T` 表示。Ternary LWE 密钥按 `0/1/q-1` 保存；构造 KS 目标时将 `q-1` 还原为 signed `-1`。均匀、自定义概率及固定重量/正负计数分布复用同一流程，Gaussian small secret 不支持。

| `PbsOrder` | 完整 PBS 链 | 外部 LWE 秘密 / 维数 |
| --- | --- | --- |
| `BootstrapKeyswitch` | BR → 环密钥切换 → compact extraction | Small LWE / `n` |
| `KeyswitchBootstrap` | Inverse extraction → 环密钥切换 → compact extraction → BR → full extraction | GLWE 系数向量 / `kN` |

两种 order 均返回各自的外部秘密域。后端 `context.allocate_lwe_ciphertext()` 根据 `external_lwe_dimension()` 分配输出， 用 `client_key.external_lwe_secret_key()` 借用对应秘密。 `blind_rotation_params()` 描述累加环域和 GGSW 控制项， `glwe_key_switching()` 描述环密钥切换。 Basis/布局兼容不能证明实际秘密一致。

`ClientKey::new` 导入系数秘密。完整 setup 检查与 BR→KS 外部绑定会核对拥有型 LWE 秘密记录的模数；即使 binary 系数相同，异模数也返回 `TfheKeyError::LweSecretKeyModulusMismatch`。这些边界也检查 small-LWE 的 binary/ternary 系数范围，无效值返回 `TfheKeyError::InvalidLweSecretKeyCoefficient`。Accumulator 仍支持 Gaussian 秘密，其幅值要求继续由后端契约规定。

## Sparse 系数密钥

`SparseGlweBootstrappingKey<T, M>` 统一持有系数 GGSW、公开 bucket map、布局、模数与 basis。NTT 后端使用 `M = BarrettModulus<T>`，Fourier 使用 `NativeModulus<T>`，均在 `sparse` 模块重导出家族类型。`bucket(i)` 借用递增的输入索引与 GGSW，每桶末尾额外包含一个 dummy。

通常通过后端 `KeyGenerator` 加密生成。`try_new(data, map, hamming_weight, &ggsw_parameters)` 导入已有系数控制密文并检查组合布局，不转换或复制密文；加密选择、实际秘密与噪声预算仍由生成方保证。Raw sparse BR 使用后端的 `SparseGlweBlindRotationWorkspace::blind_rotate_lookup_table_to(&key, input, lut, output, table_or_fft)`；普通 PBS/CBS 继续使用已有 evaluator。

## 客户端与 LUT

通过 `PbsMessageConfig::new(t_in)` 和可选的 `with_output_modulus(t_out)` 设置 `config.messages`。后端 `context.encryptor(external_secret)`、`public_encryptor(&public)` 自动准备 Rounded 输入；`pbs_decryptor` 选择普通 PBS/ManyLUT 的 Rounded 输出，`mvb_decryptor` 选择 MVB 的 Scaled 输出。客户端不接收 codec 或 LUT，`pbs_lookup_table_compiler()` 和 `compile_mvb_fn` 使用同一默认选择。家族 `PbsParameters` 提供同样的默认客户端工厂且无需变换表，Context 委托这些方法。高级同钥消息域通过家族 `*_with_codec` 工厂绑定已准备的 codec；见[选择输出编码](../primus_tfhe/README.zh_CN.md#选择输出编码)。

`ClientKey` 保留为生成服务端密钥的完整 setup 组合。普通消息先取 `let external_secret = client.external_lwe_secret_key();`：BR→KS 借用 `ExternalLweSecretKey::SmallLwe(&small)`，KS→BR 借用 `ExternalLweSecretKey::ExtractedGlwe(&glwe)`。也可直接用这两个变体借用独立持有的秘密；`into_parts()` 无复制地移出两把密钥。消息客户端只检查该外部角色，setup 仍检查完整组合。环客户端只接收 `client.glwe_secret_key()`。

优先通过 `context.try_generate_keys(rng)` 生成配套 client/server 密钥；仅需系数秘密时使用 `ClientKey::generate(&parameters, &mut rng)`。

高级显式入口可独立于密钥生成选择 `RoundedCodec`。通过 `br.encryptor_with_codec(external_secret, &codec)`、`br.public_encryptor_with_codec(&public, &codec)`、`br.decryptor_with_codec(external_secret, &codec)` 绑定外部密钥；`br.try_generate_public_key(external_secret, rng)` 生成对应的 LWE 公钥。两种 PBS 顺序使用各自的外部秘密与维数。公钥加密的总噪声要求见 [LWE 公钥契约](../primus_lwe/README.zh_CN.md#公钥加密)。

客户端读写接收 LWE 借用视图：向 `encrypt_to` 传入 `output.as_mut_view()`，向 `decrypt` 或 `decrypt_phase` 传入 `ciphertext.as_view()`。分配型加密方法仍返回 `LweCiphertext<T>`；Boolean 客户端遵循同样的约定。

显式 codec 入口解密 LUT 结果时，将返回输出 codec 传给 `br.decryptor_with_codec(external_secret, &output_codec)`，再调用 `decrypt()`。Rounded 和 Scaled 均可绑定，包括消息模数与输入不同的 MVB 输出。已准备的解码状态按值复制，秘密保持借用；`decrypt_phase` 继续供诊断使用。

前半区 LUT 使用 `encrypt_padded`，奇数全域 LUT 使用普通 `encrypt`。显式编译时，用 `br.pbs_codecs(PbsMessageConfig::new(t_in))?` 准备编码，默认输出消息模数与输入相同；需要不同时，在准备前调用 `.with_output_modulus(t_out)`。`br.lookup_table_compiler(&codecs)?` 直接绑定选定的输入/输出编码，支持 `compile_fn` / `compile_slice` 及交错、奇数全域方法。输出 decryptor 绑定 `codecs.output_codec()`。输入、LUT 和返回密文使用同一密文模数。ManyLUT、Boolean、双输入和 MVB 的接口及编码要求见[公共指南](../primus_tfhe/README.zh_CN.md)。

## Boolean 与 CBS

`CbsParameters` 保存输入 Rounded 编码与 gadget，通过 `compile_lookup_table` / `_fn` / `_slice` 编译恒等或自定义整数函数。后端 Context 的 `compile_cbs_identity` / `compile_cbs_fn` / `compile_cbs_slice` 使用相同状态；输入加密共用 `context.encryptor`。候选环客户端接收独立 t_ring，并按累加 Q 准备 Scaled 编码。独立 codec 配对使用底层显式编译与客户端接口。

通过 `context.circuit_bootstrap_evaluator_with_lookup_table(&server, program)?` 创建拥有公共资源的默认 `CbsEvaluator`；`context.circuit_bootstrap_evaluator(&server)?` 编译并绑定恒等函数。输出为 `g_j * F(m) mod Q`，无需输出消息 codec 或额外 BR；CMux 要求完整输入域上的 F 为 bit，其他整数遵循外积噪声契约。NTT/Fourier 均支持 classic binary/ternary 与 sparse binary。显式输入编码和逐调用资源借用保留在底层 `CircuitBootstrapEvaluator`。

两个后端均提供 `context.try_generate_circuit_bootstrap_keys(rng)`，返回 `(ClientKey, CircuitBootstrapServerKey)`。该类型组合一个 BR/KS `ServerKey` 和必需 CBS key；`server.server_key()` 可绑定普通 PBS，CBS 借用同一 BR。KS→BR 的输入准备使用已有 KS，BR→KS 的 CBS 不分配返回 scratch，后续 LWE 返回仍可复用 KS。见[材料选择](../primus_tfhe/README.zh_CN.md#选择盲旋转算法)。

构造后端 Context 前设置 `config.messages = PbsMessageConfig::new(4)`，即可用 `boolean_encryptor`、`boolean_public_encryptor`、`boolean_decryptor` 和 `boolean_evaluator`，无需传 codec。输入、输出均需 t=4 才能串联门操作；密钥沿用普通 PBS 材料。高级数值组合保留共享 Boolean 构造器，调用与串联契约见[公共 Boolean 契约](../primus_tfhe/README.zh_CN.md#boolean-门)。

输入编码与 ManyLUT 容量在 CBS 程序绑定时检查：两后端均使用 `circuit_bootstrap::CircuitBootstrapEvaluator::try_new(&resources, key, &input_codec)`。默认构造使用密钥自带参数，`try_with_parameters` 显式选择兼容的替代输出 basis。同一套密钥可服务多个明文模数，前提是各程序满足容量与噪声余量。`accumulator_client(client.glwe_secret_key(), t_ring)` 独立绑定普通环消息，其 `ScaledCodec` 不必采用输入 LWE 的明文模数。

CBS 是两个后端的可选能力，提供独立的 output basis、trace/scheme-switch 参数及密钥， 两种 PBS order 均支持经典 binary/ternary 和 sparse binary。CBS 输出留在 accumulator secret 下，使用 gadget 尺度。`CbsGadgetParameters<T, M>` 由公共层定义，后端提供具体模数别名； 同层数的不同输出 basis 可复用 scheme-switch key。噪声与变换要求见对应后端契约。

`CbsGadgetParameters::try_from_config` 从 BR 派生 trace 与 scheme-switch 参数，保持相同 GLWE 布局，通过 `Arc` 共享不可变的采样状态。分解 basis 和随机采样仍然独立。

后端可独立生成和持有 BR、环 KS 与 CBS 材料，也保留完整 `ServerKey` 的便捷生成。CBS 生成只接收累加器秘密；BR→KS 的独立 CBS 不需要环 KS，KS→BR 仍需用它处理输入。普通 PBS 在两种顺序下都需要 BR 和环 KS。接口及示例见对应后端说明。

## 示例

后端 basic 示例展示默认编码和普通 PBS 缓冲复用；basic 示例固定 BR→KS，MVB 示例固定 KS→BR。 独立输出编码见共享指南。 MVB/CBS 使用专门示例，Boolean 用法见[共享指南](../primus_tfhe/README.zh_CN.md#boolean-门)。 所有示例 fixture 均用于开发，不是生产参数建议。

## 进一步阅读

[实现说明](../primus_tfhe/IMPLEMENTATION.md) · [基准入口与性能取舍](../primus_tfhe/IMPLEMENTATION.md#performance-decisions-and-reproducibility)
