# primus_tfhe_ntru_ntt

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

基于显式域模数的 NTRU TFHE 后端。 先读[任务与编码选择](../primus_tfhe/README.zh_CN.md#选择同态操作)，再读 [NTRU 参数与密钥域](../primus_tfhe_ntru/README.zh_CN.md)。示例使用功能参数，不是经认证的安全或失败概率参数。

## 快速开始

```sh
cargo run -p primus_tfhe_ntru_ntt --release --example ntru_ntt_basic
```

[basic 示例](examples/ntru_ntt_basic.rs)展示参数 → context → 配对密钥 → 客户端 → 单个 LUT → 复用 evaluator 和密文缓冲。它计算 `x % 4`，输入和输出均采用 `t=16` 编码，直接用 `decrypt` 解码。 `compile_lookup_table_fn(function)` 默认使用参数 codec；需要不同输出明文模数时，使用 `compile_lookup_table_with_codec_fn(&output_codec, function)`，见[选择输出编码](../primus_tfhe/README.zh_CN.md#选择输出编码)。 公钥加密通过 `context.public_encryptor(&public)` 创建客户端，见[家族说明](../primus_tfhe_ntru/README.zh_CN.md#客户端与-lut)。 示例的外部 `q=2^20` 与环 `Q` 不同，LUT 编译在 `Q` 下，返回 LWE 在 `q` 下。

示例区分客户端加密、服务端求值与客户端解密，见[双方职责与缓冲分配](../primus_tfhe/README.zh_CN.md#客户端与服务端边界)。

## 参数与表示

`TfheParameters::try_from_config(TfheConfig { .. })` 检查数学配置； `TfheContext::<_, U32NttTable>::try_from_parameters(parameters)` 准备变换表。 已有表用 `TfheContext::try_new(parameters, table)` 绑定。 `TfheConfig`、`TfheParameters`、`Encryptor` 和 `Decryptor` 将家族 API 特化为 `BarrettModulus`。 `TfheParameters<T, LM>` / `TfheContext<T, Table, LM>` 的 `LM` 指定独立外部模数类型（默认沿用后端模数类型）；`accumulator_modulus` 指定环 `Q`。

NTT 表需要实现 `MonomialNttTable`，内置表均支持。Context 检查长度和模数； 所有变换域密钥及数据须遵循该表的表示约定。

PBS 在 `f,Q` 下首次融合和盲旋转，再逐系数 `Q→q`、提取相位系数并执行 LWE key switch，返回独立外部秘密 `s`。只有环秘密 `f` 做可逆性筛选，Fourier 还检查其逆的稳定性。ManyLUT 共享盲旋转，每个输出分别执行 LWE key switch。外部 binary/ternary 秘密无需补零、可逆性筛选或奇数重量。

Classic binary/ternary BR 将首次 CMux 与公开 LUT 提升融合：第零坐标使用 NLEV 比特控制，后续坐标使用 NGSW。旋转后的 LUT 只分解一次，与 `I + (R-1)B+ + (R^-1-1)B-` 做外积；binary 省略 `B-`。首指数为零仍通过 `I=NLEV[1]` 提升。普通 PBS、ManyLUT、MVB 和 CBS 共用此路径。BR basis 必须能分辨 LUT 的有效尺度，包括 CBS 输出的最小 gadget 权重；参数形状检查不认证该数值预算。

## 复用 evaluator

普通/交错调用共用 `Evaluator`，`_to` 写入已有输出。 PBS/MVB/CBS 交替使用方式集中在[共享所有权说明](../primus_tfhe/README.zh_CN.md#复用-evaluator)。

使用 `FactorizedEvaluator::try_from_bootstrapper` 或 `CircuitBootstrapEvaluator::try_from_bootstrapper`，两者均拒绝 sparse 密钥。 普通 PBS 借用始终可用，`into_bootstrapper()` 无分配。

## 固定尺度分解式 MVB

`context.compile_factorized_lookup_table_fn(&scaled_codec, input_domain_len, output_count, function)` 返回绑定该 context 实例的 `NttFactorizedLookupTable`。 构造并复用 `FactorizedEvaluator`，或消费已有普通 evaluator。 输出用保留的 unsigned Scaled codec 解码，不能直接当作 Boolean 门输入。 `ScaledCodec` 的编译模数为 `Q`；返回输出使用缩放后的尺度 `(q/Q)*round(Q/t_out)`，用 `q` 下相同明文模数的 Scaled codec 解码，并预算其与 `round(q/t_out)` 的差及返回噪声。

系数模数必须为奇数；预处理后的因子保留 NTT 表示。

经典 binary/ternary 共用加密初始化和 BR，随后对每个因子乘积 KS。 因子同时放大初始化与 BR 噪声，返回 KS 噪声在乘积后加入。

运行[17 阈值示例](examples/ntru_ntt_mvb_thresholds.rs)，命令使用 `--example ntru_ntt_mvb_thresholds`。 它展示交错容量之外的多输出；算法选择及编码限制见[共享 MVB 契约](../primus_tfhe/README.zh_CN.md#固定尺度分解式-mvb)。

## 实验性稀疏 PBS

为 external-LWE 选择固定重量 binary 分布，并显式调用稀疏生成器； 仅选择低重量分布仍使用经典 BR。要求 `0<h<n`、`copy_count>=1`、`bucket_count>=max(copy_count,h)`。

```rust,ignore
let mut generator = KeyGenerator::new(&context);
let client = generator.try_generate_client_key(&mut rng)?;
let server = generator.try_generate_sparse_server_key(&client, 3, 2 * h, &mut rng)?;
let mut evaluator = context.evaluator(&server)?;
```

普通/交错 PBS 复用原 evaluator。CBS/MVB 拒绝 sparse 密钥，包括另传 CBS 材料的构造方式。 `server.sparse_bootstrapping_key()` 提供选择密文。

首桶存储 NLEV selectors 和 NLEV dummy，按单项式加权聚合后直接提升旋转后的公开 LUT；后续桶聚合 NGSW 控制。首桶公开为空、未占用或指数为零时，仍处理 dummy 和加密零，不再单独生成稀疏初始化器。`first_bucket()` 返回首桶 NLEV 控制；`ngsw_bucket(j)` 仅接受 `j >= 1`，返回 NGSW 控制；两者均将 dummy 放在末尾。在线计算复用聚合与外积缓冲，不额外分配。

固定客户端后最多重试八张公开映射，不重新采样客户端秘密。 每个桶的加密零与 dummy 都贡献噪声；匹配成功不代表安全或完整失败概率得到认证。 见[稀疏旋转不变量](../primus_tfhe/IMPLEMENTATION.md#ternary-and-sparse-rotation)和[message/carry 示例](examples/ntru_ntt_sparse.rs)。

## 可选电路自举

`context.try_generate_keys(Some(cbs_config), &mut rng)` 生成配对材料， `ServerKey` 持有附加参数及 trace/scheme-switch 密钥。 调用 `context.circuit_bootstrap_evaluator(&server)` 或消费普通 evaluator。 经典密钥若使用 `None` 生成，CBS 绑定返回 `MissingCircuitBootstrapKey`。 使用 `allocate_output`、`circuit_bootstrap_to` 和 `cmux_to`； [CBS → CMUX 示例](examples/ntru_ntt_circuit_bootstrap.rs)展示完整消费链。

输出为 `f_acc` 下的 `NttNgswCiphertext`。Circuit key 绑定完整输出 basis； `try_from_parts(context, server, circuit_key)` 从该密钥取得参数。 NTT trace 归一化要求奇数 Q 且小于 `2^(T::BITS-1)`。

独立生成组件时须配对秘密并使用同一变换表示，形状检查不能证明身份。 输入/输出与消费要求见[共享 CBS 契约](../primus_tfhe/README.zh_CN.md#cbs-输出与消费)及 [家族 CBS 说明](../primus_tfhe_ntru/README.zh_CN.md#cbs-与示例)。

## One-hot CBS

`OneHotCircuitBootstrapEvaluator::try_new(&context, &server)` 为一个 chunk 绑定现有 CBS 密钥；完整输出接口包含默认 selector r=0。也可通过 `try_from_bootstrapper` 复用 PBS 工作区，通过 `bootstrapper_mut()` 借用普通 PBS，最后用 `into_bootstrapper()` 取回工作区。首版支持 classic binary/ternary，拒绝 sparse 和缺少 CBS 材料的密钥；普通 CBS 接口保持不变。

先调用 `allocate_nlev_output()` / `allocate_ngsw_output()`，再重复使用 `one_hot_nlev_to`、`one_hot_ngsw_to` 或 `one_hot_to(input, nlev, ngsw)`。三者每次均只执行一次 BR；只需要一种表示时不会生成另一种完整输出批次。NLEV 是 Q 下的系数表示，每行 N 个整数；NGSW 是 NTT 表示，每行 N 个整数。扁平布局为 `[selector][level][行元素]`，不含 padding；level 顺序来自 `evaluator.parameters().output_basis().scalar_iter()`。输出会完整覆盖，在线零额外分配。

消费方只需要非零分支时，用 `allocate_nonzero_ngsw_output()` 分配，再调用 `one_hot_nonzero_ngsw_to(input, output)`。它仅生成 r=1..M-1 的 M-1 个 NGSW，按 `[r-1][level][行元素]` 紧凑排列，跳过 r=0 的投影和 scheme switch。输入 m=0 时，全部目标 bit 均为零。共享 BR、输入保护区和噪声要求不变；公开 LUT 首层仍使用全部 M 个 NLEV selectors。

NLEV 用于公开多项式选择时，先用 `NlevCiphertext::write_ntt_form` 写入预分配的变换缓冲，再做外积；NGSW 可直接包装成 `NttNgswCiphertext`，配合相同 basis 消费密文候选。完整调用和消费见 [one_hot 测试](tests/one_hot.rs)，编码、容量与噪声保护区见[共用 one-hot 契约](../primus_tfhe_ntru/README.zh_CN.md#one-hot-cbs)。

## 高精度查表

[primus_tfhe_ntru_lut](../primus_tfhe_ntru_lut/README.zh_CN.md) 组合 one-hot CBS、表选择、聚合负向旋转和独立 LWE 返回，支持统一输入/输出 chunk 位宽及独立数量。底层组合可通过 `ServerKey::initializer()` 取得 context 的 BR basis 下的 classic NLEV[1]，通过 `key_switching_key()` 取得 Q→q、f→s 返回密钥。

完整 chunk 加密与查表工作流见 [ntt_lookup.rs](../primus_tfhe_ntru_lut/examples/ntt_lookup.rs)。

## 底层组合

Rustdoc 按职责组织 `key`（服务端材料）、`circuit_bootstrap`（CBS）、 `factorized`（MVB 程序和执行）与 `sparse`（桶材料）；常用工作流类型仍从 crate 根导入。

## 进一步阅读

[Boolean 门](../primus_tfhe/README.zh_CN.md#boolean-门) · [错误边界](../primus_tfhe/README.zh_CN.md#错误边界) · [实现说明](../primus_tfhe/IMPLEMENTATION.md) · [基准入口与性能取舍](../primus_tfhe/IMPLEMENTATION.md#performance-decisions-and-reproducibility)
