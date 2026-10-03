# primus_tfhe_ntru_fourier

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

基于原生环面的 NTRU TFHE 后端。 先读[任务与编码选择](../primus_tfhe/README.zh_CN.md#选择同态操作)，再读 [NTRU 参数与密钥域](../primus_tfhe_ntru/README.zh_CN.md)。示例使用功能参数，不是经认证的安全或失败概率参数。

## 快速开始

```sh
cargo run -p primus_tfhe_ntru_fourier --release --example ntru_fourier_basic
```

[basic 示例](examples/ntru_fourier_basic.rs)展示参数 → context → 配对密钥 → 客户端 → 单个 LUT → 复用 evaluator 和密文缓冲。它计算 `x % 4`，输入和输出均采用 `t=32` 编码，直接用 `decrypt` 解码。 `parameters.lookup_table_compiler(&input_codec)?` 创建可复用编译器，`compiler.compile_fn(function)` 默认按输入 codec 的明文模数在 Q 下编码；用 `compiler.try_with_output_codec(&output_codec)?` 选择其他输出编码，见[选择输出编码](../primus_tfhe/README.zh_CN.md#选择输出编码)。 公钥加密通过 `context.public_encryptor(&public, &input_codec)` 创建客户端，见[家族说明](../primus_tfhe_ntru/README.zh_CN.md#客户端与-lut)。 示例的外部 `q=2^24` 与环 `Q` 不同，LUT 编译在 `Q` 下，返回 LWE 在 `q` 下。

示例默认使用 u32；将 `type Word = u32` 改为 `u64`；需要 TFHE-FFT 时，将 `RustFftTable as Table` 导入改为 `TfheFftTable as Table`，随后执行同一运行命令。每个文件内的 `parameters()` 直接构造 `TfheConfig`，集中列出尺寸、模数类型、秘密分布、噪声和 BR/KS 分解；CBS 示例还用 `circuit_config()` 明确输出、trace 和 scheme-switch 的分解。[数值配置与验证](../../guides/development/tfhe-parameters.md)集中记录参数选择；每例复用同一组缓冲处理两次请求。

示例区分客户端加密、服务端求值与客户端解密，见[双方职责与缓冲分配](../primus_tfhe/README.zh_CN.md#客户端与服务端边界)。

| 操作 | 完整示例 |
| --- | --- |
| Classic PBS | [basic](examples/ntru_fourier_basic.rs) |
| Sparse PBS / 交错多输出 ManyLUT | [sparse](examples/ntru_fourier_sparse.rs)；`SPARSE=false` 切换 classic ManyLUT |
| Classic CBS → CMux | [circuit_bootstrap](examples/ntru_fourier_circuit_bootstrap.rs) |
| 分解式 MVB | [thresholds](examples/ntru_fourier_mvb_thresholds.rs) |
| One-hot CBS → CMux | [one_hot](examples/ntru_fourier_one_hot.rs) |
| 高精度查表 | [lookup](../primus_tfhe_ntru_lut/examples/fourier_lookup.rs) |

ManyLUT 通过交错共享一次盲旋转，多输出返回还共享一次 Q→q 转换并分块进行 LWE key switch；分解式 MVB 通过公共因子生成多输出，是不同的求值接口。 NTRU sparse 当前只支持普通/交错 PBS，不支持 CBS、one-hot 或分解式 MVB。

消息 codec 在 `main` 中独立选择，密钥生成不依赖 t。CBS/one-hot 的容量在绑定输入 codec 时检查。

客户端工厂只接收所需秘密：普通及 Boolean 加解密传入 `client_key.external_lwe_secret_key()`，`accumulator_client` 传入 `client_key.accumulator_ntru_secret_key()`。完整 `ClientKey` 组合用于生成服务端密钥；选择角色不会复制秘密缓冲区。

## 参数与表示

Fourier 环只支持 `NativeModulus`；`PowOf2Modulus` 环不受支持。 NTRU 的外部 LWE 模数 q 可独立使用 `PowOf2Modulus`。

`TfheParameters::try_from_config(TfheConfig { .. })` 检查数学配置； `TfheContext::<_, RustFftTable>::from_parameters(parameters)` 准备变换表。 已有表用 `TfheContext::try_new(parameters, table)` 绑定。 `TfheConfig`、`TfheParameters`、`Encryptor` 和 `Decryptor` 将家族 API 特化为 `NativeModulus`。 `TfheParameters<T, LM>` / `TfheContext<T, Table, LM>` 的 `LM` 指定独立外部模数类型（默认沿用后端模数类型）；`accumulator_modulus` 指定环 `Q`。

`RustFftTable` 和 `TfheFftTable` 均支持 u32/u64。变换域密钥、数据和 evaluator 必须使用同一个 FFT 表实例，长度相同不能证明表示一致。

## 求值材料

`ServerKey` 组合独立拥有的 `BlindRotationKey`、`NtruLweKeySwitchingKey` 和可选 `CircuitBootstrapKey`。`into_parts()` 移出组件，不复制密文缓冲；`ServerKey::new(br, return_key, cbs)` 组合各 owner。独立生成分别使用 `KeyGenerator::try_generate_blind_rotation_key(&client, rng)`、`parameters.try_generate_lwe_return_key(&client, rng)` 和 `generator.try_generate_circuit_bootstrap_key(client.accumulator_ntru_secret_key(), cbs_parameters, rng)`。稀疏 BR 使用 `try_generate_sparse_blind_rotation_key`。独立生成可能重复转换累加秘密；成对生成复用同一次变换。

`Evaluator::try_from_parts(context, br, return_key)` 绑定普通 PBS。独立 CBS/one-hot 先用 `context.bootstrap_resources(br)?` 准备公共 BR/外积资源，再用 `try_new(&resources, circuit_key, &input_codec)` 准备操作状态，无需返回密钥；CBS 示例展示这一流程。独立材料必须采用相同实际秘密与FFT table 实例，形状和模数检查不能证明身份。

`server_key.blind_rotation_key().classic_controls()` 返回借用的 `ClassicControls` 视图，稀疏材料返回 `None`。视图的 `initializer()` 用于提升公开多项式；首坐标使用 NLEV bit，后续坐标使用 NGSW bit，ternary 秘密按正/负 bit 配对。CBS、one-hot 和 MVB 在构造时检查所需能力。可选的 `circuit_bootstrap_key()` 仍可用于查看或组合 CBS 材料。

## 复用 evaluator

普通/interleaved `Evaluator` 拥有公共 `BootstrapResources` 和 scalar/batch 返回缓冲。CBS/one-hot 只保存 LUT 与投影缓冲，调用时最后一个参数传 `pbs.bootstrap_resources_mut()`；factorized MVB 使用 `FactorizedEvaluator::try_new(&pbs)` 构造，调用时最后一个参数传 `&mut pbs`。借用结束即可继续普通 PBS，无需转换或恢复 evaluator；在线 `_to` 复用所有缓冲。操作状态要求资源使用构造时的同一 context 和 BR key 引用，在写入前检查。

仅使用 CBS/one-hot 时，单独保留 `BootstrapResources`，不分配返回缓冲。以后需要 PBS，可用 `Evaluator::try_from_resources(resources, return_key)` 接管公共资源并分配返回缓冲。`try_rebind_return_key` 更换兼容返回密钥而不重新分配；成功时丢弃待提交样本，失败保持原绑定。资源所有权变化不验证密钥的实际秘密身份。

## 固定尺度分解式 MVB

通过 `context.compile_factorized_lookup_table_fn(&input_codec, &output_codec, domain_len, output_count, function)` 编译并绑定 `FactorizedEvaluator`；程序借用该 context，输出使用 unsigned Scaled 编码。 编译 codec 使用 Q，返回解码 codec 使用 q 和同一个明文模数；须预算 `(q/Q)*round(Q/t_out)` 与 `round(q/t_out)` 的差及返回噪声。

实际尺度 `round(2^BITS/t_out)` 必须为偶数，`t_out=10` 对 u32/u64 均可用。 奇数尺度返回 `LookupTableError::OddFactorizationScale`。因子按有符号整数变换，不作环面缩放； 须预算因子放大和 FFT 误差。

经典 binary/ternary 共用加密初始化和 BR。每个因子乘积独立完成 Q→q 和提取，再复用 PBS 工作区分块批量执行 LWE KS。提取后即复用系数多项式缓冲，不同时保留所有乘积。 因子同时放大初始化与 BR 噪声，返回 KS 噪声在乘积后加入。

运行[17 阈值示例](examples/ntru_fourier_mvb_thresholds.rs)，命令使用 `--example ntru_fourier_mvb_thresholds`。 它展示交错容量之外的多输出；算法选择及编码限制见[共享 MVB 契约](../primus_tfhe/README.zh_CN.md#固定尺度分解式-mvb)。

## 实验性稀疏 PBS

为 external-LWE 选择固定重量 binary 分布，并显式调用稀疏生成器； 仅选择低重量分布仍使用经典 BR。要求 `0<h<n`、`copy_count>=1`、`bucket_count>=max(copy_count,h)`。

```rust,ignore
let mut generator = KeyGenerator::new(&context);
let client = generator.try_generate_client_key(&mut rng)?;
let server = generator.try_generate_sparse_server_key(&client, 3, 2 * h, &mut rng)?;
let mut evaluator = context.evaluator(&server)?;
```

普通/交错 PBS 复用原 evaluator。CBS/MVB 拒绝 sparse 密钥，包括另传 CBS 材料的构造方式。 `server.blind_rotation_key().sparse_bootstrapping_key()` 提供选择密文。

外部秘密允许偶数重量。只有环秘密需要可逆且 Fourier 逆稳定；系数恢复和聚合 FFT 另引入数值误差。

## 可选电路自举

`context.try_generate_keys(Some(cbs_config), &mut rng)` 生成配对材料，`ServerKey` 持有附加参数及 trace/scheme-switch 密钥。取出 `server.circuit_bootstrap_key()`，与公共资源一起传给 `CircuitBootstrapEvaluator::try_new`；该构造器显式要求 CBS 材料。使用 `allocate_output`、`circuit_bootstrap_to` 和 `cmux_to`；[CBS → CMUX 示例](examples/ntru_fourier_circuit_bootstrap.rs)展示完整消费链。

输出为 `f_acc` 下的 `FourierNgswCiphertext`。Circuit key 绑定完整输出 basis； `try_new(&resources, circuit_key, &input_codec)` 从该密钥取得参数。 须对最小输出 gadget 尺度预算 Native trace halving 和 FFT 误差。

独立生成组件时须配对秘密并使用同一变换表示，形状检查不能证明身份。 输入/输出与消费要求见[共享 CBS 契约](../primus_tfhe/README.zh_CN.md#cbs-输出与消费)及 [家族 CBS 说明](../primus_tfhe_ntru/README.zh_CN.md#cbs-与示例)。

## One-hot CBS

[One-hot 示例](examples/ntru_fourier_one_hot.rs)生成四个 selector，并用 `TARGET=2` 对应的 δ₂ 控制 CMux；修改 `TARGET` 选择其他分支。绑定 `OneHotCircuitBootstrapEvaluator::try_new(&resources, circuit_key, &input_codec)`，分配后复用 `_to` 调用。

完整/非零输出接口、布局与输入保护区见[家族 one-hot 契约](../primus_tfhe_ntru/README.zh_CN.md#one-hot-cbs)。NLEV 输出为 Q 下的系数，需要 `write_fourier_form` 转换才能做公开多项式外积；NGSW 已在 Fourier 表示。输入、密钥和候选必须满足本页的变换契约。

`ngsw_selector_len()` 返回单个变换域 NGSW selector 的长度；`ngsw_batch_len()` 返回包含分支零的完整批次长度。两者均以复数个数计量，不是字节数。

## 高精度查表

[primus_tfhe_ntru_lut](../primus_tfhe_ntru_lut/README.zh_CN.md) 组合 one-hot CBS、表选择、聚合负向旋转和独立 LWE 返回，支持统一输入/输出 chunk 位宽及独立数量。底层组合可通过 `server_key.blind_rotation_key().classic_controls().unwrap().initializer()` 取得 context 的 BR basis 下的 classic NLEV[1]，通过 `key_switching_key()` 取得 Q→q、f→s 返回密钥。

完整 chunk 加密与查表工作流见 [fourier_lookup.rs](../primus_tfhe_ntru_lut/examples/fourier_lookup.rs)。

自定义返回先绑定 `LweReturnEvaluator::new(server.key_switching_key(),
context.parameters().external_lwe().cipher_modulus())`，再按需准备 scalar/batch 工作区，
显式传给 `return_at_to`、`return_prefix_to` 或流式操作。one-hot 与变换工作区可独立复用。
详见[家族返回契约](../primus_tfhe_ntru/README.zh_CN.md#ntrulwe-返回)。

## 底层组合

Rustdoc 按职责组织 `key`（服务端材料）、`circuit_bootstrap`（CBS）、 `factorized`（MVB 程序和执行）与 `sparse`（桶材料）；常用工作流类型仍从 crate 根导入。

## 进一步阅读

默认 features 为空；可选 `simd` 启用依赖中的 nightly SIMD 算术。

[Boolean 门](../primus_tfhe/README.zh_CN.md#boolean-门) · [错误边界](../primus_tfhe/README.zh_CN.md#错误边界) · [实现说明](../primus_tfhe/IMPLEMENTATION.md) · [基准指南](../primus_tfhe/BENCHMARKS.md)
