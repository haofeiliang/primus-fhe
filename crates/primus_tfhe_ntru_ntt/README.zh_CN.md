# primus_tfhe_ntru_ntt

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

基于显式域模数的 NTRU TFHE 后端。 先读[任务与编码选择](../primus_tfhe/README.zh_CN.md#选择同态操作)，再读 [NTRU 参数与密钥域](../primus_tfhe_ntru/README.zh_CN.md)。示例使用功能参数，不是经认证的安全或失败概率参数。

## 快速开始

基础、sparse、ManyLUT 和 MVB 示例使用 `PbsMessageConfig`：`new(t)` 默认输入输出消息模数相同，`with_output_modulus(t_out)` 只修改输出。普通 PBS/ManyLUT 用 `parameters.pbs_codecs` 准备，MVB 用 `parameters.factorized_pbs_codecs` 准备；返回的 codec 分别表示输入、LUT 输出和返回输出。`context.decryptor(external_secret, codecs.output_codec())?` 同时接受 Rounded/Scaled 输出，随后用 `decrypt()` 得到消息。见[选择输出编码](../primus_tfhe/README.zh_CN.md#选择输出编码)。

```sh
cargo run -p primus_tfhe_ntru_ntt --release --example ntru_ntt_basic
```

[basic 示例](examples/ntru_ntt_basic.rs)展示参数 → context → 配对密钥 → 客户端 → 单个 LUT → 复用 evaluator 和密文缓冲。它计算 `x % 4`，输入和输出均采用 `t=32` 编码，直接用 `decrypt` 解码。 `parameters.lookup_table_compiler(&codecs)?` 直接绑定已准备的输入/输出编码，再用 `compiler.compile_fn(function)` 创建 LUT。通过 `PbsMessageConfig::with_output_modulus` 选择不同输出消息模数，见[选择输出编码](../primus_tfhe/README.zh_CN.md#选择输出编码)。 公钥加密通过 `context.public_encryptor(&public, codecs.input_codec())` 创建客户端，见[家族说明](../primus_tfhe_ntru/README.zh_CN.md#客户端与-lut)。 示例的外部 `q=2^24` 与环 `Q` 不同，LUT 编译在 `Q` 下，返回 LWE 在 `q` 下。

示例使用 `Word = u64` 和 `U64NttTable`，每条工作流只保留一套显式参数；库与数值诊断仍支持 u32/u64。每个文件内的 `parameters()` 直接构造 `TfheConfig`，集中列出尺寸、模数类型、秘密分布、噪声和 BR/KS 分解；CBS 示例还用 `circuit_config()` 明确输出、trace 和 scheme-switch 的分解。[数值配置与验证](../../guides/development/tfhe-parameters.md)集中记录参数选择；每例复用同一组缓冲处理两次请求。

示例先展示 `main`，后列本地参数；用注释标明客户端和服务端阶段。Basic 与 sparse 都计算 `x % 4`，默认输入输出消息模数相同；独立 ManyLUT 示例同时计算 `x % 4` 和 `x / 4`，显式设置 `t_in=16`、`t_out=8`，并用输出 codec 解密。每例复用 LUT、evaluator 和输出缓冲处理两次请求。见[双方职责与缓冲分配](../primus_tfhe/README.zh_CN.md#客户端与服务端边界)。

| 操作 | 完整示例 |
| --- | --- |
| Classic PBS | [basic](examples/ntru_ntt_basic.rs) |
| Sparse PBS | [sparse](examples/ntru_ntt_sparse.rs) |
| 交错多输出 ManyLUT，独立输出消息模数 | [many_lut](examples/ntru_ntt_many_lut.rs) |
| CBS → CMux | [circuit_bootstrap](examples/ntru_ntt_circuit_bootstrap.rs) |
| 分解式 MVB | [thresholds](examples/ntru_ntt_mvb_thresholds.rs) |
| One-hot CBS → CMux | [one_hot](examples/ntru_ntt_one_hot.rs) |
| 高精度查表 | [lookup](../primus_tfhe_ntru_lut/examples/ntt_lookup.rs) |

ManyLUT 通过交错共享一次盲旋转，多输出返回还共享一次 Q→q 转换并分块进行 LWE key switch；分解式 MVB 通过公共因子生成多输出，是不同的求值接口。 NTRU sparse 支持普通/交错 PBS、分解式 MVB、CBS 和 one-hot；稀疏 BR 要求 fixed-weight binary 外部秘密。

消息 codec 在 `main` 中独立选择，密钥生成不依赖 t。CBS/one-hot 的容量在绑定输入 codec 时检查。

客户端工厂只接收所需秘密：普通及 Boolean 加解密传入 `client_key.external_lwe_secret_key()`，`accumulator_client` 传入 `client_key.accumulator_ntru_secret_key()`。完整 `ClientKey` 组合用于生成服务端密钥；选择角色不会复制秘密缓冲区。

## 参数与表示

`TfheParameters::try_from_config(TfheConfig { .. })` 检查数学配置； `TfheContext::<_, U32NttTable>::try_from_parameters(parameters)` 准备变换表。 已有表用 `TfheContext::try_new(parameters, table)` 绑定。 `TfheConfig`、`TfheParameters`、`Encryptor` 和 `Decryptor` 将家族 API 特化为 `BarrettModulus`。 `TfheParameters<T, LM>` / `TfheContext<T, Table, LM>` 的 `LM` 指定独立外部模数类型（默认沿用后端模数类型）；`accumulator_modulus` 指定环 `Q`。

NTT 表需要实现 `MonomialNttTable`，内置表均支持。Context 检查长度和模数。累加秘密 `NttNtruSecretKey` 记录 Q，普通/gadget 加密在采样前核对它与参数/table 一致。所有变换域密钥及数据须遵循该表的 roots 和求值顺序；相同 Q/N 不能证明表示或秘密身份。

## 求值材料

`ServerKey` 组合独立拥有的 `BlindRotationKey`、`NtruLweKeySwitchingKey` 和可选 `CircuitBootstrapKey`。`into_parts()` 移出组件，不复制密文缓冲；`ServerKey::new(br, return_key, cbs)` 组合各 owner。独立生成分别使用 `KeyGenerator::try_generate_blind_rotation_key(&client, config, rng)`、`parameters.try_generate_lwe_return_key(&client, rng)` 和 `generator.try_generate_circuit_bootstrap_key(client.accumulator_ntru_secret_key(), cbs_parameters, rng)`。`BlindRotationConfig` 选择 classic 或 sparse BR，不额外生成返回或 CBS 材料。独立生成可能重复转换累加秘密；成对生成复用同一次变换。

仅需环输出 CBS/one-hot 时，`context.try_generate_circuit_bootstrap_keys(blind_rotation, cbs_config, rng)` 返回 `(ClientKey, CircuitBootstrapServerKey)`。生成时 BR/CBS 共享已接受的累加秘密变换和逆，不生成返回密钥，也不施加返回 q 的幅度界。通过 `server.bootstrap_resources(&context)` 绑定资源，`server.circuit_bootstrap_key()` 直接取得 CBS 材料，见[材料选择](../primus_tfhe/README.zh_CN.md#选择盲旋转算法)。

`Evaluator::try_from_parts(context, br, return_key)` 绑定普通 PBS。独立 CBS/one-hot 先用 `context.bootstrap_resources(br)?` 准备公共 BR/外积资源，再用 `try_new(&resources, circuit_key, &input_codec)` 准备操作状态，无需返回密钥；CBS 示例展示这一流程。独立材料必须采用相同实际秘密与变换表示，形状和模数检查不能证明身份。

`server_key.blind_rotation_key().classic_controls()` 返回借用的 `ClassicControls` 视图，稀疏材料返回 `None`。视图的 `initializer()` 用于提升公开多项式；首坐标使用 NLEV bit，后续坐标使用 NGSW bit，ternary 秘密按正/负 bit 配对。CBS、one-hot 在所选 classic/sparse BR 上使用独立的 trace/scheme-switch 材料；MVB 不需要额外的提升或 CBS 材料。可选的 `circuit_bootstrap_key()` 仍可用于查看或组合 CBS 材料。

`KeyGenerator::try_generate_public_lift_key(accumulator_secret, &nlev_parameters, rng)` 为需要公开提升的高精度表独立生成 NLEV[1]。参数选择其 basis 和行噪声；查表绑定时同时提供密文及这些参数。Sparse PBS/CBS/one-hot 和无公开提升的表均无需此材料。

## 复用 evaluator

普通/interleaved `Evaluator` 拥有公共 `BootstrapResources` 和 scalar/batch 返回缓冲。CBS/one-hot 只保存 LUT 与投影缓冲，调用时最后一个参数传 `pbs.bootstrap_resources_mut()`；factorized MVB 使用 `FactorizedEvaluator::new(&pbs)` 构造，调用时最后一个参数传 `&mut pbs`。借用结束即可继续普通 PBS，无需转换或恢复 evaluator；在线 `_to` 复用所有缓冲。操作状态在写入前检查同一 context。实际输入与累加秘密相同的 classic/sparse 资源可以共享准备状态；context 身份不证明秘密身份。

`Resources` 将借用的 context/计算材料与拥有的复用缓冲组合起来，不拥有或复制密钥。`Workspace` 表示缓冲及形状元数据，包括底层 BR/外积 scratch。`Evaluator` 使用自己拥有或短借用的资源执行具体流程。借用期间须保留 context/key 的 owner；串行操作可共享一个可变资源实例，并发请求需要独立的可变资源。NTT 表由 context 拥有，密钥视图与乘积必须保持该表的表示。

仅使用 CBS/one-hot 时，单独保留 `BootstrapResources`，不分配返回缓冲。以后需要 PBS，可用 `Evaluator::try_from_resources(resources, return_key)` 接管公共资源并分配返回缓冲。`try_rebind_return_key` 更换兼容返回密钥而不重新分配；成功时丢弃待提交样本，失败保持原绑定。资源所有权变化不验证密钥的实际秘密身份。

## 固定尺度分解式 MVB

通过 `context.compile_factorized_lookup_table_fn(&codecs, domain_len, output_count, function)` 编译并绑定 `FactorizedEvaluator`；程序借用该 context，输出使用 unsigned Scaled 编码。 `factorized_pbs_codecs` 从同一输出消息模数准备 Q 下的 LUT 编码和 q 下的返回解码；须预算 `(q/Q)*round(Q/t_out)` 与 `round(q/t_out)` 的差及返回噪声。

系数模数必须为奇数；预处理后的因子保留 NTT 表示。

经典 binary/ternary 和 sparse fixed-weight binary 均在所有输出间共享提升和盲旋转。每个因子乘积独立完成 Q→q 和提取，再复用 PBS 工作区分块批量执行 LWE KS。提取后即复用系数多项式缓冲，不同时保留所有乘积。 因子同时放大初始化与 BR 噪声，返回 KS 噪声在乘积后加入。

运行[17 阈值示例](examples/ntru_ntt_mvb_thresholds.rs)，命令使用 `--example ntru_ntt_mvb_thresholds`。 它展示交错容量之外的多输出；算法选择及编码限制见[共享 MVB 契约](../primus_tfhe/README.zh_CN.md#固定尺度分解式-mvb)。

## 实验性稀疏 PBS

本后端重导出家族的[共享系数密钥](../primus_tfhe_ntru/README.zh_CN.md#sparse-系数密钥) `SparseNtruBootstrappingKey<T>`；生成、变换及桶聚合仍由各后端负责。

`KeyGenerator::try_generate_server_key(&client, blind_rotation, cbs, rng)` 为已有客户端选择 `BlindRotationConfig::Classic` 或 `Sparse { copy_count, bucket_count }`；同一个 fixed-weight binary 秘密支持两者。CBS 传 `None` 只生成普通 BR/返回材料，传 `Some(config)` 则添加 CBS 密钥。成对生成快捷入口 `context.try_generate_keys(blind_rotation, cbs, rng)` 接收同样的选择并复用变换后的秘密；独立组件不要求完整密钥包。见[算法和材料选择](../primus_tfhe/README.zh_CN.md#选择盲旋转算法)。

为 external-LWE 选择固定重量 binary 分布，并显式选择 sparse；秘密分布本身不决定算法。要求 `0<h<n`、`copy_count>=1`、`bucket_count>=max(copy_count,h)`。

```rust,ignore
let blind_rotation = BlindRotationConfig::Sparse { copy_count: 3, bucket_count: 2 * h };
let (client, server) = context.try_generate_keys(blind_rotation, None, &mut rng)?;
let mut evaluator = context.evaluator(&server)?;
```

普通/交错 PBS 复用原 evaluator，分解式 MVB 每次调用时借用它。将 `None` 改为 `Some(cbs_config)` 会复用累加秘密变换并生成 CBS/one-hot 材料。仅需环输出时，以同样的 sparse 选择调用 `try_generate_circuit_bootstrap_keys`，无需返回密钥。 `server.blind_rotation_key().sparse_blind_rotation_key()` 提供选择密文。

## 可选电路自举

`parameters.circuit_bootstrap_codecs(t_in, t_ring)?` 返回 Rounded 输入与 Scaled 候选环消息编码，自动提供正确的 q/Q，两个明文域独立。将前者传给输入 encryptor 和 CBS evaluator，后者传给 `accumulator_client`；它不描述 CBS 的 gadget 输出。

用 `key.parameters().compile_lookup_table_fn(&input_codec, |m| u64::from(m >= 2))?` 编译整数函数，或将完整前半区结果切片传给 `compile_lookup_table_slice`。通过 `CircuitBootstrapEvaluator::try_with_lookup_table(&resources, key, program)?` 绑定返回的 `CircuitBootstrapLookupTable`；`try_new` 保留恒等函数默认入口。输出层使用 `g_j * F(m) mod Q`，无需输出消息 codec 或额外 BR。CMux 要求整个输入域上的 F 都是 bit；其他环整数遵循外积噪声契约。普通 CBS 示例使用 t_in=8，展示该谓词的正反分支。

`context.try_generate_circuit_bootstrap_keys(blind_rotation, cbs_config, &mut rng)` 为环输出生成配对材料，`CircuitBootstrapServerKey` 持有 BR、必要的输入准备和 CBS 材料；`circuit_bootstrap_key()` 直接返回必需的密钥。混合 PBS/CBS 仍可用 `try_generate_keys(blind_rotation, Some(cbs_config), rng)` 生成完整 `ServerKey`。取出 `server.circuit_bootstrap_key()`，与公共资源一起传给 `CircuitBootstrapEvaluator::try_new`；该构造器显式要求 CBS 材料。使用 `allocate_output`、`circuit_bootstrap_to` 和 `cmux_to`；[CBS → CMUX 示例](examples/ntru_ntt_circuit_bootstrap.rs)展示完整消费链。

输出为 `f_acc` 下的 `NttNgswCiphertext`。Circuit key 绑定完整输出 basis； `try_new(&resources, circuit_key, &input_codec)` 从该密钥取得参数。 NTT trace 归一化要求奇数 Q 且小于 `2^(T::BITS-1)`。

独立生成组件时须配对秘密并使用同一变换表示，形状检查不能证明身份。 输入/输出与消费要求见[共享 CBS 契约](../primus_tfhe/README.zh_CN.md#cbs-输出与消费)及 [家族 CBS 说明](../primus_tfhe_ntru/README.zh_CN.md#cbs-与示例)。

## One-hot CBS

[One-hot 示例](examples/ntru_ntt_one_hot.rs)生成四个 selector，并用 `TARGET=2` 对应的 δ₂ 控制 CMux；修改 `TARGET` 选择其他分支。绑定 `OneHotCircuitBootstrapEvaluator::try_new(&resources, circuit_key, &input_codec)`，分配后复用 `_to` 调用。

完整/非零输出接口、布局与输入保护区见[家族 one-hot 契约](../primus_tfhe_ntru/README.zh_CN.md#one-hot-cbs)。NLEV 输出为 Q 下的系数，需要 `write_ntt_form` 转换才能做公开多项式外积；NGSW 已在 NTT 表示。输入、密钥和候选必须满足本页的变换契约。

`ngsw_selector_len()` 返回单个变换域 NGSW selector 的长度；`ngsw_batch_len()` 返回包含分支零的完整批次长度。两者均以NTT 环元素个数计量，不是字节数。

消费时通过 `cbs.ngsw_selectors(&output)` 或
`cbs.nonzero_ngsw_selectors(&output)` 借用 `NttNgswSelectors`。
`selector(r)` 按数学编号取得 δᵣ，`iter()` 返回 `(r, control)`。
完整批次覆盖 `0..M`，紧凑批次覆盖 `1..M`，后者的 `selector(0)` 返回
`None`。视图检查精确批次长度，直接借用原缓冲，不复制、不分配。
`cbs.nlev_selectors(&output)` 同样借用完整的系数域 NLEV 批次。

取得单个 control 后，调用 `cbs.cmux_to(&control, &lhs, &rhs, &mut selected, &mut resources)`：δᵣ=0 选择 lhs，δᵣ=1 选择 rhs。`cbs.external_product_to(&control, &input, &mut output, &mut resources)` 则计算 selector 与环密文的乘积。两个入口复用已绑定的 output basis、变换环境和共享 scratch；候选的秘密、模数、编码与噪声仍须符合 CMux/外积契约。完整/非零批次使用相同消费接口，传入的是一个 selector。

需要立即消费每个结果时，`new_sparse_pair_workspace(&resources)` 分配一个额外输入状态，`with_sparse_pair` 一起执行两个 sparse 输入的盲旋转。回调依次收到索引 0、1 和受限的 `OneHotProjection`；`project_to` 将完整 NLEV 和/或非零 NGSW 写入复用缓冲，每次回调内完成消费。高精度 LUT evaluator 自动使用此路径。

## 高精度查表

[primus_tfhe_ntru_lut](../primus_tfhe_ntru_lut/README.zh_CN.md) 组合 one-hot CBS、表选择、聚合负向旋转和独立 LWE 返回，支持统一输入/输出 chunk 位宽及独立数量。底层组合可通过 `server_key.blind_rotation_key().classic_controls().unwrap().initializer()` 取得 context 的 BR basis 下的 classic NLEV[1]，通过 `key_switching_key()` 取得 Q→q、f→s 返回密钥。

完整 chunk 加密与查表工作流见 [ntt_lookup.rs](../primus_tfhe_ntru_lut/examples/ntt_lookup.rs)。

自定义返回先绑定 `LweReturnEvaluator::new(server.key_switching_key(),
context.parameters().external_lwe().cipher_modulus())`，再按需准备 scalar/batch 工作区，
显式传给 `return_at_to`、`return_prefix_to` 或流式操作。one-hot 与变换工作区可独立复用。
详见[家族返回契约](../primus_tfhe_ntru/README.zh_CN.md#ntrulwe-返回)。

## 底层组合

Rustdoc 按职责组织 `key`（服务端材料）、`circuit_bootstrap`（CBS）、 `factorized`（MVB 程序和执行）与 `sparse`（桶材料）；常用工作流类型仍从 crate 根导入。

基准集中在 [`primus_tfhe_benchmarks`](../../benchmarks/tfhe/README.zh_CN.md#targets)。按运算选择 `pbs`、`sparse_pbs`、`mvb`、`cbs` 或显式诊断 `setup` target。选择 `--features ntru-ntt`。

## 进一步阅读

本 crate 在普通依赖上固定启用 `ntt`；无需额外后端开关，单独使用不引入 Fourier/FFT。默认 features 为空；可选 `simd` 启用依赖中的 nightly SIMD 算术。

[Boolean 门](../primus_tfhe/README.zh_CN.md#boolean-门) · [错误边界](../primus_tfhe/README.zh_CN.md#错误边界) · [实现说明](../primus_tfhe/IMPLEMENTATION.md) · [基准指南](../../benchmarks/tfhe/BENCHMARKS.md)
