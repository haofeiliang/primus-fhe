# primus_tfhe_glwe_ntt

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

基于显式域模数的 GLWE TFHE 后端。 先读[任务与编码选择](../primus_tfhe/README.zh_CN.md#选择同态操作)，再读 [GLWE 参数与密钥域](../primus_tfhe_glwe/README.zh_CN.md)。示例使用功能参数，不是经认证的安全或失败概率参数。

## 实验配套参数

```rust
use primus_tfhe_glwe_ntt::{experimental, TfheContext};
use primus_ntt::U64NttTable as Table;

let config = experimental::CLASSIC_PBS_U64;
// Context 使用 config.messages；构造前修改 output_modulus 即可覆盖默认输出域。
let context = TfheContext::<u64, Table>::try_from_pbs_config(config)?;
```

`PbsConfig` 用一个纯数值类型组合 BR/KS 与输入输出消息配置；`CbsConfig` 表示环输出 CBS，其 gadget 输出不使用普通消息 codec。`experimental` 另导出 `SPARSE_PBS_U64`、`CLASSIC_MANY_LUT_U64`、`CLASSIC_THRESHOLD_MVB_U64`、`CLASSIC_CBS_U64` 和 `SPARSE_CBS_U64`。Context 保留算法、KS、消息选择与可选 CBS 状态，默认密钥生成不再补传这些参数。配置实现 `Copy`，可直接覆盖字段或使用 struct update，而无需先准备采样器。

这些 u64 常量为算术样例，安全性与失败概率尚未评估。组合方式、独立消息覆盖和数值契约见[家族配置](../primus_tfhe_glwe/README.zh_CN.md#实验配套参数)。所有示例均从对应操作配置开始；高级显式组合继续使用家族构造器。`PbsParameters` 可供兼容编码复用；改变工作负载后仍须重新确定误差预算。

## 快速开始

示例从 `config.messages` 读取输入/输出消息模数：`PbsMessageConfig::new(t)` 默认两者相同，`with_output_modulus(t_out)` 只修改输出。`context.encryptor(external_secret)` 选择 Rounded 输入；普通 PBS/ManyLUT 用 `pbs_decryptor`，MVB 的 Scaled 输出用 `mvb_decryptor`。客户端不接收 LUT，也不要求手工创建 codec。见[选择输出编码](../primus_tfhe/README.zh_CN.md#选择输出编码)。

```sh
cargo run -p primus_tfhe_glwe_ntt --release --example ntt_basic
```

[basic 示例](examples/ntt_basic.rs)展示配置 → context → 配对密钥 → 客户端 → LUT → 复用 evaluator 和缓冲。它计算 `x % 4`，输入/输出均采用 `t=32`。`context.pbs_lookup_table_compiler()?.compile_fn(function)` 编译公开 LUT，公钥客户端用 `context.public_encryptor(&public)`。输入加密使用配置中的 `messages.input_modulus`；构造 Context 前用 `config.messages = PbsMessageConfig::new(t_in).with_output_modulus(t_out)` 独立设置输入、输出域。高级同钥组合通过家族参数工厂复用已准备的 codec，见[选择输出编码](../primus_tfhe/README.zh_CN.md#选择输出编码)。

示例固定 `Word = u64`，使用下表对应的操作配置。尺寸、模数表示、秘密分布、噪声和分解集中在 `experimental`；各个 `main` 只展示准备、公开函数、客户端和求值。CBS 使用完整的 `CbsParameters`，消费端独立选择候选环消息域。 高级显式组合仍支持 u32/u64，见[家族配置](../primus_tfhe_glwe/README.zh_CN.md#实验配套参数)和[数值参数指南](../../guides/development/tfhe-parameters.md)。

注释标明客户端和服务端阶段。Basic 与 sparse 都计算 `x % 4`，默认输入输出消息模数相同；独立 ManyLUT 示例同时计算 `x % 4` 和 `x / 4`，显式设置 `t_in=16`、`t_out=8`，并用输出 codec 解密。每例复用 LUT、evaluator 和输出缓冲处理两次请求。见[双方职责与缓冲分配](../primus_tfhe/README.zh_CN.md#客户端与服务端边界)。

| 操作 | `experimental` 配置 | 完整示例 |
| --- | --- | --- |
| Classic PBS | `CLASSIC_PBS_U64` | [basic](examples/ntt_basic.rs) |
| Sparse PBS | `SPARSE_PBS_U64` | [sparse](examples/ntt_sparse.rs) |
| 交错多输出 ManyLUT，独立输出消息模数 | `CLASSIC_MANY_LUT_U64` | [many_lut](examples/ntt_many_lut.rs) |
| Classic CBS → CMux | `CLASSIC_CBS_U64` | [circuit_bootstrap](examples/ntt_circuit_bootstrap.rs) |
| Sparse CBS → CMux | `SPARSE_CBS_U64` | [sparse_circuit_bootstrap](examples/ntt_sparse_circuit_bootstrap.rs) |
| 分解式 MVB | `CLASSIC_THRESHOLD_MVB_U64` | [thresholds](examples/mvb_thresholds.rs) |

ManyLUT 通过交错共享一次盲旋转；分解式 MVB 通过公共因子生成多输出，是不同的求值接口。

客户端工厂只接收所需秘密：普通及 Boolean 加解密传入 `client_key.external_lwe_secret_key()`，`accumulator_client` 传入 `client_key.glwe_secret_key()`。完整 `ClientKey` 组合用于生成服务端密钥；选择角色不会复制秘密缓冲区。

## 参数与表示

`PbsParameters::try_from_config(pbs_config)` 保存必需 KS、算法和消息选择；`CbsParameters::try_from_config(cbs_config.pbs, cbs_config.gadget)` 增补 CBS gadget 和输入编码。Context 构造保存一份公共参数和变换表。`parameters()` 始终提供完整 PBS 域，`cbs_parameters()` 查询额外 CBS 能力。PBS 和 CBS 共享必需 KS；CBS 输出环/gadget 密文后，后续运算可用同一 KS 返回 LWE。

已有参数按值移入 `TfheContext::try_from_parameters(parameters)` 或 `try_from_cbs_parameters(parameters)`；已有表使用 `try_new(parameters, table)`。默认准备不复制公共 sampler。CBS 和 PBS 共用环 sampler 的既有 Arc，不再引入独立 BR 参数 owner。`PbsParameters::try_from_config(pbs)` 准备公共状态；`CbsParameters::try_from_config(pbs, gadget)` 或 `try_with_config(parameters, gadget)` 添加 CBS。后者直接移动已准备状态，输入消息模数取自 PBS 参数。

NTT 表需要实现 `MonomialNttTable`，内置表均支持。Context 检查长度和模数； 所有变换域密钥及数据须遵循该表的表示约定。 拥有型 `NttGlweSecretKey` 保存 q，普通加密及求值密钥生成在采样前拒绝异模数密钥；导入使用 `new(values, size, distribution, modulus)`。相同 q/N 不证明 roots/order 或秘密身份，见 [GLWE 密钥契约](../primus_glwe/README.zh_CN.md)。

`PbsOrder::BootstrapKeyswitch` 的外部维数为 n，`KeyswitchBootstrap` 为 dN。 用 `context.allocate_lwe_ciphertext()` 按当前 order 分配。 Basic 示例使用 binary 秘密和 `BootstrapKeyswitch`；MVB 示例使用 `KeyswitchBootstrap`。

## 复用 evaluator

普通/交错 `Evaluator` 拥有公共 `BootstrapResources` 与返回阶段。默认 `CbsEvaluator` 组合 CBS 程序、投影缓冲和所需输入/BR 资源；独立 `CircuitBootstrapEvaluator` 执行时短借用 `pbs.bootstrap_resources_mut()`。MVB 用 `FactorizedEvaluator::new(&pbs)` 构造，每次执行传入 `&mut pbs`。串行操作可复用同一资源实例。

`Resources` 将借用的 context/计算材料与拥有的复用缓冲组合起来，不拥有或复制密钥。`Workspace` 表示缓冲及形状元数据，包括底层 BR/外积 scratch。`Evaluator` 使用自己拥有或短借用的资源执行具体流程。借用期间须保留 context/key 的 owner；串行操作可共享一个可变资源实例，并发请求需要独立的可变资源。NTT 表由 context 拥有，密钥视图与乘积必须保持该表的表示。

`ServerKey` 仍是完整 PBS 的便捷组合。高级工作流可分别持有 `BlindRotationKey`、环 KS key 和 `CircuitBootstrapKey`，通过 `ServerKey::new(br, ks)` / `into_parts` 移动 BR/KS，或通过 `CircuitBootstrapServerKey::new(server_key, circuit_key)` / `into_parts` 移动 CBS 组合，不复制密文数组。`KeyGenerator::try_generate_blind_rotation_key(&client, config, rng)` 通过 `BlindRotationMethod` 选择 classic 或 sparse BR，不额外生成返回或 CBS 材料；`try_generate_glwe_key_switching_key` 独立生成环 KS；`try_generate_circuit_bootstrap_key(accumulator_secret, cbs_parameters.gadget().clone(), rng)` 只需要累加器秘密。独立生成可能重复转换秘密；成对生成继续复用已准备的表示。

`context.try_generate_circuit_bootstrap_keys(rng)` 返回 `(ClientKey, CircuitBootstrapServerKey)`；其中 `ServerKey` 始终含 BR/KS，CBS key 也始终存在。`server.bootstrap_resources(&context)` 仅准备实际 BR/输入 KS 工作区；BR→KS 的 CBS 不分配返回 scratch。用 `context.circuit_bootstrap_evaluator(&server)` 准备恒等 CBS，后续 LWE 返回可复用 `server.server_key()` 的 KS。见[材料选择](../primus_tfhe/README.zh_CN.md#选择盲旋转算法)。

CBS 主线接收完整服务端密钥，自动组合所需资源：

```rust,ignore
let mut cbs = context.circuit_bootstrap_evaluator(&server)?;
```

工厂为 KS→BR 选择输入 KS；BR→KS 不分配返回 scratch。通过 `cbs.into_parts()` 可移动取出操作状态和公共资源，以复用到后续 PBS。已有 PBS evaluator 时，用 `context.circuit_bootstrap_evaluator_with_resources(pbs.bootstrap_resources(), circuit_key)?`，每次执行短借用其资源；底层 `try_new` 允许显式输入编码。

独立生成材料时，使用 `context.bootstrap_resources(br, input_ks)`：BR→KS 可传 `None`，KS→BR 必须传 `Some((ks_parameters, ks))`；独立 CBS 不要求普通返回密钥。`Evaluator::try_from_parts(context, parameters.glwe_key_switching(), br, ks)` 绑定完整 PBS/ManyLUT。两种入口均支持 classic/sparse。布局、basis 和模数检查不证明实际秘密或变换身份。

`Evaluator::try_from_resources(resources, parameters.glwe_key_switching(), ks)` 组合普通 PBS，只有 BR→KS 需要分配缺少的输出阶段。`try_rebind_key_switching_key(ks)` 用兼容材料复用活跃 KS 阶段的缓冲，失败保留旧绑定。CBS/MVB 接受同一 context 创建的任意资源实例，在写入前检查；调用方仍须配对秘密，可变资源借用必须保留所属 PBS 的绑定。

## 固定尺度分解式 MVB

用 `context.compile_mvb_fn(domain_len, output_count, function)` 编译并绑定 `FactorizedEvaluator`。输入沿用 `encryptor`，unsigned Scaled 输出用 `context.mvb_decryptor(external_secret)` 解密，两者均读取配置的消息域。同一密钥配合其他输出域时，为编译和 `parameters.decryptor_with_codec` 共同复用 `parameters.factorized_pbs_codecs(messages)`；编译程序不会改变已有解密器。程序仍绑定该 context。 LUT 和返回 LWE 使用同一密文模数。 高级组合和数值对比仍可通过 `compile_factorized_lookup_table_fn` 显式传入已准备 codec。

系数模数必须为奇数；预处理后的因子保留 NTT 表示。

两种 order 均支持经典/稀疏密钥。BR→KS 在每个因子乘积后 KS，KS→BR 先对输入做一次 KS。 额外工作区大小与输出个数无关。

运行[17 阈值示例](examples/mvb_thresholds.rs)，命令使用 `--example mvb_thresholds`。 它展示交错容量之外的多输出；算法选择及编码限制见[共享 MVB 契约](../primus_tfhe/README.zh_CN.md#固定尺度分解式-mvb)。

## 实验性稀疏 PBS

普通 PBS 使用 `context.try_generate_keys(rng)` 和 `context.evaluator(&server)`；已有 client 使用 `context.try_generate_server_key(&client, rng)`。CBS 使用 `try_generate_circuit_bootstrap_keys` / `try_generate_circuit_bootstrap_server_key`，返回 `CircuitBootstrapServerKey`。`try_with_circuit_bootstrap(gadget)` 为 Context 添加 CBS 能力；普通工厂仍返回 BR/KS `ServerKey`。高级显式工厂分别接收 KS、算法，以及 CBS 工厂所需的 gadget。

为 small-LWE 选择固定重量 binary 分布，并显式选择 sparse；秘密分布本身不决定算法。要求 `0<h<n`、`copy_count>=1`、`bucket_count>=max(copy_count,h)`。

```rust,ignore
let config = experimental::SPARSE_PBS_U64;
let context = TfheContext::<_, Table>::try_from_pbs_config(config)?;
let (client, server) = context.try_generate_keys(&mut rng)?;
let mut evaluator = context.evaluator(&server)?;
```

两种 order 均支持普通/交错 PBS、MVB 和 CBS。`try_generate_circuit_bootstrap_keys` 生成 CBS 材料并共享一份 BR/KS；`ServerKey::blind_rotation_key()` 可查看 classic/sparse 变体。

独立的 `sparse_paper` 基准提供 `paper_2026_1730` NAND 和带 padding 函数对比组；普通 `sparse_pbs` 只保留固定重量对照。`complete_ring_return` 包含本后端的 ring KS 返回，`blind_rotation` 不包含返回。具体参数、测量与论文的差异见[对比记录](../../guides/performance/sparse-paper-comparison.md)；这些是实验性基准参数，不是安全参数预设。

独立的 `sparse_candidate_r2` ID 为已验证的 STD128 和三位函数配置选择两个副本、`2*h` 个桶及更少的 BR 层数。[消费者测量](../../guides/performance/sparse-consumer-measurements.md)覆盖 PBS、ManyLUT、MVB 和反馈调用。CBS 需要独立选择输出基：PBS 配置能正确工作，不代表其 gadget 控制和后续 CMux 也满足误差要求。

## 电路自举

Context 保存 Rounded 输入编码与 CBS gadget。使用 `context.encryptor(external_secret)?` 加密；`context.accumulator_client(client.glwe_secret_key(), t_ring)?` 独立准备 Q 下的 Scaled 候选环客户端，t_ring 不必等于输入或普通 PBS 输出消息模数。CBS 输出采用 gadget 标度。

用 `context.compile_cbs_fn(|m| u64::from(m >= 2))?` 编译整数函数，或将完整前半区结果切片传给 `compile_cbs_slice`；`compile_cbs_identity()` 提供恒等函数。`context.circuit_bootstrap_evaluator_with_lookup_table(&server, program)?` 移入程序并组合复用资源，`context.circuit_bootstrap_evaluator(&server)?` 则准备恒等 CBS。工厂核对输入消息区间、q/Q、basis 和密钥布局；相同输入数量不能证明编码相同。输出层为 `g_j * F(m) mod Q`；CMux 要求整个输入域上 F 都为 bit，其他环整数遵循外积噪声契约。

`context.try_generate_circuit_bootstrap_keys(&mut rng)` 生成完整 `CircuitBootstrapServerKey`。默认 `CbsEvaluator` 的 `circuit_bootstrap_to(input.as_view(), control.as_mut_view())` 与 `cmux_to(control.as_view(), lhs.as_view(), rhs.as_view(), selected.as_mut_view())` 不需要另传 resources。[CBS → CMUX 示例](examples/ntt_circuit_bootstrap.rs)展示两次请求；普通 PBS 可借用 `server.server_key()`。

逐调用借用公共资源、其他输入编码或 GLWE 替代 output basis 使用底层 `CircuitBootstrapEvaluator`。实际秘密/变换身份、候选共同编码和噪声余量仍为调用方契约。见[共享 CBS 契约](../primus_tfhe/README.zh_CN.md#cbs-输出与消费)。

## 底层组合

本后端重导出[共享系数密钥](../primus_tfhe_glwe/README.zh_CN.md#sparse-系数密钥)，使用 `SparseGlweBootstrappingKey<T, BarrettModulus<T>>`。Raw sparse BR 使用 `workspace.blind_rotate_lookup_table_to(&key, input, lut, output, ntt)`；工作区持有 scratch，仅在调用时借用密钥。

Rustdoc 按职责组织 `key`（服务端材料）、`circuit_bootstrap`（CBS）、 `factorized`（MVB 程序和执行）与 `sparse`（稀疏生成与旋转）；常用工作流类型仍从 crate 根导入。 原始 GLWE 控制材料和 BR 工作区见 `bootstrapping_key` 与 `blind_rotation`。

基准集中在 [`primus_tfhe_benchmarks`](../../benchmarks/tfhe/README.zh_CN.md#targets)。按运算选择 `pbs`、`sparse_pbs`、`mvb`、`cbs` 或显式诊断 `setup` target。选择 `--features glwe-ntt`。

## 进一步阅读

本 crate 在普通依赖上固定启用 `ntt`；无需额外后端开关，单独使用不引入 Fourier/FFT。默认 features 为空；可选 `simd` 启用依赖中的 nightly SIMD 算术。

[Boolean 门](../primus_tfhe/README.zh_CN.md#boolean-门) · [错误边界](../primus_tfhe/README.zh_CN.md#错误边界) · [实现说明](../primus_tfhe/IMPLEMENTATION.md) · [基准指南](../../benchmarks/tfhe/BENCHMARKS.md)
