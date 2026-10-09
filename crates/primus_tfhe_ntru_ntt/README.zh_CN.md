# primus_tfhe_ntru_ntt

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

基于显式域模数的 NTRU TFHE 后端。 先读[任务与编码选择](../primus_tfhe/README.zh_CN.md#选择同态操作)，再读 [NTRU 参数与密钥域](../primus_tfhe_ntru/README.zh_CN.md)。示例使用功能参数，不是经认证的安全或失败概率参数。

## 实验配套参数

```rust
use primus_tfhe_ntru_ntt::{experimental, TfheContext};
use primus_ntt::U64NttTable as Table;

let config = experimental::CLASSIC_PBS_U64;
// Context 使用 config.messages；构造前修改 output_modulus 即可覆盖默认输出域。
let context = TfheContext::<u64, Table, _>::try_from_pbs_config(config)?;
```

`PbsConfig` 用一个纯数值类型组合 BR/KS 与输入输出消息配置；`CbsConfig` 表示环输出 CBS，其 gadget 输出不使用普通消息 codec。`experimental` 另导出 `SPARSE_PBS_U64`、`CLASSIC_MANY_LUT_U64`、`CLASSIC_THRESHOLD_MVB_U64`、`CLASSIC_CBS_U64` 和 `CLASSIC_ONE_HOT_U64`。Context 保留算法、KS、消息选择与可选 CBS 状态，默认密钥生成不再补传这些参数。配置实现 `Copy`，可直接覆盖字段或使用 struct update，而无需先准备采样器。

这些 u64 常量为算术样例，安全性与失败概率尚未评估。组合方式、独立消息覆盖和数值契约见[家族配置](../primus_tfhe_ntru/README.zh_CN.md#实验配套参数)。所有示例均从对应操作配置开始；高级显式组合继续使用家族构造器。`PbsParameters` 可供兼容编码复用；改变工作负载后仍须重新确定误差预算。

## 快速开始

示例从 `config.messages` 读取输入/输出消息模数：`PbsMessageConfig::new(t)` 默认两者相同，`with_output_modulus(t_out)` 只修改输出。`context.encryptor(external_secret)` 选择 Rounded 输入；普通 PBS/ManyLUT 用 `pbs_decryptor`，MVB 的 Scaled 输出用 `mvb_decryptor`。客户端不接收 LUT，也不要求手工创建 codec。见[选择输出编码](../primus_tfhe/README.zh_CN.md#选择输出编码)。

```sh
cargo run -p primus_tfhe_ntru_ntt --release --example ntru_ntt_basic
```

[basic 示例](examples/ntru_ntt_basic.rs)展示配置 → context → 配对密钥 → 客户端 → LUT → 复用 evaluator 和缓冲。它计算 `x % 4`，输入/输出均采用 `t=32`。`context.pbs_lookup_table_compiler()?.compile_fn(function)` 编译公开 LUT，公钥客户端用 `context.public_encryptor(&public)`。输入加密使用配置中的 `messages.input_modulus`；构造 Context 前用 `config.messages = PbsMessageConfig::new(t_in).with_output_modulus(t_out)` 独立设置输入、输出域。高级同钥组合通过家族参数工厂复用已准备的 codec，见[选择输出编码](../primus_tfhe/README.zh_CN.md#选择输出编码)。 外部 `q=2^24` 与环 Q 不同：编译使用 Q，输出解码使用 q。

示例固定 `Word = u64`，使用下表对应的操作配置。尺寸、模数表示、秘密分布、噪声和分解集中在 `experimental`；各个 `main` 只展示准备、公开函数、客户端和求值。CBS 使用完整的 `CbsParameters`，消费端独立选择候选环消息域。 高级显式组合仍支持 u32/u64，见[家族配置](../primus_tfhe_ntru/README.zh_CN.md#实验配套参数)和[数值参数指南](../../guides/development/tfhe-parameters.md)。

注释标明客户端和服务端阶段。Basic 与 sparse 都计算 `x % 4`，默认输入输出消息模数相同；独立 ManyLUT 示例同时计算 `x % 4` 和 `x / 4`，显式设置 `t_in=16`、`t_out=8`，并用输出 codec 解密。每例复用 LUT、evaluator 和输出缓冲处理两次请求。见[双方职责与缓冲分配](../primus_tfhe/README.zh_CN.md#客户端与服务端边界)。

| 操作 | `experimental` 配置 | 完整示例 |
| --- | --- | --- |
| Classic PBS | `CLASSIC_PBS_U64` | [basic](examples/ntru_ntt_basic.rs) |
| Sparse PBS | `SPARSE_PBS_U64` | [sparse](examples/ntru_ntt_sparse.rs) |
| 交错多输出 ManyLUT，独立输出消息模数 | `CLASSIC_MANY_LUT_U64` | [many_lut](examples/ntru_ntt_many_lut.rs) |
| CBS → CMux | `CLASSIC_CBS_U64` | [circuit_bootstrap](examples/ntru_ntt_circuit_bootstrap.rs) |
| 分解式 MVB | `CLASSIC_THRESHOLD_MVB_U64` | [thresholds](examples/ntru_ntt_mvb_thresholds.rs) |
| One-hot CBS → CMux | `CLASSIC_ONE_HOT_U64` | [one_hot](examples/ntru_ntt_one_hot.rs) |
| 高精度查表 | `primus_tfhe_ntru_lut::experimental::NTT_CLASSIC_LOOKUP_U64` | [lookup](../primus_tfhe_ntru_lut/examples/ntt_lookup.rs) |

ManyLUT 通过交错共享一次盲旋转，多输出返回还共享一次 Q→q 转换并分块进行 LWE key switch；分解式 MVB 通过公共因子生成多输出，是不同的求值接口。 NTRU sparse 支持普通/交错 PBS、分解式 MVB、CBS 和 one-hot；稀疏 BR 要求 fixed-weight binary 外部秘密。

普通 PBS/ManyLUT/MVB 的客户端与编译器从 Context 的消息选择派生 codec，密钥生成不依赖 t。CBS/one-hot 的候选 codec 仍显式绑定。CBS/one-hot 的容量在绑定输入 codec 时检查。

外部 LWE 工厂接收 `client_key.external_lwe_secret_key()`：`encryptor` / `pbs_decryptor` / `mvb_decryptor` 及 Boolean 工厂从配置中的消息域准备编码；Boolean 门要求输入、输出均为 t=4。环客户端使用 `accumulator_client(client_key.accumulator_ntru_secret_key(), t_ring)`，显式选择独立的候选消息模数。完整 `ClientKey` 组合用于生成服务端密钥；选择角色不会复制秘密缓冲区。

## 参数与表示

`PbsParameters::try_from_config(pbs_config)` 保存必需 KS、算法和消息选择；`CbsParameters::try_from_config(cbs_config.pbs, cbs_config.gadget)` 增补 CBS gadget 和输入编码。Context 构造保存一份公共参数和变换表。`parameters()` 始终提供完整 PBS 域，`cbs_parameters()` 查询额外 CBS 能力。PBS 和 CBS 共享必需 KS；CBS 输出环/gadget 密文后，后续运算可用同一 KS 返回 LWE。

已有参数按值移入 `TfheContext::try_from_parameters(parameters)` 或 `try_from_cbs_parameters(parameters)`；已有表使用 `try_new(parameters, table)`。默认准备不复制公共 sampler。CBS 和 PBS 共用环 sampler 的既有 Arc，不再引入独立 BR 参数 owner。`PbsParameters::try_from_config(pbs)` 准备公共状态；`CbsParameters::try_from_config(pbs, gadget)` 或 `try_with_config(parameters, gadget)` 添加 CBS。后者直接移动已准备状态，输入消息模数取自 PBS 参数。 `LM` 选择外部 q 的模数类型，累加环 Q 由 `PbsConfig.acc_modulus` 指定。

NTT 表需要实现 `MonomialNttTable`，内置表均支持。Context 检查长度和模数。累加秘密 `NttNtruSecretKey` 记录 Q，普通/gadget 加密在采样前核对它与参数/table 一致。所有变换域密钥及数据须遵循该表的 roots 和求值顺序；相同 Q/N 不能证明表示或秘密身份。

## 求值材料

`ServerKey` 组合必需的 `BlindRotationKey` 和 `NtruLweKeySwitchingKey`。`CircuitBootstrapServerKey::new(server_key, circuit_key)` 再组合必需 CBS key；两者的 `into_parts()` 均移动缓冲，不复制数组。高级工作流保留独立 BR、返回 KS 和 CBS 生成接口，`BlindRotationMethod` 选择 classic/sparse。独立生成可能重复转换秘密，成对生成复用已接受的变换表示。

`context.try_generate_circuit_bootstrap_keys(rng)` 返回 `(ClientKey, CircuitBootstrapServerKey)`，共享已接受的累加秘密变换/逆元生成 BR/CBS，并生成必需返回 KS。完整组合须满足返回 q 的秘密幅度界。`server.bootstrap_resources(&context)` 只分配 BR 工作区，CBS/one-hot 本身不分配返回缓冲；`server.server_key()` 可绑定普通 PBS，`server.circuit_bootstrap_key()` 直接借用 CBS key。

`Evaluator::try_from_parts(context, parameters.key_switching(), br, return_key)` 绑定普通 PBS。独立 CBS/one-hot 先用 `context.bootstrap_resources(br)?` 准备公共 BR/外积资源，再用 `try_new(&resources, circuit_key, &input_codec)` 准备操作状态，无需返回密钥；CBS 示例展示这一流程。独立材料必须采用相同实际秘密与变换表示，形状和模数检查不能证明身份。

`server_key.blind_rotation_key().classic_controls()` 返回借用的 `ClassicControls` 视图，稀疏材料返回 `None`。视图的 `initializer()` 用于提升公开多项式；首坐标使用 NLEV bit，后续坐标使用 NGSW bit，ternary 秘密按正/负 bit 配对。CBS、one-hot 在所选 classic/sparse BR 上使用独立的 trace/scheme-switch 材料；MVB 不需要额外的提升或 CBS 材料。`CircuitBootstrapServerKey::circuit_bootstrap_key()` 直接借用必需 CBS 材料。

`KeyGenerator::try_generate_public_lift_key(accumulator_secret, &nlev_parameters, rng)` 为需要公开提升的高精度表独立生成 NLEV[1]。参数选择其 basis 和行噪声；查表绑定时同时提供密文及这些参数。Sparse PBS/CBS/one-hot 和无公开提升的表均无需此材料。

## 复用 evaluator

普通/交错 `Evaluator` 拥有公共 `BootstrapResources` 及单项/批量返回缓冲。默认 `CbsEvaluator` / `OneHotEvaluator` 拥有各自的程序、投影缓冲和公共资源，不分配返回 scratch；独立 `CircuitBootstrapEvaluator` / `OneHotCircuitBootstrapEvaluator` 每次短借用 `pbs.bootstrap_resources_mut()`。MVB 用 `FactorizedEvaluator::new(&pbs)` 构造，每次借用 `&mut pbs`。在线 `_to` 调用复用所有缓冲；独立资源须配对实际秘密与同一变换表示。

`Resources` 将借用的 context/计算材料与拥有的复用缓冲组合起来，不拥有或复制密钥。`Workspace` 表示缓冲及形状元数据，包括底层 BR/外积 scratch。`Evaluator` 使用自己拥有或短借用的资源执行具体流程。借用期间须保留 context/key 的 owner；串行操作可共享一个可变资源实例，并发请求需要独立的可变资源。NTT 表由 context 拥有，密钥视图与乘积必须保持该表的表示。

通过 `cbs.into_parts()` 或 `one_hot.into_parts()` 移动取出操作状态与公共资源，不复制或重新分配缓冲。后续 `Evaluator::try_from_resources(resources, parameters.key_switching(), return_key)` 只补充普通 PBS 的返回工作区；已准备的 CBS 状态可继续短借用它。`try_rebind_return_key` 复用返回缓冲更换兼容材料；成功会丢弃待返回样本，失败保留原绑定。

## 固定尺度分解式 MVB

用 `context.compile_mvb_fn(domain_len, output_count, function)` 编译并绑定 `FactorizedEvaluator`。输入沿用 `encryptor`，unsigned Scaled 输出用 `context.mvb_decryptor(external_secret)` 解密，两者均读取配置的消息域。同一密钥配合其他输出域时，为编译和 `parameters.decryptor_with_codec` 共同复用 `parameters.factorized_pbs_codecs(messages)`；编译程序不会改变已有解密器。程序仍绑定该 context。LUT 编码在 Q 下，输出解码在 q 下；须预算 `(q/Q)*round(Q/t_out)` 与 `round(q/t_out)` 的差及返回噪声。高级组合使用家族的 `parameters.compile_factorized_lookup_table_fn(&codecs, ...)` 编译原始程序，再交给本后端的 `NttFactorizedLookupTable::new(&context, raw)`；同钥消息域覆盖可用 `context.compile_mvb_fn_with_messages`。

系数模数必须为奇数；预处理后的因子保留 NTT 表示。

经典 binary/ternary 和 sparse fixed-weight binary 均在所有输出间共享提升和盲旋转。每个因子乘积独立完成 Q→q 和提取，再复用 PBS 工作区分块批量执行 LWE KS。提取后即复用系数多项式缓冲，不同时保留所有乘积。 因子同时放大初始化与 BR 噪声，返回 KS 噪声在乘积后加入。

运行[17 阈值示例](examples/ntru_ntt_mvb_thresholds.rs)，命令使用 `--example ntru_ntt_mvb_thresholds`。 它展示交错容量之外的多输出；算法选择及编码限制见[共享 MVB 契约](../primus_tfhe/README.zh_CN.md#固定尺度分解式-mvb)。

## 实验性稀疏 PBS

本后端重导出家族的[共享系数密钥](../primus_tfhe_ntru/README.zh_CN.md#sparse-系数密钥) `SparseNtruBootstrappingKey<T>`；生成、变换及桶聚合仍由各后端负责。

普通 PBS 使用 `context.try_generate_keys(rng)` 和 `context.evaluator(&server)`；已有 client 使用 `context.try_generate_server_key(&client, rng)`。CBS 使用 `try_generate_circuit_bootstrap_keys` / `try_generate_circuit_bootstrap_server_key`，返回 `CircuitBootstrapServerKey`。`try_with_circuit_bootstrap(gadget)` 为 Context 添加 CBS 能力；普通工厂仍返回 BR/KS `ServerKey`。高级显式工厂分别接收 KS、算法，以及 CBS 工厂所需的 gadget。

为 external-LWE 选择固定重量 binary 分布，并显式选择 sparse；秘密分布本身不决定算法。要求 `0<h<n`、`copy_count>=1`、`bucket_count>=max(copy_count,h)`。

```rust,ignore
let config = experimental::SPARSE_PBS_U64;
let context = TfheContext::<_, Table, _>::try_from_pbs_config(config)?;
let (client, server) = context.try_generate_keys(&mut rng)?;
let mut evaluator = context.evaluator(&server)?;
```

普通/交错 PBS 复用原 evaluator，分解式 MVB 每次调用时借用它。`try_generate_circuit_bootstrap_keys` 复用累加秘密变换生成 BR/CBS，并生成必需 KS。仅需环输出时，从 sparse `CbsConfig` 创建 Context，再调用 `try_generate_circuit_bootstrap_keys`。`server.server_key().blind_rotation_key().sparse_blind_rotation_key()` 提供选择密文。

## 可选电路自举

Context 保存 Rounded 输入编码与 CBS gadget。使用 `context.encryptor(external_secret)?` 加密；`context.accumulator_client(client.accumulator_ntru_secret_key(), t_ring)?` 独立准备 Q 下的 Scaled 候选环客户端，t_ring 不必等于输入或普通 PBS 输出消息模数。CBS 输出采用 gadget 标度。

用 `context.compile_cbs_fn(|m| u64::from(m >= 2))?` 编译整数函数，或将完整前半区结果切片传给 `compile_cbs_slice`；`compile_cbs_identity()` 提供恒等函数。`context.circuit_bootstrap_evaluator_with_lookup_table(&server, program)?` 移入程序并组合复用资源，`context.circuit_bootstrap_evaluator(&server)?` 则准备恒等 CBS。工厂核对输入消息区间、q/Q、basis 和密钥布局；相同输入数量不能证明编码相同。输出层为 `g_j * F(m) mod Q`；CMux 要求整个输入域上 F 都为 bit，其他环整数遵循外积噪声契约。

`context.try_generate_circuit_bootstrap_keys(&mut rng)` 生成完整 `CircuitBootstrapServerKey`。默认 `CbsEvaluator` 的 `circuit_bootstrap_to(input.as_view(), control.as_mut_view())` 与 `cmux_to(control.as_view(), lhs.as_view(), rhs.as_view(), selected.as_mut_view())` 不需要另传 resources。[CBS → CMUX 示例](examples/ntru_ntt_circuit_bootstrap.rs)展示两次请求；普通 PBS 可借用 `server.server_key()`。

逐调用借用公共资源或其他输入编码使用底层 `CircuitBootstrapEvaluator`。实际秘密/变换身份、候选共同编码和噪声余量仍为调用方契约。见[共享 CBS 契约](../primus_tfhe/README.zh_CN.md#cbs-输出与消费)。

输出为 `f_acc` 下的 `NttNgswCiphertext`。Circuit key 绑定完整输出 basis； `try_new(&resources, circuit_key, &input_codec)` 从该密钥取得参数。 NTT trace 归一化要求奇数 Q 且小于 `2^(T::BITS-1)`。

## One-hot CBS

[One-hot 示例](examples/ntru_ntt_one_hot.rs)生成四个 selector，并用 `TARGET=2` 对应的 δ₂ 控制 CMux；修改 `TARGET` 选择其他分支。用 `context.one_hot_evaluator(&server)?` 创建 `OneHotEvaluator`，分配后复用 `_to` 调用，无需另传资源。

完整/非零输出接口、布局与输入保护区见[家族 one-hot 契约](../primus_tfhe_ntru/README.zh_CN.md#one-hot-cbs)。NLEV 输出为 Q 下的系数，需要 `write_ntt_form` 转换才能做公开多项式外积；NGSW 已在 NTT 表示。输入、密钥和候选必须满足本页的变换契约。

`ngsw_selector_len()` 返回单个变换域 NGSW selector 的长度；`ngsw_batch_len()` 返回包含分支零的完整批次长度。两者均以NTT 环元素个数计量，不是字节数。

消费时通过 `cbs.ngsw_selectors(&output)` 或
`cbs.nonzero_ngsw_selectors(&output)` 借用 `NttNgswSelectors`。
`selector(r)` 按数学编号取得 δᵣ，`iter()` 返回 `(r, control)`。
完整批次覆盖 `0..M`，紧凑批次覆盖 `1..M`，后者的 `selector(0)` 返回
`None`。视图检查精确批次长度，直接借用原缓冲，不复制、不分配。
`cbs.nlev_selectors(&output)` 同样借用完整的系数域 NLEV 批次。

取得单个 control 后，调用 `cbs.cmux_to(control, lhs.as_view(), rhs.as_view(), selected.as_mut_view())`：δᵣ=0 选择 lhs，δᵣ=1 选择 rhs。`cbs.external_product_to(control, input.as_view(), output.as_mut_view())` 则计算 selector 与环密文的乘积。两个入口复用已绑定的 output basis、变换环境和共享 scratch；候选的秘密、模数、编码与噪声仍须符合 CMux/外积契约。完整/非零批次使用相同消费接口，传入的是一个 selector。

需要立即消费每个结果时，先用 `one_hot.into_parts()` 取得底层状态和资源；其 `new_sparse_pair_workspace(&resources)` 分配一个额外输入状态，`with_sparse_pair` 一起执行两个 sparse 输入的盲旋转。回调依次收到索引 0、1 和受限的 `OneHotProjection`；`project_to` 将完整 NLEV 和/或非零 NGSW 写入复用缓冲，每次回调内完成消费。高精度 LUT evaluator 自动使用此路径。

## 高精度查表

[primus_tfhe_ntru_lut](../primus_tfhe_ntru_lut/README.zh_CN.md) 组合 one-hot CBS、表选择、聚合负向旋转和独立 LWE 返回，支持统一输入/输出 chunk 位宽及独立数量。底层组合可通过 `server_key.blind_rotation_key().classic_controls().unwrap().initializer()` 取得 context 的 BR basis 下的 classic NLEV[1]，通过 `key_switching_key()` 取得 Q→q、f→s 返回密钥。

完整 chunk 加密与查表工作流见 [ntt_lookup.rs](../primus_tfhe_ntru_lut/examples/ntt_lookup.rs)。

自定义返回先绑定 `LweReturnEvaluator::new(server.key_switching_key().unwrap(),
context.parameters().external_lwe().cipher_modulus())`，再按需准备 scalar/batch 工作区，
显式传给 `return_at_to`、`return_prefix_to` 或流式操作。one-hot 与变换工作区可独立复用。
详见[家族返回契约](../primus_tfhe_ntru/README.zh_CN.md#ntrulwe-返回)。

## 底层组合

Rustdoc 按职责组织 `key`（服务端材料）、`circuit_bootstrap`（CBS）、 `factorized`（MVB 程序和执行）与 `sparse`（桶材料）；常用工作流类型仍从 crate 根导入。

基准集中在 [`primus_tfhe_benchmarks`](../../benchmarks/tfhe/README.zh_CN.md#targets)。按运算选择 `pbs`、`sparse_pbs`、`mvb`、`cbs` 或显式诊断 `setup` target。选择 `--features ntru-ntt`。

## 进一步阅读

本 crate 在普通依赖上固定启用 `ntt`；无需额外后端开关，单独使用不引入 Fourier/FFT。默认 features 为空；可选 `simd` 启用依赖中的 nightly SIMD 算术。

[Boolean 门](../primus_tfhe/README.zh_CN.md#boolean-门) · [错误边界](../primus_tfhe/README.zh_CN.md#错误边界) · [实现说明](../primus_tfhe/IMPLEMENTATION.md) · [基准指南](../../benchmarks/tfhe/BENCHMARKS.md)
