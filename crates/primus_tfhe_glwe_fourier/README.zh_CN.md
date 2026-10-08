# primus_tfhe_glwe_fourier

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

基于原生环面的 GLWE TFHE 后端。 先读[任务与编码选择](../primus_tfhe/README.zh_CN.md#选择同态操作)，再读 [GLWE 参数与密钥域](../primus_tfhe_glwe/README.zh_CN.md)。示例使用功能参数，不是经认证的安全或失败概率参数。

## 实验配套参数

```rust
use primus_tfhe_glwe_fourier::experimental;

let config = experimental::CLASSIC_PBS_U64;
let parameters = config.try_prepare()?;
// 可选：config.messages.with_output_modulus(8) 仅修改输出域。
let codecs = parameters.pbs_codecs(config.messages)?;
```

`PbsConfig` 用一个纯数值类型组合 BR/KS 与输入输出消息配置；`CbsConfig` 表示环输出 CBS，其 gadget 输出不使用普通消息 codec。`experimental` 另导出 `SPARSE_PBS_U64`、`CLASSIC_MANY_LUT_U64`、`CLASSIC_THRESHOLD_MVB_U64`、`CLASSIC_CBS_U64` 和 `SPARSE_CBS_U64`。密钥生成使用 `config.blind_rotation.algorithm`。配置实现 `Copy`，可直接覆盖字段或使用 struct update，而无需先准备采样器。

这些 u64 常量为算术样例，安全性与失败概率尚未评估。组合方式、独立消息覆盖和数值契约见[家族配置](../primus_tfhe_glwe/README.zh_CN.md#实验配套参数)。所有示例均从对应操作配置开始；高级显式组合继续使用家族构造器。`PbsParameters` 可供兼容编码复用；改变工作负载后仍须重新确定误差预算。

## 快速开始

基础、sparse、ManyLUT 和 MVB 示例使用 `PbsMessageConfig`：`new(t)` 默认输入输出消息模数相同，`with_output_modulus(t_out)` 只修改输出。普通 PBS/ManyLUT 用 `parameters.pbs_codecs` 准备，MVB 用 `parameters.factorized_pbs_codecs` 准备；返回的 codec 分别表示输入、LUT 输出和返回输出。`context.decryptor(external_secret, codecs.output_codec())?` 同时接受 Rounded/Scaled 输出，随后用 `decrypt()` 得到消息。见[选择输出编码](../primus_tfhe/README.zh_CN.md#选择输出编码)。

```sh
cargo run -p primus_tfhe_glwe_fourier --release --example fourier_basic --features rustfft
```

[basic 示例](examples/fourier_basic.rs)展示参数 → context → 配对密钥 → 客户端 → 单个 LUT → 复用 evaluator 和密文缓冲。它计算 `x % 4`，输入和输出均采用 `t=32` 编码，直接用 `decrypt` 解码。 `parameters.lookup_table_compiler(&codecs)?` 直接绑定已准备的输入/输出编码，再用 `compiler.compile_fn(function)` 创建 LUT。通过 `PbsMessageConfig::with_output_modulus` 选择不同输出消息模数，见[选择输出编码](../primus_tfhe/README.zh_CN.md#选择输出编码)。 公钥加密通过 `context.public_encryptor(&public, codecs.input_codec())` 创建客户端，见[家族说明](../primus_tfhe_glwe/README.zh_CN.md#客户端与-lut)。

示例固定 `Word = u64`，使用下表对应的操作配置。尺寸、模数表示、秘密分布、噪声和分解集中在 `experimental`；各个 `main` 只展示准备、公开函数、客户端和求值。CBS 使用 `config.gadget`，消费端独立选择候选环消息域。 Fourier 示例选择 RustFFT；需要 TFHE-FFT 时，同时切换 `Table` 导入、示例 target 的 `required-features` 和 `--features tfhe-fft`。 高级显式组合仍支持 u32/u64，见[家族配置](../primus_tfhe_glwe/README.zh_CN.md#实验配套参数)和[数值参数指南](../../guides/development/tfhe-parameters.md)。

注释标明客户端和服务端阶段。Basic 与 sparse 都计算 `x % 4`，默认输入输出消息模数相同；独立 ManyLUT 示例同时计算 `x % 4` 和 `x / 4`，显式设置 `t_in=16`、`t_out=8`，并用输出 codec 解密。每例复用 LUT、evaluator 和输出缓冲处理两次请求。见[双方职责与缓冲分配](../primus_tfhe/README.zh_CN.md#客户端与服务端边界)。

| 操作 | `experimental` 配置 | 完整示例 |
| --- | --- | --- |
| Classic PBS | `CLASSIC_PBS_U64` | [basic](examples/fourier_basic.rs) |
| Sparse PBS | `SPARSE_PBS_U64` | [sparse](examples/fourier_sparse.rs) |
| 交错多输出 ManyLUT，独立输出消息模数 | `CLASSIC_MANY_LUT_U64` | [many_lut](examples/fourier_many_lut.rs) |
| Classic CBS → CMux | `CLASSIC_CBS_U64` | [circuit_bootstrap](examples/fourier_circuit_bootstrap.rs) |
| Sparse CBS → CMux | `SPARSE_CBS_U64` | [sparse_circuit_bootstrap](examples/fourier_sparse_circuit_bootstrap.rs) |
| 分解式 MVB | `CLASSIC_THRESHOLD_MVB_U64` | [thresholds](examples/fourier_mvb_thresholds.rs) |

ManyLUT 通过交错共享一次盲旋转；分解式 MVB 通过公共因子生成多输出，是不同的求值接口。

客户端工厂只接收所需秘密：普通及 Boolean 加解密传入 `client_key.external_lwe_secret_key()`，`accumulator_client` 传入 `client_key.glwe_secret_key()`。完整 `ClientKey` 组合用于生成服务端密钥；选择角色不会复制秘密缓冲区。

## 参数与表示

Fourier 环只支持 `NativeModulus`；`PowOf2Modulus` 环不受支持。

`PbsConfig::try_prepare` / `CbsConfig::try_prepare` 准备并检查数学配置； `TfheContext::<_, RustFftTable>::from_parameters(parameters)` 准备变换表。 已有表用 `TfheContext::try_new(parameters, table)` 绑定。 `BlindRotationConfig`、`PbsConfig`、`CbsConfig`、`PbsParameters`、`Encryptor` 和 `Decryptor` 将家族 API 特化为 `NativeModulus`。

`RustFftTable` 和 `TfheFftTable` 均支持 u32/u64。变换域密钥、数据和 evaluator 必须使用同一个 FFT 表实例，长度相同不能证明表示一致。

`PbsOrder::BootstrapKeyswitch` 的外部维数为 n，`KeyswitchBootstrap` 为 dN。 用 `context.allocate_lwe_ciphertext()` 按当前 order 分配。 Basic 示例使用 binary 秘密和 `BootstrapKeyswitch`；MVB 示例使用 `KeyswitchBootstrap`。

## 复用 evaluator

普通/交错 `Evaluator` 拥有公共 `BootstrapResources` 与返回阶段。CBS 只保存 LUT/投影状态，执行时最后一个参数传 `pbs.bootstrap_resources_mut()`。MVB 用 `FactorizedEvaluator::new(&pbs)` 构造，每次执行传入 `&mut pbs`。借用结束即可继续普通 PBS，无需转换或恢复 evaluator。输入/输出 KS、BR、trace、scheme switch 与 factor 乘积共用同一 FFT engine，借用不会新建 FFT 工作区。

`Resources` 将借用的 context/计算材料与拥有的复用缓冲组合起来，不拥有或复制密钥。`Workspace` 表示缓冲及形状元数据，包括底层 BR/外积 scratch。`Evaluator` 使用自己拥有或短借用的资源执行具体流程。借用期间须保留 context/key 的 owner；串行操作可共享一个可变资源实例，并发请求需要独立的可变资源。资源拥有 FFT engine，而 engine 借用 context 的表；更换资源 owner 时仍须保持表身份。

`ServerKey` 仍是完整 PBS 的便捷组合。高级工作流可分别持有 `BlindRotationKey`、环 KS key 和 `CircuitBootstrapKey`，通过 `ServerKey::new` / `into_parts` 移动组合，不复制密文数组。`KeyGenerator::try_generate_blind_rotation_key(&client, config, rng)` 通过 `BlindRotationAlgorithm` 选择 classic 或 sparse BR，不额外生成返回或 CBS 材料；`try_generate_glwe_key_switching_key` 独立生成环 KS；`try_generate_circuit_bootstrap_key(accumulator_secret, parameters, rng)` 只需要累加器秘密。独立生成可能重复转换秘密；成对生成继续复用已准备的表示。

仅需环输出 CBS 时，`context.try_generate_circuit_bootstrap_keys(blind_rotation, cbs_config, rng)` 返回 `(ClientKey, CircuitBootstrapServerKey)`，其中 CBS 材料始终存在，仅 KS→BR 生成输入 KS。通过 `server.bootstrap_resources(&context)` 和 `server.circuit_bootstrap_key()` 绑定 evaluator，见[材料选择](../primus_tfhe/README.zh_CN.md#选择盲旋转算法)。

已有 `ServerKey`、仅需独立 CBS 时，按需准备公共资源：

```rust,ignore
let mut resources = context.bootstrap_resources_from_server_key(&server)?;
let circuit_key = server.circuit_bootstrap_key().unwrap(); // 生成时传入 Some(cbs_config)。
let mut cbs = CircuitBootstrapEvaluator::try_new(&resources, circuit_key, &input_codec)?;
```

工厂自动为 KS→BR 选择输入 KS；BR→KS 不分配输出 KS 工作区。`try_new` 使用 circuit key 自带参数。已有 PBS evaluator 时，直接传 `pbs.bootstrap_resources()`，后续 CBS 调用借用 `pbs.bootstrap_resources_mut()`。

独立生成材料时，使用 `context.bootstrap_resources(br, input_ks)`：BR→KS 可传 `None`，KS→BR 必须传 `Some(ks)`；独立 CBS 不要求普通返回密钥。`Evaluator::try_from_parts(context, br, ks)` 绑定完整 PBS/ManyLUT。两种入口均支持 classic/sparse。布局、basis 和模数检查不证明实际秘密或变换身份。

`Evaluator::try_from_resources(resources, ks)` 组合普通 PBS，只有 BR→KS 需要分配缺少的输出阶段。`try_rebind_key_switching_key(ks)` 用兼容材料复用活跃 KS 阶段的缓冲，失败保留旧绑定。CBS/MVB 接受同一 context 创建的任意资源实例，在写入前检查；调用方仍须配对秘密，可变资源借用必须保留所属 PBS 的绑定和 FFT table 实例。

## 固定尺度分解式 MVB

通过 `context.compile_factorized_lookup_table_fn(&codecs, domain_len, output_count, function)` 编译并绑定 `FactorizedEvaluator`；`codecs` 由 `parameters.factorized_pbs_codecs(messages)` 准备，输入使用 Rounded、输出使用 Scaled，均采用 context 的密文模数。程序借用该 context，输出使用 unsigned Scaled 编码。

实际尺度 `round(2^BITS/t_out)` 必须为偶数，`t_out=10` 对 u32/u64 均可用。 奇数尺度返回 `LookupTableError::OddFactorizationScale`。因子按有符号整数变换，不作环面缩放； 须预算因子放大和 FFT 误差。

两种 order 均支持经典/稀疏密钥。BR→KS 在每个因子乘积后 KS，KS→BR 先对输入做一次 KS。 额外工作区大小与输出个数无关。

运行[17 阈值示例](examples/fourier_mvb_thresholds.rs)，命令使用 `--example fourier_mvb_thresholds`。 它展示交错容量之外的多输出；算法选择及编码限制见[共享 MVB 契约](../primus_tfhe/README.zh_CN.md#固定尺度分解式-mvb)。

## 实验性稀疏 PBS

`KeyGenerator::try_generate_server_key(&client, blind_rotation, cbs, rng)` 为已有客户端选择 `BlindRotationAlgorithm::Classic` 或 `Sparse { copy_count, bucket_count }`；同一个 fixed-weight binary 秘密支持两者。CBS 传 `None` 只生成普通 BR/返回材料，传 `Some(config)` 则添加 CBS 密钥。成对生成快捷入口 `context.try_generate_keys(blind_rotation, cbs, rng)` 接收同样的选择并复用变换后的秘密；独立组件不要求完整密钥包。见[算法和材料选择](../primus_tfhe/README.zh_CN.md#选择盲旋转算法)。

为 small-LWE 选择固定重量 binary 分布，并显式选择 sparse；秘密分布本身不决定算法。要求 `0<h<n`、`copy_count>=1`、`bucket_count>=max(copy_count,h)`。

```rust,ignore
let blind_rotation = BlindRotationAlgorithm::Sparse { copy_count: 3, bucket_count: 2 * h };
let (client, server) = context.try_generate_keys(blind_rotation, None, &mut rng)?;
let mut evaluator = context.evaluator(&server)?;
```

两种 order 支持普通/交错 PBS、MVB 和 CBS。传入 `Some(cbs_config)` 添加稀疏 CBS 材料。 `ServerKey::blind_rotation_key()` 提供 `BlindRotationKey::{Classic,Sparse}`。

## 电路自举

`parameters.circuit_bootstrap_codecs(t_in, t_ring)?` 返回 Rounded 输入与 Scaled 候选环消息编码，自动提供正确的 q/Q，两个明文域独立。将前者传给输入 encryptor 和 CBS evaluator，后者传给 `accumulator_client`；它不描述 CBS 的 gadget 输出。

用 `key.parameters().compile_lookup_table_fn(&input_codec, |m| u64::from(m >= 2))?` 编译整数函数，或将完整前半区结果切片传给 `compile_lookup_table_slice`。通过 `CircuitBootstrapEvaluator::try_with_lookup_table(&resources, key, program)?` 绑定返回的 `CircuitBootstrapLookupTable`；`try_new` 保留恒等函数默认入口。输出层使用 `g_j * F(m) mod Q`，无需输出消息 codec 或额外 BR。CMux 要求整个输入域上的 F 都是 bit；其他环整数遵循外积噪声契约。普通 CBS 示例使用 t_in=8，展示该谓词的正反分支。

`context.try_generate_circuit_bootstrap_keys(blind_rotation, cbs_config, &mut rng)` 为环输出生成配对材料，`CircuitBootstrapServerKey` 持有 BR、必要的输入准备和 CBS 材料；`circuit_bootstrap_key()` 直接返回必需的密钥。混合 PBS/CBS 仍可用 `try_generate_keys(blind_rotation, Some(cbs_config), rng)` 生成完整 `ServerKey`。取得 `server.circuit_bootstrap_key()` 后，显式传给上述 CBS 构造器。使用 `allocate_output`、`circuit_bootstrap_to` 和 `cmux_to`，每次操作借用公共资源；[CBS → CMUX 示例](examples/fourier_circuit_bootstrap.rs)展示成组生成 BR/CBS 材料及完整消费链。

[稀疏 CBS 示例](examples/fourier_sparse_circuit_bootstrap.rs)直接展示固定重量秘密、稀疏密钥生成与 CBS 参数。两种 PBS 顺序都支持；后面的 CBS 与 CMux 调用方式相同。

输入编码与交错容量在程序编译时检查；绑定检查域和 basis，兼容程序可以用同一套密钥选择另一明文模数。

输出为 accumulator 秘密下的 `FourierGgsw`。密钥绑定输出布局及 trace/scheme-switch basis； `try_with_parameters(&resources, parameters, circuit_key, &input_codec)` 显式选择层数相同的另一输出 basis。预编译程序使用 `try_with_parameters_and_lookup_table(&resources, parameters, circuit_key, program)`，其 basis 必须与所选参数一致。 须对最小输出 gadget 尺度预算 Native trace halving 和 FFT 误差。

独立生成组件时须配对秘密并使用同一变换表示，形状检查不能证明身份。 输入/输出与消费要求见[共享 CBS 契约](../primus_tfhe/README.zh_CN.md#cbs-输出与消费)及 [家族 CBS 说明](../primus_tfhe_glwe/README.zh_CN.md#boolean-与-cbs)。

## 底层组合

本后端重导出[共享系数密钥](../primus_tfhe_glwe/README.zh_CN.md#sparse-系数密钥)，使用 `SparseGlweBootstrappingKey<T, NativeModulus<T>>`。Raw sparse BR 使用 `workspace.blind_rotate_lookup_table_to(&key, input, lut, output, &mut fft)`；工作区持有 scratch，仅在调用时借用密钥。

Rustdoc 按职责组织 `key`（服务端材料）、`circuit_bootstrap`（CBS）、 `factorized`（MVB 程序和执行）与 `sparse`（稀疏生成与旋转）；常用工作流类型仍从 crate 根导入。 原始 GLWE 控制材料和 BR 工作区见 `bootstrapping_key` 与 `blind_rotation`。

基准集中在 [`primus_tfhe_benchmarks`](../../benchmarks/tfhe/README.zh_CN.md#targets)。按运算选择 `pbs`、`sparse_pbs`、`mvb`、`cbs` 或显式诊断 `setup` target。选择 `--features glwe-fourier,rustfft`，也可将 `rustfft` 换为 `tfhe-fft`。

## 进一步阅读

本 crate 在普通依赖上固定启用 `fourier`；无需额外后端开关，单独使用不引入 NTT。默认 features 为空；`rustfft` / `tfhe-fft` 显式选择 FFT 引擎，可同时启用。泛型 API 不强制具体引擎。示例使用 `rustfft`；显式双引擎对照测试仍要求 `rustfft,tfhe-fft`。基准可独立使用任一引擎；同时启用时以 RustFFT 为主，`pbs` 另加一项 TFHE-FFT shortint 对照。可选 `simd` 只启用依赖中的 nightly SIMD 算术，不选择 FFT 引擎。

[Boolean 门](../primus_tfhe/README.zh_CN.md#boolean-门) · [错误边界](../primus_tfhe/README.zh_CN.md#错误边界) · [实现说明](../primus_tfhe/IMPLEMENTATION.md) · [基准指南](../../benchmarks/tfhe/BENCHMARKS.md)
