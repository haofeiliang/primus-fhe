# primus_tfhe_glwe_fourier

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

基于原生环面的 GLWE TFHE 后端。 先读[任务与编码选择](../primus_tfhe/README.zh_CN.md#选择同态操作)，再读 [GLWE 参数与密钥域](../primus_tfhe_glwe/README.zh_CN.md)。示例使用功能参数，不是经认证的安全或失败概率参数。

## 快速开始

```sh
cargo run -p primus_tfhe_glwe_fourier --release --example fourier_basic
```

[basic 示例](examples/fourier_basic.rs)展示参数 → context → 配对密钥 → 客户端 → 单个 LUT → 复用 evaluator 和密文缓冲。它计算 `x % 4`，输入和输出均采用 `t=16` 编码，直接用 `decrypt` 解码。 `compile_lookup_table_fn(function)` 默认使用参数 codec；需要不同输出明文模数时，使用 `compile_lookup_table_with_codec_fn(&output_codec, function)`，见[选择输出编码](../primus_tfhe/README.zh_CN.md#选择输出编码)。 公钥加密通过 `context.public_encryptor(&public)` 创建客户端，见[家族说明](../primus_tfhe_glwe/README.zh_CN.md#客户端与-lut)。

示例区分客户端加密、服务端求值与客户端解密，见[双方职责与缓冲分配](../primus_tfhe/README.zh_CN.md#客户端与服务端边界)。

## 参数与表示

`TfheParameters::try_from_config(TfheConfig { .. })` 检查数学配置； `TfheContext::<_, RustFftTable>::try_from_parameters(parameters)` 准备变换表。 已有表用 `TfheContext::try_new(parameters, table)` 绑定。 `TfheConfig`、`TfheParameters`、`Encryptor` 和 `Decryptor` 将家族 API 特化为 `NativeModulus`。

`RustFftTable` 和 `TfheFftTable` 均支持 u32/u64。变换域密钥、数据和 evaluator 必须使用同一个 FFT 表实例，长度相同不能证明表示一致。

`PbsOrder::BootstrapKeyswitch` 的外部维数为 n，`KeyswitchBootstrap` 为 dN。 用 `context.allocate_lwe_ciphertext()` 按当前 order 分配。 Basic 示例在两种 order 下使用 ternary 输入秘密。

## 复用 evaluator

普通/交错调用共用 `Evaluator`，`_to` 写入已有输出。 PBS/MVB/CBS 交替使用方式集中在[共享所有权说明](../primus_tfhe/README.zh_CN.md#复用-evaluator)。

GLWE MVB 使用 `FactorizedEvaluator::from_bootstrapper` 消费普通工作区； CBS 使用 `CircuitBootstrapEvaluator::try_from_bootstrapper`，需要 ServerKey 内的 CBS 材料。 独立 BR→KS CBS 省略返回 KS 缓冲：`bootstrapper_mut()` 返回 `None`， `into_bootstrapper()` 在此时显式补分配。KS→BR CBS 及从普通 PBS 转入的 CBS 保留这些资源， 普通借用为 `Some`，回收无分配。

## 固定尺度分解式 MVB

`context.compile_factorized_lookup_table_fn(&scaled_codec, input_domain_len, output_count, function)` 返回绑定该 context 实例的 `FourierFactorizedLookupTable`。 构造并复用 `FactorizedEvaluator`，或消费已有普通 evaluator。 输出用保留的 unsigned Scaled codec 解码，不能直接当作 Boolean 门输入。

实际尺度 `round(2^BITS/t_out)` 必须为偶数，`t_out=10` 对 u32/u64 均可用。 奇数尺度返回 `LookupTableError::OddFactorizationScale`。因子按有符号整数变换，不作环面缩放； 须预算因子放大和 FFT 误差。

两种 order 均支持经典/稀疏密钥。BR→KS 在每个因子乘积后 KS，KS→BR 先对输入做一次 KS。 额外工作区大小与输出个数无关。

运行[17 阈值示例](examples/fourier_mvb_thresholds.rs)，命令使用 `--example fourier_mvb_thresholds`。 它展示交错容量之外的多输出；算法选择及编码限制见[共享 MVB 契约](../primus_tfhe/README.zh_CN.md#固定尺度分解式-mvb)。

## 实验性稀疏 PBS

为 small-LWE 选择固定重量 binary 分布，并显式调用稀疏生成器； 仅选择低重量分布仍使用经典 BR。要求 `0<h<n`、`copy_count>=1`、`bucket_count>=max(copy_count,h)`。

```rust,ignore
let mut generator = KeyGenerator::new(&context);
let client = ClientKey::generate(context.parameters(), &mut rng);
let server = generator.try_generate_sparse_server_key(&client, 3, 2 * h, None, &mut rng)?;
let mut evaluator = context.evaluator(&server)?;
```

两种 order 支持普通/交错 PBS、MVB 和 CBS。传入 `Some(cbs_config)` 添加稀疏 CBS 材料。 `ServerKey::bootstrapping_key()` 提供 `BootstrappingKey::{Classic,Sparse}`。

固定客户端后最多重试八张公开映射，不重新采样客户端秘密。 每个桶的加密零与 dummy 都贡献噪声；匹配成功不代表安全或完整失败概率得到认证。 见[稀疏旋转不变量](../primus_tfhe/IMPLEMENTATION.md#ternary-and-sparse-rotation)。

## 电路自举

`context.try_generate_keys(Some(cbs_config), &mut rng)` 生成配对材料， `ServerKey` 持有附加参数及 trace/scheme-switch 密钥。 调用 `context.circuit_bootstrap_evaluator(&server)` 或消费普通 evaluator。 经典密钥若使用 `None` 生成，CBS 绑定返回 `MissingCircuitBootstrapKey`。 使用 `allocate_output`、`circuit_bootstrap_to` 和 `cmux_to`； [CBS → CMUX 示例](examples/fourier_circuit_bootstrap.rs)展示完整消费链。

示例使用经典密钥展示两种 order，复用 LWE 输入、GGSW 控制与 GLWE 选择结果缓冲。 稀疏 CBS 沿用[实验性稀疏 PBS](#实验性稀疏-pbs)中的显式密钥生成流程， 将 `None` 改为 `Some(cbs_config)`，再创建 `context.circuit_bootstrap_evaluator(&server)`。 CBS 与 CMUX 调用方式相同。

输出为 accumulator 秘密下的 `FourierGgsw`。密钥绑定输出布局及 trace/scheme-switch basis； 高级 `try_from_parts` 可以传入层数相同的另一输出 basis。 须对最小输出 gadget 尺度预算 Native trace halving 和 FFT 误差。

独立生成组件时须配对秘密并使用同一变换表示，形状检查不能证明身份。 输入/输出与消费要求见[共享 CBS 契约](../primus_tfhe/README.zh_CN.md#cbs-输出与消费)及 [家族 CBS 说明](../primus_tfhe_glwe/README.zh_CN.md#boolean-与-cbs)。

## 底层组合

Rustdoc 按职责组织 `key`（服务端材料）、`circuit_bootstrap`（CBS）、 `factorized`（MVB 程序和执行）与 `sparse`（桶材料）；常用工作流类型仍从 crate 根导入。 原始 GLWE 控制材料和 BR 工作区见 `bootstrapping_key` 与 `blind_rotation`。

## 进一步阅读

[Boolean 门](../primus_tfhe/README.zh_CN.md#boolean-门) · [错误边界](../primus_tfhe/README.zh_CN.md#错误边界) · [实现说明](../primus_tfhe/IMPLEMENTATION.md) · [基准入口与性能取舍](../primus_tfhe/IMPLEMENTATION.md#performance-decisions-and-reproducibility)
