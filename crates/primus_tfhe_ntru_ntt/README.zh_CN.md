# primus_tfhe_ntru_ntt

[English](README.md) | 简体中文

基于显式域模数的 NTRU TFHE 后端。
先读[任务与编码选择](../primus_tfhe/README.zh_CN.md#选择同态操作)，再读
[NTRU 参数与密钥域](../primus_tfhe_ntru/README.zh_CN.md)。示例使用功能参数，不是经认证的安全或失败概率参数。

## 快速开始

```sh
cargo run -p primus_tfhe_ntru_ntt --release --example ntru_ntt_basic
```

[basic 示例](examples/ntru_ntt_basic.rs)展示参数 → context → 配对密钥 → 客户端 → 单个 LUT →
复用 evaluator 和密文缓冲。它计算 `x % 4`，输入和输出均采用 `t=16` 编码，直接用 `decrypt` 解码。
`compile_lookup_table_fn(function)` 默认使用参数 codec；需要不同输出明文模数时，使用
`compile_lookup_table_with_codec_fn(&output_codec, function)`，见[选择输出编码](../primus_tfhe/README.zh_CN.md#选择输出编码)。
公钥加密沿用同一客户端 API，见[家族说明](../primus_tfhe_ntru/README.zh_CN.md#客户端与-lut)。

示例区分客户端加密、服务端求值与客户端解密，见[双方职责与缓冲分配](../primus_tfhe/README.zh_CN.md#客户端与服务端边界)。

## 参数与表示

`TfheParameters::try_from_config(TfheConfig { .. })` 检查数学配置；
`TfheContext::<_, U32NttTable>::try_from_parameters(parameters)` 准备变换表。
已有表用 `TfheContext::try_new(parameters, table)` 绑定。
`TfheConfig`、`TfheParameters`、`Encryptor` 和 `Decryptor` 将家族 API 特化为 `BarrettModulus`。

NTT 表需要实现 `MonomialNttTable`，内置表均支持。Context 检查长度和模数；
所有变换域密钥及数据须遵循该表的表示约定。

PBS 顺序固定：在 `f_acc` 下加密初始化和 BR，然后返回 KS，再在 `f_client` 下紧凑提取。
Binary/ternary 客户端秘密须通过可逆性筛选，Fourier 还检查逆的数值稳定性。

## 复用 evaluator

普通/交错调用共用 `Evaluator`，`_to` 写入已有输出。
PBS/MVB/CBS 交替使用方式集中在[共享所有权说明](../primus_tfhe/README.zh_CN.md#复用-evaluator)。

使用 `FactorizedEvaluator::try_from_bootstrapper` 或
`CircuitBootstrapEvaluator::try_from_bootstrapper`，两者均拒绝 sparse 密钥。
普通 PBS 借用始终可用，`into_bootstrapper()` 无分配。

## 固定尺度分解式 MVB

`context.compile_factorized_lookup_table_fn(&scaled_codec, input_domain_len, output_count, function)`
返回绑定该 context 实例的 `NttFactorizedLookupTable`。
构造并复用 `FactorizedEvaluator`，或消费已有普通 evaluator。
输出用保留的 unsigned Scaled codec 解码，不能直接当作 Boolean 门输入。

系数模数必须为奇数；预处理后的因子保留 NTT 表示。

经典 binary/ternary 共用加密初始化和 BR，随后对每个因子乘积 KS。
因子同时放大初始化与 BR 噪声，返回 KS 噪声在乘积后加入。

运行[17 阈值示例](examples/ntru_ntt_mvb_thresholds.rs)，命令使用 `--example ntru_ntt_mvb_thresholds`。
它展示交错容量之外的多输出；算法选择及编码限制见[共享 MVB 契约](../primus_tfhe/README.zh_CN.md#固定尺度分解式-mvb)。

## 实验性稀疏 PBS

为 external-LWE 选择固定重量 binary 分布，并显式调用稀疏生成器；
仅选择低重量分布仍使用经典 BR。要求 `0<h<n`、`copy_count>=1`、`bucket_count>=max(copy_count,h)`。

```rust,ignore
let mut generator = KeyGenerator::new(&context);
let client = generator.try_generate_client_key(&mut rng)?;
let server = generator.try_generate_sparse_server_key(&client, 3, 2 * h, &mut rng)?;
let mut evaluator = context.evaluator(&server)?;
```

普通/交错 PBS 复用原 evaluator。CBS/MVB 拒绝 sparse 密钥，包括另传 CBS 材料的构造方式。
`server.sparse_bootstrapping_key()` 提供选择密文。

固定客户端后最多重试八张公开映射，不重新采样客户端秘密。
每个桶的加密零与 dummy 都贡献噪声；匹配成功不代表安全或完整失败概率得到认证。
见[稀疏构造与成本](../../docs/tfhe-ntru-sparse.md)和[message/carry 示例](examples/ntru_ntt_sparse.rs)。

## 可选电路自举

`context.try_generate_keys(Some(cbs_config), &mut rng)` 生成配对材料，
`ServerKey` 持有附加参数及 trace/scheme-switch 密钥。
调用 `context.circuit_bootstrap_evaluator(&server)` 或消费普通 evaluator。
经典密钥若使用 `None` 生成，CBS 绑定返回 `MissingCircuitBootstrapKey`。
使用 `allocate_output`、`circuit_bootstrap_to` 和 `cmux_to`；
[CBS → CMUX 示例](examples/ntru_ntt_circuit_bootstrap.rs)展示完整消费链。

输出为 `f_acc` 下的 `NttNgswCiphertext`。Circuit key 绑定完整输出 basis；
`try_from_parts(context, server, circuit_key)` 从该密钥取得参数。
NTT trace 归一化要求奇数 q 且小于 `2^(T::BITS-1)`。

独立生成组件时须配对秘密并使用同一变换表示，形状检查不能证明身份。
输入/输出与消费要求见[共享 CBS 契约](../primus_tfhe/README.zh_CN.md#cbs-输出与消费)及
[家族 CBS 说明](../primus_tfhe_ntru/README.zh_CN.md#cbs-与示例)。

## 底层组合

Rustdoc 按职责组织 `key`（服务端材料）、`circuit_bootstrap`（CBS）、
`factorized`（MVB 程序和执行）与 `sparse`（桶材料）；常用工作流类型仍从 crate 根导入。

## 进一步阅读

[Boolean 门](../primus_tfhe/README.zh_CN.md#boolean-门) · [错误边界](../primus_tfhe/README.zh_CN.md#错误边界) ·
[实现与开发验证](../../docs/tfhe.md) · [基准测量](../../docs/benchmarks/tfhe.md)
