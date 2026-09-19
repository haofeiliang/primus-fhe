# primus_tfhe_glwe_fourier

[English](README.md) | 简体中文

基于 GLWE、采用原生 torus 的 TFHE 后端。支持两种 PBS order、ManyLUT、Boolean 门、经典 CBS 及私钥/公钥客户端。
完整能力与编码约定见[公共指南](../primus_tfhe/README.zh_CN.md)，
参数与秘密域见 [GLWE family](../primus_tfhe_glwe/README.zh_CN.md)。

`Encryptor`、`Decryptor`、`TfheConfig` 和 `TfheParameters` 是公共类型固定为 `NativeModulus` 的别名；
`ClientKey`、`EncryptionKey` 和 `PbsOrder` 直接重导出。

## 运行完整示例

```sh
cargo run -p primus_tfhe_glwe_fourier --example fourier_basic
```

[示例源码](examples/fourier_basic.rs) 用相同流程运行两种 order：参数 → context → 配套密钥
→ 公钥 encryptor / client decryptor → 编译 LUT → 复用 evaluator 与输出。
涵盖单 PBS、`t_in=4 → t_out=8` 的双输出 ManyLUT、客户端 `encrypt_padded_to`、Boolean 门、NOT 和 MUX。

`BootstrapKeyswitch` 的外部密文维数为 `n`，`KeyswitchBootstrap` 为 `kN`。
输入和输出均遵循选定的外部秘密域。示例的维数、噪声和分解参数仅用于功能演示，
不是生产安全或失败概率建议。

## Context 与复用

先用 `TfheParameters::try_from_config(TfheConfig { .. })` 声明数学参数，再调用
`TfheContext::<_, RustFftTable>::try_from_parameters(parameters)` 自动创建匹配的变换表。
表类型仍由调用方选择，建表失败通过 `TfheContextError::TransformTable` 保留底层 FFT 错误；
已有表可用 `try_new(parameters, table)` 显式注入。

`TfheContext::try_new` 检查 FFT 长度。所有变换域密钥、值与 evaluator 必须使用同一
FFT table 实例；长度相同不能证明表示兼容。示例使用 `RustFftTable`，也支持 `TfheFftTable`。
FFT engine 和 evaluator 从同一个 context 创建。

前半区 LUT 通过 `context.parameters()` 上的
`compile_lookup_table_fn` / `compile_lookup_table_slice` 编译，多输出使用
`compile_interleaved_lookup_table_*`，第一个参数均为输出 `RoundedCodec`。输出尺度不同时，
用 `decrypt_phase` 与该 codec 解码。输入采用 unsigned padded 编码，并考虑 ManyLUT 较低的
旋转分辨率。Evaluator 持有可变 scratch，创建一次后复用 `apply_lookup_table_to` /
`apply_interleaved_lookup_table_to`；这些入口在写入前检查全部输出维数。

奇数全域使用 parameters 的 `compile_odd_full_domain_lookup_table_fn` / `_slice` 与普通
`encrypt`，复用现有单输出 evaluator。条件见[共享契约](../primus_tfhe/README.zh_CN.md#奇数全域-pbs)。

`t=4` 时使用 `boolean_encryptor`、`boolean_decryptor`、`boolean_evaluator`，
直接复用采用模 4 下 Boolean `0/1` 编码的 `LweCiphertext`。Encryptor 支持私钥或公钥及
`encrypt_to`；evaluator 处理内部模 8 的 LUT 尺度，通过 `evaluate_binary_to`、`not_to`、`mux_to` 重复求值。

## Binary 与 ternary small 秘密

在 `LweParameters` 中选择 `SecretKeyDistr::UniformTernary` 或其他 ternary 家族，
即可沿用原有密钥生成与 evaluator 接口；basic 示例使用该配置。两种 PBS order、
普通/交错 LUT 和公钥输入均支持。Ternary 比 binary 需要更多密钥与工作区存储，
见[设计与成本](../../docs/tfhe-ternary.md)。

## 实验性稀疏 PBS

small-LWE 秘密采用 `FixedHammingWeightBinary` 时，显式生成稀疏 server key，
随后复用普通 evaluator 和 LUT 接口：

```rust,ignore
let server = KeyGenerator::new(&context)
    .try_generate_sparse_server_key(&client, copy_count, bucket_count, &mut rng)?;
let mut evaluator = context.evaluator(&server)?;
evaluator.apply_lookup_table_to(&input, &lut, &mut output);
```

RustFFT/TfheFFT 均支持两种 PBS order、普通 LUT 和 ManyLUT。
要求 `0 < h < n`、`copy_count >= 1`、`bucket_count >= max(copy_count, h)`。
生成返回 `SparseBootstrappingKeyError`，其 `BucketMap` 分支保留映射错误；
固定同一秘密，最多尝试八份公开映射，私有匹配在生成结束后擦除。

稀疏 BSK 保存 `(copy_count*n + bucket_count)` 份系数域 GGSW。每桶均执行一次外积，
未占用桶及加密零条目也会贡献噪声；需要考虑密钥存储、聚合噪声与变换成本，
实际加速取决于负载。固定重量安全性及完整噪声界仍属实验范围，见[构造与限制](../../docs/tfhe-sparse-pbs.md)。
不支持 sparse ternary 和 sparse CBS；CBS 构造遇到稀疏 server key 时返回
`UnsupportedSparseBootstrapping`。

`ServerKey::bootstrapping_key()` 和 `into_parts()` 返回 `BootstrappingKey::{Classic, Sparse}`，
evaluator 自动绑定并分派所选工作区。底层组合可使用 `try_generate_sparse_bootstrapping_key`、
`SparseGlweBlindRotationContext::new(&key)` 以及 `fourier_blind_rotate_lookup_table_to` /
`fourier_blind_rotate_interleaved_lookup_table_to`；它们输出 accumulator 秘密下的系数域 GLWE，
不做密钥切换或提取。`bucket(j)` 借用公开输入索引及对应 selector，最后一项为 dummy。

## Circuit bootstrapping

经典 CBS 支持 binary/ternary small 秘密、两种 PBS order 和两种 FFT，输出为 accumulator
私钥下的 Fourier GGSW。稀疏 CBS 尚不支持。

通过 `CircuitBootstrapConfig` 指定 output/trace/scheme-switch 分解及独立的 trace/SS 噪声。
Native 模数、环布局与秘密分布从 accumulator 派生，构造器检查补齐后的 gadget
层数容量并绑定输入明文模数。`CircuitBootstrapParameters::try_new` 仍可直接绑定已有 basis 与 GLev/GGSW 参数。
Scheme-switch key 绑定输出布局；层数相同的其他输出 basis
可以复用该密钥。

通过 `context.try_generate_keys(Some(config), &mut rng)`
生成配套 client/server key。`ServerKey` 持有 CBS 参数及 trace/scheme-switch key，
与普通 PBS 材料从同一组私钥和变换表生成。仅需 PBS 时使用 `None`，
不分配 CBS 密钥材料或工作区。`context.evaluator(&server)` 与
`context.circuit_bootstrap_evaluator(&server)` 共用这份 server key；未启用 CBS 时后者返回
`MissingCircuitBootstrapKey`。各 evaluator 只分配自身需要的工作区。生成错误为 `KeyGenerationError`。

高级组合仍可使用接收已准备参数所有权的 `try_generate_circuit_bootstrap_key`，以及显式传入
参数和材料的 `CircuitBootstrapEvaluator::try_from_parts`。调用方负责配套私钥与生成时的
变换表示；布局检查不能证明身份。绑定的参数可通过
`server.circuit_bootstrap_key().unwrap().parameters()` 访问。

`circuit_bootstrap_to` 覆盖写入已有 `FourierGgsw`，其长度为
`parameters.output_size().fourier_ggsw_len()` 个复数，在线不分配；`circuit_bootstrap` 则分配输出。
完整链复用普通 evaluator 的输入 KS/BR 工作区，再投影各 gadget 层并执行 scheme switching。
输入使用 unsigned rounded LWE 编码，消息位于 `0..ceil(t/2)`，噪声须适应较粗的 ManyLUT
旋转区间。用于 CMUX 时输入须为 0 或 1。结果保留在 accumulator 私钥下并采用 gadget
尺度，不经过普通 PBS 的输出 KS。

Native reverse trace 沿用底层逐级整数除二；其舍入、trace key switching、scheme-switch
分解与 FFT 精度均需计入 CBS 误差预算。参数检查不验证噪声或安全性。

[CBS→CMUX 示例](examples/circuit_bootstrap.rs) 用 LWE bit 选择两条加密 GLWE 消息之一，
展示两种 order 与输出复用：

```sh
cargo run --release -p primus_tfhe_glwe_fourier --example circuit_bootstrap
```

参数选择的误差预算与成本见 [CBS 专项](../../docs/tfhe-cbs.md)。示例参数不是生产参数建议。

使用 `evaluator.allocate_output()` 分配原有 CBS 控制密文，随后调用
`evaluator.cmux_to(control, lhs, rhs, output)` 或 `external_product_to(control, input, output)`。
`context.accumulator_client(&client)` 绑定环加解密与转换工作区。
详见[公共消费契约](../primus_tfhe/README.zh_CN.md#cbs-输出与消费)及[完整示例](examples/circuit_bootstrap.rs)。

错误归属与转换规则见[公共 TFHE 错误边界](../primus_tfhe/README.zh_CN.md#错误边界)。

## 进一步阅读

[实现设计与开发验证](../../docs/tfhe.md) · [基准与测量](../../docs/benchmarks/tfhe.md)
