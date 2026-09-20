# primus_tfhe_glwe_fourier

[English](README.md) | 简体中文

基于 GLWE、采用原生 torus 的 TFHE 后端。支持两种 PBS order、ManyLUT、偶尺度 MVB、Boolean 门、经典 CBS 及私钥/公钥客户端。
完整能力与编码约定见[公共指南](../primus_tfhe/README.zh_CN.md)，
参数与秘密域见 [GLWE family](../primus_tfhe_glwe/README.zh_CN.md)。

`Encryptor`、`Decryptor`、`TfheConfig` 和 `TfheParameters` 是公共类型固定为 `NativeModulus` 的别名；
`ClientKey`、`EncryptionKey` 和 `PbsOrder` 直接重导出。

## 复用 evaluator

已有普通 `Evaluator` 时，用 `FactorizedEvaluator::from_bootstrapper` 或
`CircuitBootstrapEvaluator::try_from_bootstrapper` 转入 MVB/CBS，仅分配新增能力的缓冲区。
通过 `bootstrapper_mut()` 可交替执行普通单输出/交错 PBS；先导入
`primus_tfhe::{ProgrammableBootstrap, ProgrammableBootstrapInterleaved}`。
这个借用只开放 PBS 操作，不能替换内部 evaluator。`into_bootstrapper()` 回收普通工作区，
释放额外缓冲区；从普通 evaluator 转入再回收不分配。

独立构造 BR→KS CBS 会省去返回 KS 的工作区，因此 `bootstrapper_mut()` 返回 `None`；
此时 `into_bootstrapper()` 会显式补充分配。KS→BR CBS 保留前置 KS。需要频繁交替 PBS/CBS
时，从普通 evaluator 转入，取得的 PBS 借用为 `Some`，在线操作不重新构造工作区。

## 运行完整示例

```sh
cargo run -p primus_tfhe_glwe_fourier --example fourier_basic
```

[示例源码](examples/fourier_basic.rs) 用相同流程运行两种 order：参数 → context → 配套密钥
→ 公钥 encryptor / client decryptor → 编译 LUT → 复用 evaluator 与输出。
涵盖单 PBS、`t_in=4 → t_out=8` 的双输出 ManyLUT、Scaled `t_out=10` 的 MVB、客户端 `encrypt_padded_to`、Boolean 门、NOT 和 MUX。

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

## 固定尺度分解式 MVB

输入使用 unsigned Rounded 编码，输出显式提供 unsigned `ScaledCodec`：

```rust,ignore
let codec = ScaledCodec::new(10u32, NativeModulus::new());
// 假定 t_in >= 8，且输入和输出都有足够的噪声余量。
let lut = context.compile_factorized_lookup_table_fn(
    &codec, 4, 3, |m, i| u32::from(m > i),
)?;
let mut evaluator = context.factorized_evaluator(&server_key)?;
let mut outputs = vec![LweCiphertext::zero(context.parameters().external_lwe_dimension()); 3];
evaluator.apply_lookup_table_to(&input, &lut, &mut outputs);
let value = codec.decode_value(decryptor.decrypt_phase(&outputs[0])?);
```

codec 后的参数分别为输入前缀长度和实际输出数。`FourierFactorizedLookupTable`
借用本 context；即使参数相同，另一个实例也会被拒绝。底层调用方可先编译共享
`FactorizedLookupTable`，再用 `FourierFactorizedLookupTable::new` 准备。

支持 u32/u64、RustFFT/TfheFFT、经典 binary/ternary 和固定重量 sparse binary 密钥及两种 order。
实际 `delta=round(2^BITS/t_out)` 必须为偶数；奇尺度返回
`LookupTableError::OddFactorizationScale`。明文模数不必为二次幂，10 在两种字宽下
都可用。稀疏 MVB 复用普通 sparse PBS 的 `KeyGenerator::try_generate_sparse_server_key`。

因子按有符号整数一次准备，不做 torus 缩放。所有输出共享一次 BR；BK 逐输出 KS，
KB 在 BR 前切换输入。`apply_lookup_table_to` 在写入前检查 context 和全部维数，
在线不分配；额外工作区为 `(d+2)*N/2` 个复数，不随输出数增长。预处理程序存储
N 个 torus 系数和 `output_count*N/2` 个复数，不保留因子的系数副本。

因子范数放大 BR 噪声，Fourier 乘法另引入相位数值误差；构造成功不代表噪声预算成立，
u64 同样如此。须用提供的 Scaled codec 解码，串联时计入与 Rounded 中心的差异。
见[编码约定](../primus_tfhe/README.zh_CN.md#固定尺度分解式-mvb)和
[精度证据与限制](../../docs/tfhe-mvb-fourier.md)。

[17 阈值示例](examples/fourier_mvb_thresholds.rs) 将 `0..64` 的一个分数转为交错容量之外的
17 个数值标志。这些 Scaled `t_out=2` 标志须按对应 codec 使用，不能直接当作 Boolean 门
密文或另一明文模数的输入。算法选择取决于因子范数、交错容量、输出数和密钥大小；
见[成本测量](../../docs/tfhe-mvb-fourier-costs.md)。

```sh
cargo run -p primus_tfhe_glwe_fourier --example fourier_mvb_thresholds
```

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
    .try_generate_sparse_server_key(&client, copy_count, bucket_count, None, &mut rng)?;
let mut evaluator = context.evaluator(&server)?;
evaluator.apply_lookup_table_to(&input, &lut, &mut output);
```

RustFFT/TfheFFT 均支持两种 PBS order、普通 LUT 和 ManyLUT。
要求 `0 < h < n`、`copy_count >= 1`、`bucket_count >= max(copy_count, h)`。
server 和独立 sparse BSK 生成均返回 `KeyGenerationError`，其 `SparseBootstrapping` 包装
`SparseBootstrappingKeyError`，后者的 `BucketMap` 分支保留映射错误；
固定同一秘密，最多尝试八份公开映射，私有匹配在生成结束后擦除。

稀疏 BSK 保存 `(copy_count*n + bucket_count)` 份系数域 GGSW。每桶均执行一次外积，
未占用桶及加密零条目也会贡献噪声；需要考虑密钥存储、聚合噪声与变换成本，
实际加速取决于负载。固定重量安全性及完整噪声界仍属实验范围，见[构造与限制](../../docs/tfhe-sparse-pbs.md)。
不支持 sparse ternary。可选的 sparse CBS 材料见下节。

`ServerKey::bootstrapping_key()` 和 `into_parts()` 返回 `BootstrappingKey::{Classic, Sparse}`，
evaluator 自动绑定并分派所选工作区。底层组合可使用 `try_generate_sparse_bootstrapping_key`、
`SparseGlweBlindRotationContext::new(&key)` 以及 `fourier_blind_rotate_lookup_table_to` /
`fourier_blind_rotate_interleaved_lookup_table_to`；它们输出 accumulator 秘密下的系数域 GLWE，
不做密钥切换或提取。`bucket(j)` 借用公开输入索引及对应 selector，最后一项为 dummy。

## Circuit bootstrapping

CBS 支持经典 binary/ternary 和固定重量 binary 稀疏密钥、两种 PBS order 和两种 FFT，
输出为 accumulator 私钥下的 Fourier GGSW。

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
`MissingCircuitBootstrapKey`。各 evaluator 只分配自身需要的工作区。稀疏 CBS 使用
`generator.try_generate_sparse_server_key(&client, copies, buckets, Some(config), &mut rng)`。
两种 server-key 工厂均返回 `KeyGenerationError`。

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
分解与 FFT 精度均需计入 CBS 误差预算。参数检查不验证噪声或安全性。稀疏 CBS 还须计入
每个桶的加密零/dummy 与聚合 FFT 误差，并针对最小输出 gadget 尺度留出余量；CMUX 解码
成功本身不能证明该余量。见[已验证参数范围](../../docs/tfhe-cbs.md#7-b63-fourier-sparse-cbs)。

[CBS→CMUX 示例](examples/circuit_bootstrap.rs) 用 LWE bit 选择两条加密 GLWE 消息之一，
展示两种 order 与输出复用；传入 `--sparse` 可选择稀疏密钥：

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
