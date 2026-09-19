# primus_tfhe_ntru_ntt

[English](README.md) | 简体中文

基于 NTRU 的 TFHE NTT 后端。使用显式域模数和 context 的 NTT 表示。
API 和参数仍处于实验阶段；示例和基准是功能工作负载，不是安全参数建议。

完整能力与编码约定见[公共指南](../primus_tfhe/README.zh_CN.md)，参数和秘密域见
[NTRU family](../primus_tfhe_ntru/README.zh_CN.md)。两路 NTRU 后端均支持 PBS、ManyLUT 和 CBS，
Boolean 门使用共享求值器，契约见[公共指南](../primus_tfhe/README.zh_CN.md#boolean-门)。
NTT 后端另支持固定尺度分解式 MVB。

自定义 NTT 表须实现 `MonomialNttTable`；内置 `UintNttTable` 已支持。

## 普通 PBS 与 ManyLUT

先用 `TfheParameters::try_from_config(TfheConfig { .. })` 声明数学参数，再调用
`TfheContext::<_, U32NttTable>::try_from_parameters(parameters)` 自动创建匹配的变换表。
表类型仍由调用方选择，建表失败通过 `TfheContextError::TransformTable` 保留底层 NTT 错误；
已有表可用 `try_new(parameters, table)` 显式注入。

`TfheContext` 绑定参数和变换 table。通过 `context.try_generate_keys(circuit_bootstrap, rng)` 生成配套密钥，
建立 encryptor、evaluator、decryptor，再通过 `context.parameters()` 编译 LUT。[message/carry 示例](examples/ntru_ntt_basic.rs)
展示多个输出共享一次 BR 和一次环密钥切换。普通 PBS 返回 client secret 下的 LWE；
BR 后的 NTRU 密钥切换将 f_acc 转为 f_client。

```sh
cargo run -p primus_tfhe_ntru_ntt --example ntru_ntt_basic
```

示例从一个输入计算 message、carry 和 parity（`x % 4`、`x / 4`、`x % 2`），
三个输出占用四个交错槽，不代表完整的加密整数系统。

LUT 编译的第一个参数为输出 `RoundedCodec`。示例采用 `t_in=16 → t_out=4`，
通过 `decrypt_phase` 与该 codec 解码；输入几何仍遵循参数编码。

同一示例还用 `BivariateLookupTable` 比较 `0..3` 内的加密 `x` 与 `0..2` 内的加密 `y`，
打包 `x+3*y` 后调用一次普通 PBS，复用密钥、evaluator scratch 和输出缓冲区。
共同输入尺度和误差放大条件见[共享双输入契约](../primus_tfhe/README.zh_CN.md#有界双输入-pbs)。

输入域、输出 codec、奇数全域 PBS 和 ManyLUT 噪声余量见
[共享编码指南](../primus_tfhe/README.zh_CN.md#选择输出编码)与
[NTRU 客户端/LUT 契约](../primus_tfhe_ntru/README.zh_CN.md#客户端与-lut)。

## 实验性稀疏 PBS

`external_lwe` 使用 `SecretKeyDistr::fixed_hamming_weight_binary(n, h)`，要求
`0<h<n`。先生成一份可逆客户端，再显式选择桶聚合；仅选择低重量分布仍使用经典 BR。

```rust,ignore
let mut generator = KeyGenerator::new(&context);
let client = generator.try_generate_client_key(&mut rng)?;
let server = generator.try_generate_sparse_server_key(&client, 3, 2 * h, &mut rng)?;
let mut evaluator = context.evaluator(&server)?;
```

`TfheContext` 也提供固定客户端的生成入口。返回原有 `ServerKey`，通过
`sparse_bootstrapping_key()` 可访问系数域 NGSW selector。普通和交错 LUT
复用原有 evaluator 与缓冲区。CBS 和分解式 MVB 返回 `UnsupportedSparseBootstrapping`，
包括使用独立 CBS 材料的绑定方式。

映射最多重试八次，保持客户端不变；通过 `KeyGenerationError::SparseBootstrapping`
返回错误并保留底层 `BucketMap` 失败。NTRU 转换错误仍进入 `KeyGenerationError::Ntru`。
可逆性和匹配成功共同影响秘密/映射分布。需预算初始化、每个桶、ManyLUT 粗粒度旋转
和返回 KS 的误差；此实验路径未认证安全性或失败概率。

运行[稀疏 message/carry 示例](examples/ntru_ntt_sparse.rs)：

```sh
cargo run -p primus_tfhe_ntru_ntt --release --example ntru_ntt_sparse
```

## 公钥客户端

`client_key.try_generate_public_key(context.parameters(), &mut rng)` 生成外部
binary/ternary 前缀秘密下的 `LwePublicKey`；将其传入 `context.encryptor(&public_key)`
即可使用 `encrypt`、`encrypt_padded`、`encrypt_centered`。
三种加密均提供 `_to(message, output, rng)`，公钥和私钥客户端都可无分配地复用
密文存储。消息或维数错误不会改变输出及 RNG。

公钥噪声、存储和密钥身份要求集中于
[NTRU 客户端契约](../primus_tfhe_ntru/README.zh_CN.md#客户端与-lut)。

## Boolean 门

将 `external_lwe` 明文模数设为 4，通过 `context.try_generate_keys(None, rng)` 生成普通 PBS
密钥，再从 context 绑定 `boolean_encryptor`（私钥/公钥）、`boolean_decryptor` 和
`boolean_evaluator`。`evaluate_binary_to`、`not_to`、`mux_to` 复用原始 LWE 输出，无需附加求值密钥。
示例和编码契约见[公共指南](../primus_tfhe/README.zh_CN.md#boolean-门)。

## 固定尺度分解式 MVB

`context.compile_factorized_lookup_table_fn` 准备绑定本 context 的程序；
`context.factorized_evaluator(&server)` 复用普通 PBS 密钥和工作区，只多一份 NTT 多项式。
以下使用 `t_in=16` 的 context：

```rust,ignore
let codec = ScaledCodec::new(4u32, context.parameters().accumulator_ntru().cipher_modulus());
let program = context.compile_factorized_lookup_table_fn(&codec, 8, 3, |m, i| {
    match i { 0 => (m % 4) as u32, 1 => (m / 4) as u32, _ => (m % 2) as u32 }
})?;
let input = context.encryptor(&client)?.encrypt_padded(6, &mut rng)?;
let decryptor = context.decryptor(&client)?;
let mut mvb = context.factorized_evaluator(&server)?;
let mut outputs = vec![LweCiphertext::zero(context.parameters().external_lwe_dimension()); 3];
mvb.apply_lookup_table_to(&input, &program, &mut outputs);
for (output, expected) in outputs.iter().zip([2, 1, 0]) {
    assert_eq!(codec.decode_value(decryptor.decrypt_phase(output)?), expected);
}
```

输入采用参数的 Rounded 前半区编码，输出统一为相同奇数密文模数下的 unsigned Scaled
编码；保留输出 codec 解密。输出数量不补齐，也不降低旋转分辨率。

全部输出共享共同多项式的一次 `NLev[1]` 初始化和 BR；随后各自乘因子、执行 NTRU KS，
再提取外部客户端秘密下的 compact LWE。因子范数放大初始化与 BR 误差，KS 误差在其后加入。
程序的 context 身份、输入维数、准确输出数量及所有输出维数均在
写输出前检查；`_to` 调用零分配。

代数和编码限制见[共享契约](../primus_tfhe/README.zh_CN.md#固定尺度分解式-mvb)。

运行[阈值示例](examples/ntru_ntt_mvb_thresholds.rs)，将 `0..64` 的一个加密分数
转换为交错容量之外的 17 个数值标志：

```sh
cargo run -p primus_tfhe_ntru_ntt --release --example ntru_ntt_mvb_thresholds
```

示例复用程序和密文缓冲，并用保留的 Scaled codec 解码；数值标志与 Boolean evaluator
的编码不同。与重复 PBS 或交错 ManyLUT 比较时，参考 [NTRU MVB 成本与噪声](../../docs/tfhe-mvb-ntru.md)。

## 可选 circuit bootstrapping

通过 `CircuitBootstrapConfig` 独立选择 output/trace/scheme-switch 分解和 trace/SS 噪声；
长度、模数与 accumulator 秘密分布自动派生。`CircuitBootstrapParameters::try_new` 仍可绑定已有 basis/NLev 参数。

通过 `context.try_generate_keys(Some(config), &mut rng)`
生成配套 client/server key。`ServerKey` 持有 CBS 参数及 trace/scheme-switch key，
与普通 PBS 材料从同一组私钥和变换表生成。仅需 PBS 时使用 `None`，
不分配 CBS 密钥材料或工作区。`context.evaluator(&server)` 与
`context.circuit_bootstrap_evaluator(&server)` 共用这份 server key；经典 key 未启用 CBS 时后者返回
`MissingCircuitBootstrapKey`，稀疏 key 则明确拒绝。各 evaluator 只分配自身需要的工作区。生成错误为
`KeyGenerationError`，NTRU 采样/变换失败通过 `Ntru` 分支返回，`ClientKey` 仅表示兼容性错误。

高级组合仍可使用接收已准备参数所有权的 `try_generate_circuit_bootstrap_key`，以及显式传入
参数和材料的 `CircuitBootstrapEvaluator::try_from_parts`。调用方负责配套私钥与生成时的
变换表示；布局检查不能证明身份。绑定的参数可通过
`server.circuit_bootstrap_key().unwrap().parameters()` 访问。

NTT CBS 输出 `NttNgswCiphertext`，trace 归一化要求奇数 q 且 q 小于 `2^(T::BITS-1)`。
Gadget 尺度、accumulator 密钥身份及独立噪声/安全预算见
[共享 CBS 契约](../primus_tfhe_ntru/README.zh_CN.md#cbs-与示例)。

运行 [CBS → CMUX 示例](examples/ntru_ntt_circuit_bootstrap.rs)：

```sh
cargo run -p primus_tfhe_ntru_ntt --example ntru_ntt_circuit_bootstrap
```

示例创建配套的普通/CBS key，在 `f_acc` 下加密两个 NTRU 候选密文，再将外部 LWE bit
重复转换为 gadget 尺度的 NGSW 控制。CMUX 在输入 0 时选第一个候选，输入 1 时选第二个。
输入、control、选择结果和服务端 scratch 均复用，最后通过解密检查结果。

使用 `evaluator.allocate_output()` 分配原有 CBS 控制密文，随后调用
`evaluator.cmux_to(control, lhs, rhs, output)` 或 `external_product_to(control, input, output)`。
`context.accumulator_client(&client)` 绑定环加解密与转换工作区。
详见[公共消费契约](../primus_tfhe/README.zh_CN.md#cbs-输出与消费)及[完整示例](examples/ntru_ntt_circuit_bootstrap.rs)。

错误归属与转换规则见[公共 TFHE 错误边界](../primus_tfhe/README.zh_CN.md#错误边界)。

## 进一步阅读

[实现设计与开发验证](../../docs/tfhe.md) · [基准与测量](../../docs/benchmarks/tfhe.md)
