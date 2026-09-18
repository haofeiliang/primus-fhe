# primus_tfhe_glwe_ntt

[English](README.md) | 简体中文

基于 GLWE、采用显式域模数的 TFHE 后端。支持两种 PBS order、ManyLUT、分解式 MVB、Boolean 门及私钥/公钥客户端。
完整能力与编码约定见[公共指南](../primus_tfhe/README.zh_CN.md)，
参数与秘密域见 [GLWE family](../primus_tfhe_glwe/README.zh_CN.md)。

`Encryptor`、`Decryptor`、`TfheConfig` 和 `TfheParameters` 是公共类型固定为 `BarrettModulus` 的别名；
`ClientKey`、`EncryptionKey` 和 `PbsOrder` 直接重导出。

## 运行完整示例

```sh
cargo run -p primus_tfhe_glwe_ntt --example ntt_basic
```

[示例源码](examples/ntt_basic.rs) 用相同流程运行两种 order：参数 → context → 配套密钥
→ 公钥 encryptor / client decryptor → 编译 LUT → 复用 evaluator 与输出。
涵盖单 PBS、`t_in=4 → t_out=8` 的双输出 ManyLUT、客户端 `encrypt_padded_to`、Boolean 门、NOT 和 MUX。

`BootstrapKeyswitch` 的外部密文维数为 `n`，`KeyswitchBootstrap` 为 `kN`。
输入和输出均遵循选定的外部秘密域。示例的维数、噪声和分解参数仅用于功能演示，
不是生产安全或失败概率建议。

## Context 与复用

先用 `TfheParameters::try_from_config(TfheConfig { .. })` 声明数学参数，再调用
`TfheContext::<_, U32NttTable>::try_from_parameters(parameters)` 自动创建匹配的变换表。
表类型仍由调用方选择，建表失败通过 `TfheContextError::TransformTable` 保留底层 NTT 错误；
已有表可用 `try_new(parameters, table)` 显式注入。

`TfheContext::try_new` 检查 NTT 长度和模数。NTT 域密钥与值必须采用所传 table 的表示。
`boolean_parameters()` 是开发 fixture，不是经过论证的默认参数；示例直接选取自己的小参数。

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

使用 unsigned `ScaledCodec` 编译一次，随后复用独立 evaluator：

```rust,ignore
use primus_encoding::ScaledCodec;

let codec = ScaledCodec::new(2u32, context.parameters().accumulator_glwe().cipher_modulus());
// 此例要求 t_in >= 8，并具备足够的输入和输出噪声余量。
let lut = context.compile_factorized_lookup_table_fn(
    &codec, 4, 3, |m, i| u32::from(m > i),
)?;
let mut evaluator = context.factorized_evaluator(&server_key)?;
let mut outputs = vec![LweCiphertext::zero(context.parameters().external_lwe_dimension()); 3];
let input = encryptor.encrypt_padded(2, &mut rng)?;
evaluator.apply_lookup_table_to(&input, &lut, &mut outputs);
assert_eq!(codec.decode_value(decryptor.decrypt_phase(&outputs[1])?), 1);
```

codec 后依次是输入前缀长度和有效输出数。编译返回借用本 context 的
`NttFactorizedLookupTable`；即使 q、N 相同，换一个 context 实例执行也会拒绝。
低层调用方可先编译 `FactorizedLookupTable`，再交给 `NttFactorizedLookupTable::new` 消费。

两种 order 均支持经典/稀疏密钥。BK 共享一次 BR，再逐输出乘法和 KS；KB 先共享
输入 KS，再 BR 和逐输出乘法。任意正输出数均保持旋转步长 1。`_to` 在写入前检查
context、输入、输出数量和全部输出维数，在线零分配。额外工作区仅为一个包含
`(d+1)*N` 个系数的 NTT GLWE，与输出数量无关。
程序保存 `(output_count+1)*N` 个系数。

相位解码使用输出 codec。因子范数会放大 BR 噪声；串联 PBS 时还需考虑 Scaled 与
Rounded 中心差异。见[共享契约](../primus_tfhe/README.zh_CN.md#固定尺度分解式-mvb)。

运行[阈值示例](examples/mvb_thresholds.rs)：

```sh
cargo run -p primus_tfhe_glwe_ntt --release --example mvb_thresholds
```

示例把 `0..64` 的一个加密分数转换为 17 个数值阈值标志，复用编译产物和全部密文缓冲区。
N=1024 时，交错布局仅为每个输出留下 32 个位置，无法容纳 64 个输入。
每个阈值的差分因子仅有两项、一范数为 2，限制其噪声放大。
交错容量和输入噪声余量足够时优先考虑交错；分解式以更大的程序/构造成本保留步长 1。
实测与选择条件见 [MVB 成本对照](../../docs/tfhe-mvb.md#8-p43-测量与应用选择)。

## 实验性稀疏 PBS

将 **small-LWE** 分布设为 `SecretKeyDistr::fixed_hamming_weight_binary(n, h)`，
显式生成稀疏 server key：

```rust,ignore
let mut generator = KeyGenerator::new(&context);
let client_key = ClientKey::generate(context.parameters(), &mut rng);
let server_key = generator.try_generate_sparse_server_key(&client_key, 3, 2 * h, &mut rng)?;
let mut evaluator = context.evaluator(&server_key)?;
evaluator.apply_lookup_table_to(&input, &lut, &mut output);
// 同一 evaluator 支持 apply_interleaved_lookup_table_to。
```

两种 order 均以该 small 秘密进行盲旋转。`BootstrapKeyswitch` 的外部维数仍为 `n`，
`KeyswitchBootstrap` 仍为 `kN`。普通/交错 PBS 共用既有 LUT 编译、输出 codec、KS 和提取，
`_to` 调用零分配。普通密钥工厂生成经典密钥，稀疏算法需使用上面的专用入口。
需要低层密钥的调用方通过 `ServerKey::bootstrapping_key()`
返回的 `BootstrappingKey::{Classic, Sparse}` 选择对应类型。

稀疏服务端密钥在 `t=4` 时可交给 `context.boolean_evaluator(&server_key)`，也可通过普通
evaluator 求值有界双输入或奇数全域 LUT。选择参数时须计入门预处理、打包误差放大
和奇数全域较窄的输入余量。

生成入口检查实际二元系数和重量，固定同一秘密最多尝试八个独立公开桶映射，错误时不返回部分密钥。
示例采用三个副本、`2*h` 个桶。

低层普通盲旋转使用 `try_generate_sparse_bootstrapping_key` 返回的 `SparseGlweBootstrappingKey`，
配套 `SparseGlweBlindRotationContext::new(&key)`，调用 `ntt_blind_rotate_lookup_table_to`。
输入为 small-LWE 和已编码多项式，输出为 accumulator GLWE，旋转步长为 1。

稀疏聚合噪声和交错旋转步长需要单独预算。这些参数尚无经认证的安全等级或完整 PBS 失败率，
见 [稀疏 PBS 设计与测量](../../docs/tfhe-sparse-pbs.md#p35-完整-pbs-接入与验收)。

## Binary 与 ternary small 秘密

在 `LweParameters` 中选择 `SecretKeyDistr::UniformTernary` 或其他 ternary 家族，
即可沿用原有密钥生成与 evaluator 接口；basic 示例使用该配置。两种 PBS order、
普通/交错 LUT 和公钥输入均支持。Ternary 比 binary 需要更多密钥与工作区存储，
见[设计与成本](../../docs/tfhe-ternary.md)。

NTT context/BR 要求 `MonomialNttTable`，仓库内置 NTT 表均实现此能力。
经典 ternary 同样支持 CBS 和分解式 MVB；桶聚合稀疏路径仍只支持固定重量 binary，
`SparseTernary` 分布不自动选择桶聚合算法。

## Circuit bootstrapping

CBS 要求经典 server key；稀疏密钥返回
`TfheEvaluationError::UnsupportedSparseBootstrapping`，其 gadget 尺度噪声尚未验收。
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

输出 basis 定义 GGSW gadget 尺度，输出布局从 accumulator 派生；circuit key 绑定
输出布局及 trace/scheme-switch basis。CBS 保留 accumulator secret，跳过普通 PBS
后处理。
`CircuitBootstrapConfig` 具名指定 output/trace/scheme-switch 分解和独立的 trace/SS 噪声，
环参数从 accumulator 派生；`try_new` 保留已有底层参数的直接绑定入口。
Trace/SS 噪声与秘密相关消息假设需要独立评估。

使用 `evaluator.allocate_output()` 分配原有 CBS 控制密文，随后调用
`evaluator.cmux_to(control, lhs, rhs, output)` 或 `external_product_to(control, input, output)`。
`context.accumulator_client(&client)` 绑定系数域环加解密，复用输出和工作区，在线不分配。
详见[公共消费契约](../primus_tfhe/README.zh_CN.md#cbs-输出与消费)及[完整示例](examples/circuit_bootstrap.rs)。

错误归属与转换规则见[公共 TFHE 错误边界](../primus_tfhe/README.zh_CN.md#错误边界)。

## 进一步阅读

[实现设计与开发验证](../../docs/tfhe.md) · [基准与测量](../../docs/benchmarks/tfhe.md)
