# primus_tfhe_ntru_fourier

[English](README.md) | 简体中文

基于 NTRU 的 TFHE Fourier 后端。使用原生 wrapping 模数。所有变换域密钥、值与 evaluator 必须使用同一 FFT table
实例；仅长度相同不能证明 table 身份一致。
API 和参数仍处于实验阶段；示例和基准是功能工作负载，不是安全参数建议。

完整能力与编码约定见[公共指南](../primus_tfhe/README.zh_CN.md)，参数和秘密域见
[NTRU family](../primus_tfhe_ntru/README.zh_CN.md)。两路 NTRU 后端均支持 PBS、ManyLUT、分解式 MVB 和 CBS，
Boolean 门使用共享求值器，契约见[公共指南](../primus_tfhe/README.zh_CN.md#boolean-门)。

## 普通 PBS 与 ManyLUT

先用 `TfheParameters::try_from_config(TfheConfig { .. })` 声明数学参数，再调用
`TfheContext::<_, RustFftTable>::try_from_parameters(parameters)` 自动创建匹配的变换表。
表类型仍由调用方选择，建表失败通过 `TfheContextError::TransformTable` 保留底层 FFT 错误；
已有表可用 `try_new(parameters, table)` 显式注入。

`TfheContext` 绑定参数和变换 table。通过 `context.try_generate_keys(circuit_bootstrap, rng)` 生成配套密钥，
建立 encryptor、evaluator、decryptor，再通过 `context.parameters()` 编译普通/交错 LUT。[message/carry 示例](examples/ntru_fourier_basic.rs)
展示多个输出共享一次 BR 和一次环密钥切换。普通 PBS 返回 client secret 下的 LWE；
BR 后的 NTRU 密钥切换将 f_acc 转为 f_client。

```sh
cargo run -p primus_tfhe_ntru_fourier --example ntru_fourier_basic
```

示例从一个输入计算 message、carry 和 parity（`x % 4`、`x / 4`、`x % 2`），
三个输出占用四个交错槽，不代表完整的加密整数系统。

LUT 编译的第一个参数为输出 `RoundedCodec`。示例采用 `t_in=16 → t_out=4`，
通过 `decrypt_phase` 与该 codec 解码；输入几何仍遵循参数编码。

输入域、输出 codec、奇数全域 PBS 和 ManyLUT 噪声余量见
[共享编码指南](../primus_tfhe/README.zh_CN.md#选择输出编码)与
[NTRU 客户端/LUT 契约](../primus_tfhe_ntru/README.zh_CN.md#客户端与-lut)。

## 固定尺度分解式 MVB

通过 `context.compile_factorized_lookup_table_fn(&codec, input_domain_len,
output_count, function)` 编译，输出显式提供 unsigned `ScaledCodec`，输入选择非空前半域前缀。
实际 Native 尺度必须为偶数，奇尺度返回 `LookupTableError::OddFactorizationScale`。
支持 u32/u64 和 RustFFT/TfheFFT；明文模数不必为二次幂，`t_out=10` 在两种字宽下均可用。

```rust,ignore
use primus_encoding::ScaledCodec;

let codec = ScaledCodec::new(10u32, NativeModulus::new());
let lut = context.compile_factorized_lookup_table_fn(
    &codec, 8, 3, |m, i| u32::from(m > i),
)?; // 假定 t_in >= 15，且有足够的噪声余量。
let mut evaluator = context.factorized_evaluator(&server_key)?;
let mut outputs = vec![LweCiphertext::zero(context.parameters().external_lwe_dimension()); 3];
evaluator.apply_lookup_table_to(&input, &lut, &mut outputs);
let value = codec.decode_value(decryptor.decrypt_phase(&outputs[0])?);
```

`FourierFactorizedLookupTable` 一次准备整数 Fourier 因子并借用一个 context；即使参数相同，
另一个实例也会被拒绝。显式准备入口为 `FourierFactorizedLookupTable::new(context, coefficient_lut)`。
程序存储 N 个 torus 系数和 `output_count*N/2` 个复数，不保留因子的系数副本。

全部输出共享 `NLev[1]` 加密初始化和一次 binary BR，再对每个因子乘积从 `f_acc`
切换到 `f_client`，提取为通常的外部 LWE 维数。无需附加密钥。Evaluator 额外持有
两个 Fourier 多项式（N 个复数），空间不随输出数增长；`_to` 在写入前检查全部维数，在线零分配。

因子会放大**初始化和 BR 噪声**；FFT 乘法引入 `f_acc * delta_c` 相位误差，之后还有
每个输出的 KS 误差。构造成功不代表噪声预算成立；须用提供的 Scaled codec 解码，
接入下一次 Rounded 输入 PBS 时计入中心差异。详见[共享编码契约](../primus_tfhe/README.zh_CN.md#固定尺度分解式-mvb)
及 [NTRU 精度验收](../../docs/tfhe-mvb-fourier.md#b53ntru-接入与独立误差验收)。
[基本示例](examples/ntru_fourier_basic.rs) 复用公钥输入，分别用显式输出 codec 执行 ManyLUT 与 MVB。

[17 阈值示例](examples/ntru_fourier_mvb_thresholds.rs) 将 `0..64` 的分数转为交错容量之外的
数值标志。其 Scaled `t_out=2` 输出不能直接当作 Boolean 门密文或另一明文模数的输入。
重复 PBS、交错与 MVB 的选择，包括密钥/工作区和噪声取舍，见[成本测量](../../docs/tfhe-mvb-fourier-costs.md)。

```sh
cargo run -p primus_tfhe_ntru_fourier --example ntru_fourier_mvb_thresholds
```

## 公钥客户端

`client_key.try_generate_public_key(context.parameters(), &mut rng)` 生成外部
二进制前缀秘密下的 `LwePublicKey`；将其传入 `context.encryptor(&public_key)`
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

## 可选 circuit bootstrapping

通过 `CircuitBootstrapConfig` 独立选择 output/trace/scheme-switch 分解和 trace/SS 噪声；
长度、模数与 accumulator 秘密分布自动派生。`CircuitBootstrapParameters::try_new` 仍可绑定已有 basis/NLev 参数。

通过 `context.try_generate_keys(Some(config), &mut rng)`
生成配套 client/server key。`ServerKey` 持有 CBS 参数及 trace/scheme-switch key，
与普通 PBS 材料从同一组私钥和变换表生成。仅需 PBS 时使用 `None`，
不分配 CBS 密钥材料或工作区。`context.evaluator(&server)` 与
`context.circuit_bootstrap_evaluator(&server)` 共用这份 server key；未启用 CBS 时后者返回
`MissingCircuitBootstrapKey`。各 evaluator 只分配自身需要的工作区。生成错误为
`KeyGenerationError`，NTRU 采样/变换失败通过 `Ntru` 分支返回，`ClientKey` 仅表示兼容性错误。

高级组合仍可使用接收已准备参数所有权的 `try_generate_circuit_bootstrap_key`，以及显式传入
参数和材料的 `CircuitBootstrapEvaluator::try_from_parts`。调用方负责配套私钥与生成时的
变换表示；布局检查不能证明身份。绑定的参数可通过
`server.circuit_bootstrap_key().unwrap().parameters()` 访问。

Fourier CBS 输出 `FourierNgswCiphertext`，需预算原生系数除二和 FFT 误差，并始终使用
同一 FFT table 实例。
Gadget 尺度、accumulator 密钥身份及独立噪声/安全预算见
[共享 CBS 契约](../primus_tfhe_ntru/README.zh_CN.md#cbs-与示例)。

运行 [CBS → CMUX 示例](examples/ntru_fourier_circuit_bootstrap.rs)：

```sh
cargo run -p primus_tfhe_ntru_fourier --example ntru_fourier_circuit_bootstrap
```

示例创建配套的普通/CBS key，在 `f_acc` 下加密两个 NTRU 候选密文，再将外部 LWE bit
重复转换为 gadget 尺度的 NGSW 控制。CMUX 在输入 0 时选第一个候选，输入 1 时选第二个。
输入、control、选择结果和服务端 scratch 均复用，最后通过解密检查结果。

使用 `evaluator.allocate_output()` 分配原有 CBS 控制密文，随后调用
`evaluator.cmux_to(control, lhs, rhs, output)` 或 `external_product_to(control, input, output)`。
`context.accumulator_client(&client)` 绑定环加解密与转换工作区。
详见[公共消费契约](../primus_tfhe/README.zh_CN.md#cbs-输出与消费)及[完整示例](examples/ntru_fourier_circuit_bootstrap.rs)。

错误归属与转换规则见[公共 TFHE 错误边界](../primus_tfhe/README.zh_CN.md#错误边界)。

## 进一步阅读

[实现设计与开发验证](../../docs/tfhe.md) · [基准与测量](../../docs/benchmarks/tfhe.md)
