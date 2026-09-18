# primus_tfhe_ntru_ntt

[English](README.md) | 简体中文

基于 NTRU 的 TFHE NTT 后端。使用显式域模数和 context 的 NTT 表示。
API 和参数仍处于实验阶段；示例和基准是功能工作负载，不是安全参数建议。

完整能力与编码约定见[公共指南](../primus_tfhe/README.zh_CN.md)，参数和秘密域见
[NTRU family](../primus_tfhe_ntru/README.zh_CN.md)。两路 NTRU 后端均支持 PBS、ManyLUT 和 CBS，
Boolean 门使用共享求值器，契约见[公共指南](../primus_tfhe/README.zh_CN.md#boolean-门)。
NTT 后端另支持固定尺度分解式 MVB。

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
[集成测试](tests/boolean.rs)覆盖六种二元门、NOT、MUX、门链、维数错误和零分配复用，
另保留公钥 NAND 路径。

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
全部因子共用一块连续缓冲，准备程序消费该缓冲并原地变换，求值通过 `NttPolynomialIter` 借用各因子。

全部输出共享共同多项式的一次 `NLev[1]` 初始化和 BR；随后各自乘因子、执行 NTRU KS，
再提取外部客户端秘密下的 compact LWE。因子范数放大初始化与 BR 误差，KS 误差在其后加入。
普通 PBS 工作区不变。程序的 context 身份、输入维数、准确输出数量及所有输出维数均在
写输出前检查；`_to` 调用零分配。

[集成测试](tests/factorized_pbs.rs)覆盖 1/3/17 输出，包括交错容量之外的情况，
并与相同 Scaled 编码的单输出 PBS 对照。代数和编码限制见[共享契约](../primus_tfhe/README.zh_CN.md#固定尺度分解式-mvb)。

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

## 验证与性能

```sh
cargo test -p primus_tfhe_ntru_ntt
cargo clippy -p primus_tfhe_ntru_ntt --all-targets -- -D warnings
cargo +nightly test -p primus_tfhe_ntru_ntt --features simd
cargo bench -p primus_tfhe_ntru_ntt --bench pbs
cargo bench -p primus_tfhe_ntru_ntt --bench circuit_bootstrap
```

`pbs` 复用输出，测量完整 PBS，并比较 3/4 输出 ManyLUT 与独立 PBS 调用。
准备工作位于计时之外。

CBS 测试覆盖 LWE bit 到 NGSW、再消费为 CMUX 控制的完整路径、非二次幂层数、basis
和容量错误，以及 evaluator 从首次调用起零在线分配。`circuit_bootstrap` 复用输出
和工作区，覆盖 N=1024/4096、输入维数 N/16、BR/trace/SS 的 B=2^3/2^10，以及
B=2^8、两层的输出。基准报告新增 CBS key 和 evaluator 实际请求且仍持有的堆字节数，
不包括分配器开销、借用 table、普通 server key 和调用方输出。密钥生成和内存统计
位于计时 closure 外。附加 `-- --test` 可检查 fixture，但不能得出耗时或可解密性结论。
SIMD 复用现有依赖内核，不增加公开 ISA 选择接口。
