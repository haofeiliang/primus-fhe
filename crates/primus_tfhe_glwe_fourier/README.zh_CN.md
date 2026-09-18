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
示例打印并检查这两个维数（4 和 256），输入和输出均遵循选定的外部秘密域。
所有 fixture 的维数、噪声和分解参数仅用于功能演示，不是生产安全或失败概率建议。

## Context 与复用

先用 `TfheParameters::try_from_config(TfheConfig { .. })` 声明数学参数，再调用
`TfheContext::<_, RustFftTable>::try_from_parameters(parameters)` 自动创建匹配的变换表。
表类型仍由调用方选择，建表失败返回底层 FFT 错误；已有表可用 `try_new(parameters, table)` 显式注入。

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

低层 `FourierGlweBootstrappingKey<T, LM>` 保留输入模数类型 `LM`，与 accumulator 模数独立。
密钥生成时准备普通 PBS 量化参数；ManyLUT 在系数循环前按旋转步长准备转换。
高层 context 保持既有参数约束。

## Binary 与 ternary small 秘密

在 `LweParameters` 中选择 `SecretKeyDistr::UniformTernary` 或其他 ternary 家族，
即可沿用原有密钥生成与 evaluator 接口；basic 示例使用该配置。两种 PBS order、
普通/交错 LUT 和公钥输入均支持。Binary 每坐标仍保存一份 GGSW；ternary 保存独立
加密的 `(positive, negative)` 控制对，每坐标通过组合控制执行一次外积。

低层使用 `FourierGlweBlindRotationContext::new(&key)` 创建匹配控制类型的工作区，
`resize` 保持该类型。`iter_binary_controls` / `iter_ternary_controls` 分别返回单控制或
控制对；类型不匹配时返回 `None`。ServerKey 兼容性检查包括 small secret 分布。
循环外选择内核，在线复用工作区；融合方案增加 BSK 和临时 GGSW 存储。

## Circuit bootstrapping

经典 CBS 支持 binary/ternary small 秘密、两种 PBS order 和两种 FFT，输出为 accumulator
私钥下的 Fourier GGSW。稀疏 CBS 尚不支持。

通过 `CircuitBootstrapParameters::try_from_config(tfhe, config)` 指定
`CircuitBootstrapConfig` 中的 output/trace/scheme-switch 分解及独立的 trace/SS 噪声。
Native 模数、环布局与秘密分布从 accumulator 派生，构造器检查补齐后的 gadget
层数容量并绑定输入明文模数。`try_new` 仍可直接绑定已有 basis 与 GLev/GGSW 参数。
Scheme-switch key 绑定输出布局；层数相同的其他输出 basis
可以复用该密钥。

使用同一个 `ClientKey`，通过可复用的 `KeyGenerator` 依次调用
`try_generate_server_key` 和 `try_generate_circuit_bootstrap_key`。
`TfheContext::generate_circuit_bootstrap_key` 提供便捷入口。两类密钥必须使用同一组客户端
私钥和生成时的 FFT table；布局/basis 检查不能证明实际身份。普通 `ServerKey` 不包含 CBS 材料。

通过 `context.circuit_bootstrap_evaluator(&server, &parameters, &circuit_key)` 创建 evaluator。
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

示例与基准共享 `n=728, N=1024`、三层输出的 binary profile。误差来源、最小 gadget
尺度的观测余量、密钥/工作区大小和耗时见 [CBS 专项](../../docs/tfhe-cbs.md)。
该 profile 不是生产参数建议；稀疏 CBS 仍不支持。

## 验证与性能

```sh
cargo test -p primus_tfhe_glwe_fourier
cargo clippy -p primus_tfhe_glwe_fourier --all-targets -- -D warnings
cargo +nightly test -p primus_tfhe_glwe_fourier --features simd
cargo bench -p primus_tfhe_glwe_fourier --bench pbs
cargo bench -p primus_tfhe_glwe_fourier --bench ternary_pbs
cargo bench -p primus_tfhe_glwe_fourier --bench circuit_bootstrap
```

`pbs` 复用输出，覆盖两种 order、3/4 输出 ManyLUT 与独立 PBS 的对照，以及 Boolean AND/MUX。
BR 和密钥切换阶段用于定位开销；系数提取的基准集中在 `primus_lattice`。
Fourier PBS 基准同时覆盖 RustFFT 和 TfheFFT。

`ternary_pbs` 在 `n=728, N=1024`、BR→KS 下比较 binary、融合 ternary 和双 CMUX
完整 PBS，另测 BSK+KSK 生成。参数、耗时及密钥/工作区测量见
[T3 测量](../../docs/tfhe-ternary.md#t3完整-glwe-接入与验收已完成)。

`circuit_bootstrap` 测量两种 order、两种 FFT 的完整 CBS，并按 FFT 各测一次 BR、
三层投影与 scheme switch。Setup 和相位检查不计时，在线复用全部缓冲。
