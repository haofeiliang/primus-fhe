# primus_tfhe_glwe_fourier

[English](README.md) | 简体中文

基于 GLWE、采用原生 torus 的 TFHE 后端。支持两种 PBS order、ManyLUT、Boolean 门及私钥/公钥客户端。
完整能力与编码约定见[公共指南](../primus_tfhe/README.zh_CN.md)，
参数与秘密域见 [GLWE family](../primus_tfhe_glwe/README.zh_CN.md)。

## 运行完整示例

```sh
cargo run -p primus_tfhe_glwe_fourier --example fourier_basic
```

[示例源码](examples/fourier_basic.rs) 用相同流程运行两种 order：参数 → context → 配套密钥
→ 公钥 encryptor / client decryptor → 编译 LUT → 复用 evaluator 与输出。
涵盖单 PBS、双输出 ManyLUT、客户端 `encrypt_padded_to`、Boolean 门、NOT 和 MUX。

`BootstrapKeyswitch` 的外部密文维数为 `n`，`KeyswitchBootstrap` 为 `kN`。
示例打印并检查这两个维数（4 和 256），输入和输出均遵循选定的外部秘密域。
所有 fixture 的维数、噪声和分解参数仅用于功能演示，不是生产安全或失败概率建议。

## Context 与复用

`TfheContext::try_new` 检查 FFT 长度。所有变换域密钥、值与 evaluator 必须使用同一
FFT table 实例；长度相同不能证明表示兼容。示例使用 `RustFftTable`，也支持 `TfheFftTable`。
FFT engine 和 evaluator 从同一个 context 创建。

普通 LUT 使用 `compile_lookup_table_fn` / `compile_lookup_table_slice`，多输出使用
`compile_interleaved_lookup_table_*`。输入采用 unsigned padded 编码，并考虑 ManyLUT 较低的
旋转分辨率。Evaluator 持有可变 scratch，创建一次后复用 `apply_lookup_table_to` /
`apply_interleaved_lookup_table_to`；这些入口在写入前检查全部输出维数。

`t=4` 时使用 `boolean_encryptor`、`boolean_decryptor`、`boolean_evaluator`，由适配器处理
内部模 8 的 LUT 尺度。通过 `evaluate_binary_to`、`not_to`、`mux_to` 重复求值。

低层 `FourierGlweBootstrappingKey<T, LM>` 保留输入模数类型 `LM`，与 accumulator 模数独立。
密钥生成时准备普通 PBS 量化参数；ManyLUT 在系数循环前按步长准备转换。
高层 context 保持既有参数约束。

## Circuit bootstrapping

Fourier GLWE CBS 尚未实现。已有 GLWE CBS 路径在 [NTT 后端](../primus_tfhe_glwe_ntt/README.zh_CN.md)，
其模归一化保证不能直接用于未来的 Fourier 实现。

## 验证与性能

```sh
cargo test -p primus_tfhe_glwe_fourier
cargo clippy -p primus_tfhe_glwe_fourier --all-targets -- -D warnings
cargo +nightly test -p primus_tfhe_glwe_fourier --features simd
cargo bench -p primus_tfhe_glwe_fourier --bench pbs
```

`pbs` 复用输出，覆盖两种 order、3/4 输出 ManyLUT 与独立 PBS 的对照，以及 Boolean AND/MUX。
BR 和密钥切换阶段用于定位开销；系数提取的基准集中在 `primus_lattice`。
Fourier PBS 基准同时覆盖 RustFFT 和 TfheFFT。
