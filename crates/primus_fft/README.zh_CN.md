# primus_fft

[English](README.md) | 简体中文

`primus_fft` 为 `Z[X] / (X^N + 1)` 中的多项式提供负循环 Fourier 变换。它在 RustFFT 和 `tfhe-fft` 之上提供统一的 table 与 workspace API，并实现 [Primus FHE](../../README.zh_CN.md) 的 Fourier FHE 路径所需的 torus 转换。

> [!WARNING]
> 本 crate 属于实验性的 Primus FHE workspace。其 API、Fourier 表示和数值契约 尚不稳定，可能随时发生不兼容修改。

## 核心类型

| 类型 | 职责 |
| --- | --- |
| `FftTable` | 针对一个多项式长度定义的后端无关负循环变换契约 |
| `RustFftTable` | 基于 RustFFT 的 `FftTable` 实现 |
| `TfheFftTable` | 基于 unordered `tfhe-fft` plan 的 `FftTable` 实现 |
| `FftEngine<'a, Table>` | 一个不可变 table 引用以及一份可复用的可变 workspace |
| `TorusFftValue` | 在无符号 `u16`、`u32` 或 `u64` torus 位模式与 `f64` 之间转换 |

对于 `N = 2^log_n`，每个 table 将 `N` 个系数转换成 `N / 2` 个复数值。table 拥有后端 plan 和 twist factor；engine 拥有每次变换使用的临时内存。

## Features

默认不启用具体 FFT 引擎。`FftTable`、`FftEngine`、`Complex64` 和 `TorusFftValue` 始终可用。

- `rustfft` 导出 `RustFftTable` / `RustFftWorkspace`，仅引入 RustFFT 实现。
- `tfhe-fft` 导出 `TfheFftTable` / `TfheFftWorkspace`，仅引入 TFHE-FFT 实现及其动态栈依赖。

两者可以同时启用。依赖声明显式选择，例如 `primus_fft = { path = "../primus_fft", features = ["rustfft"] }`；未选择引擎时仍可实现自己的 `FftTable`。下方示例使用 `rustfft`。

## 示例

```rust
use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable};
use primus_poly::PolyLength;

let table = RustFftTable::new(PolyLength::new(32)); // N = 32
let mut fft = FftEngine::new(&table);
let input: Vec<u32> = (0..fft.poly_length().get()).map(|value| value as u32).collect();
let mut fourier = vec![Complex64::default(); fft.fourier_length()];
let mut output = vec![0u32; fft.poly_length().get()];

fft.forward_as_torus(&input, &mut fourier);
fft.backward_as_torus(&fourier, &mut output);

assert_eq!(output, input);
```

## 变换形式

- `forward_as_torus` 将每个无符号整数重新解释为有符号位模式，再乘以 `2^-BITS`；例如 `u32::MAX` 表示 `-1 / 2^32`。
- `forward_as_integer` 执行相同的有符号位模式解释，但不做 torus 缩放。它适合 secret key、分解 digit 等小整数多项式。
- `forward_integer_f64` 接受以 `f64` 保存的整数值系数，不再执行额外的表示转换。
- `backward_as_torus` 执行逆变换、torus 反向缩放、舍入以及到无符号字长的 wrapping 转换。

负循环卷积应对 torus 多项式调用 `forward_as_torus`，对整数多项式调用 `forward_as_integer`，逐点执行复数乘法，再调用 `backward_as_torus`。

## Table 与 workspace 契约

应在拥有 Fourier 表示的 context 中构造一个固定 table，并始终复用它。Fourier 值和 scratch 内存都绑定到这个确切的 table 实例。即使后端和多项式长度相同， 也不能混用不同 table 创建的值或 scratch：后端顺序、plan 和 workspace 兼容性 都是 table 的私有属性，API 不提供跨 table 的兼容保证。

Table 不可变并实现 `Send + Sync`，因此可以在线程间共享。每个并发 worker 必须创建自己的 `FftEngine`，或者通过 `new_workspace` 获得独立 scratch；不同变换 调用之间不能共享可变 workspace。

内置 table 的 twist factor 和变换工作区使用 cache line 对齐存储。调用方的输入和输出仍接受普通 slice，包括子切片，无需额外对齐。

内置 scratch 类型在析构时抗优化擦除完整缓冲区。处理秘密数据后，可以调用 `fft.zeroize_workspace()` 擦除工作区并保留其可复用性；普通变换不会在每次调用时 自动擦除 scratch。调用方持有的输入和输出有独立生命周期；这里的堆缓冲区保证 不覆盖寄存器或编译器生成的栈副本。自定义后端自行定义 scratch 擦除行为。

输入和输出长度必须精确匹配：

- 系数 slice 包含 `poly_length().get()` 个值；
- Fourier slice 包含 `fourier_length() == poly_length().fourier_poly_len()` 个值；
- 直接传给 `FftTable` 方法的 scratch 必须由同一个 table 实例分配。

输入/输出长度错误会触发 panic。后端的 workspace 容量检查也可能 panic，但不能证明 table 身份；工作区与 Fourier 值来自同一个表实例仍由调用方保证。

`FftEngine::from_workspace(table, workspace)` 不检查来源，直接复用已有分配。`into_parts()` 返回原表引用和工作区，可以将这两个部分一起重新绑定而无需分配；应保留这对资源。无需恢复已有工作区时，使用 `FftEngine::new(table)`。

`FftTable::automorphism_map(degree)` 为 `X -> X^degree` 分配 Fourier 映射，其中 `degree` 是 `[1, 2N)` 内的奇数。第 `j` 项给出输出 `j` 对应的 `(source, conjugate)`。

应在求值密钥构造时创建并缓存映射，并复用原 table 实例。自定义 `FftTable` 实现必须按自身存储顺序提供映射。单独应用映射不执行密码学 key switching。

## 长度与精度

`FftTable::new(poly_length)` 接收检查了 FHE 共用 `32..=2^17` 范围的 `primus_poly::PolyLength`；构造直接返回表，无需额外的尺寸检查。表和 engine 的 `poly_length()` 返回同一类型，`fourier_length()` 返回复数元素数量。Table 构造包含后端 planning 和内存分配，不应放在重复变换路径中。

变换使用 `f64`，因而是近似计算。Fourier 运算能否正确舍入回预期 torus 值， 取决于累积浮点误差和整数操作数的大小；上层算法负责维持合适的精度预算。

## 测试与 benchmark

```text
cargo test -p primus_fft --features rustfft,tfhe-fft
cargo bench -p primus_fft --bench fft --features rustfft,tfhe-fft
```

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或 [MIT License](../../LICENSE-MIT)。
