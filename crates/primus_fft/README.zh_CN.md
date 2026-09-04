# primus_fft

[English](README.md) | 简体中文

`primus_fft` 为 `Z[X] / (X^N + 1)` 中的多项式提供负循环 Fourier 变换。它在
RustFFT 和 `tfhe-fft` 之上提供统一的 table 与 workspace API，并实现
[Primus FHE](../../README.zh_CN.md) 的 Fourier FHE 路径所需的 torus 转换。

> [!WARNING]
> 本 crate 属于实验性的 Primus FHE workspace。其 API、Fourier 表示和数值契约
> 尚不稳定，可能随时发生不兼容修改。

## 核心类型

| 类型 | 职责 |
| --- | --- |
| `FftTable` | 针对一个多项式长度定义的后端无关负循环变换契约 |
| `RustFftTable` | 基于 RustFFT 的 `FftTable` 实现 |
| `TfheFftTable` | 基于 unordered `tfhe-fft` plan 的 `FftTable` 实现 |
| `FftEngine<'a, Table>` | 一个不可变 table 引用以及一份可复用的可变 workspace |
| `TorusFftValue` | 在无符号 `u16`、`u32` 或 `u64` torus 位模式与 `f64` 之间转换 |

对于 `N = 2^log_n`，每个 table 将 `N` 个系数转换成 `N / 2` 个复数值。table
拥有后端 plan 和 twist factor；engine 拥有每次变换使用的临时内存。

## 示例

```rust
use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable};

let table = RustFftTable::new(3).unwrap(); // N = 8
let mut fft = FftEngine::new(&table);
let input: Vec<u32> = (0..fft.poly_length()).map(|value| value as u32).collect();
let mut fourier = vec![Complex64::default(); fft.fourier_length()];
let mut output = vec![0u32; fft.poly_length()];

fft.forward_as_torus(&input, &mut fourier);
fft.backward_as_torus(&fourier, &mut output);

assert_eq!(output, input);
```

## 变换形式

- `forward_as_torus` 将每个无符号整数重新解释为有符号位模式，再乘以
  `2^-BITS`；例如 `u32::MAX` 表示 `-1 / 2^32`。
- `forward_as_integer` 执行相同的有符号位模式解释，但不做 torus 缩放。它适合
  secret key、分解 digit 等小整数多项式。
- `forward_integer_f64` 接受以 `f64` 保存的整数值系数，不再执行额外的表示转换。
- `backward_as_torus` 执行逆变换、torus 反向缩放、舍入以及到无符号字长的
  wrapping 转换。

负循环卷积应对 torus 多项式调用 `forward_as_torus`，对整数多项式调用
`forward_as_integer`，逐点执行复数乘法，再调用 `backward_as_torus`。

## Table 与 workspace 契约

应在拥有 Fourier 表示的 context 中构造一个固定 table，并始终复用它。Fourier
值和 scratch 内存都绑定到这个确切的 table 实例。即使后端和多项式长度相同，
也不能混用不同 table 创建的值或 scratch：后端顺序、plan 和 workspace 兼容性
都是 table 的私有属性，API 不提供跨 table 的兼容保证。

Table 不可变并实现 `Send + Sync`，因此可以在线程间共享。每个并发 worker
必须创建自己的 `FftEngine`，或者通过 `new_scratch` 获得独立 scratch；不同变换
调用之间不能共享可变 workspace。

输入和输出长度必须精确匹配：

- 系数 slice 包含 `poly_length()` 个值；
- Fourier slice 包含 `fourier_length() == poly_length() / 2` 个值；
- 直接传给 `FftTable` 方法的 scratch 必须由同一个 table 实例分配。

长度错误或 workspace 不兼容会触发 panic。

## 长度与精度

`FftTable::new(log_n)` 接受 `2 <= log_n <= usize::BITS - 1`，因此支持的最小
多项式长度为四。Table 构造包含后端 planning 和内存分配，不应放在重复变换路径
中。

变换使用 `f64`，因而是近似计算。Fourier 运算能否正确舍入回预期 torus 值，
取决于累积浮点误差和整数操作数的大小；上层算法负责维持合适的精度预算。

## 测试与 benchmark

```text
cargo test -p primus_fft
cargo bench -p primus_fft --bench fft
```

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0)
或 [MIT License](../../LICENSE-MIT)。
