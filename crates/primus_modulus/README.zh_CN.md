# primus_modulus

[English](README.md) | 简体中文

`primus_modulus` 提供具体的模数 context 和算术内核，实现 [`primus_reduce`](../primus_reduce/README.zh_CN.md) 定义的契约。

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

## 模数类型

| 类型 | 模数 | 适用场景 |
| --- | --- | --- |
| `NativeModulus<T>` | 隐式 `2^T::BITS` | 原生字长环上的 wrapping 算术 |
| `PowOf2Modulus<T>` | 大于一且可表示的二次幂 | 显式二次幂模数上的掩码算术 |
| `BarrettModulus<T>` | `1 < modulus < 2^(T::BITS - 2)` | 重复乘法、宽整数约简、融合切片运算和点积 |
| `CompactModulus<T>` | `1 < modulus < 2^(T::BITS - 2)` | 不保存预计算数据的基本加、减、取负和逆元运算 |
| `UintModulus<T>` | 任意可表示的 `modulus > 1` | 紧凑范围限制不适用时的基本算术 |

`BarrettModulus` 保存 `floor(B² / modulus)`，其中 `B = 2^T::BITS`。模数预留的两个高位使其点积内核可以在约简前累加 16 个乘积。`CompactModulus` 和 `UintModulus` 只保存模数。

## 示例

```rust
use primus_modulus::{BarrettModulus, reduce::prelude::*};

let modulus = BarrettModulus::new(97u64);

assert_eq!(modulus.reduce_add(80, 30), 13);
assert_eq!(modulus.reduce_mul(12, 9), 11);

let lhs = [12, 20, 31];
let rhs = [9, 10, 11];
let mut output = [0; 3];
modulus.reduce_mul_slice_to(&lhs, &rhs, &mut output);
assert_eq!(output, [11, 6, 50]);
```

## 选择并构造模数

- 当溢出本身就表示对完整字长取模时，使用 `NativeModulus::new()`。
- 对可表示的二次幂模数使用 `PowOf2Modulus::new(value)`。
- 当受支持 Barrett 范围内的模数需要乘法和重复约简时，使用 `BarrettModulus::new(value)`。
- 对各自较小的基本运算集合使用 `CompactModulus::new(value)` 或 `UintModulus::new(value)`。

带检查的构造器会验证文档规定的范围。当调用方已经完成验证，并且有意避免重复检查时，仍可使用 `CompactModulus(value)` 和 `UintModulus(value)`。同样，调用 `BarrettModulus::new_unchecked` 和 `BarrettModulus::from_parts` 时，调用方必须维持其文档规定的倒数与范围不变量。

## Feature

- `derive` 重新导出用于编译期常量模数的 `Barrett` derive 宏。参见 [`primus_barrett_derive`](../primus_barrett_derive/README.zh_CN.md)。
- `simd` 启用 nightly portable-SIMD 内核和切片调度；同时启用 `derive` 时，生成的 Barrett context 会使用相应 SIMD 路径。

两个 feature 默认都不启用。`simd` feature 需要 nightly Rust 工具链。

## 算术契约

运算 trait、输入范围、输出范围和切片长度要求均来自 `primus_reduce`。

- 除非对应 trait 记录了更宽的输入域，规范运算通常要求输入为规范剩余类。
- 惰性运算返回 `[0, 2 * modulus)` 中的代表元，在作为规范剩余类使用前需要再执行一次单次约简。
- 底层切片内核可能只用 `debug_assert*!` 诊断形状问题；release 调用方必须维持文档中的长度契约。
- `FieldContext` 是能力 marker；它不证明模数为素数，也不保证每个非零值都可逆。

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或 [MIT License](../../LICENSE-MIT)。
