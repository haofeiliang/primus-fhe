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

`BarrettModulus` 以小端 limb `[low, high]` 保存 `floor(B² / modulus)`，其中 `B = 2^T::BITS`。模数预留的两个高位使其点积内核可以在约简前累加 16 个乘积。`CompactModulus` 和 `UintModulus` 只保存模数。

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

带检查的构造器会验证文档规定的范围。当调用方已经完成验证，并且有意避免重复检查时，仍可使用 `CompactModulus(value)` 和 `UintModulus(value)`。同样，调用 `BarrettModulus::new_unchecked`、`BarrettModulus::from_parts` 和 `SimdBarrettModulus::from_parts` 时，调用方必须维持其文档规定的倒数与范围不变量。

## Feature

- `derive` 重新导出用于编译期常量模数的 `Barrett` derive 宏。参见 [`primus_barrett_derive`](../primus_barrett_derive/README.zh_CN.md)。
- `simd` 启用 nightly portable-SIMD 内核和切片调度；同时启用 `derive` 时，生成的 Barrett context 会使用相应 SIMD 路径。

两个 feature 默认都不启用。`simd` feature 需要 nightly Rust 工具链。

`BarrettModulus::reduce_add_mul_slice_assign` 在稳定版构建中也可以选择 x86_64 原生加速：`u32` 要求 AVX-512F，`u64` 要求 AVX-512F + AVX-512DQ。无论是否启用 `simd`，符合条件的切片均优先使用这些内核；其他情况保留标量或 portable-SIMD 回退。

## 算术契约

运算 trait、输入范围、输出范围和切片长度要求均来自 `primus_reduce`。

- 除非对应 trait 记录了更宽的输入域，规范运算通常要求输入为规范剩余类。
- 惰性运算返回 `[0, 2 * modulus)` 中的代表元，在作为规范剩余类使用前需要再执行一次单次约简。
- 底层切片内核可能只用 `debug_assert*!` 诊断形状问题；release 调用方必须维持文档中的长度契约。
- `FieldContext` 是能力 marker；它不证明模数为素数，也不保证每个非零值都可逆。
- `EncodeSigned` 转换无符号幅度小于显式模数的系数；Native 接受所有 signed 值。Native 保留位模式，PowOf2 使用掩码，Uint/Compact/Barrett 共享显式模数转换。默认切片方法统一检查一次等长，再使用具体类型的标量实现。
- `ReduceDotProductSigned` 为 Native、PowOf2、Barrett 及派生 Barrett 融合有界 signed 编码与点积。入口统一检查等长，空切片返回零。Barrett 在宽累加前完成编码，保持 16 项乘积的累加界；SIMD 处理完整块，尾部走标量内核。

## 预备模切

五种模数及派生 Barrett 均实现 `PrepareModulusSwitch`，也可以直接使用 `ModulusSwitch::new(source, target)` 准备模数对。两种入口都根据固定比例选择 可复用内核：二进制缩放、精确乘除、余数分解或窄/宽整数算术。 契约见 [`primus_reduce`](../primus_reduce/README.zh_CN.md#预备模切)。 批量转换在循环前选择内核。紧凑范围内的源模数在没有适用的二进制或扩张捷径时， 使用倒数估商和一次精确修正；准备阶段根据分子上界选择单字或双字计算。 Barrett 及派生 Barrett 的 `prepare_switch_to` 复用已有倒数；直接构造及其他源 类型仅在需要时计算倒数。调用方继续使用相同的执行接口。

`modulus_switch` 基准测量缓存转换器的标量调用和批量吞吐；`primus_encoding` 的 codec 基准及 TFHE PBS 基准覆盖实际调用方。

```rust
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_modulus::reduce::{PrepareModulusSwitch, PreparedModulusSwitch};

let conversion = BarrettModulus::new(97u32).prepare_switch_to(NativeModulus::new());
let residue = conversion.switch(48);
```

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或 [MIT License](../../LICENSE-MIT)。
