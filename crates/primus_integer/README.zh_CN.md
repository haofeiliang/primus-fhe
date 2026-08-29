# primus_integer

[English](README.md) | 简体中文

`primus_integer` 定义 Primus FHE workspace 使用的整数 trait 和定宽多 limb 算术。

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。
> 其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

## 概览

主要 API 包括：

- `Integer`：汇集泛型内核所需的通用算术、位运算、转换和序列化能力；
- `SignedInteger` 和 `UnsignedInteger`：增加与符号相关的运算和相同位宽的伴随类型；
- 用于 checked、overflowing、wrapping、carrying、widening 和除法运算的细粒度 trait；
- `BigUint<S>`：基于借用或拥有所有权的小端 limb 存储的定宽无符号整数；
- 可选的默认宽度 portable SIMD 抽象。

## 示例

```rust
use primus_integer::{BigUint, UnsignedInteger};

fn significant_bits<T: UnsignedInteger>(value: T) -> u32 {
    value.bit_width()
}

assert_eq!(significant_bits(0x100u64), 9);

let value = BigUint(vec![u64::MAX, 1]);
assert_eq!(value.len(), 2);
assert_eq!(value.bit_width(), 65);
```

## `BigUint` 表示与调用方契约

`BigUint<S>` 是面向 FHE、RNS 和分解算法的底层定宽整数表示。它不是会自动增长的
通用大整数类型，也不是外部输入的校验边界。

limb 按小端顺序存储。limb 数量和前导零 limb 都属于表示和相等性的一部分：例如，
`BigUint([1u64])` 和 `BigUint([1u64, 0])` 是不同的表示。

顶层参数构造器和公开操作边界负责一次性检查维度和缓冲区布局。底层算术内核刻意避免
在 release 构建中重复这些检查。调用方必须维持以下契约：

- 参与同一运算的所有输入、输出、累加器和模数具有相同的 limb 数量；
- 需要访问最低 limb 的运算接收非空存储；
- `left_shift_assign` 和 `right_shift_assign` 的 `bits` 参数小于 `T::BITS`；
  这些方法执行单个 limb 宽度内的移位，而不是任意位数的整型移位；
- 传给模运算的操作数已经约简到 `[0, modulus)`。

违反这些契约属于调用方错误，不保证能在 release 构建中被检测。在等长契约成立时，
基于迭代器的内核会处理所有 limb，不会因为某个缓冲区较短而截断操作数。

算术仍然是定宽的：各方法会按照文档返回 carry、borrow 或高位 limb，移位操作也会
按照各自契约返回或丢弃移出的位；这些方法不会扩展表示的长度。

`BigUint` 运算不是常量时间实现，不应假定其能够抵抗侧信道攻击。

## SIMD feature

`simd` feature 启用 `SimdInteger`、`SimdArray` 及相关 trait。它使用 Rust 尚未稳定的
`portable_simd` API，因此需要 nightly：

```text
cargo +nightly test -p primus_integer --features simd
```

默认向量类型根据目标 CPU feature 选择。泛型代码应使用关联类型 `SimdT`、`MaskT`
和 `Array`，而不应直接指定 lane 数量。

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或 [MIT License](../../LICENSE-MIT)。
