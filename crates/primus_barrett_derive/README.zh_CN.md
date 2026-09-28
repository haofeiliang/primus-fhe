# primus_barrett_derive

[English](README.md) | 简体中文

`primus_barrett_derive` 实现 [`primus_modulus`](../primus_modulus/README.zh_CN.md) 使用的 `Barrett` derive 宏，为编译期常量创建零尺寸模数 context。

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其生成 API 和数值契约尚不稳定，可能随时发生不兼容修改。

workspace 内的 crate 通常应启用 `primus_modulus` 的 `derive` feature，而不是直接依赖本过程宏 crate：

```toml
[dependencies]
primus_modulus = { path = "../primus_modulus", features = ["derive"] }
```

## 示例

```rust
use primus_modulus::{Barrett, reduce::prelude::*};

#[derive(Barrett)]
#[modulus(ty = u32, value = 536813569)]
struct Modulus;

assert_eq!(Modulus::value(), 536_813_569);
assert_eq!(Modulus.reduce_mul(12_345, 67_890), 301_288_481);
```

生成的 `value()` 和 `ratio()` 函数与 unit struct 使用相同的可见性。

## 输入契约

该宏只接受带有一个 `modulus` 属性的 unit struct：

```rust,ignore
#[derive(Barrett)]
#[modulus(ty = u64, value = 1125899906826241)]
pub struct CiphertextModulus;
```

- `ty` 必须是裸标识符 `u16`、`u32` 或 `u64`。
- 对应类型的 `value` 必须满足 `1 < value < 2^(BITS - 2)`。
- 无效的结构、类型、字面量和模数范围会产生编译期错误。

## 生成实现

对于每个模数，该宏在展开期间计算双 limb 倒数 `floor(B² / modulus)`，其中 `B = 2^BITS`。生成的 unit struct 不保存运行时 context。

展开结果提供：

- 关联函数 `value()` 和 `ratio()`；
- `primus_reduce` 的标量、切片、惰性约简、逆元、幂运算、融合运算和点积实现；
- `EncodeSigned`，使用与 `UintModulus` 相同的有界系数转换，并传入编译期常量模数；
- `Copy`、`Clone`、`PartialEq`、`Eq`、`Debug` 和 `Hash` 实现。

不要在同一个 struct 上再次 derive 这些标准 trait，否则会与宏生成的实现冲突。

## SIMD

生成的 context 自动使用受支持的原生内核；同时启用 `primus_modulus` 的 `derive` 和 `simd` features，可使用需要 nightly 的 portable-SIMD 路径。具体硬件资格和常量模数回退见[实现说明](../primus_modulus/IMPLEMENTATION.md)。

标量与 SIMD 展开遵循同样的 `BarrettModulus` 契约：调用方保证切片尺寸，惰性结果位于 `[0, 2*modulus)`，逆元操作要求输入可逆；编译期常量模数不保证素性。

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或 [MIT License](../../LICENSE-MIT)。
