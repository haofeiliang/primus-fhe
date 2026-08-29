# primus_reduce

[English](README.md) | 简体中文

`primus_reduce` 定义 Primus FHE 中模数实现与上层算法共享的模算术契约。

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

## 概览

本 crate 的 trait 将模数或约简上下文放在 receiver 位置：

```text
modulus.reduce_add(a, b)
modulus.reduce_mul_slice_to(a, b, output)
```

各运算被拆分为细粒度 trait，使模数类型只实现自身真正支持的标量、切片、惰性约简、逆元或融合运算。具体模数类型和数值内核位于 [`primus_modulus`](../primus_modulus)。

主要 API 分组如下：

- 用于规范算术、逆元、除法和幂运算的标量 `Reduce*` trait；
- 用于批量运算和 SIMD 调度的 `Reduce*Slice` trait；
- 结果位于 `[0, 2 * modulus)` 的 `LazyReduce*` trait；
- 描述模数元数据的 `Modulus` 和 `ExplicitModulus`；
- 能力 marker `RingContext` 和 `FieldContext`。

## 示例

```rust
use primus_modulus::BarrettModulus;
use primus_reduce::prelude::*;

let modulus = BarrettModulus::new(97u64);

assert_eq!(modulus.reduce_add(80, 30), 13);
assert_eq!(modulus.reduce_mul(12, 9), 11);

let mut values = [80, 30];
let rhs = [30, 80];
modulus.reduce_add_slice_assign(&mut values, &rhs);
assert_eq!(values, [13, 13]);
```

## 调用方契约

本 crate 定义接口，而不是输入校验边界。每个公开方法分别记录其输入范围、表示、输出状态和长度要求。

- 顶层构造器和批处理 API 应一次性检查维度与布局。
- 底层数值内核可能只通过 `debug_assert*!` 诊断形状不匹配；release 调用方必须维持文档中的契约。
- 点积在所有构建模式下都会显式检查两个切片等长。
- 惰性约简结果在被视为规范剩余类之前，需要再执行一次单次约简。
- 可失败逆元 trait 通过 `ReduceError` 报告错误；当所需逆元不存在时，不可失败的逆元和除法 trait 可能 panic。

`FieldContext` 表示某个模数类型实现了列出的运算集合。它不证明模数为素数，也不保证每个非零剩余类都可逆。调用方仍须验证自身算法所需的代数条件。

## Value-side 镜像

[`primus_modulo`](../primus_modulo/README.zh_CN.md) 提供可选的 value-receiver 镜像，例如 `a.add_modulo(b, modulus)`。本 crate 的 modulus-side trait 仍是主要实现边界和 workspace 集成边界。

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或 [MIT License](../../LICENSE-MIT)。
