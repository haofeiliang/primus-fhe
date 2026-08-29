# primus_modulo

[English](README.md) | 简体中文

`primus_modulo` 提供 value-side 扩展 trait，镜像 [`primus_reduce`](../primus_reduce/README.zh_CN.md) 中的 modulus-side 运算。

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 尚不稳定，可能随时发生不兼容修改。

## 概览

每个 blanket impl 只反转调用顺序：

| Value side | Modulus side |
| --- | --- |
| `a.add_modulo(b, modulus)` | `modulus.reduce_add(a, b)` |
| `a.mul_modulo(b, modulus)` | `modulus.reduce_mul(a, b)` |
| `values.add_modulo_slice_assign(rhs, modulus)` | `modulus.reduce_add_slice_assign(values, rhs)` |

这些 wrapper 不增加分配、缓冲区、校验或算术逻辑。输出范围、panic 行为、长度要求和惰性约简保证均继承自对应的 `primus_reduce` 运算。

## 示例

这些运算是扩展 trait 方法，因此调用方通常应导入 prelude：

```rust
use primus_modulo::prelude::*;
use primus_modulus::BarrettModulus;

let modulus = BarrettModulus::new(97u64);

assert_eq!(80u64.add_modulo(30, modulus), 13);
assert_eq!(12u64.mul_modulo(9, modulus), 11);

let mut values = [80, 30];
let rhs = [30, 80];
values
    .as_mut_slice()
    .add_modulo_slice_assign(rhs.as_slice(), modulus);
assert_eq!(values, [13, 13]);
```

不希望使用通配 prelude 时，也可以单独导入所需 trait。

## 维护状态

`primus_modulo` 作为薄镜像继续维护，但 Primus FHE 中目前没有其他 crate 依赖它。workspace 实现和泛型算术直接使用 `primus_reduce`。

只有当提供方法的 trait 已进入作用域时，Rust 才能发现对应的扩展方法；大量细粒度 blanket trait 的错误提示也可能不如 modulus-side 调用直接。因此，新的 workspace 代码通常应优先使用 `primus_reduce`；当外部调用方希望使用 value-receiver 语法时，仍可选择本 crate。

本镜像刻意不引入剩余类 wrapper、新的模数 context、兼容别名或第二层输入校验。

## 调用方契约

调用方必须维持对应 `primus_reduce` trait 记录的相同契约。特别是，切片长度和剩余类范围通常由调用方维持；惰性约简结果在执行一次单次约简前仍位于 `[0, 2 * modulus)`。导入本 crate 不会为底层数值内核增加 release 模式检查。

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或 [MIT License](../../LICENSE-MIT)。
