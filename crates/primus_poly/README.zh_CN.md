# primus_poly

[English](README.md) | 简体中文

`primus_poly` 为 [Primus FHE](../../README.zh_CN.md) 中使用的各种多项式表示提供存储 wrapper 和算术操作。它将系数、NTT、CRT/DCRT、多 limb 和 Fourier 数据明确区分，同时避免为每个多项式保存 context。

> [!WARNING]
> 本 crate 属于实验性的 Primus FHE workspace。其 API、数据表示和数值契约尚不稳定，可能随时发生不兼容修改。

## 数据表示

| 类型 | 表示与布局 | 主要操作 |
| --- | --- | --- |
| `ArrayBase<S>` | 无符号整数的一维平坦数组 | 逐元素模算术与 butterfly helper |
| `Polynomial<S>` | 单个模数下按幂次递增排列的 `N` 个系数 | 加、减、取负、scalar/factor 乘法、负循环单项式、朴素乘法、求值和采样 |
| `NttPolynomial<S>` | 单个模数下的 `N` 个点值；顺序由 NTT context 定义 | 逐点算术、融合乘加、逆元和 uniform 采样 |
| `CrtPolynomial<S>` | modulus-major 系数数据：每个模数对应一个连续的 `N` 系数多项式 | 分量算术、scalar/factor 操作、负循环单项式以及共享的 uniform-binary/sparse-ternary/Gaussian 采样 |
| `DcrtPolynomial<S>` | modulus-major NTT 数据：每个模数对应一个连续的 `N` 点变换结果 | 逐点算术、融合乘加、逆元、uniform 采样和 butterfly 内核 |
| `BigUintPolynomial<S>` | coefficient-major 数据：每个系数是固定宽度的小端 limb 分块 | 多 limb 模加、模减和模取负 |
| `FourierPolynomial<S>` | 独立复数求值；顺序由 Fourier 后端定义 | 逐点加、减、取负、乘法、融合乘加和 scalar 乘法 |

`primus_poly` 负责保存数值并实现算术，不拥有变换表，也不替调用方选择表示。[`primus_ntt`](../primus_ntt) 负责系数与 NTT、CRT 与 DCRT 表示之间的转换；[`primus_fft`](../primus_fft) 提供 Fourier 变换。

## 示例

```rust
use primus_modulus::CompactModulus;
use primus_poly::PolynomialOwned;

let modulus = CompactModulus::new(97_u64);
let mut lhs = PolynomialOwned::from_slice(&[80, 12, 5, 40]);
let rhs = PolynomialOwned::from_slice(&[30, 9, 96, 70]);

lhs.add_assign(&rhs, modulus);
assert_eq!(lhs.as_slice(), &[13, 21, 4, 13]);

// 在 Z_97[X]/(X^4 + 1) 中乘以 X。
lhs.mul_monomial_assign(1, modulus);
assert_eq!(lhs.as_slice(), &[84, 13, 21, 4]);
```

## 存储与所有权

大多数多项式类型都对 backing store `S` 泛型化；`S` 实现 [`primus_data`](../primus_data/README.zh_CN.md) 提供的连续存储 trait。常用的系数、NTT、Fourier 和数组表示提供了 `Vec` owned 别名与 slice borrowed 别名。CRT、DCRT 和多 limb wrapper 同样可以通过泛型类型构造在 owned 或 borrowed 存储之上。

操作名称说明结果写入位置：

- `operation` 消耗一个支持修改的 wrapper，更新其存储后返回该 wrapper；
- `operation_assign` 原地更新 `self`；
- `operation_to` 将结果写入独立的输出 wrapper；
- `operation_rev_assign` 将交换操作数后的非交换运算写入可变操作数。

消耗以 `&mut [T]` 为 backing store 的 wrapper 仍会修改调用方的 slice。

## 布局与算术契约

这些 wrapper 有意不保存多项式长度、模数值、变换表、归一化状态或 limb 宽度。调用方必须在拥有相应契约的 FHE、RNS 或 transform 边界建立以下不变量，并在底层运算之间维持它们：

- 一起参与运算的所有输入和输出具有相同表示与布局；
- backing storage 能被传入的多项式长度或多 limb 系数宽度精确整除；
- CRT/DCRT 存储长度等于 `moduli.len() * poly_length`；按分量使用的 scalar、factor、distribution 和 modulus slice 均为每个分量提供一个元素，而 butterfly `w` 这类逐点 factor polynomial 与 backing storage 具有相同的 modulus-major 布局和长度；
- 数值满足所选 `primus_reduce` 或 `primus_factor` 操作要求的规范或惰性范围；
- 单项式指数位于对应文档规定的 `[0, 2N)` 范围内，需要二次幂 `N` 的方法收到满足条件的长度；
- NTT 和 Fourier 操作数由相互兼容的变换 context 产生。

重复算术路径中的许多形状检查只是 `debug_assert*!` 诊断。release 调用方必须维持文档契约；iterator 的 `zip` 和 `chunks_exact` 不能替代边界验证。

## 随机采样

直接在 NTT 和 DCRT 表示中进行的采样仅支持 uniform 分布。若要采样非 uniform 的系数分布，应先构造系数域的 `Polynomial` 或 `CrtPolynomial`，再执行变换。CRT uniform-binary、sparse-ternary 和 Gaussian 采样会生成一个逻辑系数，并在每个分量模数下编码同一个值；其中 sparse ternary 分布满足 `P(0) = 1/2`、`P(1) = P(-1) = 1/4`。随机 API 要求 RNG 同时实现 `rand::Rng` 和 `rand::CryptoRng`。

## SIMD feature

可选的 `simd` feature 启用 portable-SIMD DCRT butterfly 路径以及算术依赖中相应的 SIMD 支持。该 feature 默认关闭，并且需要 nightly Rust 工具链。

```text
cargo +nightly test -p primus_poly --features simd
```

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或 [MIT License](../../LICENSE-MIT)。
