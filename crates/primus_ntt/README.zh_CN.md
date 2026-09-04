# primus_ntt

[English](README.md) | 简体中文

`primus_ntt` 为 `Z_q[X] / (X^N + 1)` 中的多项式提供原地负循环数论变换。它包含
通用无符号整数 table、优化的 `u32` 和 `u64` table、直接 monomial 变换，以及
[Primus FHE](../../README.zh_CN.md) 使用的 modulus-major DCRT 变换。

> [!WARNING]
> 本 crate 属于实验性的 Primus FHE workspace。其 API、NTT 表示、数值契约和
> backend 选择尚不稳定，可能随时发生不兼容修改。

## 核心类型

| 类型 | 职责 |
| --- | --- |
| `NttTable` | 通用构造及正向/逆向变换契约 |
| `MonomialNttTable` | 无需构造系数多项式，直接变换 `coeff * X^degree` |
| `UintNttTable<T>` | 使用 Shoup 乘法的通用无符号整数实现 |
| `U32NttTable` | 针对小于 `2^30` 的 `u32` 模数优化的 table |
| `U64NttTable` | 针对小于 `2^62` 的 `u64` 模数优化的 table |
| `DcrtTable<Ntt>` | 为每个 CRT 模数保存一个相同长度的 NTT table |
| `U32DcrtTable`、`U64DcrtTable`、`UintDcrtTable<T>` | 常用 DCRT 别名 |

专用 table 拥有 root power 和预计算 backend 布局。变换会调度到有效的 scalar
或指令集专用 kernel，原地执行，并且每次调用不需要 scratch 分配。

## 示例

```rust
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable};

let modulus = BarrettModulus::new(97_u32);
let table = U32NttTable::new(3, modulus).unwrap(); // N = 8；2N 整除 97 - 1
let expected = vec![3, 1, 4, 1, 5, 9, 2, 6];
let mut values = expected.clone();

table.transform_slice(&mut values);
// `values` 现在以 bit-reversed 顺序保存 NTT 求值。
table.inverse_transform_slice(&mut values);

assert_eq!(values, expected);
```

Table 的构造应放在重复变换路径之外，并复用构造结果。Table 不可变并实现
`Send + Sync`，因此可以在线程间共享。

## 表示与取值范围

对于 `N = 2^log_n`，正向变换读取按幂次升序排列的系数，生成 bit-reversed 顺序的
求值；逆向变换读取这种 bit-reversed 表示，并恢复按幂次升序排列的系数。

每个单模数输入或输出 slice 都必须恰好包含 `table.poly_length()` 个值。
`NttTable` 实现在进入 unchecked kernel 前强制执行这项检查。

| 操作 | 输入范围 | 输出范围 |
| --- | --- | --- |
| `transform_slice` | `[0, q)` | `[0, q)` |
| `inverse_transform_slice` | `[0, q)` | `[0, q)` |
| `lazy_transform_slice` | `[0, 4q)` | `[0, 4q)` |
| `lazy_inverse_transform_slice` | `[0, 2q)` | `[0, 2q)` |

Lazy 值表示模 `q` 的剩余类，但其更宽的整数范围属于调用契约。特别是，lazy
forward 的结果不一定能直接作为 lazy inverse 的输入；调用 inverse 前应先将其
规范化到对应方法接受的范围。

消费 wrapper 的 `transform_inplace` 和 `inverse_transform_inplace` 使用 canonical
变换，同时在 [`Polynomial`](../primus_poly/README.zh_CN.md) 与 `NttPolynomial`
之间改变存储 wrapper。

## 构造约束

- 支持的契约要求 `log_n >= 1`，即 `N >= 2`；`N = 1` 不是受支持的变换长度。
- 模数必须存在一个本原 `2N` 次单位根。对于素数模数，这要求 `2N` 整除
  `q - 1`。
- `U32NttTable` 和 `UintNttTable<u32>` 要求 `q < 2^30`；`U64NttTable` 和
  `UintNttTable<u64>` 要求 `q < 2^62`。预留的两个高位保证所有小于 `4q` 的
  lazy 值均可表示。
- 通用 table 还要求 `N < q`；如果 `N` 无法由其系数类型表示，也会返回构造错误。

`NttTable::new` 会搜索本原根，并预计算 root power、预处理因子和所选 backend
布局。满足 `FieldContext` 的模数 context 提供算术操作，但其本身不能证明模数为
素数，也不能保证所需的 root 存在。

## Monomial 变换

`MonomialNttTable` 将 `coeff * X^degree` 的 NTT 表示直接写入长度严格匹配的输出
slice。Degree 按模 `2N` 解释，与负循环环中的 `X^N = -1` 一致。

`transform_monomial` 要求 `coeff` 是 canonical residue，即
`0 <= coeff < q`；该方法不会约简或验证系数。常见的 `X^degree` 和
`-X^degree` 情形应分别使用 `transform_coeff_one_monomial` 和
`transform_coeff_minus_one_monomial`。

## DCRT 布局

`DcrtTable` 为每个模数保存一个 NTT table，并让它们共享同一个 `N`。系数和变换
slice 都采用 modulus-major 布局，总长度为 `moduli_count * N`：

```text
[a_0 mod q_0, ..., a_(N-1) mod q_0,
 a_0 mod q_1, ..., a_(N-1) mod q_1,
 ...]
```

这与 [`primus_poly`](../primus_poly/README.zh_CN.md) 中 `CrtPolynomial` 和
`DcrtPolynomial` 的布局一致。重复 DCRT 路径中的形状检查只是 debug 诊断；
release 调用方必须保证总长度严格匹配并维持 modulus-major 顺序。

对于 `DcrtTable::transform_monomial`，传入的单个 `coeff` 必须对每个分量模数都是
canonical 的；该方法不会针对每个 limb 分别约简系数。

## SIMD backend 与编译目标

在 `x86_64` 上，专用 table 会在运行时检测 CPU 能力，并按适用条件从 scalar、
AVX2、AVX-512 DQ 和 AVX-512 IFMA kernel 中选择。其他架构使用 scalar 实现。
这些 x86 kernel 不需要启用 crate 的可选 `simd` feature；该 feature 用于启用依赖
crate 中配套的 portable-SIMD 支持，目前需要 nightly Rust。

仓库级 [`.cargo/config.toml`](../../.cargo/config.toml) 设置了
`target-cpu=native`。这与 runtime dispatch 是两件不同的事：编译器不仅可以在所选
backend 中使用本机指令，也可能在普通 Rust 代码中使用本机专用指令。构建可移植
二进制或执行受控 ISA benchmark 时，应覆盖这项 rustflags 配置。

## 测试与 benchmark

```text
cargo test -p primus_ntt
cargo bench -p primus_ntt --bench bench_ntt
cargo +nightly test -p primus_ntt --features simd
```

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0)
或 [MIT License](../../LICENSE-MIT)。
