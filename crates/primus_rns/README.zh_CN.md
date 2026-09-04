# primus_rns

[English](README.md) | 简体中文

`primus_rns` 提供剩余数系统基、CRT 组合与分解、基转换，以及
[Primus FHE](../../README.zh_CN.md) 使用的 Hybrid `Q`/`P` 运算。其无分配的
多项式路径在平坦 slice 上工作，并使用调用方拥有的可复用 workspace。

> [!WARNING]
> 本 crate 属于实验性的 Primus FHE workspace。其 API、数据布局和数值契约
> 尚不稳定，可能随时发生不兼容修改。

## 主要类型

| 类型 | 职责 |
| --- | --- |
| `RNSBase<T, M>` | 非空、模数两两互素的 RNS 基及其 CRT 预计算 |
| `BaseConverter<T, M>` | 在两个 RNS 基之间执行 fast 或 corrected 转换的预计算 |
| `ExactConversionContext<T>` | corrected 批量转换使用的可复用 workspace |
| `HybridRNSPartitioning` | 在 modulus chain 各层之间共享的固定 full-`Q` 分区规则 |
| `HybridRNS<T, M>` | 一个 active Hybrid-RNS level 的基与预计算 |
| `HybridRNSPartition<T, M>` | 一个连续 `Q` 分区及其 approximate ModUp converter |

`T` 是无符号 FHE 整数类型。`M` 是 `primus_reduce::FieldContext<T>`；重复执行
多项式运算时通常使用 [`BarrettModulus`](../primus_modulus/README.zh_CN.md)。

## 示例

```rust
use primus_modulus::BarrettModulus;
use primus_rns::RNSBase;

let moduli = [3_u64, 5, 7].map(BarrettModulus::new);
let base = RNSBase::new(&moduli).unwrap();

let value = base.compose(&[2, 4, 6]);
assert_eq!(value.digits(), &[104]);
assert_eq!(base.decompose(value.view()), [2, 4, 6]);
```

`compose` 返回 `[0, Q)` 中的规范代表元，其中 `Q` 是基中所有模数的乘积。

## 数据布局

批量 residue 始终采用 modulus-major 布局。对于 `k` 个值和模数
`q_0, ..., q_(n-1)`，长度为 `n * k` 的 slice 排列如下：

```text
[a_0 mod q_0, ..., a_(k-1) mod q_0,
 a_0 mod q_1, ..., a_(k-1) mod q_1,
 ...]
```

批量大整数采用相反的分组方式：每个值占据一个连续、定宽的小端 limb 分块，
分块宽度为 `RNSBase::big_uint_value_len()`。

[`CrtPolynomial`](../primus_poly/README.zh_CN.md) 使用相同的 modulus-major
系数布局，因此多项式 wrapper 可以直接转发到 slice 运算，无需重排数据。

## RNS 基

`RNSBase::new` 从非空、模数两两互素的 slice 克隆构造基；
`from_owned_moduli` 可以避免这次克隆。RNS 基会预计算 `Q`、每个穿孔积
`Q / q_i` 以及 `(Q / q_i)^-1 mod q_i`。

主要操作族包括：

- `compose*` 和 `decompose*`：执行 scalar、批量及多项式 CRT 转换；
- `wrapping_decompose*`：从较小模数执行居中提升；
- 融合的 `add_*_decompose_*_scaled_assign`：用于多项式热路径；
- `extend` 和 `extend_with`：追加一个模数或另一个基，并复用已有 CRT 预计算。

居中小值分解将小于 `ceil(t / 2)` 的值解释为非负数，其余值解释为模 `t` 的
负代表元。模数 `t = 2` 是有意保留的特例：`0` 和 `1` 会直接保留，`1` 不会被
提升为 `-1`。

## 基转换

`BaseConverter` 拥有输入基和输出基。`new` 会克隆现有基；
`from_owned_bases` 则转移所有权。

两类转换具有不同的数学契约：

- `fast_convert` 和 `fast_convert_array` 执行 SEAL 风格的 approximate CRT
  lift。输入基包含多个模数时，结果表示某个整数 `x + kQ`，通常不等于规范的
  `x mod p_j`。只有外层算法会消去或允许这个 `Q` 倍数项时才能使用。单模数输入
  使用精确的直接约简。
- `exact_convert_array` 应用商修正，将输入解释为 `[-Q/2, Q/2)` 中的居中
  代表元，并要求输出基恰好包含一个模数。名称“exact”沿用 SEAL 的术语；修正
  使用 `f64`，因此靠近 `-Q/2`/`Q/2` 边界的值仍可能相差一个 `Q` 的倍数。

通过 `exact_conversion_context` 创建 `ExactConversionContext`，并在同一个
converter 和多项式长度下复用。Fast conversion 使用由
`fast_convert_scratch_len` 或 `fast_convert_array_scratch_len` 确定大小的原始
scratch slice。

## Hybrid RNS

`HybridRNS` 将密文基 `Q` 与辅助基 `P` 组合，并以 `Q || P` 顺序保存完整基。
`HybridRNSPartitioning` 根据 full `Q` 基和请求的 digit 数 `dnum` 推导固定的最大
分区大小 `alpha`：

```text
alpha = ceil(full_q_moduli_count / dnum)
```

固定分区大小必须恰好产生 `dnum` 个非空分区。例如五个 `Q` 模数和
`dnum = 3` 会产生 `[0..2, 2..4, 4..5]`；请求 `dnum = 4` 会被拒绝，因为相同
固定大小只能产生三个分区。

在同一 modulus chain 的较短有序前缀 level 上，应使用
`HybridRNS::from_partitioning`，以保持与 key 兼容的固定分区边界。构造器只验证
active 模数数量；拥有 modulus chain 的 context 负责保证前缀关系。

每个分区都支持 approximate ModUp 到完整的 `Q || P` 基。Streaming 形式只
生成转换后的 complement limb，使上层 key switching 可以直接复用采用其他表示
的 partition limb。ModDown 将 `P` correction 转换到 `Q`，执行减法，再乘以
`P^-1 mod q_i`。

## 调用方契约与 workspace

- 除非方法记录了更宽的范围，传给算术和基转换内核的 residue 必须是对应模数下
  的规范剩余类。
- 组合进同一个基的模数必须两两互素，包括 `Q || P`。
- Slice 长度、modulus-major 顺序必须与所选基和多项式长度严格匹配。
- Converter context 和 scratch buffer 应在热循环外创建并复用。调用方提供输出和
  workspace 后，批量 API 不会在内部执行分配。
- 一些重复执行的底层路径只使用 `debug_assert*!` 诊断形状错误；release 调用方
  必须在拥有契约的公开或 scheme 边界建立这些不变量。

## SIMD feature

可选的 `simd` feature 启用 portable-SIMD 小值和模算术路径。该 feature 默认
关闭，并且需要 nightly Rust 工具链。

```text
cargo +nightly test -p primus_rns --features simd
```

## 测试与 benchmark

```text
cargo test -p primus_rns
cargo bench -p primus_rns --bench decompose
```

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0)
或 [MIT License](../../LICENSE-MIT)。
