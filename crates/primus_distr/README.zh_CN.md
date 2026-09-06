# primus_distr

[English](README.md) | 简体中文

`primus_distr` 为 [Primus FHE](../../README.zh_CN.md) 提供离散概率分布与批量采样
helper，覆盖 binary/ternary secret、中心离散 Gaussian 噪声、模表示与有符号表示、
CRT 批量布局以及统计诊断。

> [!WARNING]
> 本 crate 属于实验性的 Primus FHE workspace。其 API、采样算法和数值契约尚不稳定，
> 可能随时发生不兼容修改。

## 主要分布

| 类型 | 输出与职责 |
| --- | --- |
| `BinaryDistr` | 从 `{0, 1}` 中均匀采样 |
| `SparseTernaryDistr<T>` | 以 `1/2`、`1/4`、`1/4` 的概率从 `{0, 1, -1}` 采样；`-1` 的表示由调用方提供 |
| `DiscreteGaussian<T>` | 将中心 Gaussian 样本编码为调用方所给模数下的规范无符号 residue |
| `SignedDiscreteGaussian<T>` | 使用有符号整数类型直接表示中心 Gaussian 样本 |
| `CDTSampler<T>` / `SignedCDTSampler<T>` | 显式选择的 portable 64-bit cumulative-distribution-table backend |
| `DiscreteZiggurat<T>` / `SignedDiscreteZiggurat<T>` | 用于较大 support 的显式离散 Ziggurat backend |

所有 sampler 类型均实现 `rand::distr::Distribution`。批量 helper 要求 RNG 同时实现
`rand::Rng` 与 `rand::CryptoRng`。

## 示例

```rust
use primus_distr::{SignedDiscreteGaussian, sample_crt_gaussian_values};
use rand::{SeedableRng, rngs::StdRng};

let gaussian = SignedDiscreteGaussian::<i64>::new(3.2).unwrap();
let moduli = [97_u64, 193];
let poly_length = 8;
let mut rng = StdRng::seed_from_u64(7);

let samples = sample_crt_gaussian_values(
    poly_length,
    &moduli,
    &gaussian,
    &mut rng,
);

assert_eq!(samples.len(), poly_length * moduli.len());
assert!(samples[..poly_length].iter().all(|&x| x < moduli[0]));
assert!(samples[poly_length..].iter().all(|&x| x < moduli[1]));
```

## Gaussian 构造与表示

`DiscreteGaussian` 与 `SignedDiscreteGaussian` facade 使用 12 个标准差的默认 tail cut。
构造过程会拒绝非有限参数、小于 `MIN_STANDARD_DEVIATION` 的标准差、所选输出类型无法
表示的 support，以及无法放入所给模数的 modular support。

截断 support 能放入 magnitude 上限为 255 的 portable CDT 表时，facade 选择 CDT
backend；否则选择 Ziggurat backend。需要直接指定 tail cut 或 backend 时，应显式构造
`*CDTSampler` 或 `*Ziggurat`。

`DiscreteGaussian::new(sigma, modulus_minus_one)` 返回
`[0, modulus_minus_one]` 中的值。逻辑负样本 `-x` 编码为
`modulus_minus_one - x + 1`。`SignedDiscreteGaussian::new(sigma)` 则直接返回正值、
零和负值。

## 批量采样

本 crate 同时提供返回新分配 `Vec` 的函数和写入调用方 slice 的对应 `_to` 函数。除
uniform binary、sparse ternary 和 uniform ternary 外，还提供显式概率、固定 Hamming
weight、uniform 整数分布以及离散 Gaussian 的批量 helper。

CRT batch 使用 modulus-major 布局。对于多项式长度 `N` 和分量模数
`q_0, ..., q_(k-1)`，长度为 `k * N` 的 slice 排列如下：

```text
[a_0 mod q_0, ..., a_(N-1) mod q_0,
 a_0 mod q_1, ..., a_(N-1) mod q_1,
 ...]
```

`sample_crt_uniform_binary_values*`、`sample_crt_sparse_ternary_values*` 和
`sample_crt_gaussian_values*` 每次生成一个逻辑系数，并在所有分量中编码同一个系数。
`sample_crt_uniform_values*` 则为每个分量使用一个独立的
`rand::distr::Uniform` 分布。

对于非空 CRT batch，调用方必须提供非零多项式长度，并保证输出长度严格等于多项式
长度乘以分量数。重复执行的底层路径使用 debug-only shape 诊断；release 调用方必须在
拥有相应契约的参数或 scheme 边界建立布局不变量。

CRT Gaussian helper 接收 signed distribution 和原始模数值，但不会验证每个模数能否编码
分布的完整截断 support。对于标准差为 `sigma`、tail cut 为 `tau` 的 sampler，每个模数
必须大于 `max(1, floor(sigma * tau))`；facade 使用 `tau = 12`。

## 统计诊断

`stats` 模块提供：

- `gaussian_stats`：将规范 modular 样本转换为居中代表元，并计算 mean、population
  standard deviation 和累计 magnitude count；
- `theoretical_cumulative_probs`：计算对应截断离散 Gaussian 的理论累计概率。

这些函数用于测试和验证工具，而不是采样热路径。其 rustdoc 记录了精确的浮点数与模数
限制。

## High-precision feature

可选的 `high_precision` feature 提供 `PreciseCDTSampler` 和
`SignedPreciseCDTSampler`。它们使用 256-bit CDT threshold，并支持比 portable CDT
backend 更大的表；facade 类型不会自动选择这些 backend。

```text
cargo test -p primus_distr --features high_precision
```

## 测试与 benchmark

```text
cargo test -p primus_distr
cargo bench -p primus_distr --bench gen_sampler
cargo bench -p primus_distr --bench sample_gaussian
```

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0)
或 [MIT License](../../LICENSE-MIT)。
