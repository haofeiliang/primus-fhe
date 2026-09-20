# primus_distr

[English](README.md) | 简体中文

`primus_distr` 为 [Primus FHE](../../README.zh_CN.md) 提供离散概率分布与批量采样 helper，覆盖 binary/ternary secret、中心离散 Gaussian 噪声、模表示与有符号表示、 CRT 批量布局以及统计诊断。

> [!WARNING]
> 本 crate 属于实验性的 Primus FHE workspace。其 API、采样算法和数值契约尚不稳定， 可能随时发生不兼容修改。

## 主要分布

| 类型 | 输出与职责 |
| --- | --- |
| `BinaryDistr` | 从 `{0, 1}` 中均匀采样 |
| `SparseTernaryDistr<T>` | 以 `1/2`、`1/4`、`1/4` 的概率从 `{0, 1, -1}` 采样；`-1` 的表示由调用方提供 |
| `DiscreteGaussian<T>` | 将中心 Gaussian 样本编码为调用方所给模数下的规范无符号 residue |
| `SignedDiscreteGaussian<T>` | 使用有符号整数类型直接表示中心 Gaussian 样本 |
| `CDTSampler<T>` / `SignedCDTSampler<T>` | 显式选择的 portable 64-bit cumulative-distribution-table backend |
| `DiscreteZiggurat<T>` / `SignedDiscreteZiggurat<T>` | 用于较大 support 的显式离散 Ziggurat backend |

上表中的标量 sampler 类型均实现 `rand::distr::Distribution`。批量 helper 要求 RNG 同时实现 `rand::Rng` 与 `rand::CryptoRng`。

## 私钥分布参数

`SecretKeyDistr` 描述 binary、ternary、固定权重和 Gaussian 私钥系数分布；它是参数 枚举，不是 sampler。构造函数检查概率与完整逻辑密钥的权重。 Gaussian 参数由所选 Gaussian sampler 的构造器检查。 每种密码方案自行决定支持哪些分布变体。

自定义概率使用 `SecretKeyDistr::binary(one_probability)` 或 `SecretKeyDistr::ternary(negative_one_probability, one_probability)` 构造； 构造时检查各概率有限且位于 `[0, 1]`，三元概率之和不超过一。 `SecretKeyDistr::gaussian(standard_deviation)` 构造带命名字段的 `Gaussian { standard_deviation }`，参数校验仍由 Gaussian sampler 完成。 无参数变体直接使用枚举值。完整私钥采样器在构造时也检查概率，以覆盖直接构造枚举变体的情况。

固定重量构造函数区分总重量和固定组成：

| 构造函数 | 分布 |
| --- | --- |
| `fixed_hamming_weight_binary(length, weight)` | 均匀选取位置，恰好包含 `weight` 个 `1` |
| `fixed_hamming_weight_ternary(length, weight)` | 恰好包含 `weight` 个非零位置，各符号独立均匀随机 |
| `fixed_composition_ternary(length, negative_weight, positive_weight)` | 分别固定负一和正一的数量 |

构造时拒绝超过完整逻辑私钥长度的重量及重量和溢出。 长度不保存在枚举中，且仍可直接构造枚举变体，因此采样入口继续校验实际输出长度。

`SecretKeySampler<T>::new(distribution)` 为两种输出表示准备同一份 Gaussian 表及 binary/ternary 概率阈值。`T` 是无符号类型，signed 输出使用 `T::SignedInteger`。 `sample_signed(length, rng)` / `sample_signed_to(output, rng)` 生成 signed 私钥； `sample_encoded(length, modulus_minus_one, rng)` / `sample_encoded_to(output, modulus_minus_one, rng)` 生成规范模数表示。 `_to` 方法无分配地覆盖调用方存储。固定重量作用于完整输出，非法长度在写入或采样前拒绝。 完整私钥采样器不实现标量 `Distribution`，因为固定重量会关联不同系数。

`maximum_magnitude()` 返回样本幅度的无符号上界（包含端点）。构造时要求 Gaussian 支持集可由对应的 signed 类型表示；binary 和 ternary 保守返回一。 encoded 采样要求 `modulus_minus_one >= maximum_magnitude()`，其中 `T::MAX` 表示 native 模数。这是调用方契约，由 LWE、GLWE、RNS GLWE 和 NTRU 参数构造器一次性检查， 不在每批采样时重复检查。参数持有 sampler 以复用预计算。

底层 `SignedDiscreteGaussian::maximum_magnitude()` 也保留显式后端的自定义 tail cut。 共享私钥 sampler 和 signed Gaussian sampler 均不保存密文模数。

自定义概率和固定重量的 binary/ternary 向量 helper 也提供 `_to` 版本。 Encoded 采样器直接生成模数表示，不先分配 Signed 向量。 采样算法可能改变不同版本间的 RNG 消费顺序和固定 seed 的输出； 空输出并非一概保证不消耗随机数。自定义三元采样将各概率向下量化为 `2^-64` 的整数倍， 将总非零概率限制在一以内以处理浮点边界舍入。

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

`DiscreteGaussian` 与 `SignedDiscreteGaussian` facade 使用 12 个标准差的默认 tail cut。 构造过程会拒绝非有限参数、小于 `MIN_STANDARD_DEVIATION` 的标准差、所选输出类型无法 表示的 support，以及无法放入所给模数的 modular support。

截断 support 能放入 magnitude 上限为 255 的 portable CDT 表时，facade 选择 CDT backend；否则选择 Ziggurat backend。需要直接指定 tail cut 或 backend 时，应显式构造 `*CDTSampler` 或 `*Ziggurat`。

`DiscreteGaussian::new(sigma, modulus_minus_one)` 返回 `[0, modulus_minus_one]` 中的值。逻辑负样本 `-x` 编码为 `modulus_minus_one - x + 1`。`SignedDiscreteGaussian::new(sigma)` 则直接返回正值、 零和负值。

## 批量采样

`DiscreteGaussian` 和 `SignedDiscreteGaussian` 提供 `sample_vec(length, rng)` 与 `sample_to(output, rng)`，每批仅选择一次后端。前者直接由采样值初始化新向量； 后者无分配地覆盖调用方存储。两者的输出和 RNG 消费量与反复调用标量 `Distribution::sample` 一致，空批次不消耗随机数。现有 `sample_gaussian_values*` 函数转发到这些方法。标量 `sample(rng)` 继续由 `Distribution` 提供。

本 crate 同时提供返回新分配 `Vec` 的函数和写入调用方 slice 的对应 `_to` 函数。除 uniform binary、sparse ternary 和 uniform ternary 外，还提供显式概率、固定 Hamming weight、uniform 整数分布以及离散 Gaussian 的批量 helper。

CRT batch 使用 modulus-major 布局。对于多项式长度 `N` 和分量模数 `q_0, ..., q_(k-1)`，长度为 `k * N` 的 slice 排列如下：

```text
[a_0 mod q_0, ..., a_(N-1) mod q_0,
 a_0 mod q_1, ..., a_(N-1) mod q_1,
 ...]
```

`sample_crt_uniform_binary_values*`、`sample_crt_sparse_ternary_values*` 和 `sample_crt_gaussian_values*` 每次生成一个逻辑系数，并在所有分量中编码同一个系数。 `sample_crt_uniform_values*` 则为每个分量使用一个独立的 `rand::distr::Uniform` 分布。

对于非空 CRT batch，调用方必须提供非零多项式长度，并保证输出长度严格等于多项式 长度乘以分量数。重复执行的底层路径使用 debug-only shape 诊断；release 调用方必须在 拥有相应契约的参数或 scheme 边界建立布局不变量。

CRT Gaussian helper 接收 signed distribution 和原始模数值，但不会验证每个模数能否编码 分布的完整截断 support。对于标准差为 `sigma`、tail cut 为 `tau` 的 sampler，每个模数 必须大于 `max(1, floor(sigma * tau))`；facade 使用 `tau = 12`。

## 统计诊断

`stats` 模块提供：

- `gaussian_stats`：将规范 modular 样本转换为居中代表元，并计算 mean、population standard deviation 和累计 magnitude count；
- `theoretical_cumulative_probs`：计算对应截断离散 Gaussian 的理论累计概率。

这些函数用于测试和验证工具，而不是采样热路径。其 rustdoc 记录了精确的浮点数与模数 限制。

## High-precision feature

可选的 `high_precision` feature 提供 `PreciseCDTSampler` 和 `SignedPreciseCDTSampler`。它们使用 256-bit CDT threshold，并支持比 portable CDT backend 更大的表；facade 类型不会自动选择这些 backend。

```text
cargo test -p primus_distr --features high_precision
```

## 测试与 benchmark

```text
cargo test -p primus_distr
cargo bench -p primus_distr --bench gen_sampler
cargo bench -p primus_distr --bench sample_gaussian
cargo bench -p primus_distr --bench sample_secret_key
```

## 许可证

本 crate 可由你选择使用 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或 [MIT License](../../LICENSE-MIT)。
