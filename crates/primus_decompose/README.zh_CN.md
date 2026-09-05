# primus_decompose

[English](README.md) | 简体中文

`primus_decompose` 为 [Primus FHE](../../README.zh_CN.md) 提供近似有符号 radix 分解。
它将可复用的 basis 预计算与单值、批量 digit 提取分开，用于 gadget product 和
key switching。

> [!WARNING]
> 本 crate 属于实验性的 Primus FHE workspace。其 API、表示与数值契约可能发生
> 不兼容修改。

## 核心类型

| 类型 | 职责 |
| --- | --- |
| `primitive::ApproxSignedBasis<T>` | 单 limb 输入，使用显式模数或隐式 native 模数 `2^T::BITS` |
| `big_integer::BigUintApproxSignedBasis<T>` | 定宽、多 limb 输入，使用显式整数模数 |
| `OnceSignedDecomposer`、`OnceBigUintSignedDecomposer` | 提取一个保留层，由对应 basis 的 `decomposer_iter()` 返回 |
| `ApproxSignedBasisError` | `try_new` 返回的构造参数错误 |

`T: FheUint` 在 primitive basis 中是无符号系数类型，在 BigUint basis 中是 limb 类型。
`BigUint` 来自 [`primus_integer`](../primus_integer/README.zh_CN.md)，不是动态扩容的
大整数库。应一次构造 basis，复用其权重和提取窗口。

## 数学契约

设 `B = 2^log_basis`、`L = decompose_length()`、`d = drop_bits()`，分解的 signed digit
及其权重满足：

```text
-B/2 <= digit_i < B/2
weight_i = 2^d * B^i                  (0 <= i < L)
reconstructed = sum(digit_i * weight_i) mod modulus
```

`decomposer_iter()` 和 `scalar_iter()` 都从最低保留层迭代到最高层。输入与重组结果
之间的模环距离不超过 `approximate_error_bound()`：`d == 0` 时为零，否则为
`2^(d - 1)`。

初始化负责选择内部代表元并计算初始舍入 carry。被丢弃的位按最近值舍入，在该代表元中
恰好位于中点时向上舍入。特别是，native 输入的重组结果为
`round_half_up(input / 2^d) * 2^d` 模 `2^T::BITS`。对于其他模数，不能用直接舍入
canonical 输入替代初始化：代表元调整属于正确性前提。

输出的编码取决于具体操作：

| 操作 | 数学 digit `z` 的编码 |
| --- | --- |
| Primitive `decompose*` | 单个模 `q` 的 canonical residue；负 `z` 编码为 `q + z`，native 模数下使用相应 wrapping 表示 |
| BigUint `decompose*` | 模 `Q` 的全宽 canonical residue；负 `z` 编码为 `Q + z` |
| BigUint `unsigned_decompose*` | 单 limb 的 `[0, B)` 值，编码 `z mod B`；`u >= B/2` 应解读为 `u - B` |

虽然名称包含 `unsigned`，`unsigned_decompose*` 表示的仍然是 **signed digit**。
例如 `B = 256` 时，输出 `255` 表示 `-1`，不是正数 `255`。

## 构造与保留层数

两种 basis 都要求 `2 <= log_basis < T::BITS`，且模数不小于 `B`。
参数无效时，`new` 会 panic，`try_new` 返回 `ApproxSignedBasisError`。

不同表示的分解位宽 `m` 定义如下：

| Basis 与模数 | 位宽 `m` |
| --- | --- |
| Primitive，`None` | `T::BITS`，隐式模数为 `2^T::BITS` |
| Primitive，显式二次幂模数 `q` | `log2(q)` |
| Primitive，其他显式模数 `q` | `bit_width(q)` |
| BigUint，任意显式模数 `Q` | `bit_width(Q)`，**包括二次幂模数** |

完整层数为 `floor(m / log_basis)`。构造参数 `reverse_length` 表示可选的**保留层数**，
不是迭代方向：`Some(L)` 要求 `1 <= L <= full_length`，`None` 使用全部完整层。
两种情况下都有 `drop_bits = m - L * log_basis`，因此当 `m` 不能被 `log_basis`
整除时，即使传入 `None` 也会丢弃低位。

BigUint 模数必须是非空、little-endian 的 limb slice，最高 limb 不能为零。Basis
拥有模数的一份副本。每个输入都必须使用与模数相同的 limb 数，即使输入值较小，也要
保留高位的零 limb。

## Primitive 工作流

对一批输入初始化一次，然后让同一份 adjusted values 和不断更新的 carry 缓冲区依次
经过所有层。每层输出会被下一层覆盖，应先消费当前结果：

```rust
use primus_decompose::primitive::ApproxSignedBasis;

let basis = ApproxSignedBasis::new(Some(97_u32), 2, None);
let values = [42_u32, 96];
let mut adjusted = [0_u32; 2];
let mut carries = [false; 2];
let mut digits = [0_u32; 2];
let mut reconstructed = [0_u32; 2];

basis.init_value_carry_slice_to(&values, &mut adjusted, &mut carries);
for (decomposer, weight) in basis.decomposer_iter().zip(basis.scalar_iter()) {
    decomposer.decompose_slice_to(&adjusted, &mut digits, &mut carries);
    // 本例参数较小，中间乘积不会超出 u32。
    for (sum, &digit) in reconstructed.iter_mut().zip(&digits) {
        *sum = (*sum + digit * weight) % 97;
    }
}

assert_eq!(basis.drop_bits(), 1);
assert_eq!(reconstructed, [42, 0]); // 模 97 的环距离分别为 0 和 1。
```

二次幂模数的输入不需要 adjusted-value 缓冲区。使用 `init_carry_slice`，并直接把
原始输入传给各层 operator；native Fourier 路径采用这种方式：

```rust
use primus_decompose::primitive::ApproxSignedBasis;

let basis = ApproxSignedBasis::<u32>::new(None, 8, Some(3));
let values = [0x1234_5678_u32, u32::MAX];
let mut carries = [false; 2];
let mut digits = [0_u32; 2];
let mut reconstructed = [0_u32; 2];

basis.init_carry_slice(&values, &mut carries);
for (decomposer, weight) in basis.decomposer_iter().zip(basis.scalar_iter()) {
    decomposer.decompose_slice_to(&values, &mut digits, &mut carries);
    for (sum, &digit) in reconstructed.iter_mut().zip(&digits) {
        *sum = sum.wrapping_add(digit.wrapping_mul(weight));
    }
}

assert_eq!(reconstructed, [0x1234_5600, 0]);
```

`init_carry_slice` 也接受显式二次幂模数，但对非二次幂模数会 panic。单值处理使用
`init_value_carry`，再调用 `decompose` 或 `decompose_to`，同样逐层传递 carry。

## BigUint 工作流与布局

对于 `N` 个值、每个值 `W = big_uint_value_len()` 个 limb，全宽缓冲区有 `N * W`
个 limb，采用 **value-major** 布局，每个值内部为 little-endian：

```text
[value_0_low, ..., value_0_high, value_1_low, ..., value_1_high, ...]
```

Carry 缓冲区有 `N` 个布尔值。全宽 digit 输出有 `N * W` 个 limb；紧凑的
`unsigned_decompose_slice_to` 输出只有 `N` 个 limb。即使 `Q` 是二次幂，BigUint
版本也必须执行输入初始化。

```rust
use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_integer::BigUint;

let modulus = [1_u32, 1]; // Q = 2^32 + 1，little-endian limbs。
let basis = BigUintApproxSignedBasis::new(BigUint(&modulus[..]), 8, None);
let values = [42_u32, 0, u32::MAX, 0]; // 两个值：42 和 Q - 2。
let mut adjusted = [0_u32; 4];
let mut carries = [false; 2];
let mut digits = [0_u32; 2];
let mut reconstructed = [0_i64; 2];

basis.init_value_carry_slice_to(&values, &mut adjusted, &mut carries);
for (decomposer, weight) in basis.decomposer_iter().zip(basis.scalar_iter()) {
    decomposer.unsigned_decompose_slice_to(&adjusted, &mut digits, &mut carries);
    // 本例数值较小，可将全宽权重与紧凑 digit 转换后直接重组。
    let weight = i64::from(weight[0]) + (i64::from(weight[1]) << 32);
    for (sum, &digit) in reconstructed.iter_mut().zip(&digits) {
        let signed = if digit < 128 {
            i64::from(digit)
        } else {
            i64::from(digit) - 256
        };
        *sum += signed * weight;
    }
}

assert_eq!(reconstructed, [42, -2]); // -2 在模 Q 下表示 Q - 2。
```

本 crate 不依赖 `primus_rns`。RNS/CRT 转换由
[`primus_rns`](../primus_rns/README.zh_CN.md) 负责；其 residue 批次使用 modulus-major
布局，不是上述 value-major 布局。`primus_glwe_rns` 中的 `CrtGlevParameters` 预计算
各重组权重在每个 RNS 模数下的 residue，并通过 `scalar_residue_iter()` 提供访问。
它们与本 basis 保存的全宽整数权重是不同的表示。

## 调用方契约与分配

- 原始输入必须为 canonical 值：位于 `[0, q)` 或 `[0, Q)`。Primitive native
  模数允许系数类型的任意位模式。这些方法不会对输入做模约简。
- Adjusted inputs 是内部位表示，不保证是 canonical residue。整个分解过程应保持
  它们不变，不能再做模约简。
- 按层数升序应用每个 operator，不能跳层或重置 carry。Digit 为零时也可能有 carry。
  新的一批输入必须重新初始化，不能复用上一批输入的最终 carry 值。
- Primitive 的输入、输出和 carry slice 必须等长；BigUint 必须满足上述精确形状。
  这些重复计算路径中的形状检查是 debug 诊断，不是 release 模式的输入验证。
- Slice 方法覆盖输出并更新 carry，不会累加 digit。
  `init_value_carry_slice_assign` 还会覆盖原始输入。
- 构造器会分配预计算存储。Slice 和调用方提供输出的方法内部不分配。
  BigUint 的 `init_value_carry`、`decompose`、`approximate_error_bound` 返回新分配的
  vector 或大整数；重复计算路径应优先使用可复用缓冲区和 `_to`/slice 方法。

## Feature 与验证

默认 feature 集为空。可选的 `simd` feature 转发到 `primus_integer/simd`，需要
nightly Rust；它不选择独立的分解 backend。普通循环也可以受益于编译器自动向量化。

```text
cargo test -p primus_decompose
cargo bench -p primus_decompose --bench decompose
cargo +nightly test -p primus_decompose --features simd
```

基准分别测量 basis 构造和在线分解。Primitive 覆盖 scalar 以及零复制/adjusted 批量
路径；BigUint 以紧凑批量输出为主，覆盖固定步长与通用 fallback，并保留一组相同参数的
全宽输出对照。每批处理 4096 个系数，包含初始化与所有保留层。Workspace 已通过
[`.cargo/config.toml`](../../.cargo/config.toml) 设置 `target-cpu=native`。

## 许可证

可任选 [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) 或
[MIT License](../../LICENSE-MIT)。
