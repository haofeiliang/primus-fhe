# 库使用导航

[English](README.md) | 简体中文

本指南用于组合或扩展 workspace 中的库，说明已有接口及其边界；详细契约仍以 rustdoc 为准。各库职责见 [workspace 导航](../../README.zh_CN.md#workspace-导航)，验证命令见[测试指南](testing.md)。

## 选择算术域

先选择模数，再选择变换和分解 basis。实现见 [primus_modulus](../../crates/primus_modulus/src/lib.rs)，算术能力 trait 见 [primus_reduce](../../crates/primus_reduce/src/lib.rs)。

| 数值域 | 模数类型 | 约束 |
| --- | --- | --- |
| 隐式 `2^BITS` | `NativeModulus<T>` | 机器字 wrapping，模数本身不可表示 |
| 显式 `2^b` | `PowOf2Modulus<T>` | `1 <= b < T::BITS`，例如 `PowOf2Modulus::new(1u64 << 24)` |
| 显式模数下的重复乘法 | `BarrettModulus<T>` | `1 < q < 2^(BITS-2)`；NTT 还要求对应的素数/单位根条件 |
| 有界基础算术 | `CompactModulus<T>` | 同样保留两个高位，无 Barrett 预计算 |
| 一般可表示模数 | `UintModulus<T>` | `q > 1`；不替代变换的更强契约 |

`RingContext` / `FieldContext` 表示可用算术能力，不证明素性或可逆性。NTT 需阅读[单位根和范围要求](../../crates/primus_ntt/README.zh_CN.md#构造约束)。Gadget 运算使用 [primus_decompose](../../crates/primus_decompose/README.zh_CN.md) 和调用方的 basis 层次顺序。分解、归一化和 lazy range 是数值契约，不能从缓冲区类型推断。

## 选择存储并建立布局

[primus_data](../../crates/primus_data/src/traits.rs) 分开元素类型（`RawData`）、读取（`Data`）、修改（`DataMut`）和拥有型构造（`DataOwned`）。`Polynomial<S>` 和密文 wrapper 通过这些 trait 同时支持拥有型容器及借用切片。

`Polynomial::new(storage.as_slice())` 创建只读借用，`Polynomial::new(storage.as_mut_slice())` 创建可变借用，不复制或变换元素；`Polynomial::new(storage)` 移动容器。消费一个可变 view 的算术方法仍可能修改调用方存储；需要明确体现原地修改时用 `*_assign`，写入可复用输出时用 `*_to`。

Raw 多项式/密文构造器不建立模数、秘密身份、表示或完整布局。`Polynomial<S>` 不另存环长度：包装 `batch_count*N` 个元素，不会自动把单多项式运算变成批量运算。只有接口契约明确接受批次时才直接传入；否则先迭代出完整对象。

GLWE 布局优先使用已有的 [size 类型](../../crates/primus_lattice/src/size.rs)：

| 类型 | 描述内容 |
| --- | --- |
| `GlweSize` | k 个 mask 多项式和一个 body；`glwe_len() = (k+1)*N` |
| `GadgetSize` | 每个 GLev 有 L 层，每个 GGSW 有 k+1 个 GLev 行 |
| `RnsGlweSize` | 带有明确 RNS 模数数量的 GLWE |
| `RnsGadgetSize` | 该 RNS 布局上的 gadget 层与行 |

这些类型检查支持的维数及展平长度溢出，不检查实际存储，也不验证 basis、表或噪声。拥有契约的公开边界须将完整缓冲长度与派生长度比较。NTRU 中一个 Ntru 占 N 个值，一个 Nlev/Ngsw 占 L*N 个值；使用运算参数/basis，并检查批次长度。Nlev 与 Ngsw 虽然布局相同，但加密相位和合法乘积不同。

## 遍历数学对象

分块代表一个完整多项式或密文时使用语义迭代器。`new(data, object_len)` 接受的是**存储元素数**，不是维数、层数或字节数。可变版本以 `IterMut` 结尾，子结构方法有 `_mut` 版本。标量权重、索引以及没有对应对象类型的批次，仍使用普通 slice iterator 或 `chunks_exact(_mut)`。

| 对象 | 批次迭代器 / 子结构接口 | 单个子对象长度 |
| --- | --- | --- |
| 系数多项式 | `PolynomialIter`、`PolynomialIterMut` | N 个系数 |
| NTT 多项式 | `NttPolynomialIter`、`NttPolynomialIterMut` | N 个环元素 |
| Fourier 多项式 | `FourierPolynomialIter`、`FourierPolynomialIterMut` | N/2 个复数 |
| CRT/DCRT 多项式 | `CrtPolynomialIter`、`DcrtPolynomialIter` 及可变版本 | modulus_count*N 个值 |
| NTRU 家族 | `NtruIter`、`NlevIter`、`NgswIter` 及可变版本；`Nlev::iter_ntru(N)`、`Ngsw::iter_ntru(N)` | Ntru 为 N；Nlev/Ngsw 为 L*N |
| GLWE 家族 | `GlweIter`、`GlevIter`、`GgswIter` 及可变版本 | 使用 `GlweSize` / `GadgetSize` 的长度 |
| GGSW → GLev → GLWE → 多项式 | `iter_glev(glev_len)`、`iter_glwe(glwe_len)`、`iter_poly(N)` | 行 → 层 → 分量 |
| GLWE mask/body | `a_b(N)`、`a_b_mut(N)` | mask 多项式迭代器及一个 body 多项式 |

接口入口见[多项式导出](../../crates/primus_poly/src/lib.rs)、[密文模块](../../crates/primus_lattice/src/lib.rs)及[迭代器生成](../../crates/primus_lattice/src/macros/iter.rs)。NTT 密文使用 `NttNgswIter` 等带前缀的类型，子结构方法为 `iter_ntt_ntru`、`iter_ntt_glev`、`iter_ntt_glwe`、`iter_ntt_poly`。Fourier 对应 `FourierNgswIter` 等类型，但子结构方法是 `iter_ntru`、`iter_glev`、`iter_glwe`、`iter_fourier_poly`，长度均以复数个数计；GLWE size 类型已有对应的 `fourier_*_len()` 可用。

这些迭代器会略过不完整尾块，`zip` 会在较短一侧结束。应在构造前一次性检查完整长度和配对数量，不能用迭代次数或“没有 panic”证明布局合法。

### 批量多项式运算

以下完整片段将 `Z_256[X]/(X^4+1)` 中的两个多项式乘 X，需要依赖 `primus_modulus` 和 `primus_poly`。这里的小环用于展示算术，不是加密参数组。

```rust
use primus_modulus::PowOf2Modulus;
use primus_poly::{PolynomialIter, PolynomialIterMut};

let n = 4;
let modulus = PowOf2Modulus::new(256u32);
let input = [1u32, 2, 3, 4, 5, 6, 7, 8];
let mut output = [0u32; 8];

assert_eq!(input.len() % n, 0);
assert_eq!(output.len(), input.len());
for (input, mut output) in PolynomialIter::new(&input, n)
    .zip(PolynomialIterMut::new(&mut output, n))
{
    input.mul_monomial_to(1, &mut output, modulus);
}
assert_eq!(output, [252, 1, 2, 3, 248, 5, 6, 7]);
```

### Gadget 布局和借用视图

以下片段依赖 `primus_lattice`，遍历一个 GGSW 的行和层，再分开每个 GLWE 的 mask/body。零缓冲区只展示布局访问，没有采样加密；子对象均为借用视图，遍历过程不分配。

```rust
use primus_lattice::{GadgetSize, GlweSize, ggsw::Ggsw};

let glwe_size = GlweSize::new(2, 8);
let gadget_size = GadgetSize::new(glwe_size, 3);
let storage = vec![0u32; gadget_size.ggsw_len()];

assert_eq!(storage.len(), gadget_size.ggsw_len());
let ggsw = Ggsw::new(storage.as_slice());
let mut level_count = 0;
for row in ggsw.iter_glev(gadget_size.glev_len()) {
    for level in row.iter_glwe(glwe_size.glwe_len()) {
        let (mask, body) = level.a_b(glwe_size.poly_length());
        assert_eq!(mask.len(), glwe_size.dimension());
        assert_eq!(body.poly_length(), glwe_size.poly_length());
        level_count += 1;
    }
}
assert_eq!(level_count, 9); // (k+1) 行 * L 层
```

## 显式区分变换表示

| 表示 | 入口 | 复用与相容性 |
| --- | --- | --- |
| 系数 ↔ NTT | [NttTable](../../crates/primus_ntt/README.zh_CN.md#表示与取值范围)、`transform_inplace` / `inverse_transform_inplace`；密文的 `into_ntt_form` / `write_ntt_form` | 同一 N、模数和变换约定复用表；canonical/lazy range 与存储长度分别检查。 |
| 系数 ↔ Fourier | [FftTable / FftEngine](../../crates/primus_fft/README.zh_CN.md#变换形式) | 复用原始表实例及其工作区；密文使用归一化 torus 尺度，小整数因子使用整数尺度。 |
| CRT ↔ DCRT | [DcrtTable](../../crates/primus_ntt/README.zh_CN.md#dcrt-布局)、[RNS 运算](../../crates/primus_rns/README.zh_CN.md) | 保持模数顺序及 modulus-major 的 N 元素块。 |

换一个 wrapper 或迭代器不等于执行变换。Fourier 每个多项式占 N/2 个复数，结果存在近似误差；长度相同的任意 FFT 表不能互换。并行 worker 可以共享只读表，但各自需要可变工作区。

## 组合密文工作流

从拥有该运算的最低层开始。[LWE](../../crates/primus_lwe/README.zh_CN.md)、[GLWE](../../crates/primus_glwe/README.zh_CN.md)、[NTRU](../../crates/primus_ntru/README.zh_CN.md) 和 [RNS GLWE](../../crates/primus_glwe_rns/src/lib.rs) 提供加密、密钥及求值原语。[共享 TFHE](../../crates/primus_tfhe/README.zh_CN.md) 提供 LWE 客户端、编码、LUT 几何和公共求值接口；[GLWE](../../crates/primus_tfhe_glwe/README.zh_CN.md) 与 [NTRU](../../crates/primus_tfhe_ntru/README.zh_CN.md) 家族分别定义自身参数和密钥契约。

按后端示例顺序阅读：参数 → 验证后的 context/table → client/server key → 公开 LUT → evaluator 和输出分配 → 重复 `*_to` 求值 → 客户端解密。四个具体入口是 [GLWE NTT](../../crates/primus_tfhe_glwe_ntt/examples/ntt_basic.rs)、[GLWE Fourier](../../crates/primus_tfhe_glwe_fourier/examples/fourier_basic.rs)、[NTRU NTT](../../crates/primus_tfhe_ntru_ntt/examples/ntru_ntt_basic.rs) 和 [NTRU Fourier](../../crates/primus_tfhe_ntru_fourier/examples/ntru_fourier_basic.rs)。其中参数是功能 fixture，须按目标操作选择并验证。

NTRU 将外部 LWE 的秘密/模数/维数与累加 NTRU 环的秘密/模数/长度分开；GLWE 的 PBS order 有自身输入输出域契约。缓冲区尺寸相同不代表密钥可以互换。保留后端参数检查，并明确调用方仍需保证的秘密和表身份。

对加密 chunk 计算高精度函数，使用 [primus_tfhe_ntru_lut](../../crates/primus_tfhe_ntru_lut/README.zh_CN.md)。One-hot CBS 位于 NTRU 后端，表分区、选择和旋转位于查表库。其 evaluator 借用 context、server key 和编译后的 LUT，拥有可复用缓冲。输出只分配一次并复用 `evaluate_to`，在线循环内不重新构造密钥或表。

## 区分运行环境与工作区

命名规则按职责区分。现有 API 尚未全部采用该规则；下表列出当前名称，帮助定位实现，不增加兼容别名。

| 职责 | 命名规则 | 当前入口 |
| --- | --- | --- |
| 保存一组复用临时缓冲和形状不变量 | `*Workspace` | [Ntt/FourierNtruExternalProductContext](../../crates/primus_lattice/src/context/ntru_external_product.rs)、[NtruLweKeySwitchingContext](../../crates/primus_ntru/src/key_switch/lwe.rs) 当前仍使用 Context 名称 |
| FFT 后端拥有的临时缓冲 | 同样使用 `*Workspace` | [FftTable::Scratch / new_scratch 和 FftEngine](../../crates/primus_fft/src/table.rs) 当前仍使用 Scratch 词干 |
| 绑定已验证参数、模数和变换环境 | `*Context` | [TfheContext](../../crates/primus_tfhe_ntru_ntt/src/context.rs)；算术 `RingContext` / `FieldContext` 仍为能力 trait |
| 绑定密钥/表和可变工作区并提供执行流程 | `*Evaluator` / `*Engine` | TFHE evaluator、`FftEngine`；混合状态按实际职责判断 |
| 借用的一段临时切片或区域 | 局部变量 `scratch` / `buffer` | 无需另加 wrapper；第三方 `PodBuffer` / `PodStack` 保留原名 |

工作区长度相同不证明 basis、模数、表或秘密相容。在重复操作前构造缓冲，遵循接口的覆盖/累加规则；借用工作区或调用方 accumulator 需要恢复时须明确恢复契约。秘密密钥和工作区擦除后的状态可能不同，复用前阅读各类型的 `zeroize` 契约。

## 按实际消费者选择拥有型容器

复用、固定长度、额外对齐是独立判断。对实际系数数组（包括密钥数据）使用下表，不机械替换所有 `Vec`。

| 数据及生命周期 | 候选存储 |
| --- | --- |
| 固定长度的热点数值数组，对齐有契约要求或实测收益 | `ABox<[T]>`；元素仍可修改 |
| 确需增长且额外对齐有用 | `AVec<T>`；转固定存储时检查复制/重分配 |
| 固定长度且无额外对齐要求 | `Box<[T]>`，或因明确构造/复用需求保留 `Vec<T>` |
| 动态元数据、索引、短小控制数据或对象描述符 | 普通 `Vec`、数组或 Box |
| 后端专属临时内存 | 保留后端分配、容量和借用契约 |

启用 `primus_data/aligned-vec` 后，[AVec 和 ABox 实现 RawData/Data/DataMut](../../crates/primus_data/src/impls.rs)，**未实现 DataOwned**。该 trait 还要求从迭代器构造及消费，aligned 分配则有自己的对齐选择。应显式分配容器，用 `new` 包装，再使用支持 `DataMut` 的运算；不能假定 `Polynomial::zero` 等受 `DataOwned` 约束的构造器接受 aligned 目标。

整块分配对齐不保证子块对齐，需检查实际步长，尤其是长度为 n+1 的 LWE 行。对齐 `Vec<Key>` 不会对齐各密钥内部的系数。修改存储前检查实际 kernel，测量受影响负载、构造/转换成本和内存，同时保留秘密擦除与所有权契约；对齐本身不能证明提速。

## 验证对应契约

遵循 [AGENTS.md](../../AGENTS.md) 和[测试指南](testing.md)。普通测试（含密文端到端）优先使用能保留目标契约的小参数，只有特定路径或回归需要时才保留大尺寸案例。All-targets 用于编译/lint；lib/tests 与 doctest 分开执行，选定的 Criterion smoke 与普通测试、真实性能采样分别运行。
