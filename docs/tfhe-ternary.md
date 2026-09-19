# Ternary LWE secret 与融合盲旋转

本文记录算法选择、数学契约和实施进度。**T1–T3 已完成：NTT/Fourier 单步原语和完整经典 GLWE ternary TFHE 已接入**。算法清单见 [后续候选](tfhe-next.md)，当前任务以 [HANDOFF](../HANDOFF.md) 为准。

首个目标为经典 **GLWE NTT / Fourier**：真正进入 BR 的 small-LWE 秘密可以取 `-1/0/1`。沿用现有 LUT、量化和两种 PBS order；binary 路径保留。NTRU ternary、桶聚合稀疏 ternary、automorphism BR 分开安排。

## 1. 来源与符号

本方案采用用户提出的融合分解，并参考本机笔记 [analysis.typ](/home/lhf/codes/notes/fhe/analysis.typ) 中的 `External Product`、`Ternary LWE Secret Key` 和 `Optimized Ternary LWE Secret Key`。该绝对路径仅为本机参考，不是构建依赖；关键推导在本文完整记录。

- 工作环为 `R_q = Z_q[X]/(X^N+1)`，`q` 为 accumulator 模数。
- `s_i = s_i⁺ - s_i⁻`，其中 `s_i⁺ = [s_i=1]`、`s_i⁻ = [s_i=-1]`，两者互斥。
- `K_i⁺`、`K_i⁻` 分别为同一 accumulator 秘密、basis 和布局下独立加密的 GGSW 控制。`k=1` 时即常称的 RGSW。
- `α_i = RotationQuantizer::exponent(a_i)`，范围为 `0..2N`，表示**量化后的**指数。普通步长为 1，交错步长沿用 LUT 的 `padded_output_count`。
- 仓库先以 `X^{-Q(b)}` 初始化 accumulator，再逐项乘 `X^{α_i s_i}`。笔记使用 `(X^{-a_i}-1)` 与 `K_i⁺-X^{a_i}K_i⁻`；将其 `a_i` 替换为 `-α_i`，即得到本文约定。

负指数由同一个 `α_i` 在模 `2N` 下取负。不要另算 `Q(-a_i)`：舍入 tie 处未必满足 `Q(-a_i)=-Q(a_i)`。

## 2. 一次外积的更新

令当前 GLWE accumulator 为 `C`：

\[
K_{i,\alpha}=K_i^+-X^{-\alpha_i}K_i^-,\qquad
Y=(X^{\alpha_i}-1)C,
\]

\[
\boxed{C'=C+K_{i,\alpha}\boxtimes Y.}
\]

`⊠` 表示 GGSW 与 GLWE 的外积。用户公式中的 `xy` 是 accumulator 的**增量**，还要加回原来的 `C`。

忽略加密误差和分解残差，组合控制的明文为

\[
M_{i,\alpha}=s_i^+-X^{-\alpha_i}s_i^-.
\]

因此

\[
\begin{aligned}
C'&=\left[1+(s_i^+-X^{-\alpha_i}s_i^-)(X^{\alpha_i}-1)\right]C\\
  &=\left[1+s_i^+(X^{\alpha_i}-1)+s_i^-(X^{-\alpha_i}-1)\right]C\\
  &=X^{\alpha_i s_i}C.
\end{aligned}
\]

| `s_i` | `(s_i⁺,s_i⁻)` | `M_{i,α}` | 理想更新 |
| --- | --- | --- | --- |
| 0 | `(0,0)` | 0 | `C` |
| 1 | `(1,0)` | 1 | `X^α C` |
| -1 | `(0,1)` | `-X^-α` | `X^-α C` |

这不要求 `2` 在模 `q` 下可逆，因而代数上同时适用于 Native 和奇数显式模数。它只涉及实际 selector 值，不要求正负概率相等，也不要求不同坐标独立；概率假设属于后续噪声与安全参数分析。

公开指数 `α=0` 时可以跳过，复用 binary 路径已有的优化。秘密为 0 时不能由 evaluator 跳过：两个控制仍有加密噪声，且 evaluator 不知道明文 selector。

### 与其他 ternary 写法的关系

直接连续执行正、负两个 CMUX 每坐标需要两次外积，可作测量参照。另一种写法先构造 `(X^α-1)K⁺+(X^-α-1)K⁻`，再与 `C` 外积，见 [Joye–Paillier §3.2](https://marcjoye.github.io/papers/JP22ternary.pdf)。

本文首选用户的分解：两份控制先形成 `K⁺-X^-α K⁻`，对 `(X^α-1)C` 分解一次。近似 gadget decomposition 不是线性操作，不能把这些写法的明文恒等式推广为密文输出或噪声完全相同。

## 3. 噪声：先保留准确递推

记 `φ(C)=B-Σ A_j S_j` 为 GLWE phase，`D(Y)` 为实际 gadget 分解结果，`G` 为 gadget 矩阵。定义重构残差

\[
\rho(Y)=D(Y)G-Y.
\]

设两份控制各行的误差向量为 `e⁺`、`e⁻`，则组合控制行误差为

\[
e_\alpha=e^+-X^{-\alpha}e^-.
\]

在精确环运算下有

\[
\boxed{\phi(C')=X^{\alpha s_i}\phi(C)
+M_{i,\alpha}\phi(\rho(Y))
+D(Y)e_\alpha.}
\]

这条等式将三类误差分开：

1. 已有 accumulator 误差只随 `X^{αs_i}` 作符号置换，不因构造 `Y` 而额外倍增。
2. 新的近似分解误差乘 `0`、`1` 或 `-X^-α`。必须计算 `Y` 的残差，不能搬用对 `C` 分解得到的残差。
3. 新控制误差来自两份 GGSW。独立同方差的两份行噪声相减后，单系数方差为两倍；仅减少外积次数并不把它变回 binary 的控制噪声。

Fourier 实现还须计入浮点运算与逆变换误差；上式是其精确环参照，不是浮点结果的逐位恒等式。

### 如何使用本机笔记

笔记给出的 `Var(E_EP,fused) ≈ 2 Var(E_EP)` 可作为同一 digit 二阶矩及相应独立性假设下的估计起点。实际分解输入是 `(X^α-1)C`，其系数和 digit 的联合分布不能自动当作独立均匀。

笔记中的 `E(FBS_ternary-fused)=0` 也不直接作为参数保证。负循环单项式会改变部分系数的符号，非零均值未必保持。例如 `α=N` 时 `X^-N=-1`，故 `M=s⁺+s⁻=|s_i|`；此时不能用“正负 selector 互斥且同概率”直接消去近似误差均值。总均值还取决于指数、accumulator、残差及后续旋转的联合分布。

实现阶段从准确递推核对本仓库的 Native / Barrett basis，再做独立测量。模切误差、BR 误差、KS 误差和 Fourier 误差分别处理；有限样本不用于宣称生产失败率。对称 ternary 的零均值秘密也不意味着每项模切或 BR 误差都为零均值。

## 4. 表示与热路径

### 密钥布局

- binary 继续每坐标一份 GGSW；ternary 每坐标一对 `(positive, negative)`，保存加密后的 selector，不保存明文符号或非零位置。
- 两份控制必须使用相同 accumulator 秘密、模数、basis、维度和变换表；独立加密。
- 由密钥布局在 BR 循环外选择 binary / ternary 内核，不在逐系数算术内再判断秘密分布。
- 经典/稀疏保持现有执行区分。`SparseTernary` 是一个采样分布名称，不自动选择 P3 的桶聚合算法。
- `iter_binary_controls` 返回一坐标一控制，`iter_ternary_controls` 返回一坐标一对；不匹配时返回 `None`。BSK 保存输入分布，server key 兼容性同时检查它。

### NTT 首选实现

现有 [MonomialNttTable](../crates/primus_ntt/src/ntt/mod.rs) 已能直接生成 `NTT(X^-α)`，复用实际表顺序。控制密钥长期保存在 NTT 域，无须每轮 inverse NTT 再整体变回 NTT。

先实现容易验证的版本：

1. 在复用的 GLWE 缓冲中计算 `Y=(X^α-1)C`。
2. 生成一个单项式的 NTT 向量，对控制各多项式逐点计算 `K⁺-NTT(X^-α)·K⁻`，写入复用的 GGSW 缓冲。
3. 调用现有外积内核，只分解/变换一份 `Y`，得到增量后加回 `C`。

若完整 GGSW 临时缓冲的写读成本明显，再比较按 gadget row 组合并立即与 digit 相乘的实现。后者能减少 scratch，但增加外积内核复杂度；只有完整负载测量支持时才保留。不预先添加覆盖全部后端的控制策略 trait。

### Fourier 对应实现

组合仍可在 Fourier 域逐点完成，单项式因子必须是**整数尺度**，不能通过 torus 缩放生成。变换顺序依赖实际 `FftTable` 实例，不能硬编码另一张表的自然频率顺序。

T2 使用 `FourierGgsw::sub_mul_monomial_to`：通过现有 `forward_as_integer` 变换一个单项式，
随后逐点组合完整 GGSW。系数单项式复用外积的 digit buffer，组合后由分解覆盖；不重新变换
控制密文。实测单项式 FFT 只占基准融合单步的约 2.6%–3.4%，因此暂不增加直接生成接口、
频率布局 trait 或按指数预存的表。此选择适用于当前测量布局，后续可按完整 PBS 成本复核。

### 成本预期与限制

令 GLWE 维数为 `k`、分解层数为 `ℓ`。每坐标两份控制，BSK 元素数由 binary 的 `nℓ(k+1)²N` 增至两倍；Fourier 按其半长复数布局另外统计实际字节数。

融合方案仍为每坐标一次外积，新增 `O(ℓ(k+1)²N)` 的控制组合工作。完整临时 GGSW 版本额外需要同阶 scratch 和一个单项式变换缓冲；按行融合可以降低临时存储。它省去的是第二次 GLWE 分解、digit 变换和外积调用中的相应工作，**不保证耗时等于 binary，也不保证比双 CMUX 快两倍**。

## 5. 当前代码的接入点

| 位置 | 已落实的契约 |
| --- | --- |
| [SecretKeyDistr](../crates/primus_distr/src/secret_key_distr.rs) 与 [LweSecretKey](../crates/primus_lwe/src/secret_key/owned.rs) | 已有 ternary 采样与模 `q` 剩余类存储，继续复用 |
| [GLWE TFHE 参数](../crates/primus_tfhe_glwe/src/parameters.rs) | 接受全部 binary/ternary small-LWE 家族，拒绝 Gaussian；保留模数/维数/basis 约束 |
| [GLWE client key](../crates/primus_tfhe_glwe/src/key.rs) | 构造 padded ring secret 时按输入模数将 `q-1` 还原为 `-1`，其余 padding 保持零 |
| [NTT BSK](../crates/primus_tfhe_glwe_ntt/src/bootstrapping_key.rs) / [Fourier BSK](../crates/primus_tfhe_glwe_fourier/src/bootstrapping_key.rs) | 按实际系数生成相邻的正负 selector，独立加密；验证支持集与分布，检查长度溢出，清除临时 selector 数组 |
| [Ternary CMUX](../crates/primus_lattice/src/ggsw/ternary.rs) 与 [外积](../crates/primus_lattice/src/ggsw/external_product.rs) | T1/T2 已增加 NTT/Fourier 融合单步及对应 scratch；binary CMUX 仍只接收 bit 控制 |
| [NTT BR](../crates/primus_tfhe_glwe_ntt/src/blind_rotation.rs) / [Fourier BR](../crates/primus_tfhe_glwe_fourier/src/blind_rotation.rs) | 循环外分派，复用量化、初始化、buffer 交换与公开零指数跳过 |
| ServerKey / evaluator / CBS / MVB | 两种 order、普通/交错 LUT、公钥客户端及 NTT CBS/MVB 已接通；桶聚合路径仍拒绝 ternary |

Ternary 剩余类到有符号系数的转换在 key 构造/导入边界完成。仅需处理当前支持的 `0/1/q-1`，不为这个任务设计一般整数解码框架；也不能把明文 codec 的缩放解码用于秘密系数。

采样分布的支持范围与算法正确性分开：融合恒等式适用于 ternary 家族，但非对称、固定重量和固定正负计数不能套用 iid 对称分布的参数估计。BR→KS 与 KS→BR 中外部 LWE 秘密不同，public-key 加密和 signed view 沿用已有入口，并检查实际参数/秘密域。

## 6. 实施顺序与完成条件

三个实施单元均已完成；以下保留实现选择及测量口径，后续修改按相关前提复测。

### T1：NTT 单步原语与成本对照（已完成）

入口为 `positive.cmux_ternary_monomial_to(&negative, &input, exponent, &mut output,
&basis, modulus, &ntt, &mut context)`，工作区为
`NttGlweTernaryCmuxContext::new(size)`。两份控制显式传入，工作区固定 `GadgetSize`；
没有新增跨后端策略 trait，也没有改变 binary 入口。控制组合调用通用 NTT
`sub_mul_monomial_to`：生成一次 `NTT(-X^-α)`，复用逐点 fused multiply-add 写入完整 GGSW，
再调用已有外积累加内核。NTT 单项式方法由 `impl_ntt_monomial!` 为单模数密文统一提供；
其 scratch 由调用方复用，不在逐多项式循环里重新生成单项式变换。

保留两个聚焦测试：lattice 的 `u32` 无噪声对角控制用独立负循环 oracle 检查两个分解深度下的
逐系数误差界；GLWE 的 `u64` 真实加密控制由独立 schoolbook phase 检查旋转结果。
分别使用 `N=16/32, k=2`，遍历三个秘密值和所有 `2N` 个指数，复用脏输出和工作区，
并在最后回到零指数检查精确复制。没有新增完整 PBS 测试矩阵；在线整体分配检查留在 T3。

#### T1 测量与取舍

2026-09-17，Ryzen 9 9955HX3D / x86_64 Linux，固定 CPU 2、串行计时，boost/SMT 开启且 CPU
未隔离。两种 feature 配置均用 nightly 1.100.0（2026-08-26）、仓库构建配置和 Criterion 0.8.2；
50 samples、1 s warm-up、3 s measurement。`u32, q=132120577, log B=8, α=floor(N/3)`。
下表为均值；95% 区间及拆分结果见 [CSV](benchmarks/tfhe-ternary-t1.csv)。

| N / k / ℓ | 默认：双 CMUX → 融合（µs） | SIMD：双 CMUX → 融合（µs） |
| --- | --- | --- |
| 1024 / 1 / 3 | 37.480 → 22.095（−41.0%） | 40.134 → 22.652（−43.6%） |
| 2048 / 1 / 3 | 75.960 → 45.661（−39.9%） | 78.617 → 46.959（−40.3%） |
| 1024 / 1 / 2 | 27.772 → 16.088（−42.1%） | 29.869 → 16.654（−44.2%） |
| 1024 / 2 / 3 | 60.799 → 37.588（−38.2%） | 64.997 → 38.503（−40.8%） |

常驻入口为 `primus_lattice/benches/glwe_ntt.rs` 的 `ternary_two_cmux` / `ternary_fused`，
复用已有四组布局。每次迭代仅计算一个完整 ternary 单步，输出均为系数域；控制变换、分配和
数据生成在计时外。复用固定的稠密算术控制，未模拟真实加密噪声或整把 BSK 的顺序访存。
这证明所测单步有收益，不代表等安全参数或完整 PBS 的加速比。

将内联控制组合迁入通用 NTT 单项式接口后，按相同配置和四组布局复测融合单步，默认耗时变化
**−2.40%～−0.41%**，SIMD 为 **−2.26%～+0.40%**，未见明显回退。CSV 中
`t1-monomial-before/after-default/simd` 记录此次对照；scratch 大小不变，不据此宣称算法加速。

```sh
taskset -c 2 cargo +nightly bench -p primus_lattice --bench glwe_ntt -- 'ternary_' --warm-up-time 1 --measurement-time 3 --sample-size 50 --save-baseline t1-default --noplot
taskset -c 2 cargo +nightly bench -p primus_lattice --bench glwe_ntt --features simd -- 'ternary_' --warm-up-time 1 --measurement-time 3 --sample-size 50 --save-baseline t1-simd --noplot
```

一次性成本拆分使用 `N=1024, ℓ=3, k=1/2`：控制组合包括生成 `NTT(-X^-α)` 和完整 GGSW 的逐点
乘加；分解/变换对预先计算的 `Y` 执行所有 `(k+1)ℓ` 个 digit NTT，不含密钥乘加、逆变换或加回
原输入。默认配置的组合耗时为 **3.44/7.70 µs**，分解/变换为 **11.94/17.83 µs**；同轮完整
融合为 **23.27/39.45 µs**。SIMD 分别为 **3.28/7.24、11.32/17.08、21.93/36.74 µs**。
独立测量存在缓存与计时差异，不把各段耗时相加当作完整单步耗时。

还比较了在每个 digit NTT 后逐多项式组合、立即累加到 NTT GLWE 的原型；先检查它与完整缓冲
版本的原始输出相等，再在相同进程内计时。四项耗时变化为 **−1.1%、−0.6%、−1.0%、+1.7%**
（默认 k1/k2、SIMD k1/k2）。原型虽节省 scratch，却需要另一套外积分解循环；收益不稳定，
故未保留。拆分与原型 benchmark 一并移除，仅在 CSV 留下结果。T3 若整把密钥访存暴露出瓶颈，
再重新衡量这种取舍。

工作区按逻辑 payload 计数，不含 `Vec` 元数据、allocator 开销、输入、输出、控制密钥或 NTT 表。
外积 context 为 `(k+3)N*sizeof(T)+N*sizeof(bool)`；融合额外使用
`[ℓ(k+1)²N+N]*sizeof(T)`。双 CMUX 则在外积 context 外需要一个 `(k+1)N` 的中间 GLWE。

| N / k / ℓ（u32） | 双 CMUX scratch（KiB） | 融合 scratch（KiB） |
| --- | --- | --- |
| 1024 / 1 / 3 | 25 | 69 |
| 2048 / 1 / 3 | 50 | 138 |
| 1024 / 1 / 2 | 25 | 53 |
| 1024 / 2 / 3 | 33 | 133 |

### T2：Fourier 单步原语（已完成）

入口为 `positive.cmux_ternary_monomial_to(&negative, &input, exponent, &mut output,
&basis, &mut fft, &mut context)`，工作区为 `FourierGlweTernaryCmuxContext::new(size)`。
组合调用 `FourierGgsw::sub_mul_monomial_to`，保持与 NTT 相同的数学职责；Fourier 方法显式
接收 FFT engine、长度 `N` 的整数 scratch 和长度 `N/2` 的复数 scratch。只增加实际使用的
GGSW 方法，没有扩展全部 Fourier 密文的单项式方法族。零指数 CMUX 精确复制输入；
单独调用 `sub_mul_monomial_to` 的零指数则计算 `self - rhs`。

常驻验证集中在已有文件：`lattice/tests/ternary_cmux.rs` 用 `u32/u64`、两种 FFT 后端、
完整/截断分解检查独立系数 oracle；`lattice/tests/fourier.rs` 直接检查稠密 GGSW 的单项式减法；
`glwe/tests/cmux.rs` 用真实独立加密控制和 schoolbook phase 检查三个秘密值。小环遍历全部
指数并复用脏 scratch。当时没有新增完整 PBS 测试矩阵；端到端接入在 T3 完成。

#### T2 测量与取舍

测量日期、机器、CPU 2、nightly 工具链与 Criterion 设置同 T1；两种配置均使用 nightly。
固定 `u64, q=2^64, log B=8, α=floor(N/3)`，分别使用 RustFFT / TFHE-FFT 的表布局。
数据生成、表和控制变换、分配均在计时外；每次迭代执行一次完整单步并返回系数域结果。
下表为接口提取前的均值，95% 区间与接口提取后的复测见 [CSV](benchmarks/tfhe-ternary-t2.csv)。

| FFT / N / k / ℓ | 默认：双 CMUX → 融合（µs） | SIMD：双 CMUX → 融合（µs） |
| --- | --- | --- |
| RustFFT / 1024 / 1 / 3 | 23.908 → 14.037（−41.3%） | 23.861 → 14.176（−40.6%） |
| RustFFT / 2048 / 1 / 3 | 53.449 → 31.137（−41.7%） | 53.444 → 31.493（−41.1%） |
| RustFFT / 1024 / 1 / 2 | 20.858 → 12.157（−41.7%） | 20.503 → 12.142（−40.8%） |
| RustFFT / 1024 / 2 / 3 | 37.583 → 23.187（−38.3%） | 38.531 → 22.926（−40.5%） |
| TFHE-FFT / 1024 / 1 / 3 | 22.324 → 12.898（−42.2%） | 21.838 → 12.547（−42.5%） |
| TFHE-FFT / 2048 / 1 / 3 | 46.122 → 27.420（−40.5%） | 46.392 → 26.845（−42.1%） |
| TFHE-FFT / 1024 / 1 / 2 | 18.673 → 11.052（−40.8%） | 19.738 → 11.355（−42.5%） |
| TFHE-FFT / 1024 / 2 / 3 | 34.459 → 21.387（−37.9%） | 34.857 → 20.744（−40.5%） |

常驻入口复用 `primus_lattice/benches/glwe_fourier.rs` 的四组布局和两种后端，新增
`ternary_two_cmux` / `ternary_fused`。稠密算术控制与热工作区的限制同 T1，不能外推完整 PBS
或等安全参数的性能。

控制组合提取为 `sub_mul_monomial_to` 后，分轮复测曾出现少量 3%–5% 的上升；随后将原内联
实现和新接口放在同一进程、同一工作区中逐项对照。八项布局/后端的变化为默认
**−0.27%～+0.69%**、SIMD **−0.47%～+0.39%**，未重现明显回退，因此保留接口拆分。
CSV 的 `t2-interface-paired-*` 保存同进程结果；临时 `t2_inline_reference` 已移除。

```sh
taskset -c 2 cargo +nightly bench -p primus_lattice --bench glwe_fourier -- 'ternary_' --warm-up-time 1 --measurement-time 3 --sample-size 50 --save-baseline t2-fft-default --noplot
taskset -c 2 cargo +nightly bench -p primus_lattice --bench glwe_fourier --features simd -- 'ternary_' --warm-up-time 1 --measurement-time 3 --sample-size 50 --save-baseline t2-fft-simd --noplot
```

一次性拆分测量包含单项式清零、写入 `±1` 和整数 FFT，输出复用已有缓冲。
`N=1024, k=1, ℓ=3` 时默认耗时为 RustFFT **0.477 µs**、TFHE-FFT **0.331 µs**，
SIMD 为 **0.472/0.336 µs**。直接生成接口尚未实现或对测；按这部分的成本占比选择保留 FFT，
不宣称它已经是最快实现。拆分用例已移除，CSV 中保留 `t2_profile_monomial_fft` 数据。

浮点诊断采用上述四组布局、无噪声对角控制、三种秘密值和
`α∈{0,1,⌊N/3⌋,N/2,N,N+1,2N−1}`。先独立计算 `Y=(X^α−1)C` 并舍入到保留的 gadget
位数，再按控制计算理想增量，从而将分解残差与浮点误差分开。两种后端和 feature 下观测到的
最大浮点偏差不超过 **10240 个 u64 单位（约 5.55×10^-16 torus）**；这是有限确定性样本，
不是全局误差界或失败率证明。同一诊断逐次记录的在线分配数为零；大型诊断已移除，常驻小环
测试保留数值回归覆盖，完整 PBS 分配验收属于 T3。

Scratch 按逻辑 payload 计，不含 `Vec` 元数据、allocator 开销、输入、输出、控制密钥、
FFT 表和 engine 自身的变换工作区。外积 context 为
`N*sizeof(T)+8(k+2)N+N` 字节；融合新增 `[ℓ(k+1)²+1]*(N/2)*sizeof(Complex64)`。
系数单项式复用 digit buffer；双 CMUX 则额外需要 `(k+1)N*sizeof(T)` 的中间 GLWE。

| N / k / ℓ（u64） | 双 CMUX scratch（KiB） | 融合 scratch（KiB） |
| --- | --- | --- |
| 1024 / 1 / 3 | 49 | 137 |
| 2048 / 1 / 3 | 98 | 274 |
| 1024 / 1 / 2 | 49 | 105 |
| 1024 / 2 / 3 | 65 | 265 |

### T3：完整 GLWE 接入与验收（已完成）

应用只需在 `LweParameters` 选择 ternary 家族，密钥生成、LUT、client 和 evaluator 的调用不变。
不向 LUT 添加秘密分布参数。两种 order 都以 small-LWE 进入 BR；KS 输出仍为补零后的
同一 small secret。参数原有 `q > t >= 2` 保证 `+1/-1` 可区分，无须重复检查 `q=2`。

低层变化：

- BSK 记录 `input_distribution()`，提供 `iter_binary_controls` / `iter_ternary_controls`。
  Ternary 连续存储每坐标的正负控制；临时明文 selector 在释放时擦除。
- `NttGlweBlindRotationContext::new(&key)` / Fourier 对应构造器仅创建所需类型的 scratch。
  `resize` 保持 binary/ternary 类型；更换类型需重建工作区。移除无调用方的 `rebind`。
- BR 在循环外选择 binary CMUX 或 ternary 融合 CMUX；共同复用初始化、量化、零指数跳过
  和交替输出缓冲。Ternary 负指数从同一个量化指数导出，交错 LUT 的列对齐规则不变。
- NTT context/evaluator 要求 `MonomialNttTable`；仓库的 U32/U64/Uint 表均实现该能力。
  不增加通用控制策略 trait，classic/sparse 的既有区分不变。

验证复用已有端到端测试：两种 order、普通/交错 LUT、不同输出尺度、有界双输入、奇数全域、
导入 client key 和 LWE 公钥。NTT CBS 的投影/CMUX 消费及 MVB 的 Scaled 输出也包含 ternary。
保留 binary Boolean 和 sparse/classic 路径覆盖。新增的常驻检查集中于 Native/Barrett/PowOf2
秘密系数还原，以及 ternary MVB；不为五种分布展开完整 PBS 矩阵。在线 `_to` 分配数为零。
验收通过 `just tfhe`、`just tfhe-simd`（各 56 项测试）、workspace all-target check，
以及更新后的 NTT/Fourier basic 示例；默认检查同时包含 Clippy 和文档构建。

#### T3 测量

常驻 `primus_tfhe_glwe_{ntt,fourier}/benches/ternary_pbs.rs` 固定 `u32, n=728, N=1024,
k=1, t=4`，只测 BR→KS 的普通单输出 PBS。NTT 使用 `q=132120577`；Fourier 使用 `q=2^32`，
分别运行 RustFFT / TFHE-FFT。BSK 为 `log B=8, ℓ=3`，KSK 为 `log B=2, ℓ=13`；
small LWE 噪声标准差为 `3.2*q/16384`，GLWE 为 6.4，accumulator secret 为 SparseTernary。
small secret 分别为 UniformBinary / UniformTernary，固定 seed `0x54335042`。
这些是算术成本配置，不表示等安全强度或等失败率，也不直接横比不同 q 的后端。

每次在线迭代处理一个输入，交替使用预先加密的 0/1 和同一个 `[1,0]` LUT，包含 BR、环 KS、
compact extraction。融合与双 CMUX 使用同一 ternary BSK/KSK/输入；双 CMUX 仅为 benchmark
参照，不增加生产执行策略。计时前检查实际输出；零分配由端到端测试覆盖。Keygen 单独测 BSK+KSK，复用
client、表及 generator，排除返回密钥的析构。每后端只有 3 个在线和 2 个 keygen 用例。

测量机器、CPU 2、nightly 与 T1/T2 相同；默认和 SIMD 均用同一工具链，串行执行，
1 s warm-up、3 s measurement、在线 20 samples、keygen 10 samples。数值和 95% 区间见
[CSV](benchmarks/tfhe-ternary-t3.csv)。

下表为完整 PBS 均值（ms）；降幅相对于同一配置的双 CMUX。

| 后端 / feature | Binary | Ternary 双 CMUX | Ternary 融合 | 融合降幅 |
| --- | ---: | ---: | ---: | ---: |
| ntt / default | 5.278 | 10.522 | 7.932 | 24.6% |
| ntt / simd | 5.020 | 10.092 | 7.750 | 23.2% |
| rustfft / default | 6.244 | 15.097 | 9.216 | 39.0% |
| rustfft / simd | 6.440 | 15.146 | 9.054 | 40.2% |
| tfhe_fft / default | 5.387 | 13.161 | 8.191 | 37.8% |
| tfhe_fft / simd | 5.273 | 13.088 | 8.248 | 37.0% |

| BSK+KSK 生成（ms） | 默认 binary / ternary | SIMD binary / ternary |
| --- | ---: | ---: |
| ntt | 48.73 / 98.76 | 48.56 / 98.34 |
| rustfft | 54.46 / 115.83 | 54.29 / 113.95 |
| tfhe_fft | 54.33 / 115.32 | 53.17 / 114.21 |

上述测量使用了分配计数器；常驻 benchmark 精简后移除该计数器及内存打印，保留解密预检。
密钥按有效元素 payload 计；evaluator 按当时构造的净分配请求字节数计，包含内部 BR/KS/GLWE/LWE
缓冲及 Fourier engine scratch，不含表、密钥、调用方输出、栈上元数据和 allocator 额外开销。
默认/SIMD 相同：

| 后端 | BSK binary → ternary（MiB） | KSK（KiB） | Evaluator binary → ternary（KiB） |
| --- | ---: | ---: | ---: |
| NTT | 34.125 → 68.250 | 104 | 60.848 → 112.848 |
| RustFFT / TFHE-FFT | 68.250 → 136.500 | 208 | 100.848 → 204.848 |

融合减少了双 CMUX 的完整在线成本，但仍比 binary 慢；BSK 翻倍，组合 GGSW 与单项式
工作区分别额外增加 NTT **52 KiB**、Fourier **104 KiB**。完整负载仍有收益，保留当前融合实现；
本轮未重新实现按行组合或直接 Fourier 单项式生成，不能据此宣称当前实现已达最优。

```sh
taskset -c 2 cargo +nightly bench -p primus_tfhe_glwe_ntt -p primus_tfhe_glwe_fourier --bench ternary_pbs -- --warm-up-time 1 --measurement-time 3 --sample-size 20 --save-baseline t3-default --noplot
taskset -c 2 cargo +nightly bench -p primus_tfhe_glwe_ntt -p primus_tfhe_glwe_fourier --bench ternary_pbs --features simd -- --warm-up-time 1 --measurement-time 3 --sample-size 20 --save-baseline t3-simd --noplot
```

## 7. 独立的后续工作

**NTRU ternary：** 同类恒等式可以作用于 NGSW 控制，但当前 client key 还必须是可逆 NTRU 多项式。Native、二次幂 `N` 下至少要求 `f(1)` 为奇数；固定偶数非零重量 ternary 不会因重试而满足该条件。[B7.1–B7.3](tfhe-ntru-ternary.md)已完成底层采样/拒绝条件、padding、条件分布说明及 NTT/Fourier NGSW 融合单步；完整链留给 B7.4，TFHE 仍限制 binary。

**桶聚合稀疏 ternary：** 可以研究复用 support matching，但正负选择密文、dummy、聚合规则和公开映射的联合分布需要重新分析。不把 `SecretKeyDistr::SparseTernary` 与 P3 的固定重量二元桶算法混同。

## 8. 证据边界

本机笔记与现有参数/key、BSK、NTT BR/CMUX/外积、单项式 NTT、Fourier 表契约已作定向核对。
T1/T2 覆盖单步独立 oracle、真实控制加密及单步性能；T3 覆盖完整 GLWE ternary PBS、
组合功能、在线分配和整把密钥访问下的性能。尚无完整噪声统计论证；功能成功、有限样本和
相同算术参数下的成本对照不构成生产失败率或等安全证明。
