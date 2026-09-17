# Ternary LWE secret 与融合盲旋转

本文记录算法选择、数学契约和实施进度。**T1 的 NTT 单步原语已实现；完整 ternary TFHE 支持尚未接入**。算法清单见 [后续候选](tfhe-next.md)，当前任务以 [HANDOFF](../HANDOFF.md) 为准。

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
- 现有 `iter_ntt_ggsw` / Fourier 迭代器隐含“一坐标一控制”；实施时迁移消费者，明确 binary 控制与 ternary 控制对的区别，不能仅把底层数组长度翻倍。

### NTT 首选实现

现有 [MonomialNttTable](../crates/primus_ntt/src/ntt/mod.rs) 已能直接生成 `NTT(X^-α)`，复用实际表顺序。控制密钥长期保存在 NTT 域，无须每轮 inverse NTT 再整体变回 NTT。

先实现容易验证的版本：

1. 在复用的 GLWE 缓冲中计算 `Y=(X^α-1)C`。
2. 生成一个单项式的 NTT 向量，对控制各多项式逐点计算 `K⁺-NTT(X^-α)·K⁻`，写入复用的 GGSW 缓冲。
3. 调用现有外积内核，只分解/变换一份 `Y`，得到增量后加回 `C`。

若完整 GGSW 临时缓冲的写读成本明显，再比较按 gadget row 组合并立即与 digit 相乘的实现。后者能减少 scratch，但增加外积内核复杂度；只有完整负载测量支持时才保留。不预先添加覆盖全部后端的控制策略 trait。

### Fourier 对应实现

组合仍可在 Fourier 域逐点完成，单项式因子必须是**整数尺度**，不能通过 torus 缩放生成。变换顺序依赖实际 `FftTable` 实例，不能硬编码另一张表的自然频率顺序。

当前没有与 `MonomialNttTable` 对应的直接单项式接口。原型可用现有 `forward_as_integer` 变换单个单项式，建立正确性和成本参照；再决定是否增加与表绑定的直接生成能力。避免为全部 `2N` 指数预存 `O(N²)` 张量，也避免每坐标重新变换完整 GGSW。最终选择取决于与双 CMUX 的实测对照。

### 成本预期与限制

令 GLWE 维数为 `k`、分解层数为 `ℓ`。每坐标两份控制，BSK 元素数由 binary 的 `nℓ(k+1)²N` 增至两倍；Fourier 按其半长复数布局另外统计实际字节数。

融合方案仍为每坐标一次外积，新增 `O(ℓ(k+1)²N)` 的控制组合工作。完整临时 GGSW 版本额外需要同阶 scratch 和一个单项式变换缓冲；按行融合可以降低临时存储。它省去的是第二次 GLWE 分解、digit 变换和外积调用中的相应工作，**不保证耗时等于 binary，也不保证比双 CMUX 快两倍**。

## 5. 当前代码的接入点

| 位置 | 要处理的契约 |
| --- | --- |
| [SecretKeyDistr](../crates/primus_distr/src/secret_key_distr.rs) 与 [LweSecretKey](../crates/primus_lwe/src/secret_key/owned.rs) | 已有 ternary 采样与模 `q` 剩余类存储，继续复用 |
| [GLWE TFHE 参数](../crates/primus_tfhe_glwe/src/parameters.rs) | 当前只接受 binary small-LWE；扩大接受范围时同步真实密钥、BSK/KSK 的兼容性 |
| [GLWE client key](../crates/primus_tfhe_glwe/src/key.rs) | padded ring secret 当前直接 `cast_to_signed`；显式模数下须将 `q-1` 还原为 `-1`，其余 padding 保持零 |
| [NTT BSK](../crates/primus_tfhe_glwe_ntt/src/bootstrapping_key.rs) / [Fourier BSK](../crates/primus_tfhe_glwe_fourier/src/bootstrapping_key.rs) | 按 ternary 系数生成互斥的两个加密 selector，明确布局与溢出边界 |
| [Ternary CMUX](../crates/primus_lattice/src/ggsw/ternary.rs) 与 [外积](../crates/primus_lattice/src/ggsw/external_product.rs) | T1 已增加 NTT 一次融合外积及对应 scratch；binary CMUX 仍只接收 bit 控制，Fourier 待 T2 |
| [NTT BR](../crates/primus_tfhe_glwe_ntt/src/blind_rotation.rs) / [Fourier BR](../crates/primus_tfhe_glwe_fourier/src/blind_rotation.rs) | 循环外分派，复用量化、初始化、buffer 交换与公开零指数跳过 |
| ServerKey / evaluator / CBS / MVB | 两种 order 都以 small-LWE 为 BR 秘密；迁移布局消费者并验证后处理，不能只放开参数枚举 |

Ternary 剩余类到有符号系数的转换在 key 构造/导入边界完成。仅需处理当前支持的 `0/1/q-1`，不为这个任务设计一般整数解码框架；也不能把明文 codec 的缩放解码用于秘密系数。

采样分布的支持范围与算法正确性分开：融合恒等式适用于 ternary 家族，但非对称、固定重量和固定正负计数不能套用 iid 对称分布的参数估计。BR→KS 与 KS→BR 中外部 LWE 秘密不同，public-key 加密和 signed view 沿用已有入口，并检查实际参数/秘密域。

## 6. 实施顺序与完成条件

以下按独立实施单元推进；T1 完成，T2/T3 尚未实施。

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

### T2：Fourier 单步原语

- 建立整数尺度、表实例及单项式频率布局的契约，对照系数域 oracle。
- 先测单多项式 FFT 原型，再按证据决定直接单项式生成；检查浮点误差与完整单步成本。
- T1/T2 只增加底层能力，不提前把尚未接入的 TFHE 参数声明为支持 ternary。

### T3：完整 GLWE 接入与验收

- 同步共享参数、client padded signed key、两后端 BSK、KSK、ServerKey 和 evaluator；保留 binary 路径。
- 验证两种 order、普通/交错 LUT、输入输出编码及公开密钥入口。覆盖 GLWE NTT 已有的 CBS 与 MVB 组合；若某组合尚未满足噪声/表示条件，须在拥有契约的公开入口明确拒绝，不能默默回退到 binary。
- 最少常驻测试：单步独立 oracle、模数相关的 `-1` 转换、聚焦端到端与在线零分配；复用现有表驱动测试，不新增“分布 × LUT × order × backend”全笛卡尔积。
- 用 `n=728` 作为与现有成本组衔接的测量起点，在各后端固定参数比较 binary、双 CMUX ternary 与融合 ternary。它是相同算术配置的成本比较，不表示三者安全强度或失败率自动相同。
- Criterion 的 setup、keygen、workspace 分配移出在线计时；keygen/key/scratch 另行报告。默认/SIMD 按实际支持分别测量；最终只保留有长期诊断价值的 benchmark，统计实验不进入普通 CI。
- 同步双语 README、示例、注释与 HANDOFF，明确已支持与尚未支持的组合。

## 7. 独立的后续工作

**NTRU ternary：** 同类恒等式可以作用于 NGSW 控制，但当前 client key 还必须是可逆 NTRU 多项式。Native、二次幂 `N` 下至少要求 `f(1)` 为奇数；固定偶数非零重量 ternary 不会因重试而满足该条件。须单独设计采样/拒绝条件、padding、密钥域和参数，再接入两路后端。

**桶聚合稀疏 ternary：** 可以研究复用 support matching，但正负选择密文、dummy、聚合规则和公开映射的联合分布需要重新分析。不把 `SecretKeyDistr::SparseTernary` 与 P3 的固定重量二元桶算法混同。

## 8. 证据边界

本机笔记与现有参数/key、BSK、NTT BR/CMUX/外积、单项式 NTT、Fourier 表契约已作定向核对。
T1 已有 NTT 单步实现、独立 oracle、真实控制加密验证和单步性能测量；尚无完整 ternary PBS、
Fourier 单步或完整噪声统计论证。单步性能不能代替 T3 的整把密钥访问和端到端测量。
