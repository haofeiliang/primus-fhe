# TFHE 后端算法覆盖与补齐路线

本文以 **`7f1ef55`（2026-09-18）** 为初始源码基线，比较四个执行后端及其共享层，并随 B 步骤更新接入状态。范围是算法流程、密钥与表示前提、已有组合测试和移植条件；不构成全 crate 缺陷审查或安全参数认证。本文不授权自动开始后续实现。

公开用法以 [TFHE README](../crates/primus_tfhe/README.zh_CN.md) 为准；新算法选型见[后续候选](tfhe-next.md)。这里集中回答：已有算法能移植到哪些后端，哪些组合尚需验证，哪些当前公式不能直接使用。

实施任务、依赖和验收标准见 [B1–B8 分步计划](tfhe-backend-plan.md)。

## 1. 结论

**GLWE 两后端的主要算法线已补齐。** 两者均支持经典 binary/ternary BR、固定重量二元稀疏 BR、两种 PBS order、Boolean、经典/稀疏 CBS 和分解式 MVB；NTT 对 sparse 上层组合的验收仍更全面。NTRU 两后端均支持经典 binary/ternary 的普通/交错 PBS、Boolean 和 CBS；`primus_tfhe_ntru_ntt` 另已接入奇数模数分解式 MVB。两族 Fourier 均已接入 Native 偶尺度 MVB；NTRU 初始化与 KS 已独立验收。

可以明确安排的工程补齐包括：

1. **GLWE Fourier 经典 CBS**：B1.1–B1.3 已完成完整链、误差/成本测量与使用示例，见 [CBS 专项](tfhe-cbs.md)。
2. **NTRU 两后端 Boolean 适配**：B2 已完成共享门算法、客户端/工厂，以及完整门真值表和串联验收。
3. **NTRU NTT 分解式 MVB**：B3.1–B3.2 已完成完整链、误差/相关性和成本验收，见 [NTRU MVB 测量](tfhe-mvb-ntru.md)。
4. **GLWE Fourier 固定重量二元稀疏 PBS**：B4 已完成共享映射、系数域桶聚合、完整求值及成本验收；低重量负载有收益，保留参考实现。

**Native 偶尺度 MVB** 已完成 GLWE/NTRU 正式接入及各自误差验收；**GLWE 两后端 sparse CBS 已正式接入**。**NTRU 两后端桶聚合普通/ManyLUT 已实验性接入**；仍需独立验证的组合包括 **NTRU sparse CBS/MVB**。其中有的代数已成立，但尚未建立完整的表示、采样或误差契约。不要把“尚未验证”写成“数学上不适配”，也不要把“有底层原语”写成“已有完整功能”。

## 2. 当前能力矩阵

下表的“支持”表示已有公开执行路径；具体组合是否有专门测试见第 5 节。

| 能力 | GLWE NTT | GLWE Fourier | NTRU NTT | NTRU Fourier |
| --- | --- | --- | --- | --- |
| 密文模数/表示 | 显式模数，精确 NTT | Native `2^w`，FFT | 显式模数，精确 NTT | Native `2^w`，FFT |
| 普通单输出 PBS | 支持 | 支持 | 支持 | 支持 |
| 交错 PBSManyLUT | 支持 | 支持 | 支持 | 支持 |
| 有界双输入 `x+B*y` | 支持 | 支持 | 支持 | 支持 |
| 奇数**明文**模数单输出全域 LUT | 支持 | 支持 | 支持 | 支持 |
| 私钥 / LWE 公钥客户端 | 支持 | 支持 | 支持 | 支持 |
| 经典 binary BR | 支持 | 支持 | 支持 | 支持 |
| 经典 ternary BR | 支持 | 支持 | 支持 | 支持 |
| 固定重量 binary 使用经典 BR | 支持 | 支持 | 需生成可逆客户端秘密 | 还受奇数重量/逆元稳定性限制 |
| 固定重量 binary 桶聚合 BR | 支持 | 支持，收益取决于重量/负载 | 实验性支持普通/ManyLUT | 实验性支持普通/ManyLUT，需奇数重量及稳定逆元 |
| Boolean 门、NOT、MUX | 支持 | 支持 | 支持 | 支持 |
| CBS | 经典 binary/ternary、稀疏 binary → GGSW | 经典 binary/ternary、稀疏 binary → Fourier GGSW | binary/ternary → NGSW | binary/ternary → NGSW |
| 固定尺度差分 MVB | 支持，含经典/稀疏 | 支持，偶尺度 u32/u64、经典/稀疏 | 支持，经典 binary/ternary | 支持，偶尺度 u32/u64、经典 binary/ternary |
| 两种 PBS order | 支持 BK / KB | 支持 BK / KB | 固定 NTRU 链 | 固定 NTRU 链 |

几个容易混淆的概念：

- **秘密分布与 BR 算法是两条轴。** `FixedHammingWeightBinary` 可使用逐坐标经典 BSK；只有专门的 sparse key 生成入口才选择桶聚合。`SparseTernary` 也只是一个 ternary 分布名称，不会自动使用桶聚合。
- **奇数明文全域与奇数密文模数不同。** Fourier 能执行奇数 `t_in` 的全域 LUT；MVB 仍采用前半域输入，输出/累加器须用奇数 `q`，或 Native 配偶尺度。
- **ManyLUT、MVB、CBS 的产物不同。** 前两者产生同一输入的多个 LWE 输出；CBS 产生 accumulator 秘密下的 GGSW/NGSW，供外积或 CMUX 使用。
- **有界双输入是 LWE 线性组合，不是 LWE→环密文 packing。** 通用 digit extraction、任意二次幂明文全域 FDFB 等也不能仅凭已有 LUT 就标为完成。

## 3. 实现算法的实质差异

### 3.1 GLWE 与 NTRU 的完整链

| 阶段 | GLWE | NTRU |
| --- | --- | --- |
| 外部秘密 | BK 为 small-LWE；KB 为 accumulator GLWE 的展平秘密 | 客户端 NTRU 秘密 `f_client` 的有效前缀，其余系数补零 |
| LUT 初始化 | 平凡 GLWE accumulator | 先用 `NLev_f_acc[1]` 对旋转后的公开 LUT 做外积，产生加密 accumulator |
| 旋转控制 | GGSW；ternary 为正负 selector 对 | NGSW；ternary 同样使用正负 selector 对 |
| BR 输出 | accumulator 秘密下 GLWE | `f_acc` 下 NTRU |
| 普通 PBS 后处理 | BK：环 KS→compact extraction；KB：直接 full extraction | NTRU KS 到 `f_client`→compact extraction |
| CBS 后处理 | 留在 accumulator 秘密下，projection→scheme switch→GGSW | 留在 `f_acc` 下，projection→scheme switch→NGSW |

BK=`BootstrapKeyswitch`，KB=`KeyswitchBootstrap`。GLWE KB 在 BR 前先做输入 KS 和 compact extraction，得到 small-LWE；NTRU 当前没有对应的第二种外部密钥域与链路，不应仅为 API 对齐添加一个无实际流程的 `PbsOrder`。

NTRU 移植 MVB 或稀疏 BR 时，必须计入 `NLev[1]` 初始化误差，不能直接套用 GLWE 的平凡初始化误差为零。两族当前完整 PBS 都要求输入、累加器和输出使用相同的密文模数。共享 raw LUT 和部分低层 BR 允许更宽的模数搭配，这不代表高层完整链已经支持跨模数 PBS。

源码入口：[GLWE NTT evaluator](../crates/primus_tfhe_glwe_ntt/src/evaluator.rs)、[GLWE Fourier evaluator](../crates/primus_tfhe_glwe_fourier/src/evaluator.rs)、[NTRU NTT BR](../crates/primus_tfhe_ntru_ntt/src/blind_rotation.rs)、[NTRU Fourier BR](../crates/primus_tfhe_ntru_fourier/src/blind_rotation.rs)。

### 3.2 NTT 与 Fourier

NTT 在可用的显式模数环内做精确变换；Fourier 用原生整数表示 torus，并在变换/乘法/逆变换中引入浮点误差。Fourier 的预处理材料、密钥和 evaluator 还必须遵循同一 FFT table 的布局约定。

两个区别直接决定移植方式：

- **逆 trace 的归一化不同。** NTT 在奇数模数下使用模逆元；Fourier 使用 native 系数代表元的逐级 `floor(x/2)`，包含绕回的负代表元。后者已有独立原语，但会增加舍入误差，不能只把 NTT 类型名替换成 Fourier。
- **公开整数因子与 torus 多项式的 FFT 尺度不同。** MVB 的 `W_i`、ternary 的单项式是整数乘数；必须按其小的有符号整数 lift 变换，不能把 residue 当作巨大正整数，也不能再套 torus 缩放。

依据：[Fourier GLWE trace](../crates/primus_glwe/src/trace/fourier_operations.rs)、[Fourier NTRU trace](../crates/primus_ntru/src/trace/fourier.rs)、[Fourier ternary 单项式](../crates/primus_lattice/src/macros/fourier_monomial.rs)。

### 3.3 多输出路径共享什么

| 算法 | 共享计算 | 每输出计算与主要限制 |
| --- | --- | --- |
| Interleaved ManyLUT | 一次 BR 和普通链中的 KS | 提取各槽位；`s=next_power_of_two(k)` 降低旋转分辨率 |
| 当前 factorized MVB | 对共同 `V` 做一次步长 1 的 BR | 乘公开 `W_i`；GLWE BK / NTRU 逐输出 KS，GLWE KB 直接提取；因子放大共享初始化/BR 噪声 |
| 当前 CBS | gadget-scale ManyLUT 的 BR | 投影各 gadget level，随后 scheme switch；最低尺度的噪声余量尤其重要 |

输出越多不一定应当选 MVB。它保留输入旋转分辨率，但后乘因子、逐输出 KS 和因子范数可能使其慢于或噪声大于交错 ManyLUT。既有选择和测量见 [MVB 专项](tfhe-mvb.md)。

## 4. 可明确安排的工程补齐

“可补”表示有清楚的现成代数与原语，不表示可以省略正确性、误差和性能验收。

### 4.1 GLWE Fourier 经典 CBS

**B1.1–B1.3 已完成。** [CBS 模块](../crates/primus_tfhe_glwe_fourier/src/circuit_bootstrap/mod.rs)提供参数、附加密钥与完整 evaluator，KeyGenerator/context 提供生成与求值入口。复用普通 evaluator 的前置 KS/BR 与 FFT 工作区，再接 `FourierGlweTraceKey::project_prefix_coefficients_to` 和 `FourierGlweSchemeSwitchKey::apply_to`。四后端的 CBS 均直接按 gadget 层数投影前缀，不保存连续索引数组。

阶段划分：

```text
必要的输入 KS → gadget-scale ManyLUT BR
→ 各层系数投影 → GLev → Fourier GGSW
```

[完整链测试](../crates/primus_tfhe_glwe_fourier/tests/circuit_bootstrap.rs)覆盖两种 order × RustFFT/TfheFFT × 经典 binary/ternary，检查每行、每层相位及 `CBS→CMUX`、输出覆盖和首次调用零分配；另检查资源兼容性与写入前形状校验。Sparse CBS 的后续独立验收见 §5.3。[B1.3 专项](tfhe-cbs.md)记录逐级整数除二、trace KS、scheme-switch 分解及 FFT 误差，以及 n=728 的成本、密钥/scratch 和最小尺度余量。

基础证据：[NTT CBS](../crates/primus_tfhe_glwe_ntt/src/circuit_bootstrap/evaluator.rs)、[Fourier projection](../crates/primus_glwe/src/trace/fourier_operations.rs)、[Fourier scheme switch](../crates/primus_glwe/src/scheme_switch/fourier.rs)。底层已有两种 FFT 的[trace 测试](../crates/primus_glwe/tests/trace_packing.rs)和[scheme-switch 测试](../crates/primus_glwe/tests/scheme_switch.rs)。

前缀接口沿用逐系数 reverse trace，投影 k 项需 `k*log2(N)` 次 automorphism。共享正向展开树按当前决定暂缓：它会改变归一化和误差传播，不能作为保持 RevHomTrace 数值行为的内部优化直接替换。

### 4.2 NTRU 两后端 Boolean

两后端已经实现 `ProgrammableBootstrap`，保留 raw LUT 的输出尺度，并返回原外部客户端秘密下的 LWE；可承载现有 Boolean 的仿射预处理、正负 LUT 和输出平移。

B2.1 已将 [BooleanEvaluator](../crates/primus_tfhe/src/boolean.rs) 移入 `primus_tfhe`，以维数、codec、环长度和模数绑定，GLWE/NTRU 共用同一份门算法。两族各自绑定参数与客户端错误，保留独立 `BooleanEncryptor` / `BooleanDecryptor` 和原始 `LweCiphertext`。四后端 context 均提供 Boolean 工厂；没有新增 BSK 方案或改变 NTRU KS 链。

外部 `t=4`、内部模 8 尺度已在 NTRU NTT、RustFFT/TfheFFT 验证：六种二元门、NOT、MUX 的完整真值表、混合门链、维数/参数错误、公钥代表输入和零分配复用均通过。四后端复用从 GLWE 提取的[共同用例](../test-support/tfhe/src/boolean.rs)，不复制纯门逻辑测试；小参数功能 fixture 不代替生产噪声尾界分析。

### 4.3 NTRU NTT 分解式 MVB

共享 [FactorizedLookupTable](../crates/primus_tfhe/src/lookup_table/factorized.rs) 产生奇数 `q` 下的 `V` 和 `W_i`。NTRU 密文乘公开多项式仍属于原秘密域：`phase_f(W*c)=W*phase_f(c)`。B3.1 已用 [NttNtru 多项式乘法](../crates/primus_lattice/src/ntru/ntt.rs)接通：

```text
用 NLev_f_acc[1] 初始化 V → BR 一次并保存
→ 每输出乘 W_i → 每输出 NTRU KS → compact LWE extraction
```

NTRU 的[预处理产物和独立 MVB evaluator](../crates/primus_tfhe_ntru_ntt/src/evaluator/factorized.rs)复用现有 BR/KS 工作区，只增加一个 NTT 多项式保存共享旋转结果。采用乘后逐输出 KS，使 KS 误差不再被 `W_i` 放大；共享一次 KS 是后续独立的成本/误差取舍。

[验收](../crates/primus_tfhe_ntru_ntt/tests/factorized_pbs.rs)覆盖与单输出 Scaled LUT 的对照、1/3/17 输出、超出交错容量、奇数尺度初始化、context/维数错误及零分配复用。[B3.2](tfhe-mvb-ntru.md)已完成 n=728 负载的默认/SIMD 计时、资源及分阶段误差诊断：因子放大初始化/BR 误差，各输出再加入 KS 误差；测得相关输出，不能套用独立噪声假设或 GLWE 数值。

### 4.4 GLWE Fourier 固定重量二元稀疏 PBS

桶聚合的线性关系不依赖奇数 `q` 或 `inv2`。B4.2 已接入以下参考路径：

```text
Native 系数域旋转并累加 selector GGSW 与 dummy
→ 将聚合 GGSW 转为 Fourier → 每桶一次外积
```

这条路径将聚合保持为精确的 native 整数运算，便于对照 NTT 实现。初版不直接改为频域逐项旋转累加，避免同时引入新的浮点累积和布局问题。

**B4.1 已完成**：[BucketMap/Matching](../crates/primus_tfhe/src/sparse.rs) 已移入共享层，保持采样次序、完整增广路匹配和八次重试不变。NTT 已迁移，Fourier 提供系数域 selector/dummy [密钥生成](../crates/primus_tfhe_glwe_fourier/src/sparse/key.rs)，两种 FFT 的加密选择语义已验证。BSK 表示与加密仍属于具体后端。B4.2 的[原始 BR](../crates/primus_tfhe_glwe_fourier/tests/sparse_blind_rotation.rs)通过整数相位参照，[完整 PBS](../crates/primus_tfhe_glwe_fourier/tests/sparse_pbs.rs)通过两种 order、普通/ManyLUT、两种 FFT 及零分配验收；性能取舍见 [B4.3](tfhe-sparse-pbs.md#b43-fourier-成本与保留方案)。

首批范围为 fixed-weight binary、普通/ManyLUT、两种 order、两种 FFT。代数接入有依据，但聚合变换、密钥带宽和浮点误差会影响实际价值，B4.3 在 n=728 的完整 PBS 上确认 h=32 有收益、h=128 的所测负载无收益，保留逐条目聚合；分块原型未显示一致改善。稀疏采样分布与安全边界继续遵循[稀疏专项](tfhe-sparse-pbs.md)，不能因换后端自动视为闭合。

## 5. 现有能力的组合缺口

### 5.1 GLWE NTT 已有明确测试资产的组合

| 组合 | 当前证据 |
| --- | --- |
| sparse × 普通/ManyLUT × 两种 order | [sparse_pbs.rs](../crates/primus_tfhe_glwe_ntt/tests/sparse_pbs.rs)：对照经典路径、解码/相位距离及零分配 |
| sparse × MVB × 两种 order | [factorized_pbs.rs](../crates/primus_tfhe_glwe_ntt/tests/factorized_pbs.rs)：1/3/17 输出，包括交错布局容量之外的情况 |
| sparse × Boolean/双输入/奇数全域 × 两种 order | [sparse_pbs.rs](../crates/primus_tfhe_glwe_ntt/tests/sparse_pbs.rs)：门链、受控输入误差、相位/解码与零分配，见 §5.2 |
| ternary × MVB × 两种 order | 同一 MVB 测试文件中的独立 ternary fixture |
| ternary / sparse binary × CBS × 两种 order | [circuit_bootstrap.rs](../crates/primus_tfhe_glwe_ntt/tests/circuit_bootstrap.rs)：逐行/层相位及 CMUX |
| ternary × 双输入/奇数全域 × 两种 order | [many_lut.rs](../crates/primus_tfhe_glwe_ntt/tests/many_lut.rs) |
| ternary × 公钥输入 × Boolean XOR × 两种 order | [context.rs](../crates/primus_tfhe_glwe_ntt/tests/context.rs)；完整门真值表另有 binary fixture |

GLWE Fourier 的 [many_lut.rs](../crates/primus_tfhe_glwe_fourier/tests/many_lut.rs) 已覆盖 ternary、两种 order、两种 FFT、交错/双输入/奇数全域。因此这些不属于该后端待补的算法。

### 5.2 已有 sparse 上层组合验收（B3.3 已完成）

**GLWE NTT sparse × Boolean / bivariate / odd-full** 已在两种 order 下通过聚焦端到端验证；沿用统一 evaluator 的 sparse BR 分派，未改变算法或新增类型。

两个小型 fixed-weight fixture 分别覆盖 Boolean 真值表/门链和共用密钥的双输入/奇数全域；受控输入偏移检查门预处理、`x+3*y` 放大及非整除编码差、全域折叠两侧和回绕。相位/解码和首调用零分配均验证，详见[参数与代表点](tfhe-sparse-pbs.md#b33-已有上层组合验收)。这些功能样本不提供生产失败概率结论。

### 5.3 稀疏 CBS：先验证，不能只取消检查

GLWE [NTT](../crates/primus_tfhe_glwe_ntt/src/circuit_bootstrap/evaluator.rs) 已在 B6.2 正式绑定经典/稀疏 CBS，复用普通 evaluator 的 BR 工作区及相同后处理。[Fourier](../crates/primus_tfhe_glwe_fourier/src/circuit_bootstrap/evaluator.rs) 在 B6.3 通过聚合 FFT 与逐级 Native halving 的独立验证后，也已接入同一工作流。

**B6.1 已通过**：[原型记录](tfhe-sparse-cbs.md)在同一 fixed-weight client 下对照经典/稀疏 BR，验证桶内加密零/dummy 的噪声合成、逐行/层相位、独立整数卷积和非恒定 CMUX。u64、n=728、N=1024、两种 order 的 BR `(10,4/5)` 与输出 `(8,3)` 满足本组余量，默认/SIMD 结果一致；更小 gadget 尺度不纳入通过配置。材料、工作区及成本已记录，临时原型已清理。B6.2 的正式测试保留两种 order、逐行/层相位、非恒定 CMUX、错误边界和零分配；大参数诊断置于现有 CBS benchmark 的 setup，避免增加 CI 统计负担。

**B6.3 已通过**：[Fourier 验收](tfhe-cbs.md#7-b63-fourier-sparse-cbs)覆盖两种 FFT/order、逐级除二与 trace KS 的独立诊断、最小 gadget 尺度、非恒定 CMUX 及首调用零分配；u64 输出 `(8,3)` 通过，`(9,3)` 仍受余量限制。正式入口复用原后处理，保持 NTT/Fourier 表示契约的区别。

### 5.4 Native 偶尺度 MVB：GLWE/NTRU Fourier 的共同前置工作

当前分解是 `W_i=(1-X)p_i`、`V=A*(1+...+X^(N-1))`，要求 `2A=Delta mod q`。

- 奇数 `q`：现有代码用 `A=Delta*inv2 mod q`。
- Native `q=2^w`、**偶数 `Delta`**：可用整数 `A=Delta/2`，恒等式仍成立。
- Native、**奇数 `Delta`**：无解。例 `q=256,t_out=3` 的合法 Scaled 尺度为 85，向下除二将输出尺度错误地改为 84。

因此不应将“Native 不支持 MVB”作为结论。正确的首个候选是 **Native 偶尺度的同一分解**。检查实际 `Delta`，不必为了实现方便要求所有 `t_out` 都是二次幂。

**B5.1 已通过**：独立整数负循环卷积核对了 `V*W_i=Delta*p_i`；复用整数 FFT 与公开乘法，完成两种 FFT、u32/u64、`n=728,N=1024` 经典 binary BK 三输出原型。`t_out=8/10` 成功，奇尺度 `t_out=3` 拒绝；分离了 BR、公开乘法与 KS 误差，并记录默认/SIMD 诊断和两轮默认成本，见 [Fourier MVB 专项](tfhe-mvb-fourier.md)。本组 GLWE 原型不覆盖 NTRU 加密初始化和逐输出 KS；后者由 B5.3 独立验证。

**B5.2 已接入 GLWE Fourier**：共享构造器接受 Native 偶尺度，整数 Fourier 因子与 evaluator 支持两种 order、经典 binary/ternary、u32/u64；context 绑定、首调用零分配和错误边界已验收。不从本组小整数因子推断任意 u64 参数可用。详细推导见 [MVB 的除二边界](tfhe-mvb.md#12-的边界)。

**B5.3 已接入 NTRU Fourier**：两种 FFT、u32/u64 使用原 NLev 初始化和 binary BR，逐输出 KS/提取；因子准备绑定 context，首调用零分配。`n=728,N=1024` 的独立整数卷积诊断分离初始化、BR、FFT 乘法和 KS 误差，见 [NTRU 验收](tfhe-mvb-fourier.md#b53ntru-接入与独立误差验收)。组合及跨算法成本见 [B5.4](tfhe-mvb-fourier-costs.md)。

**B5.4 组合已通过**：GLWE Fourier sparse×MVB 覆盖两种 order、两种 FFT、u32/u64，默认/SIMD 全前半域诊断正确且在线零分配；两族 Fourier 的 3/17 阈值输出、资源、误差和算法选择见[成本验收](tfhe-mvb-fourier-costs.md)。

### 5.5 NTRU ternary：控制代数与秘密采样分别处理

GLWE 已使用的融合恒等式也能作用于 NGSW 控制：

```text
ACC += (NGSW(s+) - X^(-a) NGSW(s-)) ⊠ ((X^a-1) ACC)
```

NTT/Fourier NGSW 已具备 B7.2/B7.3 的 ternary 融合单步和工作区。Fourier 组合 helper 与 GGSW 共用实现，保持整数单项式变换与同一 FFT table 的契约；B7.4 已接入成对 selector 的 key 布局、BR 分派及完整 PBS/上层组合。

关键前置条件是 **`f_client` 本身必须可逆**，且 active prefix/padding 与外部 LWE 密钥一致。底层 `generate_padded_pair` 与高层参数、导入 key 及控制内核已支持 binary/ternary；生成仍遵循各后端接受条件：

- NTT 必须验证候选秘密在所选环内可逆。
- Native、`N=2^k` 下，`f(1)` 必须为奇数；固定 ternary 非零总数 `h_+ + h_-` 为偶数时必不可逆。Fourier 还检查逆元数值稳定性。
- 采样、拒绝条件、实际条件分布和安全估计必须一致；普通 PBS 通过后，再覆盖公钥输入、ManyLUT 和 CBS。

完整接入已完成，含普通/ManyLUT、公钥、Boolean、CBS 与 MVB 的代表组合。实际条件分布、固定重量拒绝、误差、完整 PBS 和资源成本见 [B7 专项](tfhe-ntru-ternary.md)。

依据：[NTRU 参数限制](../crates/primus_tfhe_ntru/src/parameters.rs)、[Native 可逆性检查](../crates/primus_ntru/src/secret_key/fourier/mod.rs)、[NTT NGSW 单项式](../crates/primus_lattice/src/ngsw/ntt.rs)、[ternary 后续工作](tfhe-ternary.md#7-独立的后续工作)。

### 5.6 NTRU 桶聚合：独立方案移植

NGSW 同样可加密桶内 selector 并形成单项式控制，但现成 GLWE sparse key 的类型、初始化和秘密分布不能直接复制。B8 已独立验证 NTRU 的固定重量 binary 可逆采样，并连接 NLev 初始化、NGSW 聚合外积及 NTRU KS。

Native 二元固定重量 `h` 为偶数时 `f(1)` 为偶数，重试不能解决；应在参数边界明确拒绝这种组合。奇数重量通过该代数条件，也仍需满足 Fourier 稳定性与所选分布的安全要求。NTT 没有同一条模 2 障碍，但仍须拒绝不可逆候选。

**B8.1–B8.2 NTT 完整链已验收**：复用可逆前缀采样和共享 `BucketMap`，专用系数 NGSW 控制接入原有 `ServerKey` 与普通/ManyLUT evaluator。独立行相位、初始化/单桶预算、完整旋转/KS 相位及零分配通过。n=728 默认/SIMD 对照中，在线快约 39%–67%，server keygen 约为经典的 3.20–3.31 倍，key 约大 3.08 倍，保持显式选择。[专项](tfhe-ntru-sparse.md)记录采样的两次条件化和完整成本，不继承 GLWE 的秘密分布或安全结论。sparse CBS/MVB 明确拒绝。低重量秘密使用经典 BR 仍是独立选择。

**B8.3 Fourier 已接入**：显式采用奇数重量并保留逆元筛选，系数 NGSW 聚合接入同一高层入口。两 FFT、u32/u64 的独立相位、聚合/外积数值偏差、完整链和零分配通过。n=728、h=33 下 u32 在线快约 65%–71%；u64 RustFFT 有小幅收益，TfheFFT 无稳定收益。keygen 约为经典的 3.47–3.67 倍，key 为 u32 约 1.54 倍、u64 约 3.09 倍，保持显式选择；详见[独立误差与成本](tfhe-ntru-sparse.md#8-b83-fourier-接入与独立验收)。两后端都尚未验证 sparse CBS/MVB，且未认证完整尾界或安全参数。

## 6. 当前不适配与有意保留的边界

| 组合/要求 | 判断与处理 |
| --- | --- |
| Native 奇数 `Delta` 直接使用当前共同因子 | `2A=Delta` 无解；改变输出编码或另选 MVB 分解，不用 floor-half 冒充原尺度 |
| Native NTRU binary/ternary 固定偶数非零重量秘密 | 非零系数均为 ±1，系数和为偶数，在当前二次幂环内不可逆；拒绝该参数组合，不能增加重试次数解决 |
| 当前 binary 桶聚合直接接受 ternary | selector 只表达一个正向单项式或 dummy；正负选择与匹配/误差需另设计，不能只扩大 enum |
| 当前经典 binary/ternary 控制直接接受 Gaussian BR 秘密 | 控制代数不覆盖任意整数；需要另一种 BR 方案，不是参数校验放宽 |
| 当前 factorized 编译器接奇数全域、任意 Rounded 输出或 CBS gadget 输出 | 尚无对应编译契约；需要独立推导和布局/噪声验证，不自动继承普通 LUT 支持 |
| 给 NTRU 增加 GLWE 的两种 order | 当前固定外部秘密与 NTRU KS 链没有对应第二条流程；除非有新链路需求，不做 API 填空 |
| NTRU packing | 用户已排除该方向，保持范围边界；不将其列为本轮待补缺口 |
| Automorphism BR | 四后端均未接入，按既有决定暂缓；trace 内部使用 automorphism 不等于支持 automorphism BR |

Full-domain FDFB、通用数字拆分、HLUT/LFBS、multi-bit 等属于[新算法候选](tfhe-next.md)，应单独选型；不以 GLWE NTT 为模板就能机械补全四后端。

## 7. 建议执行顺序与验收规模

1. **先整理高层接口，再补明确缺口**：B1 的 GLWE Fourier 经典 CBS、四后端高层接口与成本验收，以及 B2 的 NTRU Boolean 接入与门语义验收均已完成。此顺序减少重复迁移，Boolean 算法本身不依赖 CBS；后续按[分步计划](tfhe-backend-plan.md)推进。
2. **再扩展已有多输出路线**：NTRU NTT MVB 完整链、误差和成本，以及 GLWE NTT sparse×Boolean/bivariate/odd-full 的组合验收均已完成。
3. **处理性能型移植与受限表示**：GLWE Fourier sparse PBS 参考路径及 B4.3 成本验收已完成；Native 偶尺度 MVB 的 GLWE/NTRU 接入与独立误差验收已完成，B5.4 记录 sparse 组合与算法成本，不混入频域聚合等额外优化。
4. **按实际应用选择实验组合**：NTRU sparse；先验证其采样与聚合前置，再组合到其他上层功能。

测试按独立契约选择代表点，不展开所有秘密分布×order×输出数×FFT×codec 的完整笛卡尔积。建议：

- LUT 编译继续依赖共享几何测试；新后端只补端到端表示/秘密域和输出尺度验证。
- Fourier 新路径覆盖两种 FFT；至少一个路径覆盖负整数因子或负 selector。
- 新增 CBS 检查逐行/层相位及 CMUX；新增 MVB 检查 Scaled 输出和因子乘法 oracle。
- 在线路径复用同一 evaluator、scratch 和输出，检查覆盖写入、跨调用缓冲区状态及零额外分配。
- 参数探索/噪声统计与常规测试分离。基准复用现有工作负载，只为新决策增加必要 case；性能收益由同参数完整流程确认。

不要先引入统一所有后端的万能 trait。`primus_tfhe` 保留 LUT/编码与完整 PBS 契约；两族共享层负责客户端与参数；NTT/Fourier 保留各自预处理、工作区和数值约束。Boolean 算法已由两族共享；纯桶匹配组件仍等第二个实际消费者出现后再提取。

## 8. 本次分析的证据与验证边界

初始分析按功能链定向核对：四后端入口、参数/key、经典 BR 与普通/交错 evaluator；GLWE NTT sparse/CBS/MVB；当时三套已实现的 CBS；共享 LUT、Boolean、相关 trace/scheme-switch、NTRU 可逆性和多项式乘法契约，以及第 5 节列出的代表测试。源码与依赖原语按算法问题读取，未做四个 crate 的逐文件完整审查。

本次未修改 Rust 实现，也未重跑完整数值测试或性能基准。表中的“已有测试”是对仓库测试内容的核查，不是本轮测试通过声明。

另做了独立整数负循环卷积核对：`q∈{256,65536}`、`N∈{4,8,16}`、`t_out∈{2,4,8,16}`，每组 7 个确定性多项式 `p[j]=((seed+3)j+seed) mod t_out`，共 168 例满足偶尺度恒等式；穷举确认 `2A=85 mod 256` 无解。它仅佐证分解代数，不验证 FFT、完整 PBS 噪声或参数安全性。

已检查本文及索引的本地链接和最终差异。后续实现应更新本文件相应的状态与证据，不追加与当前能力相冲突的历史结论。
