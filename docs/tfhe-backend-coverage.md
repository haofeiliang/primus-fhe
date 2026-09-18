# TFHE 后端算法覆盖与补齐路线

本文以 **`7f1ef55`（2026-09-18）** 为初始源码基线，比较四个执行后端及其共享层，并随 B 步骤更新接入状态。范围是算法流程、密钥与表示前提、已有组合测试和移植条件；不构成全 crate 缺陷审查或安全参数认证。本文不授权自动开始后续实现。

公开用法以 [TFHE README](../crates/primus_tfhe/README.zh_CN.md) 为准；新算法选型见[后续候选](tfhe-next.md)。这里集中回答：已有算法能移植到哪些后端，哪些组合尚需验证，哪些当前公式不能直接使用。

实施任务、依赖和验收标准见 [B1–B8 分步计划](tfhe-backend-plan.md)。

## 1. 结论

**当前最全面的是 `primus_tfhe_glwe_ntt`。** 它同时支持经典 binary/ternary BR、固定重量二元稀疏 BR、两种 PBS order、Boolean、CBS 和分解式 MVB。`primus_tfhe_ntru_ntt` 与 `primus_tfhe_ntru_fourier` 的高层算法基本对齐，主要区别在模数、变换和误差处理。

可以明确安排的工程补齐包括：

1. **GLWE Fourier 经典 CBS**：所需 trace projection 和 scheme-switch 原语已经存在。
2. **NTRU 两后端 Boolean 适配**：现有完整 LWE→LWE PBS 能承载同一套门运算。
3. **NTRU NTT 分解式 MVB**：现有奇数模数分解、NTRU 公开多项式乘法、KS 和提取足以组成流程。
4. **GLWE Fourier 固定重量二元稀疏 PBS**：桶聚合代数可迁移，先实现系数域聚合的参考路径；收益须独立测量。

优先做原型的组合是 **Native 偶尺度 MVB、稀疏 CBS、NTRU ternary 与 NTRU 桶聚合**。其中有的代数已成立，但尚未建立完整的表示、采样或误差契约。不要把“尚未验证”写成“数学上不适配”，也不要把“有底层原语”写成“已有完整功能”。

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
| 经典 ternary BR | 支持 | 支持 | 未接入 | 未接入 |
| 固定重量 binary 使用经典 BR | 支持 | 支持 | 需生成可逆客户端秘密 | 还受奇数重量/逆元稳定性限制 |
| 固定重量 binary 桶聚合 BR | 支持 | 未接入 | 未接入 | 未接入 |
| Boolean 门、NOT、MUX | 支持 | 支持 | 未接入 | 未接入 |
| CBS | 经典 binary/ternary → GGSW | 参数/附加密钥已接入；evaluator 待 B1.2 | binary → NGSW | binary → NGSW |
| 固定尺度差分 MVB | 支持，含经典/稀疏 | 未接入 | 未接入 | 未接入 |
| 两种 PBS order | 支持 BK / KB | 支持 BK / KB | 固定 NTRU 链 | 固定 NTRU 链 |

几个容易混淆的概念：

- **秘密分布与 BR 算法是两条轴。** `FixedHammingWeightBinary` 可使用逐坐标经典 BSK；只有专门的 sparse key 生成入口才选择桶聚合。`SparseTernary` 也只是一个 ternary 分布名称，不会自动使用桶聚合。
- **奇数明文全域与奇数密文模数不同。** Fourier 能执行奇数 `t_in` 的全域 LUT；当前 MVB 限制的是输出/累加器的 `q`。
- **ManyLUT、MVB、CBS 的产物不同。** 前两者产生同一输入的多个 LWE 输出；CBS 产生 accumulator 秘密下的 GGSW/NGSW，供外积或 CMUX 使用。
- **有界双输入是 LWE 线性组合，不是 LWE→环密文 packing。** 通用 digit extraction、任意二次幂明文全域 FDFB 等也不能仅凭已有 LUT 就标为完成。

## 3. 实现算法的实质差异

### 3.1 GLWE 与 NTRU 的完整链

| 阶段 | GLWE | NTRU |
| --- | --- | --- |
| 外部秘密 | BK 为 small-LWE；KB 为 accumulator GLWE 的展平秘密 | 客户端 NTRU 秘密 `f_client` 的有效前缀，其余系数补零 |
| LUT 初始化 | 平凡 GLWE accumulator | 先用 `NLev_f_acc[1]` 对旋转后的公开 LUT 做外积，产生加密 accumulator |
| 旋转控制 | GGSW；ternary 为正负 selector 对 | 当前 NGSW binary 单控制 |
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

依据：[Fourier GLWE trace](../crates/primus_glwe/src/trace/fourier_operations.rs)、[Fourier NTRU trace](../crates/primus_ntru/src/trace/fourier.rs)、[Fourier ternary 单项式](../crates/primus_lattice/src/ggsw/fourier.rs)。

### 3.3 多输出路径共享什么

| 算法 | 共享计算 | 每输出计算与主要限制 |
| --- | --- | --- |
| Interleaved ManyLUT | 一次 BR 和普通链中的 KS | 提取各槽位；`s=next_power_of_two(k)` 降低旋转分辨率 |
| 当前 factorized MVB | 对共同 `V` 做一次步长 1 的 BR | 乘公开 `W_i`；GLWE BK 逐输出 KS，KB 直接提取；因子放大共享 BR 噪声 |
| 当前 CBS | gadget-scale ManyLUT 的 BR | 投影各 gadget level，随后 scheme switch；最低尺度的噪声余量尤其重要 |

输出越多不一定应当选 MVB。它保留输入旋转分辨率，但后乘因子、逐输出 KS 和因子范数可能使其慢于或噪声大于交错 ManyLUT。既有选择和测量见 [MVB 专项](tfhe-mvb.md)。

## 4. 可明确安排的工程补齐

“可补”表示有清楚的现成代数与原语，不表示可以省略正确性、误差和性能验收。

### 4.1 GLWE Fourier 经典 CBS

已有完整前半段经典 BR/ManyLUT，以及 `FourierGlweTraceKey::project_coefficients_to`、`FourierGlweSchemeSwitchKey::apply_to`。B1.1 已补齐 [CBS 参数与附加密钥](../crates/primus_tfhe_glwe_fourier/src/circuit_bootstrap/mod.rs)，提供 KeyGenerator/context 生成入口；[材料集成测试](../crates/primus_tfhe_glwe_fourier/tests/circuit_bootstrap.rs)已在两种 FFT 下串联投影与 scheme switch，并检查每行、每层相位。完整 evaluator 与在线工作区留给 B1.2。

建议沿用 NTT CBS 的阶段划分：

```text
必要的输入 KS → gadget-scale ManyLUT BR
→ 各层系数投影 → GLev → Fourier GGSW
```

先完成经典 binary，再覆盖已存在的经典 ternary 和两种 order。不顺带开放 sparse CBS。验收检查每行、每层输出相位及 `CBS→CMUX`；同时覆盖 RustFFT/TfheFFT、工作区复用和零在线分配。预算包含逐级整数除二、trace KS、scheme-switch 分解及 FFT 误差。

基础证据：[NTT CBS](../crates/primus_tfhe_glwe_ntt/src/circuit_bootstrap/evaluator.rs)、[Fourier projection](../crates/primus_glwe/src/trace/fourier_operations.rs)、[Fourier scheme switch](../crates/primus_glwe/src/scheme_switch/fourier.rs)。底层已有两种 FFT 的[trace 测试](../crates/primus_glwe/tests/trace_packing.rs)和[scheme-switch 测试](../crates/primus_glwe/tests/scheme_switch.rs)。

### 4.2 NTRU 两后端 Boolean

两后端已经实现 `ProgrammableBootstrap`，保留 raw LUT 的输出尺度，并返回原外部客户端秘密下的 LWE；可承载现有 Boolean 的仿射预处理、正负 LUT 和输出平移。

当前障碍是 [BooleanEvaluator](../crates/primus_tfhe_glwe/src/boolean/evaluator.rs) 的构造器与 LUT helper 绑定了 GLWE 参数，而非门算法需要 GLWE。出现 NTRU 消费者时可将真正共用的门求值与 LUT 构造部分下移 `primus_tfhe`；两族仍负责自己的参数和客户端绑定。保留独立 `BooleanEncryptor` / `BooleanDecryptor`，使用现有 `LweCiphertext`。

以 `t=4`、既有内部模 8 尺度为首批契约；验证六种二元门、NOT、MUX、私钥/公钥输入和串联后的编码。无需新增 BSK 方案或改变 NTRU KS 链。

### 4.3 NTRU NTT 分解式 MVB

共享 [FactorizedLookupTable](../crates/primus_tfhe/src/lookup_table/factorized.rs) 已能产生奇数 `q` 下的 `V` 和 `W_i`。NTRU 密文乘公开多项式仍属于原秘密域：`phase_f(W*c)=W*phase_f(c)`。已有 [NttNtru 多项式乘法](../crates/primus_lattice/src/ntru/ntt.rs)足以支持：

```text
用 NLev_f_acc[1] 初始化 V → BR 一次并保存
→ 每输出乘 W_i → 每输出 NTRU KS → compact LWE extraction
```

需要增加 NTRU 的预处理产物和独立 MVB evaluator，复用现有 BR/KS 工作区契约。首批采用乘后逐输出 KS，使 KS 误差不再被 `W_i` 放大；共享一次 KS 是后续独立的成本/误差取舍。

验收包含与单输出 Scaled LUT 的差分、多个输入/输出数、超出交错布局容量的输出数量、复用输出与分配检查。预算为因子放大的初始化/BR 误差，再加各输出的 KS 误差；不能照搬 GLWE fixture 或声称等安全参数。

### 4.4 GLWE Fourier 固定重量二元稀疏 PBS

桶聚合的线性关系不依赖奇数 `q` 或 `inv2`。可以先采用：

```text
Native 系数域旋转并累加 selector GGSW 与 dummy
→ 将聚合 GGSW 转为 Fourier → 每桶一次外积
```

这条路径将聚合保持为精确的 native 整数运算，便于对照 NTT 实现。初版不直接改为频域逐项旋转累加，避免同时引入新的浮点累积和布局问题。

[BucketMap/Matching](../crates/primus_tfhe_glwe_ntt/src/sparse/pbc.rs) 当前在 NTT 私有模块中，并未共享。第二个消费者出现时，可提取纯索引映射、匹配及其必要错误信息；密钥布局、聚合表示和外积执行仍留在各后端。

首批范围为 fixed-weight binary、普通/ManyLUT、两种 order、两种 FFT。代数接入有依据，但聚合变换、密钥带宽和浮点误差会影响实际价值，必须测完整 PBS 后再决定优化路径。稀疏采样分布与安全边界继续遵循[稀疏专项](tfhe-sparse-pbs.md)，不能因换后端自动视为闭合。

## 5. 现有能力的组合缺口

### 5.1 GLWE NTT 已有明确测试资产的组合

| 组合 | 当前证据 |
| --- | --- |
| sparse × 普通/ManyLUT × 两种 order | [sparse_pbs.rs](../crates/primus_tfhe_glwe_ntt/tests/sparse_pbs.rs)：对照经典路径、解码/相位距离及零分配 |
| sparse × MVB × 两种 order | [factorized_pbs.rs](../crates/primus_tfhe_glwe_ntt/tests/factorized_pbs.rs)：1/3/17 输出，包括交错布局容量之外的情况 |
| ternary × MVB × 两种 order | 同一 MVB 测试文件中的独立 ternary fixture |
| ternary × CBS × 两种 order | [circuit_bootstrap.rs](../crates/primus_tfhe_glwe_ntt/tests/circuit_bootstrap.rs)：逐行/层相位及 CMUX |
| ternary × 双输入/奇数全域 × 两种 order | [many_lut.rs](../crates/primus_tfhe_glwe_ntt/tests/many_lut.rs) |
| ternary × 公钥输入 × Boolean XOR × 两种 order | [context.rs](../crates/primus_tfhe_glwe_ntt/tests/context.rs)；完整门真值表另有 binary fixture |

GLWE Fourier 的 [many_lut.rs](../crates/primus_tfhe_glwe_fourier/tests/many_lut.rs) 已覆盖 ternary、两种 order、两种 FFT、交错/双输入/奇数全域。因此这些不属于该后端待补的算法。

### 5.2 已有执行路径兼容，宜补少量组合验证

**GLWE NTT sparse × Boolean / bivariate / odd-full**：统一 evaluator 可以分派到 sparse BR；这些上层操作最终使用已有普通 LUT。当前定向检索未找到三者各自的专门 sparse 端到端测试。

这里优先补聚焦的组合验收，不引入新算法或复制整套测试矩阵。分别覆盖门预处理误差、`x+B*y` 的噪声放大、奇数全域较窄的旋转区间；可以复用同一把固定重量密钥及 evaluator。

### 5.3 稀疏 CBS：先验证，不能只取消检查

GLWE NTT 的 [CBS 构造器](../crates/primus_tfhe_glwe_ntt/src/circuit_bootstrap/evaluator.rs) 当前明确返回 `UnsupportedSparseBootstrapping`，原因是 sparse BR 与 gadget-scale 输出的噪声组合尚未验证。它不是 NTT 或稀疏代数本身不适配 CBS。

先在 NTT 上做小原型：同一 fixed-weight client 对照经典/稀疏 BR，检查每个 gadget level 经 projection/scheme switch 后的相位以及 CMUX 余量。特别计入桶内所有加密零和 dummy 的噪声，以及最小输出尺度。通过后才修改高层支持范围；Fourier sparse CBS 还要等其稀疏 BR 和经典 CBS 分别完成。

### 5.4 Native 偶尺度 MVB：GLWE/NTRU Fourier 的共同前置工作

当前分解是 `W_i=(1-X)p_i`、`V=A*(1+...+X^(N-1))`，要求 `2A=Delta mod q`。

- 奇数 `q`：现有代码用 `A=Delta*inv2 mod q`。
- Native `q=2^w`、**偶数 `Delta`**：可用整数 `A=Delta/2`，恒等式仍成立。
- Native、**奇数 `Delta`**：无解。例 `q=256,t_out=3` 的合法 Scaled 尺度为 85，向下除二将输出尺度错误地改为 84。

因此不应将“Native 不支持 MVB”作为结论。正确的首个候选是 **Native 偶尺度的同一分解**。检查实际 `Delta`，不必为了实现方便要求所有 `t_out` 都是二次幂。

原型分两层：先用独立整数负循环卷积验证 `V*W_i=Delta*p_i`；再实现小整数因子的 FFT 乘法，核对有符号 lift、变换尺度、完整输出误差和成本。先以 GLWE Fourier 的现有经典 BR 为参照，再接 NTRU 的加密初始化和逐输出 KS。两者不能共享未经核对的噪声参数。

当前公共构造器仍拒绝 Native；只有原型通过后才扩展其显式契约。详细推导见 [MVB 的除二边界](tfhe-mvb.md#12-的边界)。

### 5.5 NTRU ternary：控制代数与秘密采样分别处理

GLWE 已使用的融合恒等式也能作用于 NGSW 控制：

```text
ACC += (NGSW(s+) - X^(-a) NGSW(s-)) ⊠ ((X^a-1) ACC)
```

NTT NGSW 已有变换域单项式操作；仍需补专用 ternary CMUX/workspace、两份 selector 的 key 布局及 BR 分派。Fourier 还缺对应 NGSW 融合 helper，应沿用整数单项式变换与同一 FFT table 的契约。

关键前置条件是 **`f_client` 本身必须可逆**，且 active prefix/padding 与外部 LWE 密钥一致。当前 TFHE 参数和 padded key generator 只接受 binary，不能仅删除参数检查：

- NTT 必须验证候选秘密在所选环内可逆。
- Native、`N=2^k` 下，`f(1)` 必须为奇数；固定 ternary 非零总数 `h_+ + h_-` 为偶数时必不可逆。Fourier 还检查逆元数值稳定性。
- 采样、拒绝条件、实际条件分布和安全估计必须一致；普通 PBS 通过后，再覆盖公钥输入、ManyLUT 和 CBS。

依据：[NTRU 参数限制](../crates/primus_tfhe_ntru/src/parameters.rs)、[Native 可逆性检查](../crates/primus_ntru/src/secret_key/fourier/mod.rs)、[NTT NGSW 单项式](../crates/primus_lattice/src/ngsw/ntt.rs)、[ternary 后续工作](tfhe-ternary.md#7-独立的后续工作)。

### 5.6 NTRU 桶聚合：独立方案移植

NGSW 同样可加密桶内 selector 并形成单项式控制，但现成 GLWE sparse key 的类型、初始化和秘密分布不能直接复制。应先验证 NTRU 的固定重量 binary 可逆采样，再连接 NLev 初始化、NGSW 聚合外积及 NTRU KS。

Native 二元固定重量 `h` 为偶数时 `f(1)` 为偶数，重试不能解决；应在参数边界明确拒绝这种组合。奇数重量通过该代数条件，也仍需满足 Fourier 稳定性与所选分布的安全要求。NTT 没有同一条模 2 障碍，但仍须拒绝不可逆候选。

先做 NTRU NTT 的单步/完整链原型，以较少的表示变量隔离问题，再考虑 Fourier。桶映射条件分布、聚合噪声、初始化误差、内存与完整 PBS 成本都需独立核对。**低重量秘密使用经典 BR 已可表达，不等于桶聚合后端已经实现。**

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

1. **先补高层明确缺口**：GLWE Fourier 经典 CBS；NTRU Boolean。两者可独立实施。
2. **再扩展已有多输出路线**：NTRU NTT MVB；同步补 GLWE NTT sparse×Boolean/bivariate/odd-full 的小型组合验证。
3. **处理性能型移植与受限表示**：GLWE Fourier sparse PBS、Native 偶尺度 MVB。先完成参考路径，再测收益，避免一次混入频域聚合等额外优化。
4. **按实际应用选择实验组合**：NTT sparse CBS、NTRU ternary、NTRU sparse；分别通过前置条件后，再组合到其他上层功能。

测试按独立契约选择代表点，不展开所有秘密分布×order×输出数×FFT×codec 的完整笛卡尔积。建议：

- LUT 编译继续依赖共享几何测试；新后端只补端到端表示/秘密域和输出尺度验证。
- Fourier 新路径覆盖两种 FFT；至少一个路径覆盖负整数因子或负 selector。
- 新增 CBS 检查逐行/层相位及 CMUX；新增 MVB 检查 Scaled 输出和因子乘法 oracle。
- 在线路径复用同一 evaluator、scratch 和输出，检查覆盖写入、跨调用缓冲区状态及零额外分配。
- 参数探索/噪声统计与常规测试分离。基准复用现有工作负载，只为新决策增加必要 case；性能收益由同参数完整流程确认。

不要先引入统一所有后端的万能 trait。`primus_tfhe` 保留 LUT/编码与完整 PBS 契约；两族共享层负责客户端与参数；NTT/Fourier 保留各自预处理、工作区和数值约束。出现第二个实际消费者时再提取 Boolean 算法或纯桶匹配组件。

## 8. 本次分析的证据与验证边界

已按功能链定向核对：四后端入口、参数/key、经典 BR 与普通/交错 evaluator；GLWE NTT sparse/CBS/MVB；三套已实现的 CBS；共享 LUT、Boolean、相关 trace/scheme-switch、NTRU 可逆性和多项式乘法契约，以及第 5 节列出的代表测试。源码与依赖原语按算法问题读取，未做四个 crate 的逐文件完整审查。

本次未修改 Rust 实现，也未重跑完整数值测试或性能基准。表中的“已有测试”是对仓库测试内容的核查，不是本轮测试通过声明。

另做了独立整数负循环卷积核对：`q∈{256,65536}`、`N∈{4,8,16}`、`t_out∈{2,4,8,16}`，每组 7 个确定性多项式 `p[j]=((seed+3)j+seed) mod t_out`，共 168 例满足偶尺度恒等式；穷举确认 `2A=85 mod 256` 无解。它仅佐证分解代数，不验证 FFT、完整 PBS 噪声或参数安全性。

已检查本文及索引的本地链接和最终差异。后续实现应更新本文件相应的状态与证据，不追加与当前能力相冲突的历史结论。
