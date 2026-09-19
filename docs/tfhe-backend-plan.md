# TFHE 后端补齐分步计划

依据：[后端覆盖分析](tfhe-backend-coverage.md)，初始源码基线 `7f1ef55`。本计划把已有算法的后端补齐与必要的高层接口整理拆成可独立验收的步骤；不重开已完成的 P1–P4、T1–T3，也不扩入 FDFB 等[新算法选型](tfhe-next.md)。

B1–B4 已完成，B5.1 原型通过、B5.2 已接入 GLWE Fourier，下一步 B5.3。B1.4–B1.7 整理四后端高层接口，分析与性能对照基线为 `66ae701`；B2–B8 保留原编号。当前任务与下一步记录在 [HANDOFF](../HANDOFF.md)，算法依据仍由覆盖分析和各专项文档维护。

## 执行方式

- 接下来推荐按 **`执行 B5.3` → 后续满足前置条件的步骤** 推进。`B1` 表示整个阶段；明确要求“执行 B1”时，完成其所有满足前置条件的剩余子步骤。
- 每步先核对 Git 状态、HANDOFF、本步及依赖结论；保留用户修改和暂存状态。编号不隐含暂存、提交或启动后续步骤。
- **工程接入**：现成代数与原语支持实现，仍需正常验证。**原型验证**：先回答未决问题，结论可以是通过、缩小范围或暂缓。
- “依赖原型通过”不同于“原型步骤已结束”。原型不成立时保留结论及最小反例，删除无长期价值的实验代码，暂缓依赖分支；其他独立阶段仍可执行。
- 不提前开放尚未验收的后端/密钥组合。中间步骤可以交付真实可用的密钥或低层原语，但不能据此将完整功能标为支持。

## 阶段与依赖

| 阶段 | 目标 | 子步骤 | 性质及主要依赖 |
| --- | --- | --- | --- |
| B1 | GLWE Fourier 经典 CBS、四后端高层接口整理 | B1.1–B1.7 | 全部完成；[接口成本验收](tfhe-api-costs.md) |
| B2 | NTRU 两后端 Boolean | B2.1–B2.2 | 已完成共享算法、绑定、完整门语义和串联验收 |
| B3 | NTRU NTT MVB、既有 sparse 组合验收 | B3.1–B3.3 | 全部完成；[MVB 测量](tfhe-mvb-ntru.md)、[sparse 组合](tfhe-sparse-pbs.md#b33-已有上层组合验收) |
| B4 | GLWE Fourier 二元稀疏 PBS | B4.1–B4.3 | 已完成密钥、完整 PBS 与成本验收；保留参考实现，不含 sparse CBS/ternary |
| B5 | Native 偶尺度 MVB | B5.1–B5.4 | B5.1–B5.2 已完成；下一步 NTRU 接入并独立核对初始化误差 |
| B6 | sparse CBS | B6.1–B6.3 | NTT 先验证；Fourier 还依赖 B1、B4 的对应能力 |
| B7 | NTRU 经典 ternary | B7.1–B7.4 | 先明确采样与控制原语，再接完整链；不依赖 sparse 算法 |
| B8 | NTRU 二元桶聚合 PBS | B8.1–B8.3 | 独立方案原型；复用 B4.1 的纯匹配组件，不依赖 B7 |

完成 B1 的接口整理后，后续能力沿用其参数、密钥和 evaluator 构造约定，避免重复迁移；这是工程顺序，Boolean 等算法并不依赖 CBS。其余独立能力不强制串成依赖链，例如 B5 原型失败不阻止 NTT sparse CBS；NTRU binary 桶聚合也不必等待 ternary。

## B1：经典 CBS 与四后端高层接口整理

### B1.1–B1.3：GLWE Fourier 经典 CBS（已完成）

| 步骤 | 完成入口 |
| --- | --- |
| B1.1：参数与附加密钥 | [CBS 模块](../crates/primus_tfhe_glwe_fourier/src/circuit_bootstrap/mod.rs)，独立 output/trace/scheme-switch basis 与配套密钥 |
| B1.2：完整 evaluator | [实现](../crates/primus_tfhe_glwe_fourier/src/circuit_bootstrap/evaluator.rs)、[测试](../crates/primus_tfhe_glwe_fourier/tests/circuit_bootstrap.rs)，两种 order/FFT、binary/ternary、逐层相位、CMUX 与零分配 |
| B1.3：误差、成本与示例 | [CBS 专项](tfhe-cbs.md)、[示例](../crates/primus_tfhe_glwe_fourier/examples/circuit_bootstrap.rs)、[基准](../crates/primus_tfhe_glwe_fourier/benches/circuit_bootstrap.rs) |

保留 Native 逐级整数除二与逐系数 RevHomTrace；共享正向展开树优化暂缓。经典 CBS 已支持，
生产误差尾界未认证，sparse CBS 仍由 B6 独立验证；不因 BR 输出类型相同而自动开放。

### B1.4–B1.7 的共同设计边界

基线 `66ae701` 的 [CBS 示例](../crates/primus_tfhe_glwe_fourier/examples/circuit_bootstrap.rs)需要分别构造参数、变换表、普通与 CBS 密钥；得到 GGSW 后，还要为加密、CMUX 和解密手工准备 basis、秘密变换与 scratch。`circuit_bootstrap_to(input, output)` 本身已经简洁，主要整理构造过程和输出消费过程。

- **覆盖四后端及其公共层**：统一同一角色的高层名称和工作流，保留 GLWE/NTRU 秘密域、NTRU 初始化与拒绝采样、NTT/Fourier 表示和归一化差异；不增加万能后端 trait、能力泛型框架或算法注册表。
- **构造时绑定，在线复用**：参数、密钥材料、basis、变换表和工作区在所属构造边界校验并绑定。在线调用主要提供输入、LUT/控制密文与输出；不重复变换秘密、编译 LUT、分配或 clone 大对象。
- **显式保留数学选择**：秘密分布、噪声、各用途的独立分解 basis、输出尺度和适用的 PBS order 由调用方选择；只派生重复的模数、长度与布局，不暗设“安全参数”。
- **一个常用密钥入口，按用途配置工作区**：`ServerKey` 聚合普通 PBS 及可选 CBS 材料，不再叠加一个同义的 `EvaluationKey`。普通 PBS、CBS、MVB 仍使用各自 evaluator，避免普通调用承担全部算法的 scratch。
- **保留必要的高级入口**：底层 GGSW/NGSW、NTT/Fourier 类型及算术函数继续可用；显式表注入、多 CBS 配置等已有实验用途可以保留直接构造路径。普通工作流无需手工拼装这些资源。
- **不扩大算法支持**：GLWE CBS 的同层数输出 basis 复用与 NTRU CBS 的精确输出 basis 绑定分别保留；稀疏 CBS 继续拒绝。Boolean 加密器/解密器保持独立，保留 LWE 私钥/公钥加密。

### B1.4–B1.7：高层接口（已完成）

| 步骤 | 完成入口与边界 |
| --- | --- |
| B1.4：参数与 context 构造 | 两族 `TfheConfig`、公共 `DecompositionConfig` / `CircuitBootstrapConfig`；自动建表与显式注入并存，数学选择仍显式。见[资源生命周期](../crates/primus_tfhe/README.zh_CN.md#lut-与资源生命周期) |
| B1.5：配套密钥与错误整理 | `try_generate_keys(Option<CircuitBootstrapConfig>, rng)`、可选 CBS 组件和独立配置高级入口；删除无实质作用的 options 包装及重复错误。见[错误边界](../crates/primus_tfhe/README.zh_CN.md#错误边界) |
| B1.6：输出消费 | `allocate_output`、绑定 CMUX/外积与 `AccumulatorClient`；GLWE scheme switch 直接使用 lattice 外积工作区，四后端消费复用既有 scratch。见[完整用法](../crates/primus_tfhe/README.zh_CN.md#cbs-输出与消费) |
| B1.7：集成与成本 | 统一 CBS 输入明文模数绑定，补全契约与双语文档；[当前验收与测量](tfhe-api-costs.md)记录默认/SIMD、底层与九个 release 示例验证，以及对 `66ae701` 的 PBS/CBS/完整消费、构造和工作区对照 |

四后端工作流从各自 basic/CBS 示例恢复，GLWE NTT 另有 MVB 示例，入口见[公共能力指南](../crates/primus_tfhe/README.zh_CN.md)。
常用代码无需手工拼装 basis/table/scratch；没有新增测试矩阵或为了转发接口保留独立 benchmark。
NTRU NTT 小 fixture 的资源放置敏感性及未保留的性能试验见验收文档，不能据此宣称所有参数等时。

下层仅沿真实依赖整理，不添加统一 TFHE context 到 lattice。
[GLWE 系数域加解密](glwe-coefficient-client.md)已验证减少变换、耗时和 scratch，并接入精确等价的 NTT 路径；
Fourier 因原型噪声增加，按用户决定暂不接入。不阻塞 B2.1。

## B2：NTRU 两后端 Boolean

入口：[共享 Boolean 求值器](../crates/primus_tfhe/src/boolean.rs)、[完整 PBS trait](../crates/primus_tfhe/src/bootstrap.rs)、[NTRU 客户端](../crates/primus_tfhe_ntru/src/client/mod.rs)。

### B2.1：共享门算法与 NTRU 绑定（已完成）

- `primus_tfhe::BooleanEvaluator` / `BooleanGate` 共享门预处理、四个正负 LUT 和 LWE 工作区；构造只接受维数、环长度、Rounded codec、accumulator 模数与 PBS 实现，不依赖 family 参数或客户端错误。
- GLWE 已迁移；NTRU 两后端增加 `boolean_encryptor`、`boolean_decryptor`、`boolean_evaluator` 工厂。独立加解密器保留私钥/公钥输入，密文继续使用原始 `LweCiphertext`；不需要 CBS 材料。
- Boolean 客户端返回 family `BooleanError`，通过 `Client(#[from] TfheClientError)` 保留原因；求值器构造统一返回 `TfheEvaluationError`，内部 LUT 错误沿既有 `LookupTable` 转换。
- 外部 `t=4`、内部模 8 正负值及输出平移保持一致。在线门算法和 PBS 内核未改变，没有新增 benchmark；常见用法与错误边界见[公共指南](../crates/primus_tfhe/README.zh_CN.md#boolean-门)。

### B2.2：门语义与串联验收（已完成）

- [共用用例](../test-support/tfhe/src/boolean.rs)从 GLWE 测试提取，覆盖六种二元门、NOT、MUX 的完整真值表和 `NAND → NOT → MUX → XOR` 门链；四后端共用断言，GLWE 保留两种 order，NTRU Fourier 覆盖 RustFFT/TfheFFT。
- 共享辅助通过 `dev-dependencies` 引入，避免跨 crate 的 `#[path]` 无法被 rust-analyzer 解析。`test-support/tfhe` 保存门断言，独立的 `test-support/allocations` 供包括 `primus_tfhe` 在内的调用方统计分配，避免循环依赖；测量程序显式注册计数 allocator。
- [NTT](../crates/primus_tfhe_ntru_ntt/tests/boolean.rs) / [Fourier](../crates/primus_tfhe_ntru_fourier/tests/boolean.rs) 复用固定 seed、`u32`、`n=3`、`N=256` 的功能 fixture，不增加密钥矩阵；全部门的 `_to` 路径和门链从首次调用起零分配，保留一组公钥 NAND 输入。此小 fixture 用于 CI，不提供生产失败概率结论。
- 检查输入/输出维数、拒绝后输出不变及继续复用；[客户端测试](../crates/primus_tfhe_ntru/tests/client.rs)覆盖非模 4 参数、非 Boolean 明文及客户端维数错误，后端既有 context fixture 同时检查 Boolean 工厂拒绝不兼容服务端密钥。
- 双语用法补充门结果串联和缓冲区交换。`just tfhe`、`just tfhe-simd` 通过；本步只整理测试与文档，未改变求值内核或新增 benchmark。

## B3：NTRU NTT MVB 与既有组合验收

入口：[公共 factorized LUT](../crates/primus_tfhe/src/lookup_table/factorized.rs)、[GLWE NTT MVB 参照](../crates/primus_tfhe_glwe_ntt/src/evaluator/factorized.rs)、[NTRU NTT evaluator](../crates/primus_tfhe_ntru_ntt/src/evaluator.rs)。

### B3.1：NTRU NTT MVB 完整链（已完成）

- [预处理产物与独立 evaluator](../crates/primus_tfhe_ntru_ntt/src/evaluator/factorized.rs)借用 context，接通 `NLev[1] 初始化 V → BR → 各 W_i 乘法 → 逐输出 NTRU KS → compact extraction`；工厂与 GLWE NTT 同名，使用普通服务端密钥。
- 保持奇数 `q`、Rounded 前半区输入、统一 unsigned Scaled 输出；额外一个 NTT 多项式保存共享旋转结果，各输出复用 BR/KS 缓冲。公共 LUT 与两后端的因子共用连续存储，原地变换、通过既有多项式迭代器借用；普通 evaluator 的工作区不变。
- [聚焦测试](../crates/primus_tfhe_ntru_ntt/tests/factorized_pbs.rs)覆盖相同 Scaled 编码的单输出 PBS 对照、1/3/17 输出、超出交错容量、奇数尺度初始化、context/形状/模数拒绝、覆盖写入及首次调用零分配。`just tfhe`、`just tfhe-simd` 与严格 rustdoc 通过。
- [双语用法](../crates/primus_tfhe_ntru_ntt/README.zh_CN.md#固定尺度分解式-mvb)与 [NTRU 误差来源](tfhe-mvb.md#ntru-ntt-的初始化与后处理)已同步；耗时、误差统计和应用示例见 B3.2。

### B3.2：MVB 误差与成本对照（已完成）

- [NTRU 测量](tfhe-mvb-ntru.md)记录 n=728、h=32 经典 BR 的两组等价 Scaled 阈值负载，比较重复 PBS、可容纳时的交错 ManyLUT 与 MVB；默认/SIMD 均测完整调用、密钥、程序与工作区。
- 临时分阶段诊断核对因子范数、初始化/BR 放大、逐输出 KS 与最终相位，记录输出相关性；正式调用与诊断逐字一致，所有在线路径首调用零分配。误差与资源汇总在默认/SIMD 下相同；临时诊断已删除，不进入普通 CI。
- 保留[五项在线基准](../crates/primus_tfhe_ntru_ntt/benches/mvb.rs)、[17 阈值应用示例](../crates/primus_tfhe_ntru_ntt/examples/ntru_ntt_mvb_thresholds.rs)与双语用法。`just tfhe`、`just tfhe-simd` 及两配置的 release 示例通过。
- 本组小范数 MVB 相对重复 PBS 有明显收益，三输出与交错接近；不推断所有函数更快，不提供生产安全/尾概率结论，也未比较 NTRU 连续存储改动前后的耗时。

### B3.3：GLWE NTT sparse 的三个现有组合（已完成）

- [两个新增测试](../crates/primus_tfhe_glwe_ntt/tests/sparse_pbs.rs)覆盖 sparse×Boolean、有界双输入和奇数明文全域，两种 order 均复用小型 fixed-weight 密钥/工作区；Boolean 复用共同真值表和串联断言。
- 受控相位偏移覆盖门预处理、`x+3*y` 的噪声放大及编码舍入差、奇数全域的较窄输入余量；检查输出相位、解码及首次调用零分配。参数和代表点见[专项记录](tfhe-sparse-pbs.md#b33-已有上层组合验收)。
- `just tfhe`、`just tfhe-simd` 通过；无需修改生产 API 或内核，也未增加 benchmark。sparse CBS、ternary 和其他后端仍按各自阶段验收。

## B4：GLWE Fourier 固定重量二元稀疏 PBS（已完成）

| 步骤 | 完成入口与结论 |
| --- | --- |
| B4.1：共享匹配与 Fourier 密钥 | [BucketMap/Matching](../crates/primus_tfhe/src/sparse.rs) 与系数 selector/dummy；[构造与错误边界](tfhe-sparse-pbs.md#b41-fourier-密钥材料与共享匹配) |
| B4.2：参考 BR 与完整 PBS | Native 系数聚合→FFT→外积，两种 FFT/order、普通/ManyLUT；[相位、组合与零分配验收](tfhe-sparse-pbs.md#b42-fourier-稀疏-br-与完整-pbs) |
| B4.3：性能与保留方案 | n=728 的同客户端经典/稀疏完整链、聚合/FFT/外积及资源对照；[测量与取舍](tfhe-sparse-pbs.md#b43-fourier-成本与保留方案) |

保留逐条目聚合参考实现：h=32 的所测负载有在线收益，h=128 的所测单输出负载无收益；16 KiB 分块原型未显示稳定收益，已删除。只增加一个持久完整 PBS 基准，不增加统计测试或生产 API。稀疏安全/尾界、CBS、ternary 及其他上层组合仍按各自前置条件验收，不因性能测量开放。

## B5：Native 偶尺度 MVB

入口：[除二边界](tfhe-mvb.md#12-的边界)、[覆盖分析 §5.4](tfhe-backend-coverage.md#54-native-偶尺度-mvbglwentru-fourier-的共同前置工作)。

### B5.1：表示与误差原型（已通过）

- **结果**：[表示、独立卷积参照、分阶段误差与成本](tfhe-mvb-fourier.md)。复用 `forward_as_integer` 和现有 Fourier 公开乘法，无新增生产类型或内核。
- **验证范围**：两种 FFT、u32/u64、`n=728,N=1024` 的经典 binary BK 三输出；`t_out=8/10` 偶尺度成功，`t_out=3` 奇尺度拒绝。独立小整数乘法另覆盖 `N=16/1024/4096`。
- **余量与成本**：默认/SIMD 诊断一致、首调用零分配；u64 的新增乘法相位误差单独计入，完整输出保留明确解码余量；两轮默认计时见专项。不推断任意因子/参数均满足精度。
- **边界**：临时原型已清理；本步仅提供表示/误差证据，正式接入归 B5.2，NTRU 归 B5.3，sparse 组合及交错算法对照归 B5.4。

### B5.2：GLWE Fourier MVB 正式接入（已完成）

- **实现**：共享编译器增加 Native 偶尺度分支和 `OddFactorizationScale`，保留奇数 q 路径；context 编译/准备 `FourierFactorizedLookupTable`，独立 `FactorizedEvaluator` 复用普通 evaluator 的 BR/KS。
- **契约**：两种 FFT、u32/u64、两种 order 与经典 binary/ternary；连续整数 FFT 因子绑定同一 context，新增共享 Fourier GLWE 和一个乘积多项式，在线零分配。因子放大与 FFT 相位误差仍由参数预算承担。
- **验收**：[聚焦测试](../crates/primus_tfhe_glwe_fourier/tests/factorized_pbs.rs)、默认/SIMD TFHE 检查及复用公钥输入的基本示例；[表示与完成边界](tfhe-mvb-fourier.md#b52正式接口与验收)。无新增持久基准，算法比较留给 B5.4。
- **下一步**：B5.3 的 NTRU 初始化与后处理；Fourier sparse×MVB 仍由 B5.4 验收，当前构造拒绝。

### B5.3：NTRU Fourier MVB 正式接入

- **前置**：B5.1 通过、B5.2、B3.1。
- **范围**：复用已验证的 Native 编译契约与整数因子表示，连接 NTRU 加密初始化、BR、逐输出乘法和 KS/提取；保持 NTRU 独立工作区与误差说明。
- **验收**：两种 FFT 的单输出参照、多个输出及跨调用复用；单独计入 NLev 初始化误差，不能直接使用 GLWE 的误差结论。

### B5.4：应用、组合与成本验收

- **前置**：B5.2；NTRU 部分还依赖 B5.3。
- **范围**：比较每个后端内重复 PBS、交错 ManyLUT、MVB 的等价输出负载；覆盖交错容量之外的示例。B4 已验收时补一组 GLWE Fourier sparse×MVB 验证，否则明确保留该组合未验证状态。
- **验收**：记录因子范数、完整误差、输出编码衔接、资源和时间，更新双语说明及当前覆盖矩阵；原型与临时性能分支完成取舍后清理。

## B6：稀疏 CBS

### B6.1：NTT 组合原型

- **范围**：在私有/临时路径中让现有 sparse BR 产生 CBS gadget-scale ManyLUT，复用 projection/scheme switch；公开接口仍保留拒绝检查。
- **通过条件**：同一 fixed-weight client 的经典/稀疏对照解释桶内 selector、加密零和 dummy 噪声；逐行/层相位、最小 gadget scale 及 CMUX 均满足所选参数余量，两种 order 可复现。
- **产物**：记录可用参数范围、额外材料和成本，或暂缓理由。取消 `UnsupportedSparseBootstrapping` 不算原型成功。

### B6.2：NTT 正式接入

- **前置**：B6.1 通过。
- **范围**：让 CBS 的 BR 绑定显式兼容 classic/sparse；同步构造器、错误、工作区和公开契约，复用后处理而不隐藏两种 key 的布局。
- **验收**：将少量原型中的关键回归转成正式测试，覆盖参数不兼容、逐层输出、CMUX、复用和零分配；补必要基准与文档，删除临时绕过接口。

### B6.3：Fourier 组合验证与有条件接入

- **前置**：B1.2、B4.2 已完成且对应阶段未被暂缓，B6.2。
- **范围**：先重复 Fourier 自己的 sparse CBS 原型，额外计入聚合 FFT 与逐级 native halving；NTT 通过不能代替该验证。
- **验收/分支**：两种 FFT 和最小 gadget scale 验证通过后，在本步接入公开 evaluator；否则保留经典 CBS，记录 sparse CBS 暂缓。避免未经验证就用统一 enum 自动开放此组合。

## B7：NTRU 经典 ternary

入口：[NTRU ternary 条件](tfhe-backend-coverage.md#55-ntru-ternary控制代数与秘密采样分别处理)、[既有 GLWE ternary](tfhe-ternary.md)。

### B7.1：秘密采样与可逆性前置

- **范围**：明确首批支持的 ternary 分布、active prefix、零 padding、可逆性和 bounded rejection 策略，验证 lower-level padded ternary 生成路径。
- **通过条件**：Native 对固定 composition 的偶数 `h_++h_-` 明确拒绝；NTT 逐候选检查可逆；Fourier 另检查逆元稳定性。记录实际条件分布及尚未证明的安全结论，不能用采样通过率代替证明。
- **边界**：此步不放开 TFHE 上层 binary 限制，不把 ternary 密钥送入原 binary CMUX。

### B7.2：NTT NGSW ternary 单步

- **前置**：B7.1 的目标秘密与表示契约明确。
- **范围**：复用 NTT 单项式操作，增加 ternary 组合控制、一次外积 CMUX 和必要 scratch；正负指数从同一个量化结果导出。
- **验收**：`-1/0/1` 与系数域旋转或两次 binary CMUX 的独立参照一致；覆盖零指数和负循环符号。对比等价工作量，记录一次外积带来的成本与 scratch 取舍。

### B7.3：Fourier NGSW ternary 单步

- **前置**：B7.1；以 B7.2 的代数参照为基础。
- **范围**：补 Fourier NGSW 对应组合 helper 与单步 CMUX，保持整数单项式和 FFT table 布局契约，不假定系数 residue 可直接作浮点整数。
- **验收**：两种 FFT 与独立旋转参照、两次 CMUX 参照核对；测误差、成本和工作区。数值预算或性能不成立时先调整/暂缓该分支，不影响已验证的 NTT 原语。

### B7.4：完整 NTRU 链、客户端与已有上层组合

- **前置**：B7.1 通过；对应后端的 B7.2/B7.3 通过。
- **范围**：参数和导入 key 检查、成对 selector BSK、BR 分派及密钥生成完整迁移；保留 binary 热路径。优先两后端同步接入；若仅一个后端通过，另一个明确拒绝 ternary，不能继承公共参数放宽后误走 binary 路径。
- **验收**：普通/ManyLUT、公钥客户端、既有 CBS 和已完成的 Boolean/MVB 各选择代表组合；检查秘密身份、零 padding、输出尺度、分配和性能。未完成的功能不变成此步的隐藏依赖。
- **文档**：区分“经典 ternary”与“桶聚合 ternary”；后者不在本阶段范围。

## B8：NTRU 固定重量二元桶聚合 PBS

### B8.1：采样、映射与 NGSW 聚合原型

- **前置**：B4.1 的纯匹配组件；若 B4 未执行，可在本步完成相同的必要提取，不要求先实现 GLWE Fourier PBS。
- **范围**：先针对 NTT 验证 fixed-weight binary 客户端的可逆采样、零 padding、桶映射/匹配、NGSW selector/dummy 聚合及单桶外积。
- **通过条件**：记录 NTRU 可逆性拒绝与公开映射条件分布叠加后的实际契约；不未经论证继承 GLWE 的分布结论。单桶相位与公开单项式旋转一致，NLev 初始化误差有单独预算。
- **秘密分布**：fixed-weight binary；桶聚合 ternary 另行设计。

### B8.2：NTRU NTT 完整稀疏 PBS

- **前置**：B8.1 通过。
- **范围**：专用 sparse NGSW key、参考 BR、普通/ManyLUT、NTRU KS 和提取；复用公共匹配结果，保留独立密钥表示。
- **验收**：同一可逆 fixed-weight 客户端下对照经典链，检查旋转、完整相位误差和零在线分配；比较完整 PBS、keygen、密钥及 scratch。记录额外的分布/安全未决项，能力按实验性状态交付。
- **组合边界**：初次交付不开放 sparse CBS 或 sparse MVB；后者即使经典版本存在，也需在基础链验收后另选代表组合验证。

### B8.3：NTRU Fourier 原型与有条件接入

- **前置**：B8.2 验收；复用 B4 的 Fourier 聚合经验，但重新检查 NTRU 初始化和外积误差。
- **范围**：先验证奇数固定重量 binary 秘密的可逆性/稳定性、系数域聚合与 FFT；通过后接普通/ManyLUT 完整链。
- **验收/分支**：Native 偶数 binary 重量在采样前明确拒绝；两种 FFT 下对照经典链，检查全部误差来源和收益。无法给出可用范围时记录暂缓，不靠重试或临时改分布让测试通过。

## 每步通用完成标准

1. **范围完整**：本步公开 API、workspace 调用方、相关示例、测试和双语 README 同步；没有假兼容层或未说明的半成品支持。
2. **检查边界清楚**：验证调用方数据放在拥有契约的构造/批量边界；私有 kernel 使用既有不变量。原型没有通过的组合继续明确拒绝。
3. **先窄后宽验证**：修改包运行 fmt、all-targets check、聚焦 test、Clippy；跨层原语同时检查直接消费者。阶段完成时运行 [justfile](../justfile) 的 `just tfhe` / `just tfhe-simd`，补其未覆盖的底层包验证。
4. **少而有效的资产**：以独立 oracle、表示差分及实际消费者保护契约；不展开所有分布×order×FFT×输出数的笛卡尔积。大型统计与 Criterion 不进入普通测试。
5. **性能结论可复现**：固定工具链、CPU、features、函数/编码及复用策略；新能力没有旧实现时不虚构基线。区分功能扩展、算法选择和优化变体；优化变体只在等价完整负载有依据时保留。
6. **进度可恢复**：HANDOFF 只写当前步骤、已满足/未满足前置、下一步和关键阻碍；数值推导更新对应专项，测量更新测量文档，覆盖状态更新覆盖分析。临时实验代码完成取舍后清理，不追加冗长历史日志。

### 步骤结束的最小记录

```text
步骤：B?.?
结果：完成 / 原型通过 / 缩小范围 / 暂缓
当前支持与限制：
实际验证和测量入口：
仍未验证的组合：
下一步及其前置条件：
```

完成用户指定的步骤或阶段后停在该边界，不自动提交或执行下一项。
