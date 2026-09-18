# TFHE 后端补齐分步计划

依据：[后端覆盖分析](tfhe-backend-coverage.md)，初始源码基线 `7f1ef55`。本计划把已有算法的后端补齐与必要的高层接口整理拆成可独立验收的步骤；不重开已完成的 P1–P4、T1–T3，也不扩入 FDFB 等[新算法选型](tfhe-next.md)。

B1.1–B1.7、B2.1 已完成，下一步 B2.2。B1.4–B1.7 整理四后端高层接口，分析与性能对照基线为 `66ae701`；B2–B8 保留原编号。当前任务与下一步记录在 [HANDOFF](../HANDOFF.md)，算法依据仍由覆盖分析和各专项文档维护。

## 执行方式

- 接下来推荐按 **`执行 B2.2` → `执行 B3.1` → …** 推进。`B1` 表示整个阶段；明确要求“执行 B1”时，完成其所有满足前置条件的剩余子步骤。
- 每步先核对 Git 状态、HANDOFF、本步及依赖结论；保留用户修改和暂存状态。编号不隐含暂存、提交或启动后续步骤。
- **工程接入**：现成代数与原语支持实现，仍需正常验证。**原型验证**：先回答未决问题，结论可以是通过、缩小范围或暂缓。
- “依赖原型通过”不同于“原型步骤已结束”。原型不成立时保留结论及最小反例，删除无长期价值的实验代码，暂缓依赖分支；其他独立阶段仍可执行。
- 不提前开放尚未验收的后端/密钥组合。中间步骤可以交付真实可用的密钥或低层原语，但不能据此将完整功能标为支持。

## 阶段与依赖

| 阶段 | 目标 | 子步骤 | 性质及主要依赖 |
| --- | --- | --- | --- |
| B1 | GLWE Fourier 经典 CBS、四后端高层接口整理 | B1.1–B1.7 | 全部完成；[接口成本验收](tfhe-api-costs.md) |
| B2 | NTRU 两后端 Boolean | B2.1–B2.2 | B2.1 已完成共享算法与绑定；B2.2 待验收完整门语义和串联 |
| B3 | NTRU NTT MVB、既有 sparse 组合验收 | B3.1–B3.3 | 工程接入；B3.3 建议在 B2 的 Boolean 迁移后执行 |
| B4 | GLWE Fourier 二元稀疏 PBS | B4.1–B4.3 | 参考实现与收益验证；不含 sparse CBS/ternary |
| B5 | Native 偶尺度 MVB | B5.1–B5.4 | 原型通过后接入两族 Fourier；NTRU 接入还依赖 B3.1 |
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
- 外部 `t=4`、内部模 8 正负值及输出平移保持一致。GLWE 既有真值表回归通过；NTRU 的 [NTT](../crates/primus_tfhe_ntru_ntt/tests/boolean.rs) / [Fourier](../crates/primus_tfhe_ntru_fourier/tests/boolean.rs) 代表 NAND、公钥输入和复用测试通过，Fourier 覆盖两种 FFT；在线零分配。默认/SIMD 七包检查与测试、严格 rustdoc 通过。
- 在线门算法和 PBS 内核未改变，没有新增 benchmark；常见用法与错误边界见[公共指南](../crates/primus_tfhe/README.zh_CN.md#boolean-门)。完整 NTRU 门语义和串联仍由 B2.2 验收。

### B2.2：门语义与串联验收

- **前置**：B2.1。
- **范围**：NTRU 两后端六种二元门、NOT、MUX 和短门链；Fourier 覆盖两种 FFT，公钥输入保留一组代表验证。
- **验收**：检查真值、串联编码、维数/参数错误及输出复用；复用既有 GLWE 真值表测试，不复制相同纯门逻辑测试。完善双语用法与默认/SIMD 验证。
- **基准**：优先沿用普通 PBS 基准；仅当迁移改变在线热路径时对照测量，不为机械 wrapper 增加独立 benchmark。

## B3：NTRU NTT MVB 与既有组合验收

入口：[公共 factorized LUT](../crates/primus_tfhe/src/lookup_table/factorized.rs)、[GLWE NTT MVB 参照](../crates/primus_tfhe_glwe_ntt/src/evaluator/factorized.rs)、[NTRU NTT evaluator](../crates/primus_tfhe_ntru_ntt/src/evaluator.rs)。

### B3.1：NTRU NTT MVB 完整链

- **范围**：增加借用 context 的因子预处理产物与独立 evaluator，接通 `NLev[1] 初始化 V→BR→各 W_i 乘法→逐输出 NTRU KS→compact extraction`。
- **约束**：保持奇数 `q`、Rounded 前半区输入、统一 Scaled 输出；保存一次 BR 的结果供所有输出使用。首版不把 KS 提前共享，不重复保存不需要的系数/NTT 因子。
- **验收**：用相同 Scaled 输出中心的单输出 PBS 作参照，验证代表输入和 1/3/超过交错容量的输出数；检查 context 身份、输出形状、覆盖写入及零在线分配。

### B3.2：MVB 误差与成本对照

- **前置**：B3.1。
- **范围**：记录 `||W_i||_1`、NLev 初始化/BR 误差放大、逐输出 KS 误差与输出间相关性；对照同一后端的重复 PBS 和可容纳时的交错 ManyLUT。
- **验收**：同一输入、输出函数、编码、参数及复用策略下报告耗时、密钥、额外 scratch；补一个有应用含义的例子及双语文档。不能声称 MVB 对全部函数更快。

### B3.3：GLWE NTT sparse 的三个现有组合

- **前置**：无新算法依赖；推荐在 B2.1 后执行，直接验证迁移后的 Boolean 层。
- **范围**：补 sparse×Boolean、sparse×有界双输入、sparse×奇数明文全域的聚焦端到端验证。
- **验收**：覆盖门预处理、`x+B*y` 误差放大和较窄全域旋转区间；复用少量 fixed-weight 密钥/工作区，以代表点覆盖两种 order。发现问题时只修复该组合的实际契约。
- **边界**：这些路径已经能够分派到 sparse BR，优先增加缺失证据，不另造 evaluator 或重复共享 LUT 测试。

## B4：GLWE Fourier 固定重量二元稀疏 PBS

入口：[NTT sparse](../crates/primus_tfhe_glwe_ntt/src/sparse/mod.rs)、[BucketMap/Matching](../crates/primus_tfhe_glwe_ntt/src/sparse/pbc.rs)、[稀疏专项](tfhe-sparse-pbs.md)。

### B4.1：纯匹配组件与 Fourier sparse key

- **范围**：为第二个实际后端提取不依赖 NTT 的索引映射/匹配部分，保留可读的算法注释；迁移 NTT 调用方，同时实现 Fourier 后端使用的系数 selector GGSW 与 dummy 密钥材料。
- **约束**：不在此步改变匹配算法、采样/重试分布或聚合优化策略。BSK 表示和后端错误仍明确区分。
- **验收**：保留现有匹配不变量测试；解密少量 selector/dummy 核对每桶至多一个有效选择、未占用桶恒等控制。原 NTT 路径通过相应回归检查。

### B4.2：参考 BR 与完整 PBS

- **前置**：B4.1。
- **范围**：Native 系数域单项式旋转/聚合→每桶一次 FFT→一次外积；再接普通/ManyLUT 和两种 order，使用显式 sparse server-key 生成入口。
- **验收**：固定重量二元秘密下对照经典 BR，覆盖普通/交错输出、两种 FFT、量化步长和重复调用。输出相位、解码和零在线分配均检查。
- **边界**：不接 sparse ternary、sparse CBS；不同时实现频域逐项聚合。

### B4.3：性能与保留方案

- **前置**：B4.2。
- **范围**：比较同一后端、同一 fixed-weight secret 分布下经典/稀疏完整 PBS；报告聚合、变换、外积、密钥大小与 scratch。代表性能负载使用 `n>=728`，不将小功能 fixture 当作性能依据。
- **验收**：明确哪些负载有收益、哪些受聚合变换或带宽限制。仅有解释和实测依据时才尝试进一步优化；优化无收益则保留清晰参考实现。
- **分支决定**：若参考算法本身既无可用收益也无明确独立用途，记录适用范围不足并暂缓依赖它的扩展，不为“矩阵全绿”持续增添实现。

## B5：Native 偶尺度 MVB

入口：[除二边界](tfhe-mvb.md#12-的边界)、[覆盖分析 §5.4](tfhe-backend-coverage.md#54-native-偶尺度-mvbglwentru-fourier-的共同前置工作)。

### B5.1：表示与误差原型

- **范围**：在临时或私有原型中使用 `A=Delta/2`，验证小有符号整数 `W_i` 的 FFT 表示与公开乘法，再接一个经典 GLWE Fourier 完整 MVB 工作负载。
- **约束**：实际 `Delta` 必须为偶数，不要求 `t_out` 一定是二次幂；奇数尺度拒绝。复用已有整数恒等式证据，补充真实 Fourier 乘法与输出尺度验证，不只是重复整数 oracle。
- **通过条件**：独立系数卷积参照成立；两种 FFT 的误差与所测参数/字宽可解释，完整输出仍有明确解码余量；记录成本。通过前不放开公共 factorized 构造器的 Native 契约。
- **失败处理**：区分表示错误、所选参数精度不足和公式不适配；仅在有可复现依据时缩小支持范围，不用错误的除二或隐式编码转换掩盖问题。

### B5.2：GLWE Fourier MVB 正式接入

- **前置**：B5.1 通过。
- **范围**：扩展共享编译器的 Native 偶尺度分支，保留原奇数 `q` 分支；实现 Fourier 因子预处理和 evaluator，两种 order、经典 binary/ternary 使用现有 BR。
- **验收**：明确 Scaled 输出、整数因子 FFT、context/table 身份、额外 scratch 和在线复用。支持字宽遵循实际精度验证，不从一个 u32 fixture 推断任意 u64 参数均可用。

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
