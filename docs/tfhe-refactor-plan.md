# TFHE 结构与使用方式整理计划

源码基线：`cba9c01`（2026-09-20）。依据是 B1–B8 完成后对七个 `primus_tfhe*` crate 的源码审查。
本轮整理现有能力的类型、错误、资源所有权、重复实现和学习入口；数学契约见 [TFHE 设计](tfhe.md)，已有能力与实验条件见 [B1–B8 完成入口](tfhe-backend-plan.md)。

**当前状态：R1 已完成，下一步 R2；构造性能限制见下方验收结果。** 全部工作合并为四个大步骤，替代原来的细分编号。每步内部清单用于实施和验收，无需分别发起。

## 执行原则：每步交付完整结果

使用 `执行 R1` → `执行 R2` → `执行 R3` → `执行 R4`，完成指定步骤及其调用方迁移，不自动开始下一步，也不隐含暂存或提交。

- **相关设计一起完成**：参数与错误一起迁移，evaluator 接口与内部工作区一起设计；不先发布临时包装，再安排下一步拆除。
- **优先减少必须理解的概念**：检查推荐调用链、重复保存的状态和检查边界。新增类型或 trait 必须承载真实不变量或所有权，不能只把复杂性搬到另一层；必要的表示区别仍保留。
- **同一职责一次迁移**：涉及四后端的共同接口，在同一步同步。模块、测试、示例和双语文档随实现更新；R3 负责整体整理，不承接前两步未完成的迁移。
- **优化服从清晰所有权**：已确认的重复计算直接处理；候选 scratch 复用在 R2 内得出保留或撤回结论，不为其增加一套长期模式状态。
- **内部检查点不变成新阶段**：每步允许小批量编辑和针对性验证，但交付时应是可用的完整状态。恢复时只记录所属步骤、已完成清单、未决项和下一动作，不继续派生编号。
- 每步先检查 Git、[HANDOFF](../HANDOFF.md) 和本步相关源码。保留用户修改及暂存边界；新发现的无关问题只记录，不扩张本轮。

## 目标结构与固定边界

### 三层职责

| 层 | crate | 职责 |
| --- | --- | --- |
| 共享算法 | `primus_tfhe` | LUT 表示/编译、旋转量化、Boolean 算法、小型 PBS 接口、桶映射 |
| 家族公共层 | `primus_tfhe_glwe`、`primus_tfhe_ntru` | 参数不变量、客户端秘密、编码及客户端操作、家族错误 |
| 数值后端 | 两族各自的 NTT/Fourier crate | 变换表示、求值密钥、可变工作区、BR/KS/CBS/MVB 执行 |

下层 lattice、GLWE、NTRU 只沿真实依赖局部修改，不重开全库整理。

### 类型保留与组合

| 关系 | 决定 |
| --- | --- |
| Config / Parameters | 保留用户选择与校验后参数的区别 |
| Context / Evaluator | 保留不可变参数/变换表与可变 scratch 的边界 |
| ClientKey / ServerKey | 分离秘密与求值材料；ServerKey 聚合 BSK、KS 和可选 CBS 材料 |
| CircuitBootstrapKey | 保留组件及独立生成用途；常用工作流从 ServerKey 获取 |
| 普通 / MVB / CBS evaluator | 保留能力边界，复用基础工作区，不增加算法组合对应的公共类型 |
| Encryptor / Decryptor、Boolean 客户端 | 保持独立，加密器继续支持私钥和公钥 |
| AccumulatorClient | 与外部 LWE 客户端区分秘密域 |
| ordinary / interleaved / factorized LUT | 保留布局区别；odd-full 仍是普通 LUT 构造方式；后端准备后的 MVB 程序保留表示绑定 |
| binary / ternary / sparse BR | 私有实现绑定控制材料与对应 scratch，不增加公共子类型族 |

不新增万能 Session、另一层 EvaluationKey、统一所有表示的后端 trait、算法注册表或隐式懒分配。

### 数学与使用契约

- 当前完整 PBS 链的输入与 accumulator 密文模数相等；共享 raw LUT 仍允许两者独立。高层泛型收敛不收窄底层原语。
- GLWE CBS key 绑定输出布局，保留同层数不同输出 basis 的高级用法；NTRU CBS key 绑定完整输出 basis。
- 保留 GLWE 两种 order、NTRU 初始化与返回 KS、NTT/Fourier 表示和数值差异、Native halving 与奇数模数处理。
- LUT 的两次舍入、前缀域、负循环符号、交错步长及输出尺度不变；Boolean/gadget 输出不能被强制解释为普通明文。
- 形状兼容不证明真实秘密或变换表身份相同。公开边界保留必要检查；私有 kernel 复用已经建立的不变量，不新增公共 unchecked 入口。
- 保留固定客户端后的 map-only 重试、秘密擦除、采样限制及非法配置在 RNG 消费前拒绝的既有承诺。
- 不开放 NTRU sparse CBS/MVB、sparse ternary、automorphism BR、packing 或新算法；Fourier 系数域客户端优化仍按已有决定暂缓。
- 参数安全、噪声尾界及条件采样分布的未认证问题保持开放，功能测试不替代这些结论。

## 四步安排

| 步骤 | 完整交付 | 状态 |
| --- | --- | --- |
| R1 | 公共类型、参数、错误与 LUT 接口收敛 | 已完成，构造成本见下文 |
| R2 | evaluator 所有权、工作区与重复计算一起整理 | 待执行 |
| R3 | 模块、使用指南、示例、测试与基准整体收尾 | 待执行 |
| R4 | 全链验收与交接收尾 | 待执行 |

按 R1 → R2 → R3 → R4 执行。下面的清单属于各自步骤，不单独排期。

## R1：公共类型与接口收敛

**目标**：一次确定共同的不变量、参数来源和错误边界，让调用方只迁移一次。

**入口**：两族 `src/{parameters,error,lookup_table}.rs`、`src/client/`；四后端 `src/circuit_bootstrap/{parameters,key,evaluator}.rs`、`src/accumulator.rs` 及公共导出。

### 实施清单

- [x] **GLWE 模数泛型**：将 `TfheParameters<T, LM, GM>` 及高层客户端收敛为 `T, M`。依据是当前 Config 与实际消费者已使用同一模数实现；执行时再搜索不同 LM/GM 的真实消费者。保留 small-LWE/accumulator 的参数角色和独立噪声/basis，raw LUT 不受影响。
- [x] **CBS 参数归属**：GLWE NTT/Fourier 的共同数学参数移入家族层，数值约束留在后端。默认从 key 获取参数，保留显式输出 basis 的高级入口；NTRU 从 `CircuitBootstrapKey::parameters()` 绑定，删除重复传入/保存的参数，保留完整 basis 检查与 sparse 拒绝。
- [x] **错误树**：服务端密钥和稀疏组件的可失败生成入口统一 family `KeyGenerationError`；客户端不兼容只有一个来源路径。Sparse 错误聚焦桶映射、秘密支持和控制存储。NTRU `AccumulatorClient::try_new` 使用已有 `TfheClientError` 并保留实际秘密转换原因。底层独立原语及不可失败函数不因此改成返回总错误。
- [x] **LUT 共享构造**：普通、odd-full、交错的明文/已编码输出构造及共用检查放入现有共享 LUT 层；家族入口只取得 N/t/q 并转交。去掉无价值的中间转发，保留回调顺序、失败行为和 raw 输出尺度，不引入编译器对象或参数供应 trait。
- [x] **立即修正文档契约**：修正 GLWE README 中 sparse CBS 未支持的旧描述、NTRU NTT README 中落后的 MVB 后端差异说明；补齐 NTRU NTT evaluator 的变换表示前提。所有 API 调用方和双语说明随本步迁移。

主要错误关系：

```text
TfheParameterError             → 带 BR/KS 等角色的底层参数原因
TfheContextError               → NttError / FftError
KeyGenerationError             → TfheKeyError / CircuitBootstrapParameterError
                               → SparseBootstrappingKeyError → BucketMapError
                               → NtruError（需要时）
TfheClientError                → TfheKeyError / NtruError（需要时）
BooleanError                   → TfheClientError
TfheEvaluationError            → LookupTableError
```

唯一来源使用 `#[from]`；同一 Glev/Nlev 原因用于不同角色时，用具名 variant、`map_err` 和 `#[source]` 保留上下文。普通客户端、密钥生成及在线求值保持各自的失败边界。

**验收清单**：

- [x] workspace 调用方编译通过，无过渡包装或重复别名；参数、客户端、公钥、GLWE 两种 order 及两族 CBS 绑定的原有回归通过。
- [x] 相同客户端错误在普通/稀疏生成入口归属一致；构造拒绝时机及输出行为保留，不为机械 From 转换增加测试。
- [x] LUT 中心、负循环、非二次幂明文、有效/补齐输出数和独立输出尺度回归通过；普通构造只分配最终多项式，factorized 保留连续存储契约。已有 LUT bench 已对照，性能并非全面持平，保留的构造成本见下文。

### 验收结果（2026-09-20）

- workspace all-targets、`just tfhe`、`just tfhe-simd` 与七包严格 rustdoc 通过；默认/SIMD 各 87 项测试通过。
- 原有两种 GLWE order、公私钥客户端、CBS/CMUX、稀疏和 MVB 回归通过；GLWE 同层数不同输出 basis 的高级入口保留。NTRU 已不能另传与 key 冲突的 CBS 参数。
- 共用 LUT 边界测试集中到共享层，两族保留实际客户端与独立输出 codec 的接入回归；未新增持久 benchmark target。
- **性能保留项**：最终三轮 rounded 构造对照中，Native `N=1024,t=255,k=4` 的中位数增加约 4.4%（0.06 μs）；其余五项中位数下降，但不作普遍加速承诺。未改的 raw 基准单轮仍有约 −8.0%～+7.2% 的构建间差异。保留去重实现及这些限制，不能将本步描述为零回退或 PBS 加速；方法与完整数据见[成本记录](tfhe-refactor-costs.md)。

## R2：所有权、工作区与计算整理

**目标**：在同一次设计中解决资源重复、模式配对和调用方式，避免先添加转换层再返工底层。

**入口**：四后端 `src/{context,key,blind_rotation,evaluator}.rs`、`src/evaluator/factorized.rs`、`src/circuit_bootstrap/`；GLWE `src/sparse/`、NTRU `src/sparse.rs`；共享 Boolean 的 bootstrapper 访问/回收接口。

### 一起设计和实施

- [ ] **evaluator 复用**：为 MVB/CBS 提供适合实际所有权的消费式构造、回收及受控普通操作入口，复用已有 Boolean 机制。使用固有方法，不引入每算法一对 owning/borrowed 类型或 Deref。新增能力允许构造时显式分配，日常交替执行不重新构造、不隐藏分配。
- [ ] **GLWE 按用途持有资源**：BR→KS 的 CBS 仅需 BR，独立构造时省去无用 KS context、switched GLWE 和 small-LWE；普通 BR→KS 仍保留返回 KS。KS→BR 前置 KS 不得省略。从已有普通 evaluator 转入时保留可回收资源，不丢弃后再分配；两种构造契约一起确定，不用零长度对象充当未使用工作区。
- [ ] **NTRU 材料与 scratch 配对**：构造时用一个私有枚举绑定 binary/ternary/sparse 控制及对应工作区，去掉依赖同步约定的重复分派和 sparse expect。分派在坐标循环外，保留经典零指数跳过、缓冲交换及 sparse 全桶语义。
- [ ] **GLWE sparse + CBS 密钥生成**：共用一次 accumulator 秘密变换，采用私有检查/映射准备和生成 helper；独立生成器保留完整检查。不开公开 prepared-secret 类型，不把秘密缓存进长期 Context。
- [ ] **GLWE 普通/交错 BR 共用流程**：内部合并量化、初始化、清零和控制调度，普通路径使用 step=1 和已准备量化器；保留零指数、模数相同及 step=1 快速路径，公开入口各自承担必要检查。

### 在本步内决定是否保留的试验

仅对生命周期清楚、预期能减少实际资源的候选做原型。需要复杂模式状态、扩大公共类型层或有确认时间退化时撤回，记录结论即可，不继续派生阶段。

- [ ] **GLWE 串行外积 scratch**：核对 BR 与 scheme-switch/CMUX 能否共用 [GLWE 外积 context](../crates/primus_lattice/src/context/glwe_external_product.rs)。`rebind` 只能调整允许变化的布局；ternary 合成控制仍绑定 BR basis，返回 BR 前必须恢复布局，不能暴露绕过恢复约束的可变 getter。
- [ ] **NTRU CBS scratch**：核对 BR 与 trace/automorphism 的外积空间能否共用；Fourier trace 使用系数输入时，评估省去仅供 Fourier 输入使用的 permuted 缓冲。保留既有初始化/BR/返回 KS 复用，NTT/Fourier 各自处理，不改变投影算法。

下层仅按上述真实借用需要增加局部 helper 或显式 scratch 接口；在实现前确认具体布局和长度，避免为了统一字段重构整个下层库。

**验收清单**：

- [ ] PBS→MVB→PBS、支持的 CBS/CMUX→普通 BR/PBS 交替执行、不同 BR/输出/SS basis 通过；首调用及重复在线调用零分配。
- [ ] binary/ternary/sparse 普通与 ManyLUT、受影响 CBS/MVB 回归通过；保留独立相位/整数参考、非恒定 CMUX、两 FFT 和相关 u32/u64 覆盖。
- [ ] keygen 的检查/RNG/重试/秘密擦除语义保留；实际生成材料能完成 PBS/CBS。秘密变换优化只评价 keygen，不声称加速在线 PBS。
- [ ] 对照构造分配、持有字节、完整 keygen 和完整在线调用的默认/SIMD 时间；确认退化无法消除则撤回对应优化。
- [ ] 推荐调用链没有增加需要用户同步的模式、basis 或工作区状态；试验均有保留/撤回结论，没有临时公开 API。

## R3：代码组织与使用方式收尾

**目标**：让用户从一个推荐入口学会现有能力，让维护者能定位同一职责，完成资产去重。

**入口**：七包 `src/lib.rs`、key/evaluator/sparse/MVB 模块、双语 README、examples/tests/benches、[测量索引](benchmarks/tfhe.md)。

### 实施与验收清单

- [ ] **按职责组织模块**：对齐密钥与生成、BR、普通求值、MVB 程序/执行、CBS 的组织。重点处理 NTRU sparse.rs 的密钥/执行混杂及 factorized 程序不易定位的问题；不按行数拆成小文件，不把内部 helper 升为公共 API。
- [ ] **公共入口可理解**：根入口突出 config/parameters、client/key、context、LUT 和 evaluator；低层材料通过明确模块及 rustdoc 分组查找。GLWE NTT `boolean_parameters()` 移至现有 PBS bench 支持代码，保持历史 n=512 负载，不当作安全参数推荐。
- [ ] **一份任务选择表**：共享 README 说明单函数、odd-full、交错多输出、MVB、有界双输入、Boolean、CBS/CMUX 的输入域/编码、输出类型/编码、额外密钥和资源复用方式。binary/ternary/sparse 与数值后端作为独立选择；后端 README 只补自己的限制，避免重复能力矩阵。
- [ ] **精简推荐示例**：basic 仅展示参数→context→keys→客户端→LUT→普通 PBS→复用；进阶使用现有 CBS/MVB 示例和 README。说明输入 t=16、输出 t=4 等场景的独立解码，不能互换 Scaled 标志、Boolean 密文和 CBS 控制。
- [ ] **资产按契约去重**：参数错误矩阵集中，独立数值分支、相位、selector/dummy、非恒定 CMUX 和首调用零分配保留。整理 many_lut 等测试名与实际内容不符的问题；复用现有 test-support，普通测试不加入大型统计或计时阈值。
- [ ] **基准保留独立用途**：保留 PBS/CBS/MVB/ternary/sparse 的不同工作负载，仅删重复或临时试验；不为转发函数另建 bench。记录测试整理前后数量和本机耗时，不据此承诺 GitHub CI 降幅。
- [ ] 双语章节/链接同步；推导和成本留在专项文档。修改过的 release 示例与必要 FFT 配置通过，严格 rustdoc 及 workspace all-targets 通过；无过渡导出和遗留临时资产。

## R4：全链验收与交接

**目标**：确认前三步减少了实际复杂性且保持现有能力，结束本轮整理。

- [ ] 复核最终公开类型、错误树和资源生命周期：用户应能从推荐工作流理解，不必知道内部工作区配对；没有新增同义包装抵消 R1 的收敛。
- [ ] 执行完整验证，核对现有受支持组合没有缩减；下层原语变更补对应消费者回归。
- [ ] 汇总实际保留的资源/性能变化、撤回试验及未覆盖条件。检查最终 diff、链接和临时资产，不用历史报告代替当前验证。
- [ ] 本计划压缩为最终决定和验证入口，HANDOFF 只保留有效边界与下一步；不借收尾启动新算法或下一轮全库整理。

```text
just tfhe
just tfhe-simd
cargo check --workspace --all-targets
```

另对七包运行 `RUSTDOCFLAGS="-D warnings"` 的 `cargo doc --no-deps`，运行修改过的 release 示例。
涉及 lattice、GLWE/NTRU 原语时补其检查与回归。`just tfhe-simd` 需要 nightly；无法运行的配置明确记录。

## 验证与测量的共同规则

- 实施中先窄后宽，按变化的契约检查；不在每个内部清单项后重跑全矩阵。元数据错误不乘上所有 order/FFT/分布组合，数值分支仍保留必要覆盖。
- 修改性能路径前记录直接前驱的 commit 或可复现源码状态、CPU、工具链、features、参数和命令；`cba9c01` 是结构基线，不替代各项受控对照。
- 优先已有 Criterion 负载，setup 不混入在线计时，沿用仓库 target-cpu 配置。构造看分配次数/持有字节，keygen 看完整生成，在线看完整 PBS/CBS/MVB 或消费链。
- NTT 使用精确结果，Fourier 使用独立相位参考及已有误差契约；不能用微基准代替完整调用或把统计波动称为回归/收益。
- 测量数据按需进入 `docs/benchmarks/`，方法与结论集中到 `docs/tfhe-refactor-costs.md`（首项数据产生时创建）。不创建每个内部检查点的报告。

## 暂缓项与基线证据

ManyLUT 按步长缓存量化器、factorized 编译预存几何、NTRU Fourier gadget 常数/逐层 FFT 准备仍是待证明收益的候选，不自动加入 R2。
新增算法按[候选清单](tfhe-next.md)另行选择。

计划前的只读审查覆盖七包源码及相关测试、示例、基准和双语 README，并沿依赖检查部分底层契约。
当时通过七包 `cargo check --locked --offline --all-targets`、`cargo fmt --all -- --check`、
`cargo test --locked --offline -p primus_tfhe`（17 项）；未重跑全部后端测试、SIMD 或 benchmark。
这些仅说明审查基线，不证明本轮候选优化的收益，也不替代实施验证。
