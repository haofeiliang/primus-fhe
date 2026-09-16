# Workspace 开发交接

本文只保存当前阶段、有效工作边界、未决项与恢复入口。恢复时先核对 Git 状态；历史报告中的验证结果不代表当前结果。

## 当前状态与下一步

- `primus_lattice`、`primus_lwe`、`primus_glwe`、`primus_ntru` 的既有整理和已批准原语补充基本完成；不因 TFHE 重构重新开启其整体重构。
- 七个 `primus_tfhe*` crate 的旧 S0–S9 重构与验收已完成，历史基线为 `81eb3f4`。当前新工作为 LUT/PBS 设计与 P1–P4 规划，允许有价值的大重构；不恢复旧步骤，也不把既有模块/API 选择视为永久限制。
- GLWE NTT 与两路 NTRU 已有 CBS；当前能力矩阵见 [TFHE README](crates/primus_tfhe/README.zh_CN.md)。NTRU packing 按用户决定排除，不是 CBS 的前置工作。

### 当前 LUT/PBS 任务

- 已完成：**P1.1、P1.M、P1.2 单次几何扫描与直接填充（含主循环重整收尾）**。设计和测量依据见 [TFHE 总览](docs/tfhe.md)，完成条件见 [实施步骤](docs/tfhe-plan.md)。
- 下一步：**P1.3 布局 API 与调用方完整迁移**，尚未开始；分开有效输出数与交错步长，迁移七个 TFHE crate 及实际调用方，保持 P1.1 编码/旋转和各后端秘密域契约。
- P1.2 有效边界：单输出与 ManyLUT 共用顺序主循环，中心使用虚拟坐标、填充使用实际系数切片；区间求值与负循环尾部各有私有填充函数。输出按输入优先顺序写最终多项式，没有逐列多项式、中心数组或行 scratch 分配。前半输入域、二次幂输出数、回调错误及 raw residue 检查保留。[首次构造/分配比较](docs/benchmarks/tfhe-p1.2.csv)和[主循环重整对照](docs/benchmarks/tfhe-p1.2-flow.csv)分开记录；在线 PBS 内核未改动。
- P1.M 有效边界：`RingContext` 聚合 `PrepareModulusSwitch`，`FieldContext` 继承准备能力；`PreparedModulusSwitch` 执行固定模数对的规范模切，保持独立。codec 只要求准备能力和模加法，构造时准备转换，Scaled 保持固定尺度；绝对值舍入和解码共用模切内核，批量融合符号与输出，标量包装保留各自特化路径。普通 PBS 量化在 GLWE BSK/NTRU 参数构造时准备，ManyLUT 按步长在系数循环前准备。输入与 accumulator 模数独立，描述性元数据仍可使用 `Option<T>`；Barrett 倒数求商未实施。
- 编解码输入输出统一为系数类型 `T`：codec、基础加解密和通用 TFHE client 不再转换消息类型，批量输入为 `&[T]`；应用负责转换，Boolean 保留 `bool` 和值域检查。参数构造复用 codec 校验；模数有效性由模切准备验证，codec 保留 `q > t` 和 Scaled 恢复条件。
- 有效未决项：P1.3 落实元数据字段和最终命名（语义已在 P1.1 收敛）；PBC 参数、安全/噪声条件在 P3.1 收敛；首个 MVB 算法与缩放在 P4.1 收敛。具体内容只维护在对应文档中。
- 验证：七个 TFHE crate 默认与 nightly SIMD 的 all-targets check / Clippy、各 39 项测试通过，含四后端 PBS/CBS 调用方及独立几何 oracle；格式、共享库严格 rustdoc、七包文档和 `xtask` check 通过。本步复测构造，未重新计时在线 PBS、SIMD 或非 x86 路径，也未重跑无关底层包测试；P1.4 按最终迁移范围重新验收。

## 已审范围索引

| 范围 | 恢复时应理解的边界 |
| --- | --- |
| 基础 crate | 已完整复审 data、distr、gcd、integer、reduce、modulo、modulus、barrett_derive、factor、poly、ntt、fft、rns（省略 `primus_` 前缀）；后续变化以 Git 为准。 |
| encoding / lattice | encoding 已完整覆盖，跨表示调用方按边界抽查；lattice 已覆盖类型/API/宏、算术、extraction、CMUX/外积及维护材料，并同步共享置换和 NTRU 外积工作区。 |
| LWE / GLWE / NTRU | LWE 包括私钥、公钥、batch、KS 和 Signed 路径；GLWE 包括自同构、trace/投影、packing、SS；NTRU 包括擦除、basis、常数 gadget、自同构、trace/投影、同秘密 SS，不含 packing。定向后续修改不代表再次全量复审全部依赖。 |
| TFHE | 七 crate 分析及 `f910551..38b122f` 重构改动复审已完成，覆盖 API、数学契约、调用方、测试、示例、benchmark、feature 和双语文档，未确认需修复的问题；底层按消费契约抽查，不代表重新完整审计。 |

## 当前 TFHE 工作必须保留的边界

- 普通 PBS 的输出 LWE、Boolean 内部尺度与 CBS gadget 尺度分别处理；GLWE 保留两种 order，NTRU 保留固定链。不能因 API 整齐改变秘密域和外部维数。
- GLWE BSK 从 accumulator 与 basis 派生；CBS 输出只接收 basis、从 accumulator 派生布局，trace/SS 保留完整加密参数。GLWE CBS key 绑定输出布局，NTRU CBS key 绑定完整输出 basis。
- CBS 保持可选独立参数/key/evaluator。一般 ManyLUT 不满足前缀展开的零尾前提，应走投影；NTRU CBS 留在 `f_acc` 下，不走普通 PBS 的后置 KS/extraction。
- 布局或 basis 相同不能证明实际秘密一致；Fourier table 身份、输入规范表示和噪声预算仍需遵守相应公开契约。NTT 模逆元与 Fourier 无符号整数除法不能共用误差结论。
- 不恢复 raw Ciphertext、LweBatch 或万能 domain/表示包装；复用底层已有原语。参数、布局和 basis 的检查留在拥有契约的边界。
- TFHE 公钥绑定外部 LWE 秘密：GLWE 按 order 使用 n 或 kN，NTRU 使用客户端二进制前缀。复用 LWE 公钥，不新增 NTRU 环公钥。生成直接借用 Signed/Encoded 视图；公钥总噪声及 PBS 输入余量需独立评估，不能把单项采样器当作总噪声。
- 两族三类客户端 `_to` 直接复用底层 LWE 内核，消息与维数错误先于采样/写入；输出遵循 raw LWE 的 body 布局前提。分配返回接口保留各自的高效初始化路径。

## 按需读取的技术决定

原 HANDOFF 中跨 crate 的长期决定已迁入 [实现决定参考](.agents/references/implementation-decisions.md)。按涉及的 crate/符号读取对应章节，不要求每次完整加载。

区分三类信息：用户明确的范围边界应遵守；数学前提应对照当前契约；既有实现与性能选择可在前提改变后重新验证。新证据可以支持调整实现，历史偏好不自动成为永久禁令。

## 未决项及触发条件

以下是既有未决记录，本次指令整理未重新审计这些源码；相关工作开始时应核对当前实现。

| 项目 | 当前记录 / 后续触发条件 |
| --- | --- |
| CRT Gaussian 规范编码 | `primus_glwe_rns::CrtGlweParameters::new` 对 `q_i <= floor(12σ)` 可能产生非规范 residue；处理该参数边界时核对支持集检查。 |
| GLWE RNS 测试 | `tests/glev.rs::test_key_switching` 曾仅打印解码结果；整理该 crate 时确认并补独立断言或删除重复案例。 |
| reduce 文档 | `ReduceMulAddSlice` 曾称五种 fused 形态都需要而生产调用只有三种；crate 概览漏列 `reduce_once`、double、mul-add。整理该 crate 时核对。 |
| NTRU SS/CBS 参数与安全 | f/f² 误差放大、KDM/circular-security 假设及生产失败概率需要独立论证，功能测试不构成证明。 |
| 恒时与平台 | 未做全库恒时证明或非 x86 全量验证；拒绝采样/逆元不承诺恒时，平台内核变化后须针对性验证。 |

## TFHE 可选扩展

这些项目未实施，也未自动纳入当前 P1–P4 的交付；仅在具体需求明确后启动：

- Fourier GLWE CBS、NTRU Boolean：分别复用已有 trace/SS 原语和 Boolean 编码/仿射逻辑，保留表示与尺度差异，补端到端验证。
- batch client/PBS、PBS `_assign`：分别面向多个独立输入和链式原地求值；复用 evaluator，明确布局检查及覆盖输入前的依赖，不用 clone 隐藏分配。
- ServerKey 存储量查询：用于替换 `xtask/src/ntru_params.rs` 的手写公式；明确系数存储、allocator 占用与 CBS live heap 的区别。

独立 KSK 噪声、完整整数/message-carry 类型层继续等待明确需求。原先暂缓 ManyLUT 临时列优化的选择已由当前 P1 计划替代；family LUT 包装按真实职责重新评估，输出数量与交错步长在 P1 一并分离。序列化、GPU、多位 BR 不属于当前四阶段的必要交付。

## 验证与恢复入口

- [justfile](justfile)：`just tfhe` 覆盖七包默认 check / Clippy / test / doc 及 `xtask` check；`just tfhe-simd` 覆盖七包 nightly SIMD check / Clippy / test。`just ci` 覆盖 workspace 检查及两组 SIMD；原 `just simd` 仍只覆盖六个底层包。示例与 Criterion 命令见各后端 README。
- 修改外积时还应覆盖 lattice、NTRU 及两路 NTRU TFHE；性能复测使用相应外积、NTRU primitives 和 TFHE PBS/CBS 基准，固定参数、CPU、工具链和 feature。
- 公开接口入口：[LWE](crates/primus_lwe/README.zh_CN.md)、[GLWE](crates/primus_glwe/README.zh_CN.md)、[NTRU](crates/primus_ntru/README.zh_CN.md)、[lattice](crates/primus_lattice/README.zh_CN.md)、[TFHE 能力与各层入口](crates/primus_tfhe/README.zh_CN.md)。

### S9 验收摘要（2026-09-15）

在 x86_64 Linux、stable 1.98.0 / nightly 1.100.0 下，七包默认/SIMD 测试各 36 项、workspace nextest all-targets 1470 项（含 Criterion 冒烟）、六包 SIMD nextest 392 项、LWE/GLWE SIMD 测试 50 项均通过；相关 check、Clippy、格式、严格 rustdoc 和六个示例的两配置运行通过。未重做性能计时、非 x86 验证或生产噪声/安全证明。

详细实施与 S6 性能记录保留在 Git 历史；当前验证应按改动重跑，benchmark 冒烟不代表性能结论。
