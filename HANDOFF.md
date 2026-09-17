# Workspace 开发交接

本文只保存当前阶段、有效工作边界、未决项与恢复入口。恢复时先核对 Git 状态；历史报告中的验证结果不代表当前结果。

## 当前状态与下一步

- `primus_lattice`、`primus_lwe`、`primus_glwe`、`primus_ntru` 的既有整理和已批准原语补充基本完成；不因 TFHE 重构重新开启其整体重构。
- 七个 `primus_tfhe*` crate 的旧 S0–S9 重构与验收已完成，历史基线为 `81eb3f4`。当前新工作为 LUT/PBS 设计与 P1–P4 规划，允许有价值的大重构；不恢复旧步骤，也不把既有模块/API 选择视为永久限制。
- GLWE NTT 与两路 NTRU 已有 CBS；当前能力矩阵见 [TFHE README](crates/primus_tfhe/README.zh_CN.md)。NTRU packing 按用户决定排除，不是 CBS 的前置工作。

### 当前 LUT/PBS 任务

- 已完成：**P1.1、P1.M、P1.2、P1.3、P1.R、P1.4、P2.1、P2.2、P2.3、P3.1、P3.2、P3.3、P3.4、P3.5、P4.0**。设计和测量依据见 [TFHE 总览](docs/tfhe.md)，完成条件见 [实施步骤](docs/tfhe-plan.md)。
- 进行中：无；本步剩余：无。下一步 **P4.1 MVB 算法与编码选型**，入口见实施步骤。
- P4.0 有效边界：共享量化公开为 `rotation::RotationQuantizer`，一次性模切包装删除；`bootstrap` 仍为普通/交错两个小 trait。四后端分开 BR 与后置 KS，BR 总是保留 accumulator 秘密下的系数域环密文，现有工作区、两种 order、经典/稀疏分派及零分配契约保持。阶段 helper 暂留私有，MVB 按选定算法接入；ternary 后续一起处理控制密钥、剩余类到有符号秘密的转换及参数兼容性，automorphism 暂不实现，当前 binary 限制及稀疏 CBS 拒绝保持。见 [P4.0 决定与测量](docs/tfhe.md#p40-共享旋转契约与后端执行阶段)。
- P3.1 有效边界：首版 GLWE NTT、一般固定重量二元实际 BR 秘密；实验参数组为每索引 3 个不同桶、桶数 `2h`、私有完整匹配，固定秘密最多尝试 8 个独立映射。首版 BSK 按桶保存系数域选择 GGSW 和独立 dummy；P3.3 逐桶聚合、转 NTT、一次外积，复用现有量化和 LUT。失败上界、条件联合分布、误差递推、存储与两组参数只维护在专项文档；8 轮耗尽概率不等于公开映射的统计距离。两种 order/普通交错 LUT 已在 P3.5 验收，CBS 等扩展未承诺。
- P3.2 有效边界：NTT `KeyGenerator::try_generate_sparse_bootstrapping_key` 从 client 的 small-LWE 固定重量二元秘密生成独立 `SparseGlweBootstrappingKey<T>`。公开桶映射为 CSR，`bucket(j)` 借用递增索引及对应系数 GGSW，最后额外含 dummy。实际系数/重量、桶参数和长度先验证；先直接占用空闲候选桶，冲突时以桶为节点搜索并逆向搬移；内部直接保存原始输入索引，三个私有缓冲区复用，固定秘密最多重试八次，成功后才分配密文并逐桶批量加密/原地 inverse NTT。私有支持集、匹配及选择位会擦除，未保存明文位置；没有新增参数包装/策略 trait；完整 ServerKey/evaluator 接入见 P3.5。
- P3.3 有效边界：独立 `SparseGlweBootstrappingKey::ntt_blind_rotate_lookup_table_to` 接收 small-LWE 和已编码多项式，输出 accumulator 秘密下的系数域 GLWE；普通量化器随 key 准备，`SparseGlweBlindRotationContext::new(&key)` 建立可复用工作区。`RotationQuantizer::exponent_slice_to` 批量量化到已有指数工作区、从真实 LUT 初始化、逐桶累加旋转副本与 dummy、整体 NTT、每桶一次外积，在线零分配。小环全指数和同秘密经典对照通过；完整 PBS、两种 order 的 KS/提取与交错步长已在 P3.5 接入，CBS 未承诺。见 [P3.3 实现与验证](docs/tfhe-sparse-pbs.md#p33-参考盲旋转实现与验证)。
- P3.4 有效边界：保持系数域 BSK、缓存输入指数和逐桶 NTT/外积；dummy 复制初始化，整多项式按约 16 KiB 分块聚合，同一缓冲区原地转 NTT。成本组工作区从 125 KiB 降为 77 KiB，在线零分配；没有新增公开接口或密钥预计算。三段旋转切片、延迟约简及其他无稳定收益的原型未保留。历史原始 BR 四项基准已在 P3.5 替换为完整 PBS；分项/内存与默认/SIMD 原始 BR 测量见 [P3.4 记录](docs/tfhe-sparse-pbs.md#p34-聚合表示与工作区测量)。
- P3.5 有效边界：`try_generate_sparse_server_key` 配对 sparse BSK 与既有 KSK；`ServerKey::bootstrapping_key` / `into_parts` 使用公开 `BootstrappingKey::{Classic, Sparse}`。原生成入口保持经典。Evaluator 只分配所选 BR 工作区并在 BR 入口分派一次，共用 LUT/codec、KS、提取及边界检查；两种 order 的稀疏条件都绑定 small-LWE，外部维数仍为 n/kN。普通/三输出四槽交错、不同输出尺度、秘密域与在线零分配已验收；CBS 构造明确返回 `UnsupportedSparseBootstrapping`。历史 n=512 成本组完整 PBS 耗时约减少 30%–37%，小组更慢；该组稀疏 server key 约 75.1 MiB、evaluator 114,692 B，keygen 约慢 3.7 倍。当前常驻基准按用户要求改为 n=728，其余参数不变；默认/SIMD 完整 PBS 的重构前后计时见 P4.0，不更新历史 n=512 的 keygen/内存结论。完整测量与有限样本边界只维护在 [P3.5 验收](docs/tfhe-sparse-pbs.md#p35-完整-pbs-接入与验收)，不推导生产安全或完整失败率。
- LUT 源码边界：三个公开类型统一从 `lookup_table` 导出，`single.rs` 集中 `LookupTable` 的全部 API，`interleaved.rs` 管理输出布局，`bivariate.rs` 绑定输入打包；`compile/` 分别实现前半区与奇数全域。编码/域/槽容量在编译入口检查，中点与负循环尾部填充共用。奇数全域仍是单输出构造方式；隐藏 helper 改名为 `front_half_domain_len`，family/CBS 调用方已同步。命名区分 `input_ciphertext_modulus` 与 `coefficient_modulus`、布局 `padded_output_count`（补齐输出数）/`coefficients_per_output`（每输出系数数）与执行端 `rotation_step`；CBS 使用 `lookup_table_padded_output_count()`，旋转量化统一使用 `rotation::RotationQuantizer`。见 [源码组织](crates/primus_tfhe/README.zh_CN.md#源码组织)。
- P2.3 有效边界：`LookupTable::try_new_odd_full_domain` 与两族/四后端的 `compile_odd_full_domain_lookup_table_fn/slice` 支持单输出整个 `0..t_in`，要求奇数 `t_in>=3`、`t_in<=N`、真实折叠中心不碰撞。回调按折叠中心顺序访问，切片按输入顺序；上半区取负及 `N` 处的 `-f(0)` 处理负循环符号和回绕。输入用普通 unsigned `encrypt`，输出沿用 P2.1 codec；复用原 LUT 元数据、密钥和 evaluator，无在线分支/分配。交错与双输入编译仍用前半区。几何余量不构成完整 PBS 失败概率。见 [P2.3 决定](docs/tfhe.md#p23-奇数明文模数全域)。
- P2.2 有效边界：共享 `BivariateLookupTable<T, M>` 绑定普通 LUT、基数 `B` 与模数，编译矩形域 `0..B × 0..R`，要求正域且 `B*R <= ceil(t_in/2)`。两输入用同一 unsigned rounded codec 和外部秘密；`pack_to` 一遍模乘加写 `lhs+B*rhs`，调用方复用打包缓冲区再调用现有普通 PBS。输入误差为 `e_x+B*e_y+rho`，`rho=E(x)+B*E(y)-E(x+B*y)`；噪声余量是调用前提，容量检查不证明解密成功。输出 codec、秘密域与 P2.1 一致，不新增后端执行接口或密钥。见 [P2.2 决定](docs/tfhe.md#p22-有界双输入-pbs)。
- P2.1 有效边界：两族参数/四后端 context 的四个普通 LUT 编译方法显式接收输出 `RoundedCodec`，输入参数只决定输入域和旋转中心；输出值域按 codec 的 `t_out` 检查，codec 的密文模数必须等于 accumulator。当前完整 PBS 链仍保持同一密文模数，允许不同明文模数/尺度。两族 client 新增 `decrypt_phase`，由调用方的输出 codec 解码；`decrypt` 仍用参数 codec。原尺度调用方显式传入参数 codec，raw Boolean/CBS 入口与 LUT 元数据不变。下一次 PBS 的输入编码必须匹配上一输出，context 不从 raw 密文推断编码。见 [P2.1 决定](docs/tfhe.md#p21-输入与输出编码分离)。
- P1.R 有效边界：PBS 参数、LUT 与 quantizer 均要求 `2N` 能由输入系数类型表示；quantizer 的 Native 目标分支已删除，Native 输入及通用模切的 Native 目标保留。均匀二元 `u32` 居中原型的所测量化方差约减半，完整 PBS 未观察到明确开销增加；固定 half-shift 存在合法 LUT 的零噪声反例，正式执行/API 保持原样。后续模切内核优化保持统一接口；PBS 批量融合未见稳定收益，临时入口与后端原型已删除。实验方法、数据与后续接入条件只维护在总览，临时原型不进入公共库。
- P1.3 有效边界：公开类型为 `LookupTable` / `InterleavedLookupTable`，已编码输出通过各自 `try_new` 构造；旧自由函数和 `ManyLookupTable` API 已删除。保存真实输入前缀 `D` 和有效数量 `k`，补齐输出数 `s=next_power_of_two(k)` 由 `padded_output_count()` 推导；编译器补零槽，回调/切片及输出只包含 `k` 列。四后端 BR 按 `s` 量化、按 `k` 提取，三路 CBS 以 gadget 层数构造并保持原布局/basis 绑定。Family/context 保留明文检查与编码职责，多输出 trait 明确限定为 `ProgrammableBootstrapInterleaved`。
- P1.2 有效边界：单输出与交错表共用顺序主循环，中心使用每输出系数坐标、填充使用实际系数切片；区间求值与负循环尾部各有私有填充函数。输出按输入优先顺序写最终多项式，没有逐列多项式、中心数组或输出组 scratch 分配。前半输入域、回调错误及 raw residue 检查保留。[首次构造/分配比较](docs/benchmarks/tfhe-p1.2.csv)和[主循环重整对照](docs/benchmarks/tfhe-p1.2-flow.csv)分开记录；最终同配置比较见 [P1.4 验收](docs/tfhe.md#p14-阶段验收)：所测多输出构造耗时下降 61.6%～85.6%，全部只分配最终多项式；单输出构造增加约 12～24 ns，在线 PBS 未见稳定整体加速，NTT 存在几个百分点的退化信号。
- P1.M 有效边界：`RingContext` 聚合 `PrepareModulusSwitch`，`FieldContext` 继承准备能力；`PreparedModulusSwitch` 执行固定模数对的规范模切，保持独立。codec 只要求准备能力和模加法，构造时准备转换，Scaled 保持固定尺度；绝对值舍入和解码共用模切内核，批量融合符号与输出，标量包装保留各自特化路径。普通 PBS 量化在 GLWE BSK/NTRU 参数构造时准备，ManyLUT 按步长在系数循环前准备。输入与 accumulator 模数独立，描述性元数据仍可使用 `Option<T>`；紧凑范围内的模切已按分子宽度使用倒数求商和一次精确修正；Barrett/派生 Barrett 复用已有倒数，公共准备/执行接口不变。
- 编解码输入输出统一为系数类型 `T`：codec、基础加解密和通用 TFHE client 不再转换消息类型，批量输入为 `&[T]`；应用负责转换，Boolean 保留 `bool` 和值域检查。参数构造复用 codec 校验；模数有效性由模切准备验证，codec 保留 `q > t` 和 Scaled 恢复条件。 单模数 codec 的明文模数访问器统一为 `plaintext_modulus()`；`RoundedCodec` 的密文模数访问器为 `ciphertext_modulus()`，workspace 调用方已同步。
- 有效未决项：P3 的实验方案已收敛，但固定重量/补零目标/evaluation keys 的生产安全、成功映射条件分布的影响和完整 PBS 尾界仍未认证；不得用功能测试关闭。首个 MVB 算法与缩放在 P4.1 收敛。居中/shifted 的正式接入和带辅助密钥的漂移抑制为后续候选，不构成 P1–P4 的隐含交付。具体内容只维护在对应文档中。
- 测试/基准有效边界：P3.2 保留两个私有匹配测试、两个稀疏 key 集成测试；P3.3 只新增一项表驱动 BR 集成测试，覆盖小环全指数、公开空桶、奇偶桶数、k=2、截断 basis、真实加密输入、输出写入前拒绝和零分配；P3.4 将加密场景改为 k=2 以覆盖跨块及较短尾块，不增加测试数。ManyLUT 使用代表性消息与 `k=1/3/4`，三路 CBS 使用三层和 `1→0`；两种 GLWE order、两种 FFT 和错误边界保留。P2.3 增加两个共享整数 oracle/拒绝测试，将既有四后端 fixture 改为 `15→8` 并遍历全域，共增加 135 次小参数 PBS，不增加 keygen 或测试程序。P2.2 的两个打包输入继续复用同一 fixture。P3.5 新增一项完整 sparse PBS 测试，CBS 拒绝复用现有 fixture；成本组 8 项完整 PBS、2 项 keygen 替换原始 BR 四项基准，Criterion 为 9 个 target、107 项。小组/内存/相位与匹配诊断不进入常驻测试或基准；GitHub CI 未执行 benches。
- 当前验证：P4.0 的 `just tfhe`、`just tfhe-simd` 通过，七包默认/nightly SIMD 各 51 项测试，包含普通/交错、Boolean、CBS、稀疏 PBS 与零分配断言；相关 all-targets check/Clippy、严格私有 rustdoc、workspace all-targets check、格式和 diff 检查通过。现有 Criterion 完成 52 组重构前后对照及两项波动 case 的两轮复测，未观察到稳定退化；未新增测试或 benchmark case，数据见 P4.0 记录。未重跑全 workspace 数值测试、非 x86 或生产安全/完整尾概率验证。

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

独立 KSK 噪声、完整整数/message-carry 类型层继续等待明确需求。原先暂缓 ManyLUT 临时列优化的选择已由当前 P1 计划替代；family LUT 包装保留检查/编码职责，输出数量与交错步长已在 P1.3 分离。序列化、GPU、多位 BR 不属于当前四阶段的必要交付。

## 验证与恢复入口

- [justfile](justfile)：`just tfhe` 覆盖七包默认 check / Clippy / test / doc 及 `xtask` check；`just tfhe-simd` 覆盖七包 nightly SIMD check / Clippy / test。`just ci` 覆盖 workspace 检查及两组 SIMD；原 `just simd` 仍只覆盖六个底层包。示例与 Criterion 命令见各后端 README。
- 修改外积时还应覆盖 lattice、NTRU 及两路 NTRU TFHE；性能复测使用相应外积、NTRU primitives 和 TFHE PBS/CBS 基准，固定参数、CPU、工具链和 feature。
- 公开接口入口：[LWE](crates/primus_lwe/README.zh_CN.md)、[GLWE](crates/primus_glwe/README.zh_CN.md)、[NTRU](crates/primus_ntru/README.zh_CN.md)、[lattice](crates/primus_lattice/README.zh_CN.md)、[TFHE 能力与各层入口](crates/primus_tfhe/README.zh_CN.md)。

### S9 验收摘要（2026-09-15）

在 x86_64 Linux、stable 1.98.0 / nightly 1.100.0 下，七包默认/SIMD 测试各 36 项、workspace nextest all-targets 1470 项（含 Criterion 冒烟）、六包 SIMD nextest 392 项、LWE/GLWE SIMD 测试 50 项均通过；相关 check、Clippy、格式、严格 rustdoc 和六个示例的两配置运行通过。未重做性能计时、非 x86 验证或生产噪声/安全证明。

详细实施与 S6 性能记录保留在 Git 历史；当前验证应按改动重跑，benchmark 冒烟不代表性能结论。
