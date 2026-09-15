# TFHE LUT 与 PBS 设计

本文保存设计依据、职责边界和待决问题；实施任务见 [实施步骤](tfhe-plan.md)，稀疏方案见 [稀疏 PBS](tfhe-sparse-pbs.md)。当前进度只记录在 [HANDOFF](../HANDOFF.md)，不在多份文件中维护状态。

分析基线为 `81eb3f4`（2026-09-15）。旧 S0–S9 已结束，本轮使用 P1–P4 编号。这里的类型名称是设计建议，尚不是已实现的 API。允许有价值的破坏性 API 变更，并须完整迁移调用方。

## 设计目标与范围

优先保证数学正确性、在线执行的分配与性能，再改善 API 和实现可读性。共享库围绕以下边界组织：

| 层 | 拥有的职责 |
| --- | --- |
| 应用层 | 整数/布尔语义、有效范围、message/carry、多输入打包和执行图 |
| `primus_tfhe` | 公开 LUT 编译、输入到旋转位置的规则、布局元数据、小型功能接口 |
| GLWE/NTRU、NTT/Fourier 后端 | 累加器初始化、BSK、盲旋转策略、表示变换、scratch、密钥切换和后处理 |

本轮优先公共 LUT、基础功能入口、稀疏 GLWE NTT 和一种具体 MVB。其他 full-domain、tree、multi-bit、摊销方案是候选扩展，不要求全部实现后才能验收。§5 Binary-NTT shallow 方案单独研究。

## 当前实现中已确认的设计问题

| 现状 | 影响与处理方向 |
| --- | --- |
| `output_count` 同时表示有效输出数和交错步长 | 区分逻辑数量 `k` 与物理步长 `s`；CBS 已有 3 个有效输出占 4 个槽的需求 |
| Many 编译逐列调用单输出编译器 | 产生最终多项式加每列临时多项式的 `k + 1` 次分配，并重复计算几何；改为一次几何扫描、直接写最终缓冲区 |
| 输入域默认固定为 `ceil(t/2)` | 保留当前前半区语义，同时显式表达真实有效域；奇数模数全域另行实现与验证 |
| 编译产物缺少真实域和布局的完整表达 | 保存执行、兼容性检查和后续组合实际需要的紧凑元数据 |
| `ManyLookupTable` 名称覆盖面大于实际算法 | 当前实现是交错式 PBSManyLUT，不能用它承载所有 MVB 算法 |

几何计算可以从约 `O(kD)` 降为 `O(D)`；函数求值仍为 `O(kD)`，系数填充仍为 `O(N)`。这些首先影响 LUT 构造，不能据此宣称在线 PBS 加速。构造成本使用 [共享 Criterion benchmark](../crates/primus_tfhe/benches/lookup_table.rs) 单独测量，P1.1 基线见下文。

源码入口：

- [共享 LUT](../crates/primus_tfhe/src/lookup_table.rs)：类型、域检查和编译。
- [旋转量化](../crates/primus_tfhe/src/backend_support.rs)：普通与 windowed modulus switch。
- [PBS trait](../crates/primus_tfhe/src/bootstrap.rs)：公共功能契约。
- [GLWE NTT CBS](../crates/primus_tfhe_glwe_ntt/src/circuit_bootstrap/evaluator.rs)：有效输出补齐与投影的实际调用方。

## 必须保留的数学和执行契约

1. **精确编码路径。** 当前中心由 `message → RoundedCodec → modulus switch` 得到；未经证明不能替换成理想化的单次舍入公式。编译与执行必须采用一致的符号、舍入和回绕约定。
2. **输入域与布局。** 区分明文模数 `t`、真实有效域长度 `D`、环维数 `N`、有效输出数 `k` 和交错步长 `s`。首版交错布局取 `s = next_power_of_two(k)`，输出提取位置为 `0..k`，其余槽集中补齐。
3. **容量与可解码区间。** `D <= N/s` 只是交错布局的容量条件，还须检查实际编码中心冲突。区间宽度不是完整 PBS 的失败概率证明。
4. **负循环边界。** 非均匀中心、奇数模数、负相位回绕、短前缀域的边界必须有局部依据；未编程区域不成为新的有效输入域。
5. **输入与输出编码。** 输入 LWE 模数与累加器模数独立；普通编码输出与 raw 已编码输出都保留。Boolean 内部尺度、CBS gadget 尺度不能被统一为普通消息编码。
6. **秘密和后处理。** GLWE 保留 BR→KS 与 KS→BR 两种顺序及对应外部维数；NTRU 保留既有固定链与 NLev[1] 初始化。稀疏性作用于真正执行 BR 的秘密。
7. **CBS。** 保持独立可选的参数/key/evaluator，保持 key 对布局/basis 的绑定；一般 ManyLUT 不满足前缀展开的零尾前提。NTRU CBS 保持在累加器秘密下。
8. **检查与工作区。** 在拥有契约的公开边界检查；内部几何扫描和逐系数 kernel 不逐层重复验证。不强制所有后端为旋转量新分配数组。

这些契约不要求保留现有模块结构。具体公开契约最终应落在 rustdoc/README，局部算法理由应落在源码；本文只维护跨层设计。

## PBS 能力与算法分类

| 能力/策略 | 价值与规划 |
| --- | --- |
| 单输入、单输出 PBS | 基础工作流，P1 保持并整理 |
| 交错 PBSManyLUT | 一次 BR 后多次提取；P1 分离 `k` 与 `s` |
| MVB | 同一输入计算多个函数，共享昂贵部分；P4 选择具体算法 |
| 双输入 PBS | `z = x + B*y` 后查表，适合有界比较、进位、小整数函数；P2 提供入口 |
| Full-domain PBS | P2 处理奇数模数的特定构造；其他全域算法另立需求 |
| 多数字、大 LUT、tree/LFBS | 需要加密 LUT、packing 或外积树等组合能力；P4 后按具体应用推进 |
| CBS | 已有三路，P1 完整迁移；允许环密文中间结果继续组合 |
| batch PBS | 多个独立输入的调度与复用；与密码学摊销算法分开 |
| Multi-bit / automorphism BR | 盲旋转执行策略，涉及密钥大小、并行性等权衡 |
| 稀疏 BR | P3 首先实现 GLWE NTT 固定重量二元版本，LUT 不感知桶结构 |
| Amortized bootstrapping | 改变密文组织与密码学计算；不是在循环外套 batch API |

### 交错 ManyLUT 与 MVB

交错 ManyLUT 将多个函数写入同一多项式，并将旋转量限制为 `s` 的倍数。它共享 BR，但输出槽增加会降低有效旋转分辨率。

一种 MVB 路线将各输出多项式写为 `P_i(X) = V(X) * W_i(X)`：先对共同的 `V` 做 BR，再分别乘公开多项式 `W_i` 并提取。它不必采用 `N/k` 的交错布局，但每个输出增加公开多项式乘法，噪声受其范数影响，输出共享部分噪声来源。

MVB 还存在基于 BR 展开的路线。因此编译产物应由选定算法决定。论文里的 `1/2` 也不能直接当作 native `2^w` 环中的模逆元；P4 必须先明确缩放、整除与误差处理。

### 双输入与全域

对于 `0 <= x < B`、有界 `y`，可用 `F(x + B*y) = f(x,y)`。调用层负责容量、共同编码尺度、线性组合误差和输入范围；不能仅因整数索引可打包就假定实际密文编码一致。

奇数明文模数可使用带符号的中心折叠编程全域，代价包括更窄的有效区间。必须以真实 codec 和模切中心验证构造。其他 full-domain 情形可能需要多阶段算法，不能只增加一个不区分数学前提的布尔选项。

## 公共 API 的设计方向

- 集中编译配置和几何扫描，复用 `RoundedCodec`；没有跨 LUT 复用需求时，不永久保存中心数组。
- 单输出可复用步长为 1 的编译核心。按输入行求值并直接填最终布局，不再逐列分配多项式；必要的短行 scratch 只分配一次。
- 普通 LUT 和交错 LUT 保存各自必要的域、模数和布局信息；`InterleavedLookupTable` 是建议名称。
- MVB 程序与加密 LUT 使用各自实际表示，不在普通 LUT 中堆积可选字段。
- 小型普通 PBS trait 可以保留。多输出 trait 描述结果和调用契约，不将“一次 BR、一次环 KS”承诺给所有未来算法。
- 通用接口的扩展由第二个真实实现/调用方驱动；不先设计万能 backend trait，也不预设必须增加编译器对象、缓存或 `*_to` API。
- 保留后端可用的环密文阶段，为 CBS、MVB 和未来加密 LUT 组合服务；不强行统一 GLWE/NTRU 的初始化与后处理。

## 开工前需收敛的问题

| 问题 | 收敛位置 |
| --- | --- |
| LUT 的具体字段与检查边界 | P1.1 的语义决定见下文；P1.3 实现并完整迁移调用方 |
| 类型/方法最终命名、family 包装是否还有独立职责 | P1.3，完整迁移后不留无用途兼容层 |
| 任意 `k` 与 stride 补齐 | P1.3 完成，不再作为 P2 的重复任务 |
| 奇数全域在实际参数下的中心分离与误差余量 | P2.3，条件不足的参数明确拒绝 |
| PBC 桶数、复制数、失败重试和安全/噪声条件 | P3.1，见专项文档；不能用经验成功率代替论证 |
| 首个 MVB 算法、适用模数和输出编码 | P4.1，先确认因子分解与误差，再定编译产物 |
| 大 LUT、Fourier/三元/NTRU 稀疏移植 | 由应用或实测触发，分别补充方案 |

## P1.1 的精确契约与元数据决定

几何公式及边界已归位到 [共享 README](../crates/primus_tfhe/README.zh_CN.md)、[编译模块](../crates/primus_tfhe/src/lookup_table.rs) 与 [量化 helper](../crates/primus_tfhe/src/backend_support.rs)。编译时中心经历编码和模切两次舍入；例如 `N=16, s=1, t=3, q_in=5, m=1` 得到中心 13，理想化的一次舍入会得到 11，且两者填充边界不同。

当前执行采用 `R_s(x) = s*R(x,q_in,2N/s)`，先缩小量化域再乘步长；各系数独立量化后，总旋转为 `-R_s(b) + ΣR_s(a_i)*secret_i`。当前合法 `s <= N`，虚拟旋转域至少有两个位置；不要求 helper 支持没有调用方的单位置退化域。

| 语义信息 | 保存/计算决定（P1.3 落实布局 API） |
| --- | --- |
| `N` | 从多项式长度得到，不重复保存可失配的长度字段 |
| `t, q_in, q_acc` | 继续保存，分别绑定输入编码、旋转量化与系数算术 |
| `D` | 应保存真实编程前缀长度，不能仅用 `ceil(t/2)` 推断；用于公开范围契约及组合，不声称能从 raw LWE 检查真实消息 |
| `k, s` | 保存有效输出数 `k`；首版固定 `s=next_power_of_two(k)`，可推导步长，不强制保存两份冗余数值；两者数学角色必须分开 |
| 中心、区间与临时行 | 构造期计算即可，不保存在 LUT 中，不引入持久中心数组 |
| 输出尺度、实际秘密、变换身份 | raw 输出尺度由调用工作流说明；不作为通用 LUT 兼容性检查的一部分。秘密与变换身份由后端/调用方承担 |

四后端已核对到量化、初始化与提取入口：

| 路径 | 实际消费契约 |
| --- | --- |
| GLWE NTT / Fourier，BR→KS | 使用 small-LWE 输入模数；平凡 GLWE 初始化，BR 后环 KS，提取各输出的 compact LWE |
| GLWE NTT / Fourier，KS→BR | 外部 LWE 先逆提取和环 KS 成 small LWE，再使用相同 BR 量化；最后提取完整 LWE |
| NTRU NTT / Fourier | 使用 external-LWE 输入模数；旋转 LUT 后经 NLev[1] 初始化，BR 后 KS 至客户端秘密，再 compact extraction |
| CBS 消费布局 | 有效 gadget 数可能小于物理槽数；布局/basis 绑定和一般投影前提保持，普通 PBS 的后置 KS 不自动套入 CBS |

[独立 oracle](../crates/primus_tfhe/tests/lookup_table.rs) 使用 u128 比例舍入、逐项负循环旋转和最近中心搜索，不调用生产 codec 或旋转原语计算期望值。覆盖 u16/u32/u64、Native/显式模数、完整小环、短域、raw 尺度、舍入中点/回绕、相邻中心及终止中心碰撞。它验证几何和量化，不证明完整 PBS 的噪声失败概率。

## P1.1 性能基线

2026-09-15，生产编译算法与 `7526ada` 相同；本步新增构造 harness、契约和 oracle，尚未进行 P1.2 优化。[28 项数据](benchmarks/tfhe-p1.1.csv) 保存 Criterion mean 与 95% 置信区间，单位 ns；10 项为构造，18 项为在线单输出/4 输出。它们是后续同配置回归的参照，不是跨后端同安全强度比较。

- 环境：x86_64 Linux，AMD Ryzen 9 9955HX3D，固定 CPU 0；governor 为 powersave，boost 开启，未隔离该 CPU 或关闭 SMT。
- 工具链：rustc 1.98.0（88d9e12ae），cargo 1.98.0；默认 features，无 nightly SIMD。使用仓库构建配置。
- 依赖：Criterion 0.8.2、rand 0.10.2、RustFFT 6.4.1、tfhe-fft 0.10.1。后续依赖或环境变更应重测基线。
- 采样：每项 10 samples、1 s warm-up、3 s measurement；各 benchmark 顺序执行，不并行计时。
- 构造：u32、N=1024，Native 或 Barrett `q=132120577`，`t/k` 为 `4/4, 16/1, 16/4, 16/16, 255/4`；计入验证、几何、分配、填充和结果释放。
- 在线：沿用四后端 `benches/pbs.rs`，seed=42，N=1024、t=4；GLWE small-LWE 维数 512，NTRU 为 800，详细秘密分布/分解/噪声参数以各 fixture 为准。覆盖 GLWE 两种 order 和 Fourier 两种 FFT；复用 key、LUT、scratch 和输出，计时不含 setup。在线 ID 的 `k1` 指 GLWE 维数，输出数看 `many_4` 字段。

复测命令：

```sh
taskset -c 0 cargo bench -p primus_tfhe --bench lookup_table -- --sample-size 10 --warm-up-time 1 --measurement-time 3 --save-baseline p1_1 --noplot
taskset -c 0 cargo bench -p primus_tfhe_glwe_ntt -p primus_tfhe_glwe_fourier -p primus_tfhe_ntru_ntt -p primus_tfhe_ntru_fourier --bench pbs -- 'complete_pbs_(reused_output|many_4_reused_outputs)$' --sample-size 10 --warm-up-time 1 --measurement-time 3 --save-baseline p1_1 --noplot
```

P1.2 比较时将 `--save-baseline p1_1` 改为 `--baseline p1_1`，避免覆盖原样本。原始 Criterion 数据位于 `target/criterion/**/p1_1/`，可能被清理；CSV 是持久摘要。原样本缺失时应使用 P1.1 提交的源码和 harness 重建，不能把 CSV 当成 Criterion 样本输入。记录没有分配计数，计时 benchmark 也未插入全局 allocator 计数开销。

## 文献入口与证据边界

以下为本轮分析使用的代表性一手资料，不是“出现次数最多”的文献排名。正式实现应读取对应算法、参数和证明部分；摘要不能代替推导。

| 主题 | 来源 |
| --- | --- |
| PBSManyLUT / CBS | [ASIACRYPT 2021](https://www.iacr.org/archive/asiacrypt2021/130900334/130900334.pdf) |
| MVB 电路合成 | [TCHES 2024](https://ches.iacr.org/2024/papers-issue-4/4_98.pdf) |
| 奇数全域、因子分解 MVB、AES | [Hippogryph，§2.2.3、§3.1.2](https://www.nicolasbon.com/assets/pdf/25Hippogriph.pdf) |
| BR 展开与 MVB | [MOSFHET](https://eprint.iacr.org/2022/515) |
| 多数字 LUT 应用 | [8-bit TFHE processor](https://eprint.iacr.org/2024/1201) |
| 递归 LUT 的 FDFB | [SAC 2025](https://eprint.iacr.org/2025/1255) |
| External Product Tree / LFBS | [2025/022](https://eprint.iacr.org/2025/022) |
| CBS 改进 | [EUROCRYPT 2024](https://eprint.iacr.org/2024/323) |
| Multi-bit PBS | [TFHE-rs 官方指南（0.8 版本）](https://docs.zama.org/tfhe-rs/0.8/guides/parallelized_pbs) |
| Automorphism BR | [LMKCDEY](https://eprint.iacr.org/2022/198) |
| 摊销 bootstrapping | [CCS 2025](https://eprint.iacr.org/2025/686)、[TCHES 2025 incomplete NTT](https://eprint.iacr.org/2025/696) |
| 稀疏与 shallow PBS | [本地论文](../temp/2026-1730.pdf)，推导位置和校勘见 [专项文档](tfhe-sparse-pbs.md) |

基线分析完整覆盖共享库源码、测试与双语文档，定向跟踪四路普通/Many PBS、Boolean 和三路 CBS。底层算术与论文安全证明未重新完整审计。历史 check/test 通过不作为后续步骤的验收；性能收益需按当前修改实测。

## 文档维护

- 恢复时只需读 HANDOFF、本文的相关契约和当前步骤；进入 P3 才必须加载稀疏专项文档。
- 实施中收敛的跨层决定替换本文待决项；不追加聊天记录，不把候选方案写成已实现能力。
- 已完成步骤由 Git 记录实现，HANDOFF 保留完成编号、当前步骤、未决项和下一步。完成本轮后，将长期契约归位并删除失效计划。
- 规划文件随项目维护，源码链接使用相对路径。`temp/` 中的论文仍是本地参考资料；进入 P3 前须确认原文可用，缺失时先取得同版本原文，不能只凭本笔记实现。
