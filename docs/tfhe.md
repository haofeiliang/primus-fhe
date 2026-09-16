# TFHE LUT 与 PBS 设计

本文保存设计依据、职责边界和待决问题；实施任务见 [实施步骤](tfhe-plan.md)，稀疏方案见 [稀疏 PBS](tfhe-sparse-pbs.md)。当前进度只记录在 [HANDOFF](../HANDOFF.md)，不在多份文件中维护状态。

分析基线为 `81eb3f4`（2026-09-15）。旧 S0–S9 已结束，本轮使用 P1–P4 编号。已落实的 API 决定见对应步骤章节；后续算法的名称仍为设计建议。允许有价值的破坏性 API 变更，并须完整迁移调用方。

## 设计目标与范围

优先保证数学正确性、在线执行的分配与性能，再改善 API 和实现可读性。共享库围绕以下边界组织：

| 层 | 拥有的职责 |
| --- | --- |
| 应用层 | 整数/布尔语义、有效范围、message/carry、多输入范围与噪声预算、执行图 |
| `primus_tfhe` | 公开 LUT 编译、输入到旋转位置的规则、布局元数据、有界双输入打包、小型功能接口 |
| GLWE/NTRU、NTT/Fourier 后端 | 累加器初始化、BSK、盲旋转策略、表示变换、scratch、密钥切换和后处理 |

本轮优先公共 LUT、基础功能入口、稀疏 GLWE NTT 和一种具体 MVB。其他 full-domain、tree、multi-bit、摊销方案是候选扩展，不要求全部实现后才能验收。§5 Binary-NTT shallow 方案单独研究。

## 分析基线中的设计问题

| 现状 | 影响与处理方向 |
| --- | --- |
| `output_count` 同时表示有效输出数和交错步长 | 区分逻辑数量 `k` 与物理步长 `s`；CBS 已有 3 个有效输出占 4 个槽的需求 |
| Many 编译逐列调用单输出编译器 | 产生最终多项式加每列临时多项式的 `k + 1` 次分配，并重复计算几何；改为一次几何扫描、直接写最终缓冲区 |
| 输入域默认固定为 `ceil(t/2)` | 保留当前前半区语义，同时显式表达真实有效域；奇数模数全域另行实现与验证 |
| 编译产物缺少真实域和布局的完整表达 | 保存执行、兼容性检查和后续组合实际需要的紧凑元数据 |
| `ManyLookupTable` 名称覆盖面大于实际算法 | 当前实现是交错式 PBSManyLUT，不能用它承载所有 MVB 算法 |

几何计算可以从约 `O(kD)` 降为 `O(D)`；函数求值仍为 `O(kD)`，系数填充仍为 `O(N)`。这些首先影响 LUT 构造，不能据此宣称在线 PBS 加速。构造成本使用 [共享 Criterion benchmark](../crates/primus_tfhe/benches/lookup_table.rs) 单独测量，P1.1 基线见下文。

源码入口：

- [共享 LUT](../crates/primus_tfhe/src/lookup_table.rs)：统一导出与编码元数据；单输出、交错多输出与双输入类型分别位于 `single.rs`、`interleaved.rs`、`bivariate.rs`。[前半区内核](../crates/primus_tfhe/src/lookup_table/compile/front_half.rs) 与[奇数全域内核](../crates/primus_tfhe/src/lookup_table/compile/odd_full_domain.rs) 分别处理两种几何，错误定义位于 [error.rs](../crates/primus_tfhe/src/error.rs)。
- [有界双输入](../crates/primus_tfhe/src/lookup_table/bivariate.rs)：绑定矩形输入域、打包基数与普通 LUT，复用现有 PBS。
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

对于 `0 <= x < B`、有界 `y`，可用 `F(x + B*y) = f(x,y)`。共享构造器核对公开域的容量并绑定打包基数；调用层负责实际共同编码尺度、线性组合误差和输入范围。不能仅因整数索引可打包就假定实际密文编码一致。

奇数明文模数可使用带符号的中心折叠编程全域，代价包括更窄的有效区间。必须以真实 codec 和模切中心验证构造。其他 full-domain 情形可能需要多阶段算法，不能只增加一个不区分数学前提的布尔选项。

## 公共 API 的设计方向

- 集中编译配置和几何扫描，复用 `RoundedCodec`；没有跨 LUT 复用需求时，不永久保存中心数组。
- 单输出可复用步长为 1 的编译核心。按输入行求值并直接填最终布局，不再逐列分配多项式；必要的短输出组 scratch 只分配一次。
- 普通 `LookupTable` 和交错 `InterleavedLookupTable` 保存各自必要的域、模数和布局信息。
- MVB 程序与加密 LUT 使用各自实际表示，不在普通 LUT 中堆积可选字段。
- 小型普通 PBS trait 可以保留。多输出 trait 描述结果和调用契约，不将“一次 BR、一次环 KS”承诺给所有未来算法。
- 通用接口的扩展由第二个真实实现/调用方驱动；不先设计万能 backend trait，也不预设必须增加编译器对象、缓存或 `*_to` API。
- 保留后端可用的环密文阶段，为 CBS、MVB 和未来加密 LUT 组合服务；不强行统一 GLWE/NTRU 的初始化与后处理。

## 设计决定与待决问题

| 问题 | 收敛位置 |
| --- | --- |
| LUT 的具体字段与检查边界 | 见 P1.1 元数据决定与 P1.3 API 决定 |
| 类型/方法命名、family 包装职责 | 见 P1.3；保留实际检查/编码职责，不留旧 API 兼容层 |
| 任意 `k` 与补齐输出数补齐 | 见 P1.3，不再作为 P2 的重复任务 |
| 奇数全域在实际参数下的中心分离与误差余量 | P2.3，条件不足的参数明确拒绝 |
| PBC 桶数、复制数、失败重试和安全/噪声条件 | P3.1 已固定首版实验方案，见[实现契约](tfhe-sparse-pbs.md)；生产安全与完整 PBS 尾界仍未认证 |
| 首个 MVB 算法、适用模数和输出编码 | P4.1，先确认因子分解与误差，再定编译产物 |
| 大 LUT、Fourier/三元/NTRU 稀疏移植 | 由应用或实测触发，分别补充方案 |

## P1.1 的精确契约与元数据决定

几何公式及边界已归位到 [共享 README](../crates/primus_tfhe/README.zh_CN.md)、[前半区编译模块](../crates/primus_tfhe/src/lookup_table/compile/front_half.rs) 与 [量化 helper](../crates/primus_tfhe/src/backend_support.rs)。编译时中心经历编码和模切两次舍入；例如 `N=16, s=1, t=3, q_in=5, m=1` 得到中心 13，理想化的一次舍入会得到 11，且两者填充边界不同。

当前执行采用 `R_s(x) = s*R(x,q_in,2N/s)`，先缩小量化域再乘步长；各系数独立量化后，总旋转为 `-R_s(b) + ΣR_s(a_i)*secret_i`。当前合法 `s <= N`，虚拟旋转域至少有两个位置；不要求 helper 支持没有调用方的单位置退化域。

| 语义信息 | 保存/计算决定（P1.3 落实布局 API） |
| --- | --- |
| `N` | 从多项式长度得到，不重复保存可失配的长度字段 |
| `t, q_in, q_acc` | 继续保存，分别绑定输入编码、旋转量化与系数算术 |
| `D` | 保存真实编程前缀长度，由 `input_domain_len()` 返回，不能仅用 `ceil(t/2)` 推断；用于公开范围契约及组合，不声称能从 raw LWE 检查真实消息 |
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

P1.1 数据作为初始参考，比较时使用 `--baseline p1_1`，避免覆盖原样本。P1.2 使用 P1.M 完成后的源码另存构造基线，以区分两步改动的影响，见下文的 P1.2 比较。

P1.1 原始 Criterion 数据位于 `target/criterion/**/p1_1/`，可能被清理；CSV 是持久摘要。原样本缺失时应使用 P1.1 提交的源码和 harness 重建，不能把 CSV 当成 Criterion 样本输入。记录没有分配计数，计时 benchmark 也未插入全局 allocator 计数开销。

## P1.M 模数侧缩放与量化

P1.2 前置的跨层任务见 [P1.M](tfhe-plan.md)。
`PrepareModulusSwitch` 在源模数上提供 `prepare_switch_to(target)`；关联的
`PreparedModulusSwitch` 持有固定模数对和算术策略，执行只接收系数并返回规范目标
剩余类。目标类型是准备方法的泛型，准备结果类型由源实现选择，无需为每对模数
额外编写 trait 实现。`RingContext` 聚合准备能力，`FieldContext` 随之继承；
准备 trait 仍可独立使用，执行对象不承担环运算职责。

`ModulusSwitch` 集中二进制缩放、整除、余数分解及宽度策略；`switch_map` 在循环前
选择算术，允许 codec 融合符号处理、输出写入和累加。逐值接口仍会选择保存的策略，
预备对象本身不保证编译器消除所有分派。紧凑范围内的倒数求商已在后续内核优化中
加入，接口与舍入语义保持不变，见下文的固定模数对内核优化。

Rounded 构造时准备 `t → q` 编码和 `q → t` 解码；Scaled 保持 `m*round(q/t)`，
只保存固定尺度与预备解码器。Centered/Unsigned 由 codec 处理，模切内核只接收
非负规范源剩余类。绝对值舍入和解码复用模切内核，批量转换融合输出与累加；
标量包装保留各自的特化路径。codec 仍仅要求模加法与准备能力，Uint/Compact 可用。
codec、基础加解密及通用 TFHE client 的数值输入输出统一为系数类型 `T`，批量
消息使用 `[T]`；应用负责类型转换，Boolean 等语义接口保留各自类型。参数构造
复用 codec 校验；模数至少为 2 由 `ModulusSwitch` 准备时验证，codec 负责 `q > t`
及 Scaled 的恢复条件。

普通 PBS 的 `q_in → 2N` 转换在 GLWE BSK 生成或 NTRU 参数构造时准备。
ManyLUT 的目标依赖 LUT 步长 `s`，在执行系数循环前准备，仍先量化到 `2N/s` 再乘 `s`。
`RotationQuantizer` 依赖准备结果；`q_acc`、Boolean/CBS 尺度和稀疏算法参数独立。
描述性模数元数据可继续使用 `Option<T>`。LUT 的单次几何扫描仍属于 P1.2。

### P1.M 性能比较

以下计时在编解码输入输出统一为 `T` 之前采集，作为阶段对照保留；类型接口及构造检查调整未重新计时。

2026-09-16，与修改前提交 `21f278a` 比较，[41 项数据](benchmarks/tfhe-p1.m.csv)
保存固定模数对接口完成后的 mean、95% 置信区间（ns），与修改前提交的耗时变化
为 `(after/before - 1)*100%`。
23 项 codec 使用修改前采集的 `modulus_before` 样本；18 项完整 PBS 使用该提交
重新采集的 `p1_m_before` 样本。两者都固定相同依赖锁定版本、仓库构建配置和 CPU 0，
硬件、工具链、默认 features 及 PBS 工作负载与 P1.1 相同。
每项 10 samples、1 s warm-up；codec 测量 2 s，PBS 测量 3 s，顺序计时。

- 批量 codec：耗时变化为 −14.99%～+2.75%；显式模数的 Scaled 居中编码加法为 −14.99%，4096 项整数移位居中编码为 −1.65%。
- 单值 codec：Native 移位加法编码从 0.795 ns 增至 0.973 ns（+22.44%），移位解码为 −8.86%，比例编码为 −1.10%。保留这项单值成本，不宣称所有路径加速。
- 标量包装保留各自的内联结构。另一次将提升与符号处理合并到通用 helper 的对照中，Native 单值加法编码增加约 30%，重复测量仍有回退，故未保留该合并；比例舍入和解码仍共用模切内核。
- 完整 PBS：18 项为 −4.39%～+3.34%，没有一致的整体加速；不能把准备与执行接口重整等同于 PBS 性能提升。
- 本轮没有测 SIMD 性能。CPU 未隔离且 SMT/boost 开启，区间只反映本次样本，不能排除环境和代码布局影响；这些数据不用于跨后端同安全强度比较。

`RingContext` 聚合准备能力后，按相同配置复测 23 项 codec。相较本轮包装调整前的
`ring_before`，最终批量 mean 变化为 −2.06%～+1.41%，Native 单值加法编码为
0.976 ns（−0.01%）；原始结果保存在 `target/criterion/**/ring_final/`。
本次未重新计时完整 PBS，上述 18 项 PBS 数据仍是固定模数对接口的阶段对照。

复测可使用以下命令；应先在基线源码保存样本，再在修改后的源码比较，
不同源码目录使用独立构建缓存并复制 Criterion 基线目录，避免混用编译产物。

```sh
taskset -c 0 cargo bench -p primus_encoding --bench plaintext_codec -- --sample-size 10 --warm-up-time 1 --measurement-time 2 --baseline modulus_before --noplot
taskset -c 0 cargo bench -p primus_tfhe_glwe_ntt -p primus_tfhe_glwe_fourier -p primus_tfhe_ntru_ntt -p primus_tfhe_ntru_fourier --bench pbs -- 'complete_pbs_(reused_output|many_4_reused_outputs)$' --sample-size 10 --warm-up-time 1 --measurement-time 3 --baseline p1_m_before --noplot
```

首次采集时把 `--baseline` 改为 `--save-baseline`；比较时不要覆盖基线。
原始样本在 `target/criterion/**/{modulus_before,p1_m_before,p1_m_pair_after}/`，
其中 `p1_m_pair_after` 保存固定模数对接口的最终结果；CSV 是可在清理 target 后保留的摘要。

### 固定模数对内核优化

P1.R 后补充的算术优化保持公共 trait、`ModulusSwitch<T>` 及舍入规则不变，外层不增加策略分支：

- 二次幂源模数的非整比扩张使用移位内核，避免在可用余数分解时丢失二次幂除数的信息。
- 对 `1 < q < 2^(T::BITS-2)`，在现有比例捷径之后，根据 `x*p+floor(q/2)` 的上界选择单字或双字倒数估商，并做一次精确修正及目标端点回绕。其他显式模数继续使用通用整数内核。
- Barrett 及派生 Barrett 的 `prepare_switch_to` 复用源倒数；直接构造和其他源表示仅在选中倒数内核时预计算。调用方继续使用 `switch` / `switch_map`。

**性能方法：** 2026-09-16，Ryzen 9 9955HX3D、逻辑 CPU 2、rustc 1.98.0、Criterion 0.8.2、默认 features，使用仓库编译配置；各计时负载串行运行，CPU 未隔离、boost/SMT 开启。基线为 `eef21a0` 加 P1.R 旋转域边界修改，所有 setup/预计算/分配在计时外。微基准与 codec 每项 20 samples；PBS 每项 10 samples；均为 0.5 s warm-up、2 s measurement。CSV 保存 mean 与 95% 置信区间，单位 ns。

持久基准为 `primus_modulus/benches/modulus_switch.rs`，覆盖缓存转换器的标量调用与 512 系数批量。消费者复用 23 项 codec，以及 GLWE NTT/`TfheFftTable`、两种 order、单输出/4 输出的 8 项完整 PBS；输入和参数沿用各自已有 fixture。最终算术对照及两轮融合实验见[计时数据](benchmarks/modulus-switch.csv)。

所测批量耗时如下；Native 普通量化作为未改算术的参照。

| 工作负载 | 修改前 → 后（ns） | 耗时变化 |
| --- | --- | --- |
| 512 项 Native u32 → 2048 | 14.82 → 14.70 | −0.8% |
| 512 项 u64，128 → 131 | 597.67 → 239.20 | −60.0% |
| 512 项 Barrett u32 → 2048 | 723.84 → 126.80 | −82.5% |
| 512 项 Barrett u64 → 2048 | 738.73 → 181.56 | −75.4% |
| 512 项 Barrett u64 → Native | 1343.70 → 215.55 | −84.0% |
| 4096 项 Barrett u32 解码 | 5815.76 → 1009.40 | −82.6% |
| 4096 项 Barrett u64 窄乘积解码 | 5887.85 → 1388.89 | −76.4% |

这些收益不适用于所有路径：标量 u32 Barrett 旋转从 1.403 ns 增至 1.640 ns（+16.9%），标量 128 → 131 从 1.302 ns 增至 1.552 ns（+19.2%）；u64 Barrett 旋转与 Native 扩张则分别为 −8.9% 和 −36.6%。16 项精确移位居中编码约 +10.0%，4096 项精确乘法/移位居中编码约 +5%～6%；完整数据保留这些回退。8 项完整 PBS 为 −6.4%～+0.8%，没有一致的整体加速，不能把微基准的比例外推到 PBS。

PBS 融合原型将 `(LWE 系数, GGSW)` 交给 quantizer 的批量入口，回调直接执行 CMUX，无中间数组。两轮完整 PBS 未显示稳定收益；第一轮有大离群，第二轮完整复测为 −1.1%～+3.9%，仍无一致加速。两组都使用加入窄分子特化之前的同一版算术内核，以单独比较循环融合。原型与新增批量入口已删除，未向 NTRU 推广。ELF text 对照也没有统一优势：NTT 融合版比同轮标量版多 5,852 字节，Fourier 少 2,848 字节。

**验证：** 底层/codec 默认 33 项、SIMD 34 项测试通过（含 doctest）；七个 TFHE crate 默认/SIMD 各 41 项通过，相关 check、Clippy 和文档构建通过。独立整数 oracle 覆盖 u16/u32/u64、随机规范输入、舍入边界、目标端点，以及小字宽全剩余类。未测 SIMD 性能、NTRU 性能、构造成本、非 x86 平台；这不替代 P1.4 的最终 LUT/PBS 验收。

## P1.2 共享几何与直接填充

单输出和交错 LUT 共用一次中心/区间扫描，几何工作为 `O(D)`；回调求值仍为
`O(kD)`，系数填充仍为 `O(N)`。每个非空区间的首个输出组直接接收输出值，随后复制到
区间其余位置；多输出按已初始化前缀倍增复制，单输出直接 `fill`。
首个输出组 `f(0)` 同时供负循环尾部使用，不额外求值或分配 scratch/中心数组。
编译函数直接推进中心和边界；中心使用每输出系数坐标，填充函数接收实际系数切片。
`fill_input_interval` 负责求值、检查和区间填充，`fill_negated_tail` 负责复用首个输出组填充尾部。
公共输入域、二次幂输出数量和编码契约保持不变；数量/步长的分离属于 P1.3。

### 构造时间与分配

2026-09-16，首版直接填充（主循环重整前）对照 P1.M 完成后的提交 `ea2d6a4`，使用同一构造 harness。
[10 项数据](benchmarks/tfhe-p1.2.csv) 保存修改前后的 Criterion mean、95% 置信区间
（ns）及分配计数。硬件、CPU 0、工具链、依赖、默认 features 和采样设置与 P1.1
相同；每次迭代编译并释放一个 LUT，计入验证、准备编码/量化、几何、分配和填充。

| 构造项 | Native 耗时变化 | Barrett 耗时变化 | 分配次数 | 累计申请字节 |
| --- | --- | --- | --- | --- |
| 单输出 `t=16` | +1.48%（79.80 → 80.98 ns） | +0.47%（105.10 → 105.59 ns） | 1 → 1 | 4096 → 4096 |
| 4 输出 `t=4,16,255` | −78.77%～−67.78% | −79.37%～−68.34% | 5 → 1 | 8192 → 4096 |
| 16 输出 `t=16` | −85.89% | −87.37% | 17 → 1 | 8192 → 4096 |

分配使用现有线程局部计数器单独测量相同负载，未插入 Criterion 计时路径。
字节数是累计成功申请的大小，不含 allocator 开销，也不是峰值内存；回调本身不分配。
保留“只分配结果”的回归检查及回调顺序/错误中止检查，临时记录程序已移除。
P1.1 的独立几何 oracle 继续覆盖每个系数，并补充每个输出仅占一个系数、没有尾部的边界。

单输出保留约 1 ns 的差异；这些测量不代表所有输入大小、SIMD 或非 x86 平台的表现。
本步没有改动在线 PBS 内核，也未重新计时在线 PBS；构造收益不能视为在线加速。

```sh
# 在 ea2d6a4 保存基线；每项 10 samples、1 s warm-up、3 s measurement。
taskset -c 0 cargo bench -p primus_tfhe --bench lookup_table -- --sample-size 10 --warm-up-time 1 --measurement-time 3 --save-baseline p1_2_before --noplot
# 在 P1.2 源码比较，避免覆盖修改前样本。
taskset -c 0 cargo bench -p primus_tfhe --bench lookup_table -- --sample-size 10 --warm-up-time 1 --measurement-time 3 --baseline p1_2_before --noplot
```

原始样本位于 `target/criterion/**/{p1_2_before,p1_2_after}/`；CSV 为持久摘要。
重建基线须使用对应源码与相同 harness，不能将 CSV 当作 Criterion 原始样本。

### 主循环重整对照

2026-09-16，重整前重新采集双回调版本的基线 `p1_2_flow_before`。
该版本是当时未提交的 P1.2 工作区，`lookup_table.rs` 的 SHA-256 前缀为
`bdc360afcbca46e6`；重整后为 `768bbaaff5e3a5c2`。
[10 项对照](benchmarks/tfhe-p1.2-flow.csv) 保存 mean 与 95% 置信区间。
沿用上述 CPU 0、工具链、默认 features、工作负载和采样设置，顺序计时。

| t / 输出数 | Native 前 → 后（ns） | 变化 | Barrett 前 → 后（ns） | 变化 |
| --- | --- | --- | --- | --- |
| 4 / 4 | 123.04 → 126.97 | +3.20% | 132.65 → 131.87 | −0.58% |
| 16 / 1 | 80.40 → 80.89 | +0.62% | 103.95 → 106.21 | +2.17% |
| 16 / 4 | 218.73 → 224.73 | +2.75% | 238.72 → 241.24 | +1.05% |
| 16 / 16 | 146.40 → 146.63 | +0.16% | 196.18 → 182.07 | −7.19% |
| 255 / 4 | 805.04 → 804.63 | −0.05% | 1046.82 → 1034.44 | −1.18% |

重整后保留顺序控制流和一次结果分配；本次测得部分构造项增加约 0.2～6 ns，
其余项降低约 0.4～14 ns，不据此宣称整体加速。尾部填充保留 `#[inline]`：
初次拆分时该函数未自动内联，Native 16 输出约增加 11%，内联后恢复到约 147 ns。
既有独立 oracle、回调顺序/错误中止及分配测试继续验证相同契约。

复测沿用上述构造命令，重整前使用 `--save-baseline p1_2_flow_before`，
重整后使用 `--baseline p1_2_flow_before`。原始样本另存于
`target/criterion/**/{p1_2_flow_before,p1_2_flow_after}/`。

## P1.3 布局 API 决定

- 普通表为 `LookupTable`，交错表为 `InterleavedLookupTable`；raw 编译统一为各自的 `try_new`，接收已编码输出并返回 `Result`。旧自由函数与 `ManyLookupTable` 名称删除，不保留兼容层。
- 两类表保存真实 `D`；交错表保存有效数量 `k`，通过 `padded_output_count()` 推导 `s=next_power_of_two(k)`。编译器只对 `0..k` 调用回调并补零槽，输入优先切片长度为 `D*k`，BR 接收 `s`，提取和输出切片使用 `k`。
- Family/context 的 `compile_lookup_table_*` 与 `compile_interleaved_lookup_table_*` 保留：它们从参数取得默认域，检查明文输出/切片长度并编码。直接使用构造器的 Boolean/CBS 保留各自 raw 输出尺度。
- `ProgrammableBootstrapInterleaved` 只描述交错表的多输出契约；“一次 BR、一次环 KS”属于当前四后端的具体实现。未来 MVB 程序按实际表示另定接口，不借交错表名称泛化。
- 三路 CBS 以 gadget 层数构造 LUT，补齐由共享编译器负责；参数以 `lookup_table_padded_output_count()` 描述 LUT 补齐输出数。投影与 GGSW/NGSW 保持真实层数，GLWE key 仍绑定输出布局，NTRU key 仍绑定完整输出 basis。

公开契约见共享及后端 rustdoc/README。构造基准新增 `t16/k3`，旧 case 名称与历史 CSV 保留；最终同配置计时见 [P1.4 验收](#p14-阶段验收)。

## P1.R 取整策略取舍

P1.3 后的 [P1.R](tfhe-plan.md#p1r-取整契约与旋转域边界) 已统一旋转域边界，并完成均匀二元秘密的 Centered / shifted 原型验证。正式源码保留既有舍入和 PBS 执行规则；居中/shifted 尚未接入公开 API。

### 本轮范围

| 能力 | 建议 | 原因 / 再次启动条件 |
| --- | --- | --- |
| nearest ties-up | 保持默认，补齐必要契约 | 当前规范 residue 模切、解码和 PBS 量化的一致行为 |
| Floor / Ceil | 暂不增加通用策略 | 特定算法有价值，但现有 PBS 无消费者；等对应算法明确要求后引入 |
| nearest ties-even / ties-odd | 暂缓 | 只改变精确半整数，不能代替整条 LWE 的误差补偿；尚无已选算法要求 |
| 随机舍入 | 暂缓 | 需独立 RNG/执行契约及对应的概率分析，不能视为现有确定性算法的免费改进 |
| 无辅助密钥的居中模切 / LUT shift | 已做 P1.R 原型验证，正式接入另行收敛 | 居中降低所测误差方差；固定 shift 存在合法 LUT 反例，不能全局启用 |
| 使用加密零样本的漂移抑制 | 单独的后续优化 | 涉及辅助密钥、候选选择、额外噪声与成本，不扩入本轮基础整理 |
| LMKCDEY 的 nearest-odd 映射 | 随对应 BR 算法引入 | 限制输出指数的映射不同于只在半整数上选奇数的 tie 规则 |

Floor/Ceil 的逐系数误差绝对值可接近一个目标单位，nearest 至多半个；二元秘密的线性组合还会积累单向偏移。因此不能仅因 Floor 内核简单就替换现有 PBS 舍入。[HasteBoots §3.5、附录 A.1](https://eprint.iacr.org/2025/261.pdf) 给出了在特定模数整除条件下用 Floor 简化可验证模切关系的用途，这不是当前 PBS 已有的需求。现有 BFV RNS 的 `floor(Q/t)` 尺度有自己的实现，也不构成本轮增加通用 Floor 的必要条件。

### 随机舍入的作用

[FHEW §3](https://www.iacr.org/archive/eurocrypt2015/90560159/90560159.pdf) 的模切采用 `floor(y)+Bernoulli(frac(y))`，使每个固定输入的舍入误差均值为零，并据此建立输出噪声的概率界。这里主要服务于正确性和失败概率分析；论文也明确讨论实践中采用确定性 nearest。不能据此断言确定性模切不安全，也不能把这种有界随机舍入与其他格归约中的高斯采样混为一谈。

### 居中、shift 与漂移抑制的区别

令虚拟旋转模数 `p=2N/s`，`δ_i=round(p*a_i/q)-p*a_i/q` 为按适当整数 lift 计算的 mask 舍入误差。普通模切的相位误差包含 `δ_b-Σδ_i*s_i`。若秘密系数均值为 `μ`，在 body 量化前加入目标尺度的 `μ*Σδ_i`，则该项变成 `δ'_b-Σδ_i*(s_i-μ)`；实际实现还须计入修正量自身的离散化误差。

- **居中补偿**利用公开 mask 和已知秘密分布去除可预测偏移，无需私钥、额外加密零样本或 RNG。可用一次额外 mask 扫描、零额外堆分配实现；最终是否减少扫描需结合 BR 执行顺序决定。均匀二元取 `μ=1/2`，固定重量稀疏分布应使用相应均值和协方差，不能照搬均匀二元误差结论。
- **LUT shift**把误差分布对齐到有效槽的中心，作用独立于上述均值补偿。[TFHE-rs 官方实现](https://docs.rs/tfhe/latest/src/tfhe/core_crypto/algorithms/modulus_switch.rs.html) 的 `lwe_ciphertext_centered_binary_modulus_switch` 同时包含二者，其中 half-case correction 为负半个目标单位。
- **Primus 的适配条件**：当前 LUT 以向上取整的中心中点分界。对等距、偶数宽度 `w` 的内部槽，整数位置为 `[c-w/2,c+w/2)`，其中心确为 `c-1/2`；奇数宽度、二次舍入产生的非均匀中心、前缀域和终端截断不能直接套同一 shift。交错 LUT 必须在 `p=2N/s` 下计算，再把指数乘 `s`。上述几何判断是对本仓库实现的推导，不是论文对全部布局的保证。
- **带候选选择的漂移抑制**：[BJSW25 §5](https://marcjoye.github.io/papers/BJSW25drift.pdf) 通过加密零样本改变 mask，并用公开统计量选择较好的候选。需要辅助材料生成/存储、候选评分、工作区、停止条件和额外噪声预算。复用 LWE 加法并不等于完成整套算法；与无辅助密钥的居中补偿分开规划。

统计实验可检验模型，不能独立认证生产失败概率。后续居中接口应承担整条 LWE 的修正，不让 `RotationQuantizer::exponent(value)` 承担该职责，也不预加通用预处理 trait。

### 旋转域与接口复杂度

PBS 参数、LUT 与 `RotationQuantizer` 现统一要求 `2N` 能由 `T` 表示。Quantizer 始终准备显式二次幂目标 `2N/s`，已删除此前供 `2N/s=2^T::BITS` 使用的 Native 目标分支。GLWE/NTRU 参数在构造时返回 `RotationDomainTooLarge`，raw quantizer 对非法旋转域 panic；交错步长不能放宽物理旋转域的边界。通用模切的 Native 目标仍供 `t→q` 编码使用，Native 输入也继续支持。

保持 `prepare_switch_to(target)` 和现有 codec/context/LUT/PBS 的默认调用流程。以后只有实际算法需要不同标量舍入时才增加显式准备入口，不逐系数传入策略，也不把舍入泛型扩散到所有公开类型。涉及居中/shift 的算法在 PBS 参数或 context 建立时绑定秘密分布、量化与 LUT 约定；仅在确有多种不兼容布局时保存和检查相应标识。

编码、解码和旋转量化不能共用一个任意切换的全局选项：例如 `q=97,t=4,m=1` 的 nearest 编码为 `24`，若直接改用 Floor 解码则得到 `0`。有符号 lift 的 Floor 还满足 `floor(-x)=-ceil(x)`，不能照搬当前绝对值舍入后恢复符号的流程。P1.R 保持现有 Rounded/Scaled 行为，不为尚未选定的算法重整全部内核。

### P1.R 居中原型验证

2026-09-16，以 `u32`、均匀二元秘密验证三个配对路径：原始量化、仅居中、居中并向负方向 shift 半个虚拟单位。临时原型只修正 body，mask 和 LUT 保持不变；没有加密零样本、在线随机舍入或额外堆分配。原型不作为公共 API 保留。

**可复现的整数计算：** 取未做末端模约简的 `u_i=round(p*a_i/q)`，累积 `E=Σ(q*u_i-p*a_i)`；令 `h=0` 表示仅居中、`h=1` 表示附加 shift，则 `c=round((E-h*q)/(2p))`，`b'=(b+c) mod q`。所有 round 均为 nearest ties-up，包括有符号 `c`。对 Native 输入，`Δ=q/p` 为整数，可改为累积源尺度残差 `d_i=Δ/2-((a_i+Δ/2) mod Δ)`，再计算 `c=round((Σd_i-h*Δ)/2)`。原型以 `i64` 累积所测 `u32` 参数，不能直接推广为任意字宽实现。

- **独立 oracle：** 小显式模数穷举加 Native 固定 seed 随机输入，共 343,668 个修正结果与独立 `i128` 有理数公式一致。
- **LUT 反例：** `q=5,N=8,t=4,k=3,s=4,p=4` 是合法布局。取零 mask、`m=0,b=0`，固定 half-shift 在源域舍入为 `c=-1`，得到 `b'=4`，量化到虚拟指数 `3`，读取 `-f(1)`，而原始路径读取 `f(0)`。因此即使零噪声也不能无条件开启 shift；这不是修改当前 LUT 编译器的理由。
- **误差实验：** `N=1024,n=512,t=16,k=1/3`，分别使用 Native `q=2^32` 和 Barrett `q=132120577`。每组 65,536 条零输入噪声 LWE；每 1,024 条重新采样一把均匀二元秘密，共 64 把；使用 `StdRng`，seed 为 `0x50315200+k`。误差以虚拟旋转单位计，相对于真实编码相位；按当前 LUT 检查读取值。数据见 [量化统计](benchmarks/tfhe-p1.r-quantization.csv)。

| 量化路径 | Native 方差，k=1 / 3 | Barrett 方差，k=1 / 3 |
| --- | --- | --- |
| 原始 | 21.474 / 21.390 | 21.477 / 21.390 |
| 仅居中 | 10.692 / 10.715 | 10.692 / 10.715 |
| 居中 + shift | 10.712 / 10.692 | 10.711 / 10.692 |

居中将所测方差约减半，标准差约为原来的 `0.707`。Shift 将均值移到约 `-0.5`，未进一步降低方差；它的作用是槽位对齐。`k=3` 两种模数的原始路径均有 30 次 LUT 读取错误，两个居中路径均为 0；`k=1` 三种路径均为 0。这里不含加密噪声、BR 和 KS 噪声，有限样本的零错误也不是生产失败概率结论。

**性能方法：** Ryzen 9 9955HX3D，固定逻辑 CPU 2，rustc 1.98.0、默认 feature，沿用仓库编译配置，Criterion 0.8.2。`n=512,N=1024,t=8,k=1/3`，固定 seed 42，`BootstrapKeyswitch`；计时不含 key/LUT 构造和输出分配。量化负载为整条 513 系数 LWE（居中路径包含额外 mask 扫描）；完整负载为 body 修正加现有 PBS。Fourier 使用 `TfheFftTable`、Native u32、LWE/GLWE σ=3.2、BSK `(logB=8,l=3)`、KSK `(2,13)`；NTT 使用 Barrett `132120577`、LWE σ=`3.2*q/16384`、GLWE σ=6.4、BSK `(7,3)`、KSK `(2,13)`。每种后端/输出数量/修正模式均在计时外检查全部四个输入消息的解密结果。均值及 95% 置信区间见 [计时数据](benchmarks/tfhe-p1.r-centered.csv)。

每项 20 个样本、0.5 秒预热、2 秒测量；Native `k=1` 量化组因首次波动较大按同配置复测。下表每格依次为原始 / 仅居中 / 居中 + shift：

| 后端 / 输出数 | 整条 LWE 量化（μs） | 完整 PBS（ms） |
| --- | --- | --- |
| Native Fourier / k=1 | 0.806 / 0.817 / 0.816 | 3.528 / 3.520 / 3.528 |
| Native Fourier / k=3 | 0.806 / 0.819 / 0.817 | 3.565 / 3.521 / 3.551 |
| Barrett NTT / k=1 | 0.773 / 1.530 / 1.581 | 3.580 / 3.565 / 3.556 |
| Barrett NTT / k=3 | 0.852 / 1.592 / 1.592 | 3.535 / 3.531 / 3.534 |

Native 的额外位运算扫描成本较小；Barrett 的量化成本接近翻倍，但绝对增加约 `0.8 μs`，只占所测完整 PBS 的约 `0.02%`。完整 PBS 本轮未观察到明确的开销增加；均值差异不作为加速结论，也不外推至其他参数或稀疏 BR。

**接入决定：** 居中补偿值得继续，但本步交付为可行性验证；不增加尚未完整定义的公开策略。正式接入需绑定实际 BR 秘密分布、定义跨字宽的精确累积与 body 舍入、覆盖两种 GLWE order 的修正位置，以及明确哪些 LUT 布局允许 shift。固定重量稀疏秘密、NTRU/CBS 和生产失败概率不在本次原型验证范围。后续可以先独立接入无 shift 的居中策略；现有默认 PBS、codec、LUT API 不变，P1.4 不依赖该扩展。

## P1.4 阶段验收

### 最终性能对照

2026-09-16，重新构建 P1.1 基线 `21f278a`，与 `d5da1cb` 加本步维护资产修改比较；没有直接拿历史 CSV 的计时作分母。两版锁文件、编译配置和既有 PBS 参数/函数一致。当前构造基准增加 `t16/k3`，四后端 PBS 基准以 `k=3` 替换 `k=2`，保留 `k=4` 和逐函数 PBS 对照。有效输出与补零槽不同的情况成为长期性能覆盖。

环境为 Ryzen 9 9955HX3D、逻辑 CPU 2、rustc 1.98.0、Criterion 0.8.2、默认 features。沿用仓库编译配置，前后版本顺序运行，机器未隔离、SMT/boost 开启、未固定频率。首轮每项 10 个样本、预热 1 秒、测量 3 秒；复测每项 20 个样本，保持预热/测量时间，逐用例交替前后版本，并交替先后顺序。

[完整数据](benchmarks/tfhe-p1.4.csv) 保留各轮 mean、95% 置信区间、百分比变化及构造分配量。`initial` 含 28 项等价对照和 11 项新增 `k=3` 数据；`paired` 复测两项单输出构造和 18 项在线 PBS；`rustfft_recheck` 单独重测波动较大的两项 NTRU RustFFT。新增项的 before 留空，不构造不存在的旧版 `k=3` 基线。

构造测量包含校验、几何、函数求值、结果分配、填充及释放，模数 setup 不计时。统一为 `u32,N=1024,D=ceil(t/2)`，Native 与 Barrett `q=132120577`；raw 输出为 `13*input+column`。首轮结果如下：

| t / k | Native 前 → 后（ns） | Barrett 前 → 后（ns） |
| --- | --- | --- |
| 4 / 4 | 551.06 → 121.24 | 558.58 → 142.70 |
| 16 / 1 | 81.69 → 93.71 | 100.43 → 117.92 |
| 16 / 3 | 新增 → 220.07 | 新增 → 242.49 |
| 16 / 4 | 627.14 → 213.75 | 703.78 → 239.84 |
| 16 / 16 | 1090.92 → 161.81 | 1361.26 → 196.15 |
| 255 / 4 | 2624.43 → 828.96 | 2992.85 → 1149.85 |

多输出的八项等价构造耗时下降 **61.6%～85.6%**。单输出构造首轮增加 12.0/17.5 ns；交替复测 Native 为 79.55→96.28 ns、Barrett 为 97.00→120.57 ns，增加 16.7/23.6 ns。保留共享顺序编译器的实现取舍，并明确记录这项构造退化；不能宣称所有 LUT 构造都加速。

分配使用同一工作负载和测试 allocator 单独探测，未将 allocator 计数加入 Criterion 计时。旧单输出为一次 4096 B 分配；旧多输出为 `k+1` 次、累计 8192 B。当前全部 12 项均为一次 4096 B 最终多项式分配，释放字节数与分配相等。这里是请求分配的累计字节数，不是峰值 RSS；既有公开测试继续保护一次结果分配契约。

在线测量复用 key、LUT、evaluator/scratch 和输出，计时完整 PBS。四后端覆盖两种 GLWE order、两种 Fourier table 以及 NTRU 固定链；每次产生一个或四个逻辑输出，新增三输出只报告当前耗时。GLWE 使用 `n=512,N=1024`，NTRU 使用 `n=800,N=1024`，其余参数和 seed 见各后端 `benches/pbs.rs`；这些是回归配置，不是同安全级别的跨后端比较。

在线 PBS 首轮 18 项变化为 −2.33%～+5.54%，没有稳定的整体加速。交替复测中，GLWE/NTRU NTT 项增加约 0.9%～3.3%，Fourier 多数在 −2.4%～+1.7%；GLWE NTT 首轮也有约 0.7%～1.2% 的增加，保留为小幅性能退化信号。NTRU RustFFT 第二轮出现明显运行间波动（旧版约 4.3～4.5 ms，首轮约 2.7 ms），单独重测后两版恢复到约 2.7 ms，差异 −0.31%/+0.42%。各轮均完整保留，不把异常轮解释为加速；本机条件不足以把几个百分点的变化可靠归因到某个内核。新增九项三输出 PBS 为 2.122～4.173 ms，仅表示当前配置下的绝对耗时。

复现时，分别在对应版本执行共享 `lookup_table` 和四后端 `pbs` benchmark，筛选 `^(lut_compile/|.*complete_pbs_(reused_output|many_[34]_reused_outputs)$)`；传入 `--warm-up-time 1 --measurement-time 3 --sample-size 10`，复测改为 20 个样本并逐项交替运行。原始 Criterion 数据保留在 `target/criterion-p1.4/{before,after}/**/{p1_4,p1_4_recheck,p1_4_rustfft_recheck}/`。CSV 为持久摘要，不能替代原始样本；重建基线须使用对应源码与等价 harness。

### 覆盖与维护资产

本步定向核对 P1 的共享实现、实际调用方和维护资产，未发现未迁移的公开旧 API 或需修复的功能缺陷。覆盖如下：

| 范围 | 核对与验证的契约 |
| --- | --- |
| 共享 LUT/量化 | Native、Barrett、显式二次幂、奇数/近字宽模数及多字宽整数 oracle；精确两次舍入、短/完整前缀、回绕、中心冲突、旋转域边界、回调顺序和错误中止、补零及一次结果分配 |
| GLWE/NTRU family | 明文范围、编码与 raw 职责；在既有测试中补充 `k=3` 的切片长度断言：接收 `D*k`，拒绝调用者自行补齐的 `D*s` |
| 四后端 | 按 `s` 量化、按 `k` 提取；两种 GLWE order、NTRU 固定秘密链、Fourier 两种 table；真实三输出、非法元数据/尺寸在写入前拒绝、首次及复用调用无额外分配 |
| Boolean / 三路 CBS | Boolean 内外尺度；CBS 的真实层数、GLWE 布局绑定和 NTRU 完整 basis 绑定、投影零尾及 CMUX 消费；NTRU CBS 保留 accumulator 秘密 |
| 维护资产与 workspace | 旧符号搜索、七包公开导出、14 份 README、相关测试/基准及六个示例；workspace all-targets 编译覆盖其余调用方和 xtask |

修正 GLWE BR 注释，明确直接量化到 `2N/s` 后乘 `s`；raw BR 测试使用 `rotation_step` 表示旋转步长。同步四后端双语 README，整理相关 import，统一旧居中 CSV 的换行符且不改数据。维护资产按独立契约精简如下：

- ManyLUT 端到端保留 `k=1/3/4`、消息 `0/3/4/7`；分配包装与 scalar 等价只用代表性非零消息验证，PBS 调用合计从 501 次降至 147 次。完整小域几何留在共享整数 oracle，各后端仍验证补齐输出数 1、补零/满槽、错误先于写入和工作区复用。
- 三路 CBS 保留三层 gadget 和 `1→0` 控制序列，CBS 调用从 26 次降至 10 次；保留每层 phase、CMUX、零尾、布局/basis 绑定和独立参数边界。Boolean 保留所有真值表，反馈链从 16 步降到 4 步。GLWE context 专测 split-key 工作流，fresh 路径由 PBS/Boolean 覆盖；NTRU metadata 拒绝测试改用 `N=16,n=4`。
- Criterion 用例从 166 项精简到 97 项：删除重复的 allocating 包装、Boolean XOR/NOT 微基准、已由 lattice 覆盖的系数提取，以及独立旧 key-switch 对照文件。保留 LUT 构造、BR/KS 阶段、完整 PBS/CBS、ManyLUT 与独立 PBS 的等价比较、AND/MUX。NTRU CBS 的尺寸/分解基数矩阵继续承担耗时和内存比较。

GitHub workflow 使用 `cargo nextest run --workspace` 和 nightly `--all-features`，未选择 benches；不把 bench 删减计作 CI 提速。按 CI 的 `CARGO_BUILD_RUSTFLAGS=''`、本机两个 nextest 测试线程，七包测试阶段默认由 0.908→0.547 秒、nightly all-features 由 0.887→0.539 秒。两配置仍各 41 项测试，没有 ignore/skip；不含编译，也不是 GitHub runner 总时长。精简后的 8 个 benchmark target 共 97 项冒烟通过；冒烟不代表重新计时。没有新增重复示例或永久调查程序。

实际验证：`just tfhe`、`just tfhe-simd` 全部通过，七包默认/nightly SIMD 各 41 项测试；包含 all-targets check、Clippy、默认文档构建及 xtask 检查。`cargo check --workspace --all-targets` 通过。`primus_modulus`、`primus_encoding`、`primus_barrett_derive` 的默认/derive 与 nightly SIMD 测试分别 33/34 项通过。六个现有示例在默认和 nightly SIMD 配置下共运行 12 次，均通过。相关本地文档链接、格式和最终 diff 检查通过；未运行其余 workspace 测试。

未测 SIMD 性能、非 x86 平台或生产失败概率/安全性；没有重新完整审计底层 CMUX、外积、投影和密钥生成。P2 的编码/双输入/奇数全域、P3 稀疏 BR、P4 MVB 及正式居中策略仍属后续工作。

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


## P2.1 输入与输出编码分离

普通 family/context 的四个 LUT 编译方法以 `&RoundedCodec<T, M>` 为第一个参数。
输入参数继续决定 `t_in`、可编程域和精确旋转中心；输出 codec 决定输出值域 `0..t_out`
及 unsigned rounded 尺度。编译边界核对 codec 的密文模数等于 accumulator 模数，
然后按输出值域检查。未新增 codec trait、持久编译配置或 LUT 输出元数据。

当前完整 PBS 链仍要求输入、accumulator、外部输出的密文模数相同；本步支持的是
不同的**明文模数与尺度**。普通 PBS 输出仍属于原外部 LWE 秘密，客户端新增
`decrypt_phase` 返回规范带噪 residue，由调用方保留的输出 codec 解码。
默认尺度通过显式传入参数 codec 复用；`decrypt` 继续使用参数 codec。
公开工作流、串联条件与 raw 编码边界见[共享指南](../crates/primus_tfhe/README.zh_CN.md#选择输出编码)。
Boolean、CBS、自定义/逐列编码仍走 raw 构造器，其尺度、秘密域和数学条件未改变。

验证复用已有 fixture：两族轻量测试覆盖 `t_in=4 → t_out=8`、输出越界及错误密文模数
先于 callback 拒绝；四后端 ManyLUT 改为 `16→8`，保留单输出对照、两种 GLWE order、
两种 FFT、元数据拒绝及零在线分配。测试函数总数和 PBS 执行次数未增加。
四个 basic 示例展示 GLWE `4→8` 与 NTRU `16→4`；benchmark 仅迁移显式 codec 参数，
维持原有计时负载。在线内核未改，本步不声称性能改善。

验证通过 `just tfhe`、`just tfhe-simd`、workspace all-targets check：默认/nightly SIMD
各 41 项 TFHE 测试，相关 Clippy 与默认文档通过。encoding 默认 5 项测试和 all-targets
Clippy 通过，四个修改后的 basic 示例在两配置下共 8 次运行通过。未重跑其余 workspace
测试、性能计时、非 x86 或生产噪声/安全性验证。


## P2.2 有界双输入 PBS

共享 `BivariateLookupTable<T, M>` 绑定普通 `LookupTable`、打包基数 `B` 和模数。
构造时显式接收矩形域 `B × R`、环长及输入/输出 `RoundedCodec`，只编译 `D=B*R`
个输入，并以 `(z % B, z / B)` 调用函数。它复用原 LUT 几何与兼容性元数据，不新增
后端 trait、evaluator 或密钥，也不提供整数/message-carry 状态层。

在线 `pack_to` 校验三个密文的存储长度，再调用现有模标量乘加切片内核，一遍写入
`lhs+B*rhs`，无临时分配。调用方持有一个打包缓冲区，将 `lookup_table()` 交给现有
单输出 PBS。范围和完整契约只维护在 [共享 README](../crates/primus_tfhe/README.zh_CN.md#有界双输入-pbs)
与类型 rustdoc；NTRU NTT basic 示例给出公钥输入比较，四后端共用此入口。

编码决定：使用同一 unsigned rounded 输入尺度，并将非线性舍入偏差计入输入误差，
不假定 `E(x)+B*E(y)=E(x+B*y)`。设 `epsilon(m)=E(m)-m*q/t`，有
`rho=epsilon(x)+B*epsilon(y)-epsilon(x+B*y)`，因此 `|rho| <= (B+2)/2`；
`t` 整除 `q` 时偏差为零。输入噪声先变为 `e_x+B*e_y+rho`，再计入 BR 前可能发生的
密钥切换及逐系数模切误差。`B*R <= ceil(t/2)` 保证合法整数索引留在编程前缀内，
不证明噪声余量。输出仍由独立 codec 解码；当前路径要求输入、累加器、输出密文模数相同。

验证资产仅增加两个共享测试：Native/Barrett 小矩形域的独立整数编码、线性组合与
LUT 读取 oracle，以及容量/模数/输出/缓冲区拒绝边界。显式 `q=131,t=16` 确实产生非零
舍入偏差。四后端已有固定 seed fixture 各配置补两个 `B=3,R=2` 的端到端输入，复用
密钥和 scratch，覆盖两种 GLWE order、两种 FFT 及打包/PBS 零在线分配。
没有新建测试程序或 Criterion benchmark；不声称性能改善或生产参数安全性。

验证通过 `just tfhe`、`just tfhe-simd`、workspace all-targets check：默认/nightly SIMD
各 43 项 TFHE 测试，相关 Clippy 与默认文档通过。修改后的 NTRU NTT basic 示例在两配置
均运行通过。端到端共增加 18 次 PBS，不增加 keygen；未做性能计时、其余 workspace
测试、非 x86 或生产噪声/安全性验证。

## P2.3 奇数明文模数全域

采用独立的单输出编译入口，返回原有 `LookupTable`，不增加域策略 enum、持久中心数组或
后端分支。`input_domain_len()` 为 `t`，原兼容性字段已经足够。两族参数和四后端 context
提供 `compile_odd_full_domain_lookup_table_fn/slice`，沿用 P2.1 的独立输出 codec；
raw 入口为 `LookupTable::try_new_odd_full_domain`。交错与双输入入口仍编译前半区。
使用方式和公开前提见 [共享 README](../crates/primus_tfhe/README.zh_CN.md#奇数全域-pbs)。

三个公开类型统一归入 `lookup_table/`：`single.rs` 集中 `LookupTable` 的两种构造器和访问器，
`interleaved.rs` 管理输出槽布局，`bivariate.rs` 持有普通 LUT 与输入打包参数。
`compile/` 按前半区和奇数全域分开编译算法，入口承担几何检查；共用编码检查、中点与负循环
尾部填充留在 `compile.rs`。域选择不改变输出表示，因此奇数全域作为单输出的构造方式，
不成为第四种 LUT 类型。隐藏域长度 helper 命名为 `front_half_domain_len`，family 和 CBS
调用方显式表达前半区语义。

### 符号与排序依据

奇数模数通过 accumulator 的带符号折叠支持任意全域函数，参考
[Hippogryph §2.2.3](https://www.nicolasbon.com/assets/pdf/25Hippogriph.pdf)。以下是适配本库
两次整数舍入的推导，未直接采用论文中理想化的等宽区间。

令 `t=2h+1`，`E(m)=round(m*q/t)`，`c[m]=R(E(m),q,2N)`。对 `c[m]>=N`，
把中心减去 `N`，并将输出编码值取负；提取时的负循环符号恢复原输出。理想折叠位置为
`j*N/t`，其对应输入为偶数 `j` 时的 `j/2`、奇数 `j` 时的 `h+1+j/2`，因此输入访问顺序为
`0,h+1,1,h+2,...,h`。例如 `t=5` 时为 `0,3,1,4,2`，符号依次为 `+,-,+,-,+`。

排序也适用于真实编码：记 `a=q*j/(2t)`，在密文域先减去上半区的 `q/2`。
偶数 `q` 下，折叠编码为 `round(a)`；奇数 `q` 下，偶数 `j` 为 `round(a)`，
奇数 `j` 为 `floor(a)+1/2`。相邻 `a` 增加 `q/(2t)>1/2`，故这些值不递减。
再乘 `2N/q` 并舍入仍保序，但可能合并中心。`t<=N` 保证两消息半区量化后仍在对应的
旋转半区；编译器以真实 codec/quantizer 顺序扫描，拒绝不严格递增的折叠中心。
这避免排序分配，同时保留对双重舍入和中心不足的检查。

### 区间与边界

设真实折叠中心为 `0=d[0]<...<d[t-1]<N`，追加 `d[t]=N`、值 `-f(0)`。
相邻区间边界为 `ceil((d[j]+d[j+1])/2)`，相等距离归较大中心。最后一段填 `-f(0)`，
经负循环扩展得到零点左侧的 `f(0)`，覆盖负相位回绕；上半区输入还原为各自的正输出。
有效输入从前半区扩展到全 `0..t`，旋转多项式仍满足负循环关系。

要求奇数 `t>=3`、`t<=N`，以及共用的 `q>t`、`2N` 可表示和规范输出条件。
`t` 无须为素数。容量不是充分条件：`t=5,q=8,N=8` 的折叠中心存在碰撞，应拒绝；
`t=5,q=7,N=8` 得到 `0,1,2,6,7`，可表示但余量很小。不能把两次舍入合并为
`round(2N*m/t)`，也不能仅从理想间距判定几何有效。

典型折叠中心间距为 `N/t`，前半区约为 `2N/t`。具体输入的可容纳整数旋转偏差由左右
实际中点决定，最小中心间距的一半只提供保守几何界。完整 PBS 还需计入输入加密噪声、
BR 前的密钥切换、逐系数模切以及后续外积/KS 的输出噪声；本步不提供生产失败概率。

### 验证资产

增加两个共享测试，使用独立宽整数编码和带符号中心拷贝的最近邻 oracle：遍历
`t=3/5/9/15` 的全域和 `0..2N` 的每个位置，覆盖三种字宽、Native/显式模数、两次舍入、
碰撞、回绕、中点、规范输出和回调错误中止。原分配测试覆盖新构造器，仍只分配结果多项式。
四后端既有 fixture 改用 `t_in=15`、保留 `t_out=8`，复用原密钥逐一测试 15 个消息，
覆盖两种 GLWE order、两种 FFT 及零在线分配；没有新增 keygen 或测试程序。
共增加两个测试和 135 次小参数 PBS，无新增 benchmark 或性能改善结论。

默认七包测试、nightly `just tfhe-simd` 均通过，各 45 项；相关默认/SIMD all-targets
Clippy、workspace all-targets check、格式和严格 rustdoc 通过。未重跑未修改的示例、
其余 workspace 测试、性能计时、非 x86 或生产噪声/安全性验证。
