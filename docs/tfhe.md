# TFHE LUT 与 PBS 设计

本文保存已落实的跨层契约与算法取舍；公开使用方式以 [TFHE README](../crates/primus_tfhe/README.zh_CN.md) 和 rustdoc 为准。当前状态见 [HANDOFF](../HANDOFF.md)。

| 阅读目标 | 文档 |
| --- | --- |
| 已完成的 P1–P4 | [实施索引](tfhe-plan.md) |
| 固定重量二元桶聚合 | [稀疏 PBS：推导、布局、测量](tfhe-sparse-pbs.md) |
| 同一输入、多函数输出 | [固定尺度分解式 MVB](tfhe-mvb.md) |
| 下一阶段 | [候选算法](tfhe-next.md)、[ternary 与 T1–T3](tfhe-ternary.md) |
| 当前基准入口与历史测量 | [测量索引](benchmarks/tfhe.md) |

## 职责与执行边界

| 层 | 职责 |
| --- | --- |
| 应用 | 整数/布尔语义、有效范围、message/carry、多输入与串联误差预算、执行图 |
| `primus_tfhe` | LUT 编译、几何与布局、共享旋转量化、有界双输入打包、小型 PBS 功能接口 |
| GLWE/NTRU、NTT/Fourier 后端 | BSK、BR、初始化、表示变换、scratch、KS 与提取 |

普通 PBS、Boolean 内部尺度、CBS gadget 尺度分别处理。GLWE 保留 BR→KS / KS→BR 及各自外部秘密维数；NTRU 保留真实 `NLev[1]` 初始化和固定秘密链。稀疏性、ternary 都作用于真正进入 BR 的秘密，LUT 不保存这类策略。

CBS 在密钥生成时通过 `Some(CircuitBootstrapConfig)` 可选启用，附加参数/key 由 `ServerKey` 持有，evaluator 独立分配工作区；GLWE key 绑定输出布局，NTRU key 绑定完整输出 basis。一般交错 LUT 不满足前缀展开的零尾前提，应走投影；NTRU CBS 留在 accumulator 秘密下，不执行普通 PBS 的后置 KS/extraction，也不依赖 packing。

相同布局/basis 不证明实际秘密相同；Fourier table 身份、规范剩余类与噪声预算由各公开契约承担。TFHE 公钥复用 `LwePublicKey` 并绑定外部 LWE 秘密，GLWE 按 order 为 n 或 kN，NTRU 为 client 前缀；公钥总噪声单独计入 PBS 输入预算。

### 错误组织

公共 LUT/evaluator 错误由 `primus_tfhe` 定义；两族的 `error` 模块集中维护参数、客户端及
密钥生成错误，NTT/Fourier 后端重导出。变换表错误留在后端 context，稀疏匹配保留专用错误。
不增加跨全部操作的总错误；只有无歧义转换使用 `#[from]`。BR/KS、trace/SS 在调用点
显式 `map_err` 标明用途，并以 `#[source]` 保留原因。表错误不保证 `Clone`/`Eq`，context 错误不额外承诺它们。
公开错误入口见 [README](../crates/primus_tfhe/README.zh_CN.md#错误边界)。

## P1.1 精确几何与元数据

编译中心经历 `message → RoundedCodec → modulus switch` 两次舍入，不能合并为理想化的一次比例舍入。例如 `N=16,s=1,t=3,q_in=5,m=1` 的真实中心为 13，一次舍入为 11，填充边界也不同。

旋转域要求 `s<=N`，且物理 `2N` 本身可由系数类型表示；逐系数量化与区间填充见下文。

| 信息 | 归属 |
| --- | --- |
| 环长 N | 从多项式长度得到 |
| `t_in,q_in,q_acc` | LUT 元数据分别绑定输入编码、量化和系数算术；raw 编译允许两个密文模数独立 |
| 真实编程域 D | `input_domain_len()`；不能仅由 `ceil(t_in/2)` 推断，也不能从 raw LWE 验证真实消息 |
| 有效输出数 k / 补齐数 s | 交错表保存 k，`padded_output_count()` 推导 `s=next_power_of_two(k)` |
| 中心、区间、临时行 | 仅构造期计算，不保存持久中心数组 |
| 输出尺度、实际秘密、变换身份 | 由调用工作流及后端承担，不混入通用 raw LUT 的兼容性检查 |

`D<=N/s` 只是容量条件，还须检查真实中心分离；几何余量不是完整 PBS 失败概率。负循环尾部、回绕、短前缀及非均匀中心按真实中点处理，未编程位置不成为额外有效输入域。

### 前半区旋转布局

令 `D = input_domain_len()` 为已编程前缀长度，`s = padded_output_count()`（普通 LUT 为 1），
每个输出占用的系数数为 `M = N/s`。一个**输出组**包含 `k` 个已编码函数值和 `s-k` 个零；
一个**输入区间**重复该输入的输出组。输出 `j` 占用系数 `s*r+j`，其 `M` 个系数
包括重复项和负循环尾部。

`k` 和明文模数 `t` 都不必是二次幂；补齐数量 `s = next_power_of_two(k)` 始终是二次幂，
且整除 `N`。仍须满足实际编码中心不碰撞、输入域限制和噪声余量要求。

消息先编码为 `E(m) = round(m*q_in/t) mod q_in`，再映射到每输出系数坐标中的中心
`R(E(m), q_in, 2M)`，其中 `R(x,q,L) = floor((x*L + floor(q/2))/q) mod L`，
两次舍入遇到中点均向上。Native 的 `q_in` 为 `2^T::BITS`。合并两次舍入可能改变表内容。

编译器选择最近中心的值，中点相等时选择较大的中心；最后在 `min(R(E(D), q_in, 2M), M)`
追加值为 `-f(0)` 的中心以终止编程前缀，其后的系数不是额外的输入域。

例如 `q_in=2^32`、`N=64`、`t=8`、`k=3`、`D=4` 时，以
`F(m) = [f0(m), f1(m), f2(m), 0]` 表示已编码输出组，布局为：

```text
F(0) × 2 | F(1) × 4 | F(2) × 4 | F(3) × 4 | -F(0) × 2
```

这些对齐的中心对应等长的完整区间，但首个区间被多项式边界拆分，尾部取负。
非二次幂 `t` 或中心未精确对齐时，区间长度可以不同。两种情况使用同一个编译器；
`M` 不是重复次数。

构造器的 `input_ciphertext_modulus` 即 `q_in`；`coefficient_modulus` 即 LUT 多项式
与累加器共用的 `q_acc`。raw 输出必须已经是 `q_acc` 下的规范值，越界值会被拒绝。
系数模数与输出尺度均独立于 `q_in`。

四后端使用 `rotation_step = padded_output_count()`，逐个将 LWE 系数量化为 `s*R(x, q_in, 2N/s)`，旋转指数为
`-R_s(b) + sum(R_s(a[i])*secret[i])`，不能替换为对解密相位的一次量化。
编译端使用同一个 `2N/s` 量化域，步长为 1；执行端再乘以 `s`。
由于 `s` 整除 `N`，跨越负循环边界也保留输出索引模 `s` 的余数；
提取系数 `j` 时按负循环符号读取对应输出。

## P1.M 模数侧缩放与量化

`source.prepare_switch_to(target)` 准备固定模数对；`PreparedModulusSwitch` 执行时只接收规范源系数，返回规范目标剩余类。`RingContext` 聚合 `PrepareModulusSwitch`，执行对象保持独立。目标是准备方法的泛型，返回类型由源实现选择。

`ModulusSwitch` 保存算术 kernel，标量仍可能分派；`switch_map` 在循环前选择内核。外层无需增加 match。二次幂非整比扩张使用移位；紧凑范围 `1<q<2^(T::BITS-2)` 根据分子上界选择单/双字倒数估商、精确修正和端点回绕。Barrett/派生 Barrett 复用源倒数，其他范围使用通用整数内核。

Rounded 准备 `t→q` 编码与 `q→t` 解码；Scaled 保持 `m*round(q/t)` 并准备解码。Centered/Unsigned 留在 codec，绝对值舍入、解码共用模切内核；批量融合符号/输出，标量保留实测合适的包装形态。模数有效性由准备阶段检查，codec 负责 `q>t` 与 Scaled 恢复条件。

规范 residue 的模切/解码采用 nearest ties-up；Rounded 的有符号 lift 编码采用 nearest ties-away-from-zero。两者不能因复用内核而混淆。

codec、基础加解密与通用 client 的输入输出统一为 T / `[T]`，类型转换由应用处理，Boolean 保留 bool。描述性模数元数据仍可用 `Option<T>`。普通量化在 GLWE BSK / NTRU 参数构造时准备；交错量化按 LUT 步长在系数循环前准备。性能限制及未保留的 PBS 循环融合见[测量记录](benchmarks/tfhe.md#固定模数对内核优化)。

## P1.2 共享几何与直接填充

单输出和交错表共用顺序中心/区间扫描：几何 `O(D)`、函数求值 `O(kD)`、最终系数填充 `O(N)`。首个输出组直接写最终多项式，区间内复制；单输出使用 fill。首组 `f(0)` 复用于负循环尾部，不另分配中心或逐列多项式。

中心用每输出系数坐标，填充接收实际系数切片；`fill_input_interval` 负责求值/检查/区间填充，`fill_negated_tail` 收尾。当前全部只分配最终结果。多输出构造有显著收益，单输出存在小幅成本增加，见[最终对照](benchmarks/tfhe.md#p14-最终对照)。
使用内置模数类型且 callback 不分配时，仅分配结果多项式；callback 报错或输出越界时停止，不返回部分表。

## P1.3 布局 API 决定

- raw 构造为 `LookupTable::try_new` / `InterleavedLookupTable::try_new`，接收已编码输出。旧自由函数与 `ManyLookupTable` 名称已删除。
- 交错回调/切片只含 k 个有效输出，输入优先切片长度为 `D*k`；编译器补零到 s 槽。BR 按 s 量化，提取与输出切片按 k。
- Family/context 保留明文检查、默认域和编码职责；Boolean/CBS 使用 raw 构造保持各自尺度。
- `ProgrammableBootstrapInterleaved` 只承诺交错求值，不泛指所有 MVB；一次 BR/环 KS 是当前后端实现。分解式 MVB 使用独立产物/evaluator。
- 三路 CBS 以真实 gadget 层数构造、投影，参数通过 `lookup_table_padded_output_count()` 表达补齐数。

### 源码组织

四种公开类型均从 crate 根导出。奇数全域是 `LookupTable` 的构造方式，
输出槽布局由 `InterleavedLookupTable` 管理，双输入打包由 `BivariateLookupTable` 管理。
`FactorizedLookupTable` 保存共同多项式与系数域差分因子。全部因子共用一块连续空间，
`factors()` 返回 `PolynomialIter`；`into_polynomials()` 将共同多项式与扁平因子缓冲移交后端准备。

| 文件 | 职责 |
| --- | --- |
| [bootstrap.rs](../crates/primus_tfhe/src/bootstrap.rs) | 完整普通/交错 PBS 的 LWE 输入输出契约 |
| [rotation.rs](../crates/primus_tfhe/src/rotation.rs) | LUT 编译与 BR 共用的准备、标量和批量量化 |
| [lookup_table.rs](../crates/primus_tfhe/src/lookup_table.rs) | 统一导出与共用编码元数据 |
| [single.rs](../crates/primus_tfhe/src/lookup_table/single.rs) | 单输出类型，集中前半区和奇数全域构造器 |
| [interleaved.rs](../crates/primus_tfhe/src/lookup_table/interleaved.rs) | 多输出类型及补齐输出数、有效数量接口 |
| [bivariate.rs](../crates/primus_tfhe/src/lookup_table/bivariate.rs) | 双输入范围、打包与普通 LUT 的绑定 |
| [factorized.rs](../crates/primus_tfhe/src/lookup_table/factorized.rs) | 固定尺度共同多项式与负循环差分因子 |
| [compile.rs](../crates/primus_tfhe/src/lookup_table/compile.rs) | 共用编码校验、中点与负循环尾部填充 |
| [compile/front_half.rs](../crates/primus_tfhe/src/lookup_table/compile/front_half.rs) | 前半区单输出/交错编译、域与槽容量检查 |
| [compile/odd_full_domain.rs](../crates/primus_tfhe/src/lookup_table/compile/odd_full_domain.rs) | 奇数域检查、中心折叠与区间填充 |

## P1.R 取整策略取舍

旋转域边界已统一。均匀二元秘密的 Centered / shifted 原型仅为可行性验证；默认舍入和 PBS 执行规则保持不变。

### 舍入与启动条件

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

**保留的反例：** `q=5,N=8,t=4,k=3,s=4,p=4` 为合法布局；零 mask、`m=b=0` 时，固定 half-shift 得源修正 `c=-1`、`b'=4`，虚拟指数为 3，读取 `-f(1)` 而非 `f(0)`。因此零噪声下也不能全局启用 shift。

均匀二元 u32 的所测量化方差约减半，完整 PBS 未观察到明确开销增加。正式接入还须绑定实际 BR 分布、跨字宽累积、两种 order 的修正位置及允许 shift 的布局；固定重量、NTRU/CBS 不能照搬。原型公式、参数、反例与测量入口见[居中实验](benchmarks/tfhe.md#p1r-居中原型)。

## P2.1 输入与输出编码分离

普通 family/context 的 LUT 编译显式接收输出 `RoundedCodec`，输入参数决定域与中心，输出 codec 决定 `t_out` 和尺度；其密文模数必须等于 accumulator。当前完整 PBS 链仍要求输入、accumulator、输出的密文模数相同，支持不同的是明文模数/尺度。

client 的 `decrypt_phase` 返回规范带噪 residue，由保留的输出 codec 解码；`decrypt` 沿用参数 codec。串联时下一 PBS 的输入编码须匹配，raw 密文无法自动推断尺度。Boolean/CBS 与自定义逐列编码仍用 raw 构造。[公开工作流](../crates/primus_tfhe/README.zh_CN.md#选择输出编码)。

## P2.2 有界双输入 PBS

`BivariateLookupTable<T,M>` 保存普通 LUT、基数 B 与模数，编译矩形域 `0..B × 0..R`，要求 `B*R<=ceil(t_in/2)`。`pack_to` 检查长度后一次写入 `lhs+B*rhs`，调用方复用缓冲区再执行普通 PBS；无需新后端或密钥。[公开工作流](../crates/primus_tfhe/README.zh_CN.md#有界双输入-pbs)。

两输入必须同秘密、同 unsigned rounded 编码。令 `epsilon(m)=E(m)-m*q/t`，打包的舍入差为 `rho=epsilon(x)+B*epsilon(y)-epsilon(x+B*y)`，保守界为 `|rho|<=(B+2)/2`；t 整除 q 时为零。输入误差变成 `e_x+B*e_y+rho`，之后再计入可能的前置 KS 和模切。容量检查不证明噪声余量。

## P2.3 奇数明文模数全域

`LookupTable::try_new_odd_full_domain` 及两族参数上的 `compile_odd_full_domain_lookup_table_fn/slice`（通过 `context.parameters()` 调用） 编译整个 `0..t`，返回原有单输出类型。输入用普通 unsigned 加密，输出独立 codec；交错与双输入仍用前半区。[公开前提](../crates/primus_tfhe/README.zh_CN.md#奇数全域-pbs)。

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

## P4.0 共享旋转契约与后端执行阶段

[bootstrap](../crates/primus_tfhe/src/bootstrap.rs) 描述完整 LWE→LWE 求值，[rotation](../crates/primus_tfhe/src/rotation.rs) 提供 LUT/BR 共用的 prepared quantizer；旧 `backend_support` 及无生产调用的一次性模切包装已删除。已量化指数的直接转换留在低层入口。

### 后端执行阶段

共享 trait 描述完整求值，不规定 BSK 算法、秘密分布或变换表示。各后端内部将
`blind_rotate` 与 `keyswitch_accumulator` 分开；阶段 helper 保持私有，复用工作区、
检查与入口处的一次算法分派：

| 阶段 | GLWE | NTRU |
| --- | --- | --- |
| BR 输入 | BK 直接使用 small-LWE；KB 先 ring KS、compact extraction 得到 small-LWE | 客户端秘密下的外部 LWE |
| BR 结果 | `main_glwe`，accumulator 秘密下的系数域 GLWE | `blind_rotation.current`，`f_acc` 下的系数域 NTRU |
| 普通/交错输出 | BK 将 accumulator KS 至补零 small 秘密后 compact extraction；KB 直接提取 kN LWE | KS 至客户端环秘密后 compact extraction |
| CBS | 消费 accumulator 秘密下的 BR 结果，继续投影/SS | 保持 `f_acc`，继续各自的投影/SS |

BK/KB 分别为 `BootstrapKeyswitch` / `KeyswitchBootstrap`。后置 KS 写独立缓冲区，
保留 BR 结果；MVB 的具体后处理与 KS 位置由所选算法决定。GLWE 经典 BR 在循环外选择
binary 单控制或 ternary 控制对；LWE 剩余类到 signed GLWE 私钥的转换在密钥构造边界完成。
NTRU ternary、桶聚合稀疏 ternary 及 automorphism 算法尚未接入。

MVB 已在这些阶段上接入，具体乘法与 KS 顺序见[专项设计](tfhe-mvb.md)。Ternary 的控制密钥、`q-1→-1` 转换及兼容性已在经典 GLWE 两后端接入，见[设计与测量](tfhe-ternary.md)。P4.0 重构未测得稳定性能回退，方法见[测量记录](benchmarks/tfhe.md#p40-阶段拆分)。

## 验证入口

共享整数 oracle 保护中心、区间、双输入和分解恒等式；后端 fixture 覆盖 Native/Barrett、两种 GLWE order、两种 Fourier table、实际秘密域、普通/交错/CBS 与在线零分配。按实际支持配置复用 fixture，不机械扩张笛卡尔积。

修改 encoding、lattice 或 GLWE/NTRU 底层契约时额外覆盖相应消费者。接口迁移搜索整个 workspace，不能以文档入口表替代调用方检索。历史命令通过、benchmark 冒烟和有限噪声样本均不替代当前验证或生产安全证明。

在 workspace 根目录运行：

```sh
just tfhe
just tfhe-simd
```

两条 [recipe](../justfile) 均检查七个 TFHE crate 和共享测试辅助的 check、Clippy、测试；`tfhe` 还检查
`xtask` 并构建文档。`just ci` 另执行 workspace 与底层 SIMD 检查。
局部修改可先运行 `cargo test -p <crate>`、`cargo clippy -p <crate> --all-targets -- -D warnings`
及 `cargo doc -p <crate> --no-deps`，SIMD 测试使用 nightly 和 `--features simd`。

验收资产按 [后端覆盖](tfhe-backend-coverage.md#5-现有能力的组合缺口) 和
[分步计划](tfhe-backend-plan.md) 定位：Boolean 共用门真值表与门链；sparse 的受控输入误差
见 [B3.3](tfhe-sparse-pbs.md#b33-已有上层组合验收)；MVB 的同尺度对照、容量与误差见
[GLWE](tfhe-mvb.md) / [NTRU](tfhe-mvb-ntru.md)。NTRU CBS 的
[NTT](../crates/primus_tfhe_ntru_ntt/tests/circuit_bootstrap.rs) /
[Fourier](../crates/primus_tfhe_ntru_fourier/tests/circuit_bootstrap.rs) 用例覆盖 LWE→NGSW→CMUX、
非二次幂层数、basis/容量错误和首调用零分配。

当前基准入口、计时边界与历史数据统一见[测量索引](benchmarks/tfhe.md)。README 保存
推荐工作流、公开契约与用户需要的限制；测试覆盖、阶段验收和内部布局在本页及各专项维护。
