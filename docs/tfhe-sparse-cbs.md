# NTT sparse CBS：参数、误差与接入

**B6.1 原型通过，B6.2 已正式接入。** NTT CBS 复用 classic/sparse BR 绑定及公共后处理；
稀疏服务器密钥支持可选 CBS 材料，见[正式接口与验收](#6-b62-正式接入)。
Fourier 已在 [B6.3](tfhe-cbs.md#7-b63-fourier-sparse-cbs)完成自己的聚合变换与 Native halving 验证并接入。

下文第 1–5 节记录 B6.1 在基线 `18a1288` 上的原型。原型当时未改变公开拒绝边界，
没有增加生产 API、密钥类型或数值内核；历史数据不代替后续版本的测量。

## 1. 组合与误差来源

```text
外部 Rounded t=4 LWE bit
→ [KB：环 KS + compact extraction]
→ sparse gadget-scale ManyLUT BR（3 层，补齐 4 槽）
→ 逐层 RevHomTrace 投影为常数消息 GLev
→ scheme switch → accumulator 秘密下的 NTT GGSW
→ CMUX
```

BK 输入维数为 728，KB 为 1024；CBS 输出始终留在 accumulator 秘密下，
BK 不执行普通 PBS 的后置 KS。原型仅替换[经典 CBS](../crates/primus_tfhe_glwe_ntt/src/circuit_bootstrap/evaluator.rs)
中的 BR 绑定，复用[稀疏 ManyLUT kernel](../crates/primus_tfhe_glwe_ntt/src/sparse/blind_rotation.rs)。
参数、同一 client 的 trace/scheme-switch key、输出布局与后处理相同。

### 桶内的加密零仍有噪声

设桶 b 的选择位为 `z_b,j`，dummy 为 `d_b`，量化指数为 `α_j`。
`d_b + Σ_j z_b,j = 1`，每个非零 small 秘密恰在一个副本中生效。
聚合控制为

```text
C_b = GGSW(d_b) + Σ_j X^α_j GGSW(z_b,j)
E_b = E_dummy + Σ_j X^α_j E_selector,j
```

已占用桶的消息是所选单项式，未占用桶的消息是 1；两者都有整桶 selector 和 dummy 的
加密误差。不能只按 h 次“有效旋转”估计噪声，也不能跳过未占用桶。
原型逐桶解密最高 gadget 层的 body row，验证选择位覆盖真实 binary 秘密、每桶选择和为 1，
并用独立有符号负循环求和核对上式的**精确相等**。

本组 `n=728,c=3,b=64,h=32`：2,184 个 selector 中 32 个加密 1、2,152 个加密 0；
64 个 dummy 中各 32 个加密 0/1。各 map 的公开桶大小为 18–50，未要求等长。
[桶误差 CSV](benchmarks/tfhe-b6.1-buckets.csv)记录上述代表行：selector/dummy 的 RMS 约 0.70，
已占用桶聚合约 4.18–4.28，未占用桶约 4.03–4.13；聚合最大绝对误差为 22 个整数单位。
这些是密钥行的误差，不是 BR 最终误差；外积还包含 digits 卷积、分解残差及前面桶的误差。

### 后处理预算

- **输入/量化**：small LWE 加密误差、KB 前置 KS，以及按 4 槽量化的秘密加权偏差，
  必须留在正确 LUT 平台。平台错位不能作为普通加性噪声处理。
- **BR**：桶聚合误差经外积进入 accumulator。完整链同时检查真实量化旋转的精确 LUT
  参照，以及输出前 3 个槽确实为 `bit * gadget_scalar`。
- **NTT RevHomTrace**：按 `3,5,…,N+1` 执行 `H=inv2*C; C=H+Auto(H)`。
  这里是模 q 精确除二，仍有 automorphism KS 误差，不能照搬 Fourier 的逐系数 floor 模型。
- **Scheme switch**：若投影层相位为 `bit*g_l + e_l(X)`，body row 继承它；
  mask row 的目标为 `-s_r*bit*g_l`，误差包含 `-s_r*e_l` 和 scheme-switch 外积误差。
  可用 `||s_r*e_l||∞ ≤ ||s_r||₁ ||e_l||∞` 保守估计，不能假定各行/层独立。
- **CMUX**：还须计入候选密文误差、输出 basis 对差值的近似分解及 GGSW 误差卷积。
  最小 gadget 层有余量与最终 CMUX 解码正确是两个独立检查。

## 2. 固定参数与验证方法

| 项目 | 配置 |
| --- | --- |
| 表示 | u64，`U64NttTable`，Barrett `q=1,125,899,906,826,241` |
| Small 秘密 | n=728，固定重量 binary h=32 |
| 外部输入 | Rounded t=4、bit 0/1；BK σ=`3.2*q/16384`，KB σ=0.7，沿用各自外部秘密的加密参数 |
| Accumulator | d=1，N=1024，SparseTernary，σ=0.7 |
| BR basis | logB=10，L=5（完整）或 L=4（丢弃 10 位） |
| 环 KS basis / 噪声 | logB=10，L=4；σ=0.7，继承 accumulator 噪声 |
| Sparse map | c=3，64 桶，沿用现有匹配与拒绝采样 |
| Trace / scheme switch | 均 logB=10、完整 L=5、σ=0.7 |
| 输出 basis | L=3，logB=8/9/10；4 槽交错，三次完整投影 |
| Seeds | `StdRng::seed_from_u64(0x42363101)`、`0x42363102` |

每组 `(BR L, seed, order)` 重置 RNG，依次生成 client、经典 server、稀疏 server、
公共 CBS key、四个独立输入 `1,0,1,0`、两个加密候选多项式。
候选消息分别为 `i mod 4`、`(i+1) mod 4`，CMUX 必须逐系数选中正确候选。
同一组复用 CBS key 测三种输出 basis，因为层数/布局相同。
KB 的两种 server key 有独立采样的环 KSK；其完整输出差异不能全部归因于 sparse 聚合。

临时单元模块在私有 kernel 上手工串联完整链；没有绕过公开拒绝检查。
经典原型输出与公开 `CircuitBootstrapEvaluator` 逐元素相同，并显式验证两个公开构造入口
对 sparse 的拒绝。相位统计遍历 BR 槽、每个投影层、GGSW 每行/层及 CMUX 的全部系数。
在 logB=8 的首个输入上，另用整数负循环卷积 `b−a*s` 核对 BR、所有投影层和所有 GGSW 行/层，
不以 NTT 乘法作为这项独立参照。

[逐阶段 CSV](benchmarks/tfhe-b6.1-noise.csv)以整数系数单位记录均值、未去均值 RMS 和最大绝对误差。
每组 BR 层统计 1,024 个系数样本（四输入 × 每层 256 个槽）；投影、GGSW 行/层和 CMUX 各 4,096 个。
它们共享密钥和 BR，不能当作独立失败概率样本；阶段的样本位置也不同，不能相减 RMS 来分离噪声贡献。
默认/SIMD 的全部统计摘要与分配结果相同，CSV 不重复两份。

## 3. 最小尺度与可用范围

原型接受阈值：每行/层最大相位误差 `< g_l/8`，CMUX 最大误差 `< q/64`，
并要求全部候选系数正确解码。该阈值只用于这组实验，不是通用安全或尾概率条件。

下表为跨两种 order、两 seed 的**最低 gadget 层**观测最大误差：

| BR L | 输出 logB / L | 最小尺度 | 经典最大误差 | sparse 最大误差 | 本组逐层阈值 |
| --- | --- | ---: | ---: | ---: | --- |
| 5 | 8 / 3 | 67,108,864 | 2,508,107 | 3,354,946 | 通过 |
| 4 | 8 / 3 | 67,108,864 | 2,941,731 | 2,463,581 | 通过 |
| 5 | 9 / 3 | 8,388,608 | 3,053,094 | 3,946,075 | 未通过 |
| 4 | 9 / 3 | 8,388,608 | 2,625,837 | 3,289,443 | 未通过 |
| 5 | 10 / 3 | 1,048,576 | 2,471,196 | 4,629,037 | 未通过 |
| 4 | 10 / 3 | 1,048,576 | 2,641,805 | 3,632,894 | 未通过 |

**保留 logB=8、L=3 的输出配置**：尺度按低至高为 `2^26、2^34、2^42`；BR L=4/5
均通过逐行/层阈值。最差 sparse 最低层误差约为最小尺度的 5.00%。
所测完整量化偏差 BK 最大 12、KB 最大 16 个物理指数单位，小于平台半宽 256。
该配置 CMUX 最大相位误差 15,658,442,339，约为模 4 解码半径 `q/8` 的 0.0111%。
首次及复用的 CBS→CMUX 均零分配，`1→0` 输出覆盖正确。

logB=9/10 的样本中 CMUX 也全部解码正确，但最低层未满足上述余量，因此不纳入本次通过配置。
这不证明它们必然无法使用，只说明不能仅凭一次 CMUX 解码成功宣称更小 gadget 尺度已经验收。
BR L=4/5 消耗的密钥生成随机数不同，不以两列最大值判断截断会改善噪声。

本次通过范围是上述 q、字宽、秘密分布、输入 t=4 和三个 gadget 层；没有验证任意输出 basis、
更大明文域/层数、u32 或 Fourier。稀疏 map 的条件分布及正式安全/尾界继续遵循
[稀疏 PBS 边界](tfhe-sparse-pbs.md)。

## 4. 在线成本与资源

只计时通过的 **BR L=5、输出 (8,3)、seed=0x42363101**。
完整 CBS 每次处理四输入池中的一个，包含 KB 前置 KS，不包含 CMUX、setup、解密或分配。
分项在第一个 bit=1 的真实中间密文上独立计时，每次迭代恰执行一个阶段。
分项与完整调用的缓存状态和输入池不同，不能把它们相加当作精确拆账。

2026-09-19，AMD Ryzen 9 9955HX3D、x86_64 Linux、CPU 2，仓库 `target-cpu=native`。
默认 rustc 1.98.0（88d9e12ae），SIMD nightly 1.100.0（bff8e12ff）；Criterion 0.8.2，
每项 20 samples、1 s warm-up、2 s measurement、Flat sampling，串行执行。
CPU 未隔离/锁频，powersave governor、boost/SMT 开启；置信区间不包含跨运行漂移。
工具链不同，默认/SIMD 差异不能直接归因于某个手写 SIMD kernel。

单位 ms，每格 **默认 / SIMD**；均值与 95% CI 见[计时 CSV](benchmarks/tfhe-b6.1.csv)：

| order / key | 完整 CBS | BR | 三层投影 | Scheme switch |
| --- | ---: | ---: | ---: | ---: |
| BK / classic | 31.494 / 22.684 | 30.736 / 22.123 | 0.699 / 0.474 | 0.124 / 0.080 |
| BK / sparse | 20.005 / 18.834 | 18.384 / 17.801 | 0.701 / 0.464 | 0.127 / 0.081 |
| KB / classic | 33.655 / 22.341 | 32.393 / 21.707 | 0.686 / 0.453 | 0.125 / 0.079 |
| KB / sparse | 19.267 / 17.734 | 18.430 / 18.021 | 0.702 / 0.475 | 0.125 / 0.079 |

同后端同 feature 下 sparse 完整 CBS 的均值加速约 1.20–1.75 倍。
经典 BR 最多 n=728 次控制外积，稀疏 BR 为 64 次桶外积，同时读取并聚合 2,248 个系数 GGSW；
后处理仍为 `3*log2(N)=30` 次 automorphism/KS 和 3 次 scheme-switch 外积。
本步不增加聚合优化，不能仅按外积次数推断加速。

以下为构造窗口的净请求字节，含 Vec capacity，扣除窗口内临时释放；
排除共享 context/client、栈、allocator 元数据和窗口外生成 scratch，不是 RSS 或峰值。
测 CBS key 前已在窗口外准备好 KeyGenerator 的最大 scratch，避免把其增长计入 key。
两种 order、两 seed、输出 logB 扫描及默认/SIMD 的对应资源相同。

| 对象 | BR L=5 | BR L=4 |
| --- | ---: | ---: |
| 经典普通 server key | 119,341,272 B | 95,486,144 B |
| sparse 普通 server key | 368,396,064 B | 294,733,576 B |
| 附加 CBS key（两种 key 共用） | 1,111,088 B | 1,111,088 B |
| 经典原型 workspace（含 LUT） | 288,456 B | 288,456 B |
| sparse 原型 workspace（含 LUT） | 458,120 B | 425,352 B |
| 调用方 NTT GGSW 输出 | 98,304 B | 98,304 B |

相对经典 CBS，没有新增一种密钥材料；同一 trace/scheme-switch key 可直接复用。
Sparse 的 BSK 约 3.1 倍大，工作区额外持有聚合 GGSW 和 728 个旋转指数。
这些是原型布局的资源；B6.2 的正式工作区复核见第 6 节。没有测量 keygen 时间，也未把它计入在线收益。

## 5. 原型复现入口

临时原型与分配/相位统计代码已移除，避免将重型统计加入 CI。复测时按第 2 节固定生成次序：

1. 使用 `KeyGenerator` 为同一 client 生成经典、稀疏 server 和独立 CBS key。
2. 复用[输入 KS](../crates/primus_tfhe_glwe_ntt/src/evaluator.rs)、两种 BR kernel、
   [前缀投影](../crates/primus_glwe/src/trace/ntt_operations.rs)和
   [scheme switch](../crates/primus_glwe/src/scheme_switch/ntt.rs)，保留公开拒绝边界。
3. 按本文尺度/seed/order 矩阵核对相位、整数卷积参照、非恒定 CMUX 和首次/复用分配。
4. 从诊断分离计时；基准计时闭包只执行完整链或一个阶段，所有资源提前准备。
   原始计时样本位于 `target/criterion/b61*/{complete,blind_rotation,projection,scheme_switch}/b6_1_{default,simd}/`。

默认/SIMD 原型、公开经典逐元素参照及独立整数卷积均通过。
清理后复跑既有 `circuit_bootstrap` 测试（默认/SIMD），确认公开拒绝和经典链未改变。



## 6. B6.2 正式接入

`CircuitBootstrapEvaluator` 组合普通 `Evaluator`，由已有 `BlindRotation::{Classic,Sparse}`
绑定密钥和所选 scratch；前置 KS/BR 不再重复实现，后续投影与 scheme switch 共用。
没有新增公开类型、数值 kernel 或第二份 BR 工作区。原始两种 BSK 的表示保持显式区分。

`try_generate_sparse_server_key(client, copies, buckets, Option<CircuitBootstrapConfig>, rng)`
支持附加 CBS 材料，返回 `KeyGenerationError`；`SparseBootstrapping(#[from])` 保留底层错误。
无效 CBS 配置先于采样拒绝。仅需 PBS 的调用方传 `None`，缺少 CBS 材料仍返回
`MissingCircuitBootstrapKey`。高级 `try_from_parts` 可复用同 client 的独立 CBS key，
仍由调用方保证秘密与 NTT 表示一致，构造器只检查参数、布局与 basis。

[现有测试](../crates/primus_tfhe_glwe_ntt/tests/circuit_bootstrap.rs)保留两个测试入口：
在小型 fixture 中补两种 order 的 sparse 链、bundled/独立材料、每行/层 gadget 相位、
非恒定 CMUX、外积、`1→0` 复用及首调用零分配。检查输入域/密钥/basis 不兼容、
缺少 CBS、写入前长度拒绝和无效 CBS 配置不消耗随机数。原有 ternary 两种 order 保留。

[现有 CBS benchmark](../crates/primus_tfhe_glwe_ntt/benches/circuit_bootstrap.rs)以四项
n=728 的经典/稀疏、BK/KB 完整 CBS 替换原四项小型层数扫描。复用第 2 节 BR L=5、
输出 `(8,3)`、第一 seed 与生成顺序；setup 检查所有行/层 `<g_l/8`、非恒定 CMUX 和
首调用/复用零分配，并报告 workspace 净请求字节。每迭代处理输入池中一个密文，
CMUX、检查和资源构造不计时。大参数统计不进入普通 CI 测试。

公开构造器不硬编码原型的噪声阈值；最小 gadget 尺度与完整尾界仍由应用预算承担。

### 正式入口复测

2026-09-19，基于 `507978d` 的 B6.2 工作树；沿用第 4 节硬件、工具链、CPU 2、
20 samples / 1 s warm-up / 2 s measurement / Flat sampling。默认和 SIMD 串行运行，
计时期间不编译。完整 CBS 的均值及 95% CI（ms）：

| order / key | 默认 | SIMD |
| --- | ---: | ---: |
| BK / classic | 34.346 [33.816, 34.906] | 21.511 [21.438, 21.594] |
| BK / sparse | 21.388 [20.623, 22.177] | 18.138 [17.855, 18.478] |
| KB / classic | 33.539 [33.243, 33.868] | 21.786 [21.548, 22.081] |
| KB / sparse | 20.611 [19.916, 21.365] | 17.980 [17.788, 18.291] |

同 feature 下稀疏路径本轮约快 1.19–1.63 倍。与 B6.1 的历史计时没有交替测量，
因此这组数据只描述当前入口的成本，不用于判断封装前后的微小性能变化。
原始样本位于 `target/criterion/glwe_ntt_cbs_u64_n728*/{classic,sparse}/b6_2_{default,simd}/`。

两种 order/default/SIMD 的 evaluator 净请求字节均为经典 288,456 B、稀疏 458,120 B，
调用方输出 98,304 B，与 B6.1 的 BR L=5 原型一致。计数包含 LUT 与所选工作区，
排除 context、密钥、栈和 allocator 元数据；它不是 RSS。构造器没有增加在线分配。

`just tfhe`、`just tfhe-simd`、改动三包的严格 rustdoc、经典/`--sparse` 两种 release 示例
以及上述两套基准均通过。修改后的 Markdown 本地链接检查通过。B6.2 当时未改变 Fourier 的公开拒绝边界；后续接入见 [B6.3](tfhe-cbs.md#7-b63-fourier-sparse-cbs)。
