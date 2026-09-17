# TFHE 首个 MVB：固定尺度差分分解

本文是 **P4.1 的选型与 P4.2 的实现依据**，源码分析基线为 `1a34b41`。
这里定义的 MVB 类型和入口尚未实现；当前进度见 [HANDOFF](../HANDOFF.md)，
任务划分见 [实施步骤](tfhe-plan.md#p41-mvb-算法与编码选型)。

## 1. 选型与适用范围

选择**共享阶梯多项式的盲旋转，再乘各输出的整数差分多项式**。
首版为 GLWE NTT，复用经典/稀疏 BR、两种 PBS order、已有 KSK 和提取原语。
输入沿用 unsigned `RoundedCodec` 的前半区/短前缀；所有输出共用一个 unsigned
`ScaledCodec`。一个程序有 `k >= 1` 个输出，数量不必为二次幂，也不要求 `k <= N`。
量化步长始终为 1，不增加新的秘密分布或控制密钥。

实际价值是从同一个小整数生成多个阈值标志、数值位或小型替换表输出，尤其是交错
布局容量或旋转余量不足时。输出 0/1 是数值编码，不能直接当作 Boolean evaluator
的内部编码。MVB 也不承诺优于所有可用的交错 ManyLUT。

| 路线 | 共享什么 | 主要代价 | 本轮选择 |
| --- | --- | --- | --- |
| 现有交错 ManyLUT | 一次 BR 和当前链中的 KS | `s=next_power_of_two(k)`，每输出只有 `N/s` 个系数位置 | 保留，作为比较基线 |
| 差分分解 MVB | 对共同多项式做一次完整 BR | 每输出公开乘法，噪声乘以差分因子；BK 首版逐输出 KS | **实现这一种** |
| 常数/单项式 accumulator 后乘完整 LUT | 一次 BR | 后乘因子通常稠密，噪声取决于完整 LUT 范数 | 代数简单，但不作为默认实现 |
| 基于 BR unfolding 的 MVB | 输入相关的分组旋转控制 | 分组控制密钥、缓存；每输出仍执行分组外积链 | 后续独立 BR 策略 |

差分有闭式解，无须求解稠密线性方程组，见
[CIM19 §3.1、Theorem 3.2](https://eprint.iacr.org/2018/622.pdf)。
[Hippogryph §3.1.2](https://www.nicolasbon.com/assets/pdf/25Hippogriph.pdf)
给出共同因子与差分因子的描述；下文重新推导其在本库整数编码和真实 LUT 几何中的形式。
[TCHES 2024 §3.3](https://ches.iacr.org/2024/papers-issue-4/4_98.pdf)
展示了常数 accumulator、逐输出公开多项式乘法的路线，说明后乘因子范数是选择中的关键。

[MOSFHET](https://eprint.iacr.org/2022/515) 的 unfolding 路线有不同的共享产物。
其[作者实现](https://raw.githubusercontent.com/antoniocgj/MOSFHET/main/src/bootstrap.c)
中，宽度 `u` 的分组保存二元选择项，密钥条目约为 `n*2^u/u`；phase 1 缓存 `n/u`
个输入相关 GGSW，phase 2 对每张 LUT 执行 `n/u` 次外积。它不等于共享一个已经
完成 BR 的 GLWE，也不等于仓库已有的 trace/系数展开。这里核对了作者实现；论文
PDF 本次访问受限，不引用其未核实的误差公式。Automorphism 与 ternary 不纳入首版。

## 2. 分解与恢复

### 符号和真实几何

- `N`：负循环环长，`R_q = Z_q[X]/(X^N+1)`；GLWE 维数记为 `d`，避免与输出数 `k` 混用。
- `q`：accumulator/输出密文模数，首版为奇数且可用于现有 NTT context；输入模数
  记为 `q_in`。共享几何允许区分二者，当前完整后端链仍要求 `q_in=q`。
- `t_in, D`：输入明文模数与有效前缀长度，`1 <= D <= ceil(t_in/2)`。
- `t_out`：统一输出明文模数；`Delta = round(q/t_out)`，ties upward。
- `p_i`：**未乘输出尺度的整数 LUT 多项式**；有效平台值为 `f_i(m) ∈ [0,t_out)`，
  负尾为 `-f_i(0)`，系数保留这个整数 lift 的含义。

`p_i` 的区间必须复用现有[前半区编译几何](../crates/primus_tfhe/src/lookup_table/compile/front_half.rs)：
输入先编码再量化，中心为 `R(round(m*q_in/t_in),q_in,2N)`，中点相等归较大中心，终止中心
和短前缀负尾遵循现有规则。不能把两次舍入合并，也不要求 `t_in` 为二次幂或整除 `2N`。

### 精确恒等式

在整数负循环环中定义：

```text
S(X) = 1 + X + ... + X^(N-1)
(1-X)S(X) = 1-X^N = 2

W_i(X) = (1-X)p_i(X)
w_i[0] = p_i[0] + p_i[N-1]
w_i[j] = p_i[j] - p_i[j-1]       (1 <= j < N)
```

奇数 `q` 下取 `A = Delta * 2^(-1) mod q`，以 **全部 N 个系数都等于 A** 的
`V=A*S` 初始化 BR。由此

```text
V * W_i = Delta * p_i                         in R_q
(X^(-r) * V) * W_i = X^(-r) * Delta * p_i     for every r in Z_(2N)
```

这里 `r=R(b)-sum(R(a_j)*s_j) mod 2N` 来自逐系数量化，不是把解密相位量化一次。
只要 `r` 位于消息 `m` 的有效平台，常数项就是 `Delta*f_i(m) mod q`。
分解不改变原平台的输入误差容忍区间；输出噪声则需单独预算。

`V` 是算法的共同原始多项式，不能经普通 LUT 构造器再填负尾；否则它不再是 `A*S`。
尾部可能为空，因此必须保留一般的 `w_i[0]`，不能假定它总是零。

### 一个可手算例子

`N=8, q=97, t_in=t_out=8, D=4, f(m)=m`：真实中心为 `0,2,4,6`，终止中心为 8。

```text
p     = [0, 1, 1, 2, 2, 3, 3,  0]
W     = [0, 1, 0, 1, 0, 1, 0, -3]
Delta = 12, A = 6
V*W   = 12*p  (mod 97)
```

对消息 2 的中心做 `X^(-4)` 旋转，提取值是 24，解码得到 2。
`W` 的一范数为 6，平方二范数为 12；系数 `-3` 存储为 residue 94，计算噪声范数时
不能将它当成整数 94。

## 3. 为什么使用固定尺度输出

`ScaledCodec` 编码为 `Delta*m mod q`；`RoundedCodec` 编码为 `round(q*m/t_out)`。
前者让尺度完整进入共同因子 `V`，后乘 `W_i` 只包含小整数差分。若直接对已编码的
Rounded LUT 求差分，跳变可达到 `q/t_out` 的量级，不能再声称其后乘噪声很小。

例如 `q=97,t_out=8,m=7`，Scaled 编码为 84，Rounded 为 85；两者不能在编译时
互换。其 decoder 虽相同，但 Scaled 输出接入下一次 Rounded 输入 PBS 时，要把
`Delta*m-round(q*m/t_out)` 加入确定性输入误差；相同 `t,q` 不足以证明中心相同。

**不要先将 p 或 W 在 Z_t 中约简。** 固定尺度一般不是从 `Z_t` 到 `Z_q` 的环同态。
例如 `q=97,t=8,p=[7,...,7]`，正确 `w[0]=14`；改成 `14 mod 8=6` 会把 `V*W` 的
常数项从 84 改成 36。只在密文环 `R_q` 中表示与约简公开乘数。

### `1/2` 的边界

- 奇数 `q`：`2^(-1)` 只用于**无噪声的公开共同多项式构造**；`2A=Delta mod q` 精确。
  `Delta` 为奇数时 `A` 可以很大，这不等于用大整数后乘有噪声密文。
- 不允许 BR 后再给所有密文系数乘 `2^(-1)` 充当实数除二：例如模 97 的单位误差会
  变成 residue 49，其 centered lift 是 -48，完全不是小误差的一半。
- Native `q=2^w`：不存在 `2^(-1)`。若 `Delta` 为偶数，可在构造期取整数 `A=Delta/2`，
  同一恒等式仍成立；若 `Delta` 为奇数，这个通用共同因子不存在。例如 `q=256,t=3`
  的合法 Scaled 尺度为 85，`2A=85 mod 256` 无解，向下除二会把尺度改成 84。

首版只交付 GLWE NTT 的奇数 `q`。Fourier/Native 后续需明确偶尺度条件或另一编码方案，
并核对整数乘数 FFT 与 torus FFT 的区别及浮点误差；不通过一次模逆或系数右移泛化。
NTRU 的初始化和后处理保持独立，首版不自动扩展到它。

## 4. 噪声与容量条件

输入误差与逐系数模切误差首先必须把 `r` 留在相应 `p_i` 平台。此处沿用步长 1 的
普通 PBS 几何，不能用输出成功解码替代输入位置条件。

令共享 BR 结果为 `X^(-r)V + e_BR(X)`，各输出公开乘法后的误差为 `W_i*e_BR`。
本库首版两种顺序如下：

| Order | 完整流程 | 提取后的输出误差 |
| --- | --- | --- |
| BootstrapKeyswitch（BK） | BR 一次 → 各输出乘 `W_i` → 各输出环 KS → compact extraction | `coeff_0(W_i*e_BR) + e_KS,i` |
| KeyswitchBootstrap（KB） | 输入 KS 一次 → BR 一次 → 各输出乘 `W_i` → full extraction | `coeff_0(W_i*e_BR)`；前置 KS 误差已进入输入位置预算 |

BK 的 KSK 仍是 accumulator 秘密到补零 small-LWE 秘密，外部维数保持 `n`；KB
输出仍在 accumulator 展平秘密下，维数 `dN`。公开环乘法不改变秘密域。

把 BK 的 KS 提前到所有 `W_i` 之前，在代数上也成立且只需一次 KS，但误差变成
`W_i*(e_BR+e_KS)`。首版选择乘后逐输出 KS，避免放大 KS 误差；P4.3 可按实际余量
和成本重评，不增加无人需要的策略 enum。

不假设 BR 误差系数独立。无条件的确定性界是

```text
||W_i*e_BR||_infinity <= ||W_i||_1 * ||e_BR||_infinity
```

设 `B=t_out-1`。前半区 `p_i` 最多有 `D-1` 次有效值之间的跳变，另有一次连接
`f_i(D-1)` 与 `-f_i(0)` 的带符号接缝。负尾为空时该接缝进入 `w_i[0]`，结论相同：

```text
nnz(W_i) <= D
||W_i||_1 <= (D+1)*B
||W_i||_2^2 <= (D+3)*B^2
```

实际差分通常小于这个最坏界；使用真实整数差分计算范数。若 `Sigma` 是按
`e[0],...,e[N-1]` 排列的协方差矩阵，常数项对应负循环卷积行
`v_i=(w_i[0],-w_i[N-1],...,-w_i[1])`，方差通式为 `v_i^T Sigma v_i`。
只有另行建立等方差、无相关假设时，才可简化为 `sigma^2*||W_i||_2^2`。
不同输出共享 BR 噪声，不能把其失败事件默认看成独立。

令 `epsilon=t_out*Delta-q`，消息输出值为 `y=f_i(m)`，提取噪声的整数 lift 为 `e_i`。
[ScaledCodec](../crates/primus_encoding/src/scaled.rs) 的恢复充分条件是

```text
|epsilon*y + t_out*e_i| < q/2
```

其构造器只检查无噪声条件 `|epsilon|*(t_out-1)<q/2`，不替调用方提供 MVB 噪声预算。
上述范数界与输入几何也不构成生产参数安全性或完整失败概率认证。

容量示例：`N=32,q=193,t_in=32,D=16`，同时计算阈值 `m>=3,7,12`，输出 `t_out=2`。
三张差分表各只有两个非零项，一范数 2、平方二范数 2；分解式保持完整的 16 个输入
平台。交错 3 输出需 4 槽，`N/4=8<D`，当前构造器会拒绝。此例说明表达容量，
不是可用于生产的噪声参数。

## 5. 编译产物、预处理与工作区

以下为 P4.2 的接口方向，具体签名按已有错误类型和真实调用方收敛：

1. **共享 `FactorizedLookupTable<T>`**：保存输入几何/编码兼容性、共同系数域多项式
   `V` 和 `k` 个系数域因子 `W_i`。构造时显式接收输入 Rounded、输出 Scaled codec
   与 `output_count: usize`，集中验证域、奇数 `q`、真实中心及输出范围；不使用
   `InterleavedLookupTable`，也不增加一个含可选字段的通用 LUT。
2. **后端 NTT 产物**：消费共享产物，把 `W_i` 原地变为 NTT 形式，保留原始 `V`。
   预处理一次、多次执行；不同时永久保存全部系数域和 NTT 因子。产物借用生成它的
   context，在与 evaluator 绑定时检查同一 context，封住异表混用。仅检查相同
   `q,N` 不足以保证 NTT 求值顺序和根一致；不为此扩充通用 `NttTable` trait。
3. **独立 `FactorizedEvaluator`**：复用普通 `Evaluator` 的内部阶段和已有 scratch，
   仅增加一个共享 BR 结果的 NTT 缓冲区。普通 PBS evaluator 不因 MVB 增加内存。
   输入/产物/context/输出数量及所有输出维数在写输出前验证；内部阶段可提升为
   后端内可见，不公开万能 BR 接口。
4. context 的便捷编译入口直接返回已准备的 NTT 产物，使应用只需“编译一次 →
   创建 evaluator → 对多个输入执行”。共享产物构造和后端准备保留明确边界，不增
   MVB trait；`ProgrammableBootstrapInterleaved` 的契约不变。

输入仍采用真实 Rounded 中心。构造每个 `p_i` 时可复用单输出编译核心，回调返回
尚未缩放的消息值，负尾由编译器在 `q` 中表示；先保存原首尾值，再在同一最终数组内
逆序求差分，进入模 `q` 的规范存储。公共输出范围检查不能交给 raw 编译器的 residue 检查代替。
不新增有符号秘密/消息包装，也不把乘数在 `t_out` 中约简。

`ScaledCodec` 唯一需要的小补充是与 Rounded 对应的 `ciphertext_modulus()` 只读访问器，
供构造器检查模数兼容性。`Delta` 可通过 `encode_value(1, Unsigned)` 获得，无须新增
尺度 trait 或自定义比例构造器。

### 在线缓冲区流转

令 `L=(d+1)N`，新 scratch 仅为 `L` 个 `T`，与输出数量无关：

```text
BR(input, V, step=1) -> main_glwe
main_glwe.write_ntt_form(shared_ntt)                # 一次
for each W_i_ntt:
    shared_ntt * W_i_ntt -> main_glwe 的 NTT 借用视图
    在该视图内 inverse NTT                         # main_glwe 恢复系数域
    BK: main_glwe -> ring KS -> switched -> compact LWE_i
    KB: main_glwe -> full LWE_i
```

既有[转换](../crates/primus_lattice/src/macros/ntt.rs)、
[NTT 公开乘法](../crates/primus_lattice/src/macros/ntt_polynomial.rs)、
[提取](../crates/primus_lattice/src/glwe/extract.rs)与
[evaluator 阶段](../crates/primus_tfhe_glwe_ntt/src/evaluator.rs)足够完成这个流程。
每次写入覆盖完整多项式，范围保持规范 residue；无需逐输出 GLWE 分配或 clone。
新增 context 绑定只保护新预处理产物，不替代 server key 的实际秘密与生成表契约。

## 6. 成本模型与比较方式

记 `B_1/B_s` 为步长 1/交错步长的 BR 成本，`K_out` 为输出环 KS；`K_in` 包含 KB
的完整输入转换，即 inverse extraction、环 KS 和 compact extraction。
`F_L/I_L` 为完整 GLWE 的前向/逆向 NTT，`P_L` 为 GLWE 与一张已准备因子的点乘，
`E` 为对应的最终 LWE 提取。忽略共同的边界检查，复用输入和输出缓冲区：

| 路径 | BK | KB |
| --- | --- | --- |
| k 次独立 PBS | `k*(B_1+K_out+E)` | `k*(K_in+B_1+E)` |
| 交错 ManyLUT | `B_s+K_out+k*E` | `K_in+B_s+k*E` |
| 本方案 | `B_1+F_L+k*(P_L+I_L+K_out+E)` | `K_in+B_1+F_L+k*(P_L+I_L+E)` |

`P_L=O((d+1)N)`，`F_L,I_L=O((d+1)N log N)`。因此对 BK，在等价参数和单次 BR
成本下，节省 `(k-1)B_1` 须能覆盖 `F_L+k*(P_L+I_L)`；KB 还共享了输入 KS。
不能仅以 BR 次数宣称整体提速，也不能忽略差分噪声导致的参数变化。

系数域构造约 `O(kN+kD)`，NTT 准备 `O(kN log N)`；永久程序数据约 `(k+1)N`
个 `T`，额外在线 scratch 为 `L` 个 `T`，密钥大小不变。输出密文由应用提供，单独
计入总内存。构造期不优化成复杂的稀疏存储；逐项 shift-add 可在具体小范数应用的
测量证明有收益后再考虑，不作为首版双内核要求。

P4.3 比较必须使用同一输入域、同一 `f_i`、相同 Scaled 输出中心和解码目标：
独立 PBS/ManyLUT 可用现有 raw 构造器编译 `Delta*f_i`，不能直接拿旧 Rounded
编译结果当作相同编码。记录输出因子实际范数、输入平台余量、完整延迟、准备时间、
密钥/程序/scratch/输出内存；固定 seed、CPU、工具链与 feature。既要有三输出四槽
可比较组，也要单独展示交错容量不足的场景，后者不计算不可运行方案的加速比。

## 7. P4.1 检查与 P4.2 验收入口

本步没有修改 Rust API 或增加常驻测试/基准。完成源码契约核对，以及独立 Python
整数原型（不调用生产 codec、旋转、NTT 或 LUT helper）的以下检查：

| 检查 | 枚举范围与结果 |
| --- | --- |
| 整数分解 | N=2/4 穷举 `[-2,2]^N`；N=8/16 各 32 个固定 seed `0x504431` 的 `[-3,3]` 多项式；714 次 `S*W=2p` 全系数相等 |
| 模数/全部旋转 | 上述多项式，q=17/97/257，t_out=2/3/8，全部 `r∈0..2N`；59,724 次旋转后全多项式相等 |
| 真实几何与解码 | N=8/16/32，q_in=97/256，t_in=3/4/5/8/15，完整前半区和半长短前缀；60 组几何；三种确定性函数、q_out=97/257、t_out=2/3/8，共 3,024 次消息恢复 |
| 噪声充分条件 | 对上组遍历 q_out 半模数附近的全部整数 e，筛选严格恢复不等式；170,952 次均解码正确 |
| 边界反例 | Native 奇尺度无解、噪声乘 inv2、Scaled/Rounded 中心差异、错误地 mod t 约简差分 |

几何 oracle 使用真实中心的最近邻搜索，距离相等选择较大中心；噪声 oracle 直接
计算整数比例舍入。这些检查支持代数和编码选择，不是加密执行、NTT 实现正确性、
生产失败率或性能验证。临时原型不保留为第二套常驻测试。

P4.2 用最少的持久测试保护以下独立契约：

- 小环整数 oracle：全旋转、非二次幂 `t_in`、短域、零/负差分、空负尾和接缝；明确
  区分输入几何与后乘分解的 oracle，覆盖输出范围/模数/数量的构造拒绝。
- GLWE NTT 端到端：经典/稀疏 BR、两种 order、单/三输出、输出数量大于交错容量的
  场景；使用公开解密相位加输出 Scaled decoder，保留外部秘密域验证和在线零分配。
- 预处理同 context 绑定、所有输出检查先于写入；默认/SIMD 的原语和结果一致。
- 首版不加入 odd full-domain、Native/Fourier/NTRU、CBS 输出、ternary 或 unfolding。
  奇数全域在代数上可复用分解，但必须按其折叠几何另验范数和接缝后才扩展入口。

P4.2 完成后，P4.3 再决定应用示例和性能结论。阶段内不提供推测的生产参数，也不
把论文其他方案或所有候选后端变为本步的隐含交付。
