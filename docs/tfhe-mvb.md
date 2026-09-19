# TFHE 首个 MVB：固定尺度差分分解

本文保存固定尺度差分分解的数学与实现契约，以及 P4.3 的 GLWE 成本/应用选择。NTRU NTT 的初始化与后处理见第 5 节，[B3.2 误差与成本](tfhe-mvb-ntru.md)独立记录，不套用 GLWE 数值。当前状态见 [HANDOFF](../HANDOFF.md)，阶段对应关系见[实施索引](tfhe-plan.md)和[后端计划](tfhe-backend-plan.md)。

## 1. 选型与适用范围

选择**共享阶梯多项式的盲旋转，再乘各输出的整数差分多项式**。
GLWE NTT 复用经典/稀疏 BR、两种 PBS order、已有 KSK 和提取原语；
NTRU NTT 使用加密初始化、经典 binary BR 和逐输出 NTRU KS。
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

GLWE/NTRU NTT 使用奇数 `q`；[GLWE Fourier](tfhe-mvb-fourier.md)已接入 Native
偶尺度、两种 FFT/u32/u64 的经典 binary/ternary 完整链。共享构造器接受这两种模数
情况，不通过一次模逆或系数右移泛化；Fourier 因子准备与误差要求见专项。
NTRU 的初始化和后处理保持独立，Fourier 移植归 B5.3。

## 4. 噪声与容量条件

输入误差与逐系数模切误差首先必须把 `r` 留在相应 `p_i` 平台。此处沿用步长 1 的
普通 PBS 几何，不能用输出成功解码替代输入位置条件。

令共享 BR 结果为 `X^(-r)V + e_BR(X)`，各输出公开乘法后的误差为 `W_i*e_BR`。
GLWE 的两种顺序如下：

| Order | 完整流程 | 提取后的输出误差 |
| --- | --- | --- |
| BootstrapKeyswitch（BK） | BR 一次 → 各输出乘 `W_i` → 各输出环 KS → compact extraction | `coeff_0(W_i*e_BR) + e_KS,i` |
| KeyswitchBootstrap（KB） | 输入 KS 一次 → BR 一次 → 各输出乘 `W_i` → full extraction | `coeff_0(W_i*e_BR)`；前置 KS 误差已进入输入位置预算 |

BK 的 KSK 仍是 accumulator 秘密到补零 small-LWE 秘密，外部维数保持 `n`；KB
输出仍在 accumulator 展平秘密下，维数 `dN`。公开环乘法不改变秘密域。

把 BK 的 KS 提前到所有 `W_i` 之前，在代数上也成立且只需一次 KS，但误差变成
`W_i*(e_BR+e_KS)`。采用乘后逐输出 KS，避免放大 KS 误差；P4.3 的[实测对照](#bk-是否共享一次-ks)保留了该选择。

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

两族 NTT 后端采用以下接口，使用流程见 [GLWE NTT README](../crates/primus_tfhe_glwe_ntt/README.zh_CN.md#固定尺度分解式-mvb) 与 [NTRU NTT README](../crates/primus_tfhe_ntru_ntt/README.zh_CN.md#固定尺度分解式-mvb)：

1. **共享 `FactorizedLookupTable<T>`**（也供 Fourier 准备使用）：保存输入几何/编码兼容性、共同系数域多项式
   `V` 和连续 `Vec<T>` 中的 `k` 个系数域因子 `W_i`，每因子占连续 `N` 项。
   `factors()` 返回 `PolynomialIter`；构造直接写入最终缓冲，不逐因子分配再拼接。
   构造时显式接收输入 Rounded、输出 Scaled codec
   与 `output_count: usize`，集中验证域、奇数 q 或 Native 偶尺度、真实中心及输出范围；不使用
   `InterleavedLookupTable`，也不增加一个含可选字段的通用 LUT。
2. **`NttFactorizedLookupTable::new(context, lookup_table)`**：消费共享产物，把 `W_i` 原地变为 NTT 形式，保留原始 `V`。
   两后端用 `PolynomialIterMut` 准备因子、`NttPolynomialIter` 访问 NTT 因子；准备不另分配。
   预处理一次、多次执行；不同时永久保存全部系数域和 NTT 因子。产物借用生成它的
   context，在 evaluator 执行时检查同一 context，封住异表混用。仅检查相同
   `q,N` 不足以保证 NTT 求值顺序和根一致；不为此扩充通用 `NttTable` trait。
3. **独立 `FactorizedEvaluator`**：复用普通 `Evaluator` 的内部阶段和已有 scratch，
   仅增加一个共享 BR 结果的 NTT 缓冲区。普通 PBS evaluator 不因 MVB 增加内存。
   输入/产物/context/输出数量及所有输出维数在写输出前验证。实现放在普通 evaluator
   的子模块，直接复用其私有阶段与缓冲区，无需扩大可见性。
4. context 的 `compile_factorized_lookup_table_fn(&output_codec, D, k, function)`
   直接返回已准备的 NTT 产物；`factorized_evaluator(&server_key)` 创建工作区，
   `apply_lookup_table_to` 重复求值。共享产物构造和后端准备保持独立，不增加 MVB
   trait；`ProgrammableBootstrapInterleaved` 的契约不变。

输入仍采用真实 Rounded 中心。构造每个 `p_i` 时可复用单输出编译核心，回调返回
尚未缩放的消息值，负尾由编译器在 `q` 中表示；先保存原首尾值，再在同一最终数组内
逆序求差分，进入模 `q` 的规范存储。公共输出范围检查不能交给 raw 编译器的 residue 检查代替。
不新增有符号秘密/消息包装，也不把乘数在 `t_out` 中约简。

`ScaledCodec` 新增与 Rounded 对应的 `ciphertext_modulus()` 只读访问器，
供构造器检查模数兼容性。`Delta` 可通过 `encode_value(1, Unsigned)` 获得，无须新增
尺度 trait 或自定义比例构造器。

### 连续因子存储的成本对照

公共构造只分配 `V` 与全部因子两个缓冲，两后端 NTT 准备不另分配，在线仍零分配。
输入形状先验证一次，各因子直接写入最终切片；`k*N` 与交错表长度溢出共用
`LookupTableError::TableLengthOverflow`。因子系数总量不变，省去逐因子 Vec 元数据。

2026-09-18 对照 `31b9a67` 的 GLWE 实现与连续存储版本，复用第 8 节的
`D/k=64/17`、经典 BSK 负载。Ryzen 9 9955HX3D、rustc 1.98.0、默认 feature、
`taskset -c 2`，每项 20 样本、预热 1 秒、测量 2 秒；预编译后按旧/新顺序串行跑两轮。
下表范围是两轮均值，不是置信区间：

| 项目 | 分散存储 | 连续存储 | 每轮相对变化 |
| --- | ---: | ---: | ---: |
| 编译、NTT 准备与析构 | 22.698–22.719 µs | 22.262–22.363 µs | −1.9% / −1.6% |
| 单独 NTT 准备 | 6.170–6.277 µs | 6.196–6.218 µs | −0.9% / +0.4% |
| 完整 MVB，BK | 5.175–5.230 ms | 5.337–5.418 ms | +3.6% / +3.1% |
| 完整 MVB，KB | 5.050–5.141 ms | 5.049–5.074 ms | +0.5% / −1.8% |

复现时对两个版本分别使用现有基准，无需新增测量入口：

```sh
taskset -c 2 cargo bench -p primus_tfhe_glwe_ntt --bench mvb -- \
  '^(mvb_compile/D64/k17/(factorized|prepare_ntt)|mvb/D64/k17/[^/]+/classic/factorized)$' \
  --sample-size 20 --warm-up-time 1 --measurement-time 2
```

连续存储简化分配与所有权，但不保证在线加速；本组 BK 有约 3% 回退，尚未确定其具体来源。
因子间还有逆 NTT 和 KS 的大量访存，地址连续不能保证下一个因子已驻留缓存。
这里没有比较 NTRU 存储变更前后的耗时；其当前完整误差/成本比较见 [B3.2](tfhe-mvb-ntru.md)。

### GLWE NTT 的在线缓冲区流转

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

### NTRU NTT 的初始化与后处理

[实现](../crates/primus_tfhe_ntru_ntt/src/evaluator/factorized.rs)复用普通 evaluator 的
`NLev[1] 初始化 V → BR`，将结果变换到独立 NTT 缓冲；逐输出乘已准备的 `W_i` 后，
在原 BR 缓冲中逆变换、执行 `f_acc → f_client` 的 NTRU KS，再提取 compact LWE。
全部输出使用原外部 LWE 秘密和维数。普通 PBS 工作区不变，MVB 只多 `N` 个 `T`，
不随输出数增长；程序仍只保存一份系数 `V` 和各 NTT 因子，不增加密钥材料。

NTRU 初始化本身带有噪声。令 `e_shared` 表示初始化和 BR 完成后的总相位误差，
输出误差为 `coeff_0(W_i*e_shared) + e_KS,i`。模逆元仅在公开 `V` 的构造中使用，
不对带噪声的旋转结果做模除二。公开因子不改变秘密域，逐输出 KS 避免其误差再次
被因子放大；输出间仍共享相关误差。[B3.2](tfhe-mvb-ntru.md)记录分阶段实测、完整成本和应用示例。

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

性能比较须使用同一输入域、同一 `f_i`、相同 Scaled 输出中心和解码目标：
独立 PBS/ManyLUT 可用现有 raw 构造器编译 `Delta*f_i`，不能直接拿旧 Rounded
编译结果当作相同编码。记录输出因子实际范数、输入平台余量、完整延迟、准备时间、
密钥/程序/scratch/输出内存；固定 seed、CPU、工具链与 feature。既要有三输出四槽
可比较组，也要单独展示交错容量不足的场景，后者不计算不可运行方案的加速比。

## 7. 验证入口与边界

- [共享整数 oracle 与拒绝测试](../crates/primus_tfhe/tests/factorized_lookup_table.rs)：全旋转、非二次幂 t_in、短域、零/负差分、空负尾/接缝、构造拒绝；N=1 验证输出数大于 N。
- [完整 MVB](../crates/primus_tfhe_glwe_ntt/tests/factorized_pbs.rs)：同一 fixture 覆盖经典/稀疏、两种 order、1/3/17 输出和消息 0/3/7。三输出与相同 Scaled 编码的独立/交错 PBS 对照；17 输出 MVB 成功，交错因容量拒绝。
- 功能参数为 `n/h/d/N=8/2/2/128,q=132120577,t_in=15,t_out=8`；验证实际秘密域、同 context 绑定、所有输出检查先于写入及在线零分配。默认/SIMD 按实际实现验证。
- [NTRU NTT 完整链](../crates/primus_tfhe_ntru_ntt/tests/factorized_pbs.rs)：`n/N=3/128`、同一 `q` 和 `t_in=15`，验证 1/3/17 输出及 Scaled `t_out=8` 单输出对照；另检查 `t_out=2` 的奇数尺度初始化。包含 context/形状/模数拒绝、覆盖写入和首次调用零分配。

选型时的独立整数原型另检查了分解、全旋转、真实几何和严格解码不等式，以及 Native 奇尺度、噪声乘 inv2、Scaled/Rounded 不同中心和错误 mod t 的反例；未保留第二套常驻测试。上述证据不构成生产参数或完整失败率证明。

当前未接 odd full-domain、Native/Fourier、CBS 或 unfolding；NTRU BR 秘密仍限 binary。奇数全域的代数可复用，但须按折叠几何重验范数与接缝后扩展入口。

## 8. P4.3 测量与应用选择

### 负载与方法

[常驻基准](../crates/primus_tfhe_glwe_ntt/benches/mvb.rs) 比较一个加密输入同时产生
`k` 个阈值输出：`f_i(m) = [m >= floor((i+1)D/(k+1))]`，`i=0..k`。
两组为 `D/k=8/3、64/17`，输入 Rounded `t_in=2D`，输出 unsigned Scaled `t_out=2`。
独立 PBS 与交错 ManyLUT 通过 raw 构造器使用同一 Scaled 输出中心。

共同成本参数为 `u32、q=132120577、N=1024、GLWE d=1、small-LWE n=728、h=32`；
small-LWE 使用固定重量二元秘密，accumulator 使用 SparseTernary。LWE 标准差为
`3.2*q/16384`，GLWE 为 `6.4`；BSK basis 为 `log_basis/length=7/3`，KSK 为 `2/13`。
稀疏 BSK 每索引三个候选桶，共 64 桶。经典/稀疏密钥由同一 client 生成，每组 seed
为 `0x50343300+D`。输入池为 `0、D/4-1、D/2、D-1`，计时前逐一验证所有输出。
这些是相同参数和输入下的功能/成本比较，没有证明三种方案具有相同的失败概率。

一次在线迭代计算该输入的全部输出，包含 KS 与提取，复用 evaluator、LUT 和输出；
独立方案执行 `k` 次完整 PBS。共 20 项在线负载及 7 项构造/准备负载，默认与 SIMD
各运行一次。完整构造计入分配和析构；`prepare_ntt` 单独计时消费系数产物的准备，
其系数构造和结果析构不计时，不能把该项再次加到完整 MVB 构造时间中。

环境为 Ryzen 9 9955HX3D、x86_64 Linux，`taskset -c 2`；默认 rustc 1.98.0
（88d9e12ae，2026-08-18），SIMD nightly 1.100.0（bff8e12ff，2026-08-26）。Criterion
0.8.2，20 样本、预热 1 秒、目标测量 3 秒；在线负载采用 Flat sampling。计时串行，
没有并行编译；powersave governor、boost/SMT 开启，未锁频或隔离 CPU。只在同一
feature/工具链内比较算法，不把两套工具链的差异归因为 SIMD。

[计时 CSV](benchmarks/tfhe-p4.3.csv) 保存均值和 95% bootstrap 置信区间（ns），
`p4_3_default/simd` 为常驻基准，`p4_3_ks_*` 为下文临时 KS 原型。
区间反映本次样本波动，不涵盖不同运行之间的频率或调度变化。

### 完整在线延迟

下表单位为 ms；每格依次为 **默认 / SIMD**。BK 表示 BootstrapKeyswitch，KB 表示
KeyswitchBootstrap。交错容量不足时不列虚拟时间或加速比。

| D / k | order / BSK | 独立 PBS | 交错 ManyLUT | 分解式 MVB |
| --- | --- | ---: | ---: | ---: |
| 8 / 3 | BK / 经典 | 15.139 / 14.819 | 5.020 / 4.912 | 5.098 / 5.157 |
| 8 / 3 | BK / 稀疏 | 13.528 / 13.543 | 4.486 / 4.597 | 4.480 / 4.616 |
| 8 / 3 | KB / 经典 | 15.410 / 14.887 | 5.052 / 4.946 | 5.080 / 5.198 |
| 8 / 3 | KB / 稀疏 | 13.386 / 13.598 | 4.466 / 4.626 | 4.503 / 4.616 |
| 64 / 17 | BK / 经典 | 84.124 / 84.883 | 不满足容量 | 5.334 / 5.317 |
| 64 / 17 | BK / 稀疏 | 79.730 / 78.355 | 不满足容量 | 5.217 / 4.875 |
| 64 / 17 | KB / 经典 | 86.438 / 84.275 | 不满足容量 | 4.979 / 5.060 |
| 64 / 17 | KB / 稀疏 | 70.800 / 77.605 | 不满足容量 | 4.189 / 4.570 |

MVB 相对独立 PBS 的速度比为三输出 **2.86–3.03 倍**、17 输出 **15.28–17.36 倍**。
三输出相对交错的耗时变化为约 −0.2%～+5.1%，没有统一优势；微小差异不作为稳定收益。
17 输出需要交错步长 32，此时每输出仅有 `N/32=32<D=64` 个位置，构造明确拒绝。
MVB 的价值是共享 BR 的同时保留步长 1，而不是保证超过所有交错负载。

### 构造与内存

构造均值单位为 µs，同样依次为默认 / SIMD：

| D / k | 独立 LUT 总计 | 交错 LUT | MVB 完整构造 | 其中 NTT 准备（单独计时） |
| --- | ---: | ---: | ---: | ---: |
| 8 / 3 | 0.374 / 0.356 | 0.248 / 0.239 | 2.672 / 2.827 | 1.210 / 1.198 |
| 64 / 17 | 10.689 / 10.003 | 不满足容量 | 23.162 / 23.946 | 6.415 / 6.316 |

[内存 CSV](benchmarks/tfhe-p4.3-resources.csv) 使用默认配置、线程局部分配计数，
记录构造后仍存活的请求字节数；包含 Vec capacity，排除 allocator 元数据、栈上对象、
共享 context/client 与输入池，不是 RSS 或峰值。分配次数包含构造中的临时分配。

| 持有对象 | 经典 BSK | 稀疏 BSK |
| --- | ---: | ---: |
| 完整 server key | 35,930,304 B | 110,618,376 B |
| 普通 evaluator | 62,308 B | 117,284 B |
| MVB evaluator | 70,500 B | 125,476 B |

两种 order 的以上值相同；MVB 不改变密钥，evaluator 恰好多一个完整 GLWE 缓冲
`(d+1)*N*sizeof(u32)=8192 B`，不随输出数增长。

| D / k | 独立程序 | 交错程序 | 已准备 MVB 程序 | 输出密文（BK / KB） |
| --- | ---: | ---: | ---: | ---: |
| 8 / 3 | 12,456 B | 4,096 B | 16,480 B | 8,820 / 12,372 B |
| 64 / 17 | 70,584 B | — | 74,496 B | 49,980 / 70,108 B |

全部在线路径的诊断均为零分配。仅一次 BR 不意味着只需一个 LUT 的持久内存；应用
仍需保存全部因子和输出密文。上述稀疏密钥约为经典的 3.08 倍，选择时需同时考虑。

### 实际范数、平台与误差

两组阈值的每个差分因子恰有两个非零系数，`L1=2、L2²=2`。输出尺度
`Delta=(q+1)/2=66060289` 为奇数，共同多项式依赖模逆元 `inv2`；输出噪声不会随
该模逆元一起做整数除法。不同函数的差分范数可能远大于这些阈值，不能套用此噪声结果。

按真实 Rounded 编码后再量化，这两组的中心等距。以中心为零，保证仍归属于同一
输入消息的保守整数误差区间如下；阈值在相邻消息取相同值时可能有额外余量：

| D / k 与布局 | 相邻消息中心间距 | 允许偏移（物理 2N 指数单位） |
| --- | ---: | --- |
| 8 / 3，普通或 MVB | 128 | `[-64,63]` |
| 8 / 3，交错 step=4 | 128（每输出坐标间距 32） | `[-64,60]`，只能取 4 的倍数 |
| 64 / 17，普通或 MVB | 16 | `[-8,7]` |

[误差 CSV](benchmarks/tfhe-p4.3-noise.csv) 为默认配置的独立诊断：每组 order/BSK，
D=8 使用 32 个输入（每消息四次），D=64 使用 64 个输入（每消息一次），所有方案
共享输入和密钥。`max_abs_rotation_error` 是实际 BR 输入的量化相位相对目标中心
的偏差，包含原输入噪声及 KB 的前置 KS；不是单个系数的舍入误差。D=8 普通/MVB
最大绝对值不超过 6，交错不超过 16（四个粗粒度位置）；D=64 普通/MVB 不超过 5。

`max_abs_error/rms_error` 为输出解密相位相对预期 Scaled 中心的居中误差，不能与
上面的指数单位直接比较。MVB 的 RMS 在同组独立 PBS 的约 **1.32–1.50 倍**；所有
路径最大绝对误差为 4,192,265。对于输出 `y∈{0,1}`，严格恢复条件为
`|y+2e| < q/2`，保守对称半径约 33,030,144。所有诊断输出均正确，但同一 BR 的各
输出相关，这些有限样本只说明当前负载有余量，不估计尾概率或证明生产安全。

### BK 是否共享一次 KS

临时原型把 BK 改为 `BR → 一次环 KS → NTT → 各因子乘法/逆 NTT/提取`，复用
相同密钥、程序、输入与输出，所有计时前检查和默认误差诊断通过，在线仍零分配。
原型仅检查本组 KS 前后 GLWE 尺寸相等的情况，未扩展成通用策略 API。

每轮 30 样本、预热 1 秒、目标测量 3 秒；第一轮先逐输出 KS，第二轮交换测量顺序。
下表为共享方案相对当前方案的耗时变化 `shared/per_output-1`，负数表示更快：

| D / k / BSK | 默认第一轮 | 默认反序 | SIMD 第一轮 | SIMD 反序 |
| --- | ---: | ---: | ---: | ---: |
| 8 / 3 / 经典 | +0.27% | +3.08% | +2.20% | +1.70% |
| 8 / 3 / 稀疏 | +1.77% | +2.17% | +23.34% | −4.39% |
| 64 / 17 / 经典 | −1.15% | −6.21% | −4.51% | −4.15% |
| 64 / 17 / 稀疏 | −4.72% | −7.32% | −8.68% | −3.31% |

17 输出显示了少做 KS 的收益，三输出没有稳定收益；SIMD 三输出稀疏的首轮异常未在
反序重现，不据此下单方向结论。共享顺序还把噪声从当前的 `W_i*e_BR+e_KS_i`
变成 `W_i*(e_BR+e_KS)`。本组因子小、KS 误差相对 BR 小，有限相位样本相近，
不能据此允许任意 LUT 的 KS 误差放大。

**保留 BK 逐输出 KS，KB 保持前置 KS**；不添加策略 enum。只有应用明确需要较大
输出数、建立具体因子的噪声预算并重复证明整体收益后，再考虑显式的共享 KS 入口。
临时原型和统计程序已删除，仅保存本节方法与 CSV；常驻基准继续测正式接口。

### 应用入口与后续范围

[阈值示例](../crates/primus_tfhe_glwe_ntt/examples/mvb_thresholds.rs) 使用 KB/经典
密钥，把 `0..64` 的加密分数转成 17 个阈值标志。它复用一份预处理程序和所有密文
缓冲区，以输出 Scaled codec 解码；同时展示交错容量拒绝。运行方式：

```sh
cargo run -p primus_tfhe_glwe_ntt --release --example mvb_thresholds
```

- 交错容量、输入噪声余量均足够时，优先考虑交错：程序小、构造便宜，本组在线并不逊于 MVB。
- 同一输入要得到很多输出、交错容量或旋转精度受限，而且真实差分范数较小时，选用 MVB。
- 差分范数很大时，应重新核算输出噪声与参数；独立 PBS 仍是直接的比较基线。
- 示例输出为数值 0/1，不是 Boolean evaluator 的内部编码。继续串联计算时，必须检查
  下一步输入编码和误差余量。

其他 full-domain、大域与摊销路线的启动条件见[后续候选](tfhe-next.md)，不属于本方案的隐含交付。
