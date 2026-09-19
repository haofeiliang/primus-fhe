# 稀疏私钥 PBS：实现契约

本文保存已实现的 **GLWE NTT/Fourier、固定重量二元 BR 秘密、系数域桶聚合**契约，以及表示/参数取舍的测量依据。NTT 的历史测量与 Fourier 新增参考路径分开记录，后者见 [B4.2](#b42-fourier-稀疏-br-与完整-pbs)。参数用于开发与比较，尚无生产安全等级或完整 PBS 失败概率保证。

来源是 [2026-1730.pdf](../temp/2026-1730.pdf)：Aayush Jain、Huijia Lin、Zeyu Liu、Sagnik Saha，*New Techniques for Fast and Shallow FHE Bootstrapping and Beyond*。本文使用 PDF 一基页码，依据 §3.4、§4、§7.1，重点为 p.17–19 的公式/伪码和 p.43 参数表。文件 SHA-256：`0ba34c2052e2fc717e17271ac04058096075bfd21e8922b7009c9328119eef12`。下文的匹配上界与 Primus 噪声递推是本项目推导，不是论文给出的具体安全结论。

## 实现范围

| 项目 | 决定 |
| --- | --- |
| 实际 BR 秘密 | 复用 `SecretKeyDistr::FixedHammingWeightBinary`；长度 `n`、重量 `h`，均匀选择支持集；不采用结构化 one-hot |
| 公开映射 | 每个输入索引独立、均匀选择 `c` 个不同桶；两个首版参数组均取 `c=3, bucket_count=2h` |
| 私有分配 | 在支持集与桶之间求完整匹配；每个支持索引只选一个副本，每桶至多选一个索引 |
| 失败行为 | 固定同一秘密，独立重采整个公开映射；最多 8 次。耗尽后返回错误，不返回部分 key，不重采秘密或自动退回经典路径 |
| BSK | 每个副本独立加密选择位，每桶额外独立加密一个 dummy；按桶保存系数域 GGSW |
| 在线执行 | 输入旋转量计算一次；逐桶系数旋转/相加，将聚合 GGSW 转 NTT/Fourier，再做一次 external product |
| 共享层 | 复用 LUT、`RotationQuantizer`、GGSW、分解和外积；不向 `primus_tfhe::lookup_table` 加稀疏参数或策略 trait |
| 已接入组合 | 两后端普通/交错 LUT、两种 GLWE order；NTT 另有 [MVB](tfhe-mvb.md)。Sparse CBS、稀疏三元及 NTRU 未支持 |

参数中的 `h` 只约束**进入 BR 的 small-LWE 秘密**。KS→BR 顺序的外部秘密仍是 accumulator 的 `kN` 维系数展开；不能把它改标成固定重量二元分布。以下用 `k` 表示 GLWE 维数，`b` 表示桶数，`s` 表示交错 LUT 的 `padded_output_count`，避免与输出函数个数混用。

## 公开映射、匹配与分布

### 映射与完整匹配

对每个 `i in 0..n`，从 `0..b` 中均匀无放回抽取 `c` 个桶。可以使用无偏整数采样并拒绝该索引已选中的桶；**不**先独立哈希三次再保留重复副本。后一种模型的失败概率不同。不同索引的选择独立，不使用支持集构造或调节桶负载。

首版直接保存展开后的映射，不新增公开 seed 格式、哈希版本或序列化契约，也不公开 keygen RNG 的状态。映射按桶展开，桶内索引递增。同一个索引恰好出现 `c` 次，同一桶内不重复。

keygen 私下按支持索引递增顺序执行增广路匹配：先直接占用第一个空闲候选桶，仅在候选桶全部被占用时初始化搜索工作区并完整搜索可达桶，允许重新安置原索引。单轮找不到增广路才算映射失败；不使用有踢出次数上限的随机 cuckoo 插入，避免将启发式超时误当成图上无匹配。候选顺序与完整 BFS 相同；匹配直接保存原始输入索引，BFS 记录桶之间的前驱，找到空桶后沿路径逆向搬移。全部直接分配时为 `O(b+ch)`，最坏工作量仍为 `O(h(ch+b))`，只发生在 keygen。

公开构造边界检查 `0<h<n`、`c>=1`、`b>=max(h,c)`、长度乘加不溢出；生成时检查实际秘密的每项为 `0/1` 且总重量确为 `h`。仅检查分布标签不能保护从原始系数构造的密钥。首版参数组的 `c=3,b=2h` 满足这些条件；这些参数不是任意 `h` 都合法的隐藏默认值。

### 单轮失败上界

令 `F` 是映射，`H` 是任一固定的大小为 `h` 的支持集。由 Hall 条件，匹配失败时，存在 `r` 个支持索引，其全部邻居位于某 `r-1` 个桶中。对所有选择作 union bound：

\[
\Pr[\operatorname{Fail}(F,H)]\le U(h,b,c)
=\min\left(1,\sum_{r=c+1}^{h}
 {h\choose r}{b\choose r-1}
 \left(\frac{{r-1\choose c}}{{b\choose c}}\right)^r\right).
\]

空和取零。这是**每个索引选择不同桶**、完整匹配、独立均匀映射模型的上界；未假定桶负载相等。具体数字可用以下精确有理数计算复现，不依赖采样未观察到失败：

```python
from fractions import Fraction
from math import comb

def failure_bound(h, b, c):
    return min(Fraction(1), sum((
        Fraction(comb(h, r) * comb(b, r - 1))
        * Fraction(comb(r - 1, c), comb(b, c)) ** r
        for r in range(c + 1, h + 1)
    ), Fraction()))
```

|参数组| `(h,b,c)` | 单轮失败上界 `U` | 8 轮耗尽上界 `U^8` |
| --- | --- | --- | --- |
| 回归 | `(4,8,3)` | `5.69425e-6`，约 `2^-17.42` | 小于 `2^-139.37` |
| 成本比较 | `(32,64,3)` | `5.92266e-8`，约 `2^-24.01` | 小于 `2^-192.07` |

表中指数仅描述**理想独立采样下的匹配失败**。实际使用 `CryptoRng`；这些值不是 LWE 安全位数，也不是 PBS 解密失败率。

### 重试后秘密与公开映射的联合分布

秘密先采样一次，失败只重采映射。由于映射对输入索引的重标号对称，完整匹配的成功概率 `p` 对每个大小为 `h` 的 `H` 相同。因此，8 轮内返回成功时，`H` 的边缘分布仍均匀，但返回的 `(H,F)` 是原独立联合分布在“匹配成功”上的条件分布，二者**不再独立**。

在该模型中，此条件分布与原独立联合分布的统计距离是单轮失败概率 `1-p`，至多 `U`。8 轮只把“没有生成 key”的概率压到 `(1-p)^8`，**不会**把上述距离也压到 `U^8`。所以成本参数组的 `2^-24` 上界不足以推出 128-bit 安全；不以秘密熵或成功解密作替代证明。

失败映射、支持集、匹配、明文选择位和重试轨迹都不进入 server key；失败只返回统一错误。首版 keygen 不承诺恒时，匹配和重试在持有秘密的本地环境执行。不要把它直接当作可观察内部执行的远程密钥生成协议。

论文 §7.1 的 `c=3,b=h+3` 使用经验成功率和额外熵损失猜想；本轮不采用。其 `b≈1.5h` 引用的成功率也不能直接用于我们的无放回映射。选择 `2h` 是以更多外积换取上述可独立复算的失败上界，并不把参数提升为生产配置。

## 聚合与旋转不变量

设桶 `j` 的公开索引列表为 `C_j`，私有位 `u_{j,i}` 只在匹配选择了副本 `(j,i)` 时为 1；`d_j=1-sum_i u_{j,i}`。生成独立 GGSW 加密 `K_{j,i}=Enc(u_{j,i})` 和 `D_j=Enc(d_j)`。所有行/层使用同一个 accumulator 秘密、模数和 basis。

对输入 `(a,b_lwe)`，使用现有量化器：

\[
R_s(x)=s\operatorname{round}_{\uparrow}\left(\frac{2N}{sq_{\rm in}}x\right)\pmod{2N},
\quad \alpha_i=R_s(a_i),\quad\beta=R_s(b_{\rm lwe}).
\]

普通 LUT 取 `s=1`，交错 LUT 取其补齐输出数。对每个系数分别量化，不能先求点积再量化。这里 `q_in` 可以在低层为 Native，但 `2N` 必须由系数类型表示；当前完整 GLWE NTT 链使用显式 `q_in=q_acc=q`。

从真实 LUT `P` 初始化平凡 GLWE `A_0=(0,X^{-beta}P)`。每桶计算：

\[
G_j=D_j+\sum_{i\in C_j}X^{\alpha_i}K_{j,i},\qquad
A_{j+1}=G_j\mathbin{\boxdot}A_j.
\]

`G_j` 的明文是一个单项式：占用桶为所选 `X^{alpha_i}`，未占用桶为 `1`。因此忽略加密和分解误差，最终相位为：

\[
P(X)X^{-\beta+\sum_{i\in H}\alpha_i}
=P(X)X^{-\beta+\sum_{i=0}^{n-1}\alpha_i s_i}
\pmod{X^N+1}.
\]

执行总共 `b` 次外积，处理全部 `cn` 个副本。没有公开的“活跃桶”列表；即使某副本的选择位为零，它也有独立加密噪声。不能在每个副本中直接加密原始 `s_i`，否则支持位置重复旋转 `c` 次。未占用桶需要 **Enc(1)**，不是 Enc(0)。首版不按特殊指数省略外积，以保持固定、易核对的执行模型。

## 噪声预算与两种顺序

以下两类误差分别检查：**旋转是否落在正确 LUT 区间**，以及**输出相位是否仍可解码**。桶数减少不意味着总噪声同比减少。

### 输入与旋转量化

写 `phase=b_lwe-<a,s>=E_in(m)+e_pre mod q`、`rho=2N/q`，并把每个模切的舍入余量提升为 `epsilon_x in [-s/2,s/2]`。相对于 LUT 的实际中心 `-R_s(E_in(m))`，总旋转偏差为：

\[
\delta_r=-\rho e_{\rm pre}-\epsilon_b
 +\sum_{i\in H}\epsilon_{a_i}+\epsilon_{E_{\rm in}(m)}.
\]

因而有保守界 `|delta_r| <= rho*|e_pre| + s(h+2)/2`（按模 `2N` 的相应提升解释）。必须小于当前 LUT 在该中心两侧的有效距离；不能用容量 `D<=N/s` 代替这个条件。最后一个编码中心项不可遗漏，尤其是非二次幂明文。居中/shifted 舍入未接入，不在这里暗中改变原量化器。

### 聚合与外积

设 `L_j=|C_j|`，每个原始 GGSW 行误差系数独立、中心化，实际标准差为 `sigma_g`。单项式仅置换/变号，故聚合行误差有方差 `(L_j+1)*sigma_g^2`，**`+1` 来自 dummy，包括加密零的 dummy**。公开桶不等长，不能用平均桶长替代最坏桶长。

给出更直接的递推：令 `D_g(A)` 是 accumulator 的 gadget digits，`G` 是 gadget 矩阵，`rho_g=D_g(A)G-A`。设桶明文为单项式 `M_j`，聚合 GGSW 行误差为 `e_{j,r,l}`，则

\[
E_{j+1}=M_jE_j+M_j\operatorname{phase}(\rho_g)
 +\sum_{r,l}D_g(A_j)_{r,l}\,e_{j,r,l}.
\]

`M_j` 的系数范数为 1，不放大已有误差。设 `B=2^log_basis`、层数 `ell`、`eps_g=basis.approximate_error_bound()`、accumulator 秘密为 `S=(S_1,...,S_k)`，每个原始行误差系数绝对值不超过 `E_g`。逐项卷积给出不依赖独立性近似的保守界：

\[
\|E_b\|_\infty\le\|E_0\|_\infty
 +b\,\mathrm{eps}_g\left(1+\sum_r\|S_r\|_1\right)
 +(k+1)\ell N\frac B2 E_g\,(cn+b).
\]

平凡 LUT 初始化的 `E_0=0`。`eps_g` 应取现有 basis 的返回值，不假设 `B^ell>=q`。NTT 是有限域精确变换，不另加浮点变换误差。

用于选实验参数的常见估算是：将 digits 视为均匀且与当前行误差独立，新增外积方差约为

\[
(k+1)\ell N(B^2/12)\,\sigma_g^2(cn+b),
\]

再计入逐桶分解残差。这里 digits 依赖此前的密文与复用 key，且实际采样器截断、离散化；该估算不是尾概率证明。特别是 `cn+b` 约为经典路径的三倍，不能只把经典公式里的 `n` 换成 `b` 后继续使用原噪声预算。

### 完整链

| 顺序 | 旋转前误差 `e_pre` | 输出解码需要控制的误差 |
| --- | --- | --- |
| BootstrapKeyswitch | small-LWE 输入误差；若用公钥加密，使用其总误差 | BR 聚合/外积误差 + 后置 GLWE KS 的加密与分解误差 |
| KeyswitchBootstrap | 外部 `kN` 维输入误差 + 前置 GLWE KS 的加密与分解误差 | BR 聚合/外积误差 |

提取本身只重排/选取相位，不新增随机噪声。前置 KS 的目标是补零后的 small-LWE 秘密；其非零支持只在前 `n` 项，不能视为在整个补零环中均匀固定重量。安全估计还须覆盖该结构、所有 evaluation-key 消息及所依赖的 circular/KDM 假设。

Primus 当前两种链都保持同一个密文模数，没有论文中 `Q -> Q' -> q` 的输出模切；因此不能照抄其 `q/Q` 噪声缩减因子或普通 LWE KS 公式。KS 用实际 `GlweKeySwitchingParameters`、basis、目标秘密范数单独计入。输出误差必须落在输出 codec 对目标编码的真实解码区间内；不同 `t_out`、奇数全域、双输入打包和 CBS 都需要自己的余量。

## 首版参数与经典对照

以下为 P3.1–P3.5 首轮测量使用的历史参数。当前常驻 `sparse_pbs` 基准已将成本组
`n` 提高到 728，`h=32`、`N=1024` 和其余参数保持不变；下文成本组的历史耗时、内存及误差数字仍对应 `n=512`。

两个参数组都是**未经安全认证的实验参数**，使用 `u32`、`BarrettModulus`、`q_in=q_acc=132120577`、GLWE 维数 `k=1`、`t_in=t_out=8`、unsigned rounded codec，首轮测前半区。该已有 NTT 素数满足 `2N | q-1`；不修改现有 `boolean_parameters()` 默认值。

| 参数 | 小型回归 | 成本比较 |
| --- | --- | --- |
| `n,h` | `16,4` | `512,32` |
| `N` | `256` | `1024` |
| 实际 BR 秘密 | `FixedHammingWeightBinary(h=4)` | `FixedHammingWeightBinary(h=32)` |
| accumulator 秘密 | `UniformBinary` | `SparseTernary`（现有 `P(0)=1/2` 分布，不是固定重量） |
| small-LWE 噪声参数 | `0.7` | `3.2*q/2^14` |
| GLWE / BSK / KS 噪声参数 | `0.7` | `6.4` |
| BR basis 构造参数 | `log_basis=9, reverse_length=None`，`ell=3, eps_g=0` | `log_basis=7, reverse_length=Some(3)`，`ell=3, eps_g=32` |
| KS basis 构造参数 | `log_basis=9, reverse_length=None`，`ell=3, eps_ks=0` | `log_basis=2, reverse_length=Some(13)`，`ell=13, eps_ks=1` |
| `c,b,最大尝试次数` | `3,8,8` | `3,64,8` |

成本参数组从已有 NTT benchmark 的模数、环、噪声和 basis 出发，显式把 BR 分布改为固定重量，并选 `t=8` 留出普通/交错输出空间。它与论文参数没有相同安全等级的承诺。KS→BR 的外部加密噪声来自 GLWE 参数，不是表中的 small-LWE 噪声。

回归组取 `log_basis=9` 是因为 `q` 的位宽为 27，恰好三层且不丢低位。现有 `ApproxSignedBasis` 的完整层数是位宽除以 `log_basis` **向下取整**；`reverse_length=None` 本身不保证零分解误差。

上述启发式外积估算给出成本参数组的 `sigma_BR≈7.41e5`，而 `q/(2*t_out)≈8.26e6`；这只支持将其作为实验起点。严格最坏界远大于此，未给出完整链的目标失败率。参数变更后须重测相位误差与 LUT 余量；失败时调整双方相同参数，不能挑选成功 seed 或放宽断言。`sigma` 参数也不能直接当成有限精度采样器的精确实际标准差。

论文 Table 3 的一般二元参数为 `(n,h,N,q,Q,Q')=(1024,43,1024,512,2^28,2^12)`、`(1024,31,1024,512,2^28,2^12)` 和 `(2048,70,2048,2^12,2^54,2^35)`。这些是 OpenFHE 场景，不能把 `h` 或 STD128 标签移植到上述单素数链；论文对该标签给出的估计也只有约 120 bit。我们没有重跑 lattice-estimator，没有得到 Primus 的生产安全结论。

对照必须用**同一把客户端秘密**分别生成经典和稀疏 BSK；相同模数、噪声、basis、LUT、输入/输出尺度、order 和输入样本。经典路径仍逐个处理全部二元系数，不向 evaluator 暴露支持集来跳过零。不能用经典均匀二元秘密与稀疏固定重量秘密的差异冒充算法收益。允许原路径按公开旋转指数为零跳过 CMUX，记录实际计数而不禁用已有优化。

## 密钥布局、所有权和存储

两后端各自定义 `SparseGlweBootstrappingKey<T>`，长期保存的是**系数域** GGSW，不以变换域类型包装未变换的数据。`primus_tfhe::sparse` 共享纯索引 `BucketMap` 与私有 `Matching`，具体 key/BR 留在后端；不创建通用 PBC/backend trait。P3.5 已让 server/evaluator 在调用入口选择经典或稀疏执行，LUT 构造器不承担策略选择。

| 数据 | 保存/建立位置 |
| --- | --- |
| `n,h,c,b`、输入/输出共享的模数、GGSW size/basis、普通量化器 | 具体 BSK；与实际秘密及现有参数绑定，量化器在 keygen 准备 |
| `bucket_offsets[b+1]`、`input_indices[cn]` | 具体 BSK；公开展开映射，evaluator 直接借用 |
| `[bucket][entry...,dummy][row][level][component][coefficient]` | 单个系数数组；每桶 dummy 位于该桶条目之后 |
| 支持集、匹配 owner/前驱、明文选择位 | keygen 私有临时数据；不放入 server key |
| 全部输入的 `alpha[n]`、一份原地转 NTT 的聚合 GGSW、GLWE ping-pong 和外积 context | evaluator 独占、初始化时一次分配；每次调用复用 |
| KSK、客户端秘密、LUT 元数据 | 沿用现有归属；不在 sparse key 中重复保存 |

若一份 GGSW 含 `G=(k+1)^2*ell*N` 个系数，经典 BSK 存 `nG` 个，稀疏 BSK 存 `(cn+b)G` 个。CSR 偏移只描述 `input_indices`，桶 `j` 的密文起点为 `(bucket_offsets[j]+j)*G`，dummy 起点为 `(bucket_offsets[j+1]+j)*G`；不再保存一份可推导的密文偏移数组。

生成时复用 `NttGlweSecretKey` 的常数 GGSW 加密和已有 inverse NTT，逐份写入最终系数存储；不同时保存整份 NTT BSK 和系数 BSK。匹配成功后才分配/加密这些密文。每个副本和 dummy 都重新取加密随机数，不能复用 Enc(0) 或噪声样本。evaluator 只需要 key、NTT table 与 scratch，不依赖 keygen 的秘密缓存。

在 64-bit 平台、`T=u32` 的成本参数组中：

- 经典 BSK 系数载荷为 **24 MiB**，稀疏为 **75 MiB**，另加公开映射约 12.5 KiB；不含 KSK、allocator 和对象元数据。
- BR 名义上从最多 `512` 次 CMUX 外积变为 `64` 次外积；聚合仍读 `1536` 份选择 GGSW，并加 `64` 份 dummy。不能据此宣称八倍加速或 O(h) 密钥大小。
- 在线 scratch 系数数为 `G+(2k+4)N`，另有 `N` 个 carry bool 和 `n` 个 `usize` 旋转量，约 **77 KiB**；另有调用方输出 GLWE **8 KiB**。这是 BR 工作区，不含 LUT、table、完整 evaluator 的 KS/输入/多输出缓冲区或容量开销。
- keygen 峰值为最终 BSK 加单份 GGSW/变换、加密和匹配工作区，另计客户端/NTT 秘密及 KSK；避免整 key 的隐式 clone。P3.4 的实际请求字节数见下文测量。

## P3.2 实现入口

- [KeyGenerator 与稀疏 key](../crates/primus_tfhe_glwe_ntt/src/sparse/key.rs)：`try_generate_sparse_bootstrapping_key(&client, copy_count, bucket_count, rng)` 复用已验证的 context，返回独立 BSK。复用 context 的显式模数，不另建参数包装；完整 server key 入口见 P3.5。
- [共享索引映射与私有匹配](../crates/primus_tfhe/src/sparse.rs)：逐索引无放回采样、完整增广路匹配、固定秘密最多八次尝试；CSR 只在匹配成功后生成，桶内索引递增。
- `bucket(j)` 返回公开索引切片和 GGSW 迭代器；密文比索引多一项，最后为 dummy。所有权在 BSK，读取不依赖 client/keygen，BSK 的读取 API 不返回匹配或占用位。
- 入口先校验上下文兼容性、固定重量分布、实际二元系数/重量、桶参数及存储长度，再消费随机数。匹配成功后按桶批量加密，直接在最终分配中原地 inverse NTT。支持集、匹配工作区、选择位用 `Zeroizing`，NTT 秘密和 gadget context 沿用已有擦除契约。
- 保留四项聚焦测试：216 个小图与暴力匹配对照；强制第二/第八次成功及八次耗尽；[公开入口与加密语义](../crates/primus_tfhe_glwe_ntt/tests/sparse_key.rs)覆盖实际支持集恰好一次、每桶选择/dummy 总和为 1、公开空桶及非法输入在采样前拒绝。测试只在客户端侧恢复合成测试密钥的选择位，不给 server 增加明文辅助数据。

参考 sparse BR 入口见下节 P3.3；完整 PBS 接入与验收见 P3.5，历史原始稀疏/经典 BR 对照见 P3.4。

### P3.2 匹配表示与测量

`augment` 分为直接占空桶、`find_relocation_path` 搜索、`apply_relocation_path` 搬移三步。桶直接保存原始输入索引，搜索前驱表示“哪个桶的占用者可以搬进当前桶”；起始桶的前驱指向自身，作为放入新索引的终点。工作区从四个数组减为三个，删除 `assigned_buckets` 和非零位置转换，少一次分配及 `h` 个 `usize`；私有数组仍在释放时擦除。

2026-09-17，Ryzen 9 9955HX3D、rustc 1.98.0、默认 feature/release，固定逻辑 CPU 2；临时 Criterion 使用 100 samples、0.5 s warmup、2 s measurement，同一程序包含基线和当前版，两轮交换执行顺序。**基线已包含此前的直接占空桶优化**。匹配计时复用工作区，每次处理一个图，循环使用 128 张随机图；图由 `StdRng`、seed `0x504243+n` 预先生成，非零索引为 `p*n/h`，`p in 0..h`。完整桶映射生成包含采样、分配、匹配、CSR 转换和结果释放，两版本都从 seed `0x5033504243` 开始。下表为两轮点估计范围，均取 `c=3,b=2h`。

| `(n,h)` | 匹配：基线 → 桶路径版 | 完整桶映射生成：基线 → 桶路径版 |
| --- | --- | --- |
| `(16,4)` | 7.89–8.85 ns → 7.56–7.76 ns | 346–358 ns → 310–314 ns |
| `(512,32)` | 55.7–56.2 ns → 39.7–42.7 ns | 5.58–5.79 µs → 5.08–5.11 µs |
| `(2048,128)` | 279–300 ns → 208–228 ns | 21.81–22.16 µs → 19.64–19.71 µs |

保留桶路径表示：上述场景两轮均未观察到退化，`n=512,h=32` 的匹配耗时下降约 24%–29%。另外检查 `n=128,h=32,c=3,b=32` 的高冲突随机图、`h=32,c=2,b=64` 的长增广路径和 `h=32,c=3,b=64` 的无匹配图，耗时也均下降。四组共 512 张随机图及两张构造图的成功状态和最终分配与基线一致；原有 216 图穷举 oracle 改用不连续的原始输入索引，测试数不变。仅拆分函数的原型出现退化信号，已撤回；本次未测完整 keygen/PBS，临时程序未加入常驻 benchmark 或 CI。

## B4.1 Fourier 密钥材料与共享匹配

[共享 `BucketMap`](../crates/primus_tfhe/src/sparse.rs) 的 `try_generate` 接收严格递增的非零输入索引，检查索引、桶数及映射存储边界后采样。返回公开 CSR 映射和用 `Zeroizing` 包装的私有分配；未占用桶使用 `BucketMap::UNASSIGNED`，调用方在加密后丢弃私有分配。`Matching` 仍为私有实现，抽取没有改变候选采样、增广路径选择或八次尝试的随机数消费顺序。

[Fourier keygen](../crates/primus_tfhe_glwe_fourier/src/sparse/key.rs) 沿用 `try_generate_sparse_bootstrapping_key`，逐份独立加密 selector/dummy。复用现有 Fourier 常数 GGSW 加密，将每份结果 inverse FFT 写入最终 Native 系数数组；临时只保存一份 Fourier GGSW。这里的 FFT→整数转换会引入舍入误差，必须计入桶聚合与外积误差，不能套用 NTT 精确变换的结论。

纯映射错误定义在共享层；GLWE family 的 `SparseBootstrappingKeyError::BucketMap(#[from] BucketMapError)` 直接保留桶参数、非零索引、映射存储和匹配失败信息。外层负责客户端、分布、重量、实际系数及 GGSW 存储错误，并由两后端重导出；不再复制底层分支或把非法索引转换为私钥系数错误。GGSW 存储检查留在后端，映射缓冲区检查由共享入口承担。所有返回的校验错误均在消耗随机数前发生。

[Fourier 聚焦测试](../crates/primus_tfhe_glwe_fourier/tests/sparse_key.rs) 使用 `u64,n=16,h=4,N=128,k=1,t=8`、`log_basis=8,ell=6` 和噪声参数 `0.7`，分别运行 RustFFT/TfheFFT；`(c,b)=(3,8)` 验证多副本，`(1,17)` 保证存在公开空桶。对加密 GLWE 做外积并解密，核对每个支持索引恰好一次、每桶 selector/dummy 总和为 1、首尾多项式系数及错误前 RNG 不变。原 216 图匹配 oracle、受控重试和 NTT 密钥/完整 PBS 回归继续保留。

此步只交付密钥材料；完整 BR/PBS 见 B4.2，收益测量属于 B4.3。条件映射分布、安全和完整尾界仍未闭合。

## B4.2 Fourier 稀疏 BR 与完整 PBS

[实现](../crates/primus_tfhe_glwe_fourier/src/sparse/blind_rotation.rs)批量量化输入 mask，body 使用同一 `RotationQuantizer`；普通量化器在 keygen 准备，ManyLUT 根据 padded output count 准备步长。每桶从 dummy 拷贝开始，逐条目执行 Native 单项式旋转/相加，再把整份聚合 GGSW 转为 Fourier 并执行一次外积。系数域 GLWE 在调用方输出与 scratch 之间交替，奇数桶最后拷回输出；公开空桶也保留 dummy 外积。

Fourier `ServerKey` 通过 `BootstrappingKey::{Classic,Sparse}` 持有具体表示，`try_generate_sparse_server_key` 生成相同秘密域的配套 KSK。高层 evaluator 在 BR 入口分派一次，保留原 BK 的后置 KS/compact extraction 和 KB 的前置 KS/full extraction。只分配所选工作区；raw BR 无 KS/提取。CBS 的 `try_new` 和 `try_from_parts` 均拒绝稀疏 key，不能靠提供独立 CBS 材料绕过限制。

Fourier BR 的额外存储为 `n` 个公开指数、一份系数聚合 GGSW、一份 Fourier 聚合 GGSW、一份 GLWE 与底层外积工作区；变换引擎由 evaluator 复用。聚合前复制 dummy、外积覆盖下一个 accumulator，重复调用不需要调用方清零。本步采用清晰的逐条目遍历，没有移植 NTT 的缓存分块，也没有逐项频域累积；具体成本由 B4.3 比较。

误差来自 keygen 的 Fourier→系数转换、全部 selector/dummy 加密噪声、聚合后的 FFT、分解/外积及 GLWE 逆变换；KS 另按 order 位于 BR 前或后。Native 系数加减和单项式旋转本身是精确环运算，但这不消除已有的密钥舍入误差。下列相位检查覆盖整条被测路径的总误差，没有分离噪声来源或建立概率尾界：

| 验收 | 固定 fixture 与检查 |
| --- | --- |
| [原始 BR](../crates/primus_tfhe_glwe_fourier/tests/sparse_blind_rotation.rs) | u32，`n=16,h=4,N=16,t=8`，basis `8×3`，噪声参数 `0.7`；`(k,c,b)=(1,3,8),(2,1,17)`。两种 FFT，独立整数模切/负循环旋转/GLWE 相位 oracle 对照经典 BR；普通全部旋转、step=4、舍入半点、模回绕、奇偶桶、空桶、k=2、首调用零分配及 raw 拒绝前输出不变 |
| [完整 PBS](../crates/primus_tfhe_glwe_fourier/tests/sparse_pbs.rs) | u64，`n=16,h=4,N=256,k=1,c=3,b=8,t_in=15,t_out=16`，BR/KS basis `8×6`，噪声参数 `0.7`，accumulator 为 UniformTernary；两种 FFT/order，共用客户端对照经典链，消息 `0,3,7` 加 `±q/1024` 受控输入偏移；普通/三输出 LUT、step 1→4→1、相位/解码及首调用零分配 |
| 绑定与 CBS 边界 | 拒绝不同重量/basis 的 sparse server key，两个 CBS 构造入口均返回 `UnsupportedSparseBootstrapping` |

相位误差必须小于对应输出解码半径：u32 为 `2^28`，u64 为 `2^59`。这些固定小型 fixture 保护表示、布局和组合契约，不证明生产安全/失败率；尚未为 Fourier sparse 的 Boolean/bivariate/odd-full 等组合做独立验收，性能与资源结果见下节 B4.3。默认/SIMD 验证入口为 `just tfhe` / `just tfhe-simd`。

## B4.3 Fourier 成本与保留方案

**保留逐条目系数聚合参考实现。** `n=728,h=32` 的普通/三输出 PBS 测得在线收益，但增大到 `h=128,b=256` 后所测单输出负载更慢。16 KiB 分块聚合未显示一致收益，未接入生产代码。此结论只适用于下述成本配置，不是固定重量秘密的安全参数或失败率认证；CBS/ternary 等扩展仍需独立验收。

### 参数与完整链

2026-09-19，生产源码 `5102a4b`；新增持久[基准](../crates/primus_tfhe_glwe_fourier/benches/sparse_pbs.rs)。Native u32，`n/h/N=728/32/1024,k=1,c=3,b=64,t=8`；small-LWE 为 fixed-weight binary，σ=`3.2*2^32/16384`；accumulator 为 SparseTernary，σ=6.4；BR basis `8×3`，KS `2×13`。经典/稀疏共用客户端、输入和 LUT，分别生成 server key。固定 seed=`0x50354252+728`，依次生成客户端、经典 key、稀疏 key，再加密消息 `0..4`。

单输出 `f(m)=(3m+1)%8`，三输出 `f_i(m)=(m+2i)%8`、padded count=4。每次迭代处理四个输入之一，包含 BR、KS、提取，复用所有输出和 scratch。计时前解密检查全部被测输入/输出。两种 order 的外部维数分别为 728/1024，不跨 order 声称等价安全性。

Ryzen 9 9955HX3D、固定逻辑 CPU 2，boost/SMT 开启，未隔离机器负载；该核共享 96 MiB L3。默认 rustc 1.98.0，SIMD 为 nightly 1.100.0（2026-08-26），Criterion 0.8.2。各轮串行运行；30 samples、0.2 s warmup、1 s measurement、1000 resamples（不足时 Criterion 自动延长）；keygen 为 10 samples。默认完整链另复测一轮。

首轮均值如下，单位 ms，每格为 **经典 / 稀疏**；全部均值与 95% CI、复测及原型结果见 [CSV](benchmarks/tfhe-b4.3.csv)。BK=BR→KS，KB=KS→BR。

| feature / FFT | order | 单输出 | 三输出 ManyLUT |
| --- | --- | --- | --- |
| 默认 / RustFFT | BK | 6.229 / 4.345 | 6.120 / 4.319 |
| 默认 / RustFFT | KB | 6.095 / 4.353 | 6.010 / 5.035 |
| 默认 / TfheFFT | BK | 5.162 / 4.199 | 5.169 / 4.162 |
| 默认 / TfheFFT | KB | 5.461 / 4.319 | 5.367 / 4.253 |
| SIMD / RustFFT | BK | 6.093 / 4.616 | 6.068 / 4.565 |
| SIMD / RustFFT | KB | 6.070 / 4.639 | 6.234 / 4.611 |
| SIMD / TfheFFT | BK | 5.552 / 4.558 | 5.480 / 4.522 |
| SIMD / TfheFFT | KB | 5.309 / 4.565 | 5.218 / 4.228 |

首轮均值下降约 14%–30%；默认复测下降约 4%–35%。其中复测 TfheFFT/KB/ManyLUT 为 5.282 / 5.079 ms，置信区间重叠，不能宣称这项存在稳定收益。两轮均支持保留低重量参考方案，但收益幅度依赖负载和运行环境；也不以不同工具链的差异宣称 SIMD 加速。

仅把重量改为 `h=128`、桶数随之改为 256，其他配置和 seed 不变，临时测 BK 单输出：默认 RustFFT 为 6.171 / 7.358 ms、TfheFFT 为 5.285 / 6.530 ms；SIMD 分别为 6.525 / 7.790 ms、5.483 / 6.908 ms。稀疏约慢 19%–26%，因此不应仅凭“桶数少于 n”选择算法。该配置也通过原基准的输入/输出解密检查，没有筛选新 seed。

### 阶段与资源

临时阶段诊断使用同一 h=32 配置、BK 的消息 1 和普通 LUT。每次迭代执行一个输入的全部 64 桶：聚合包含 dummy 拷贝和所有 selector 旋转；FFT 使用预计算的真实聚合 GGSW；外积使用预计算的 Fourier GGSW 及真实前一桶 GLWE，包含分解、正变换、乘加和逆变换。拆分重放与生产 raw BR 的输出逐系数完全一致。准备、存储中间结果及分配均不计时。

| feature / FFT | 系数聚合（ms） | 聚合 GGSW→FFT（ms） | 64 次外积（ms） |
| --- | --- | --- | --- |
| 默认 / RustFFT | 3.107 | 0.380 | 0.479 |
| 默认 / TfheFFT | 3.120 | 0.255 | 0.406 |
| SIMD / RustFFT | 3.638 | 0.378 | 0.475 |
| SIMD / TfheFFT | 3.646 | 0.260 | 0.404 |

这些是独立阶段测量，缓存状态不同，不能相加当作完整 PBS 时间。聚合明显占主导：每次 BR 至少读取 105.375 MiB 的系数 BSK，已超过该核的 L3 容量；这是带宽/缓存受限的证据，但未用硬件计数器确定具体瓶颈。外积从约 n 次减到 b 次后，收益不再按 n/b 缩放。增大 b 还会增加完整 GGSW 的 FFT 与外积次数。

尝试将聚合工作集限制为 16 KiB 完整多项式块，其他计算不变，先逐桶核对整数结果。默认两种 FFT 的相同聚合工作负载分别慢约 5%、快约 4%；SIMD 分别快约 4%、慢约 9%。没有一致收益，不做完整链推广，保留清晰参考循环；后续若更换 N、字宽或存储布局，可重新测量。

下表为 h=32、BK、两种 FFT/default/SIMD 一致的资源结果。BSK payload 按切片长度计算；其余为线程 allocator 在构造期间申请减释放的常驻字节，不含栈、allocator 元数据或进程 RSS。server key 测量前预热 generator，排除其工作区扩容。

| 资源 | 经典 | 稀疏 |
| --- | ---: | ---: |
| BSK ciphertext payload | 71,565,312 B（68.250 MiB） | 110,493,696 B（105.375 MiB） |
| server key 常驻堆（含 KSK、元数据/映射） | 71,778,496 B | 110,724,872 B |
| raw BR scratch，不含 FFT engine/调用方输出 | 37,888 B | 191,168 B |
| 完整 evaluator 常驻堆，含 FFT/KS/BR 缓冲 | 103,268 B | 256,548 B |
| 首次普通/ManyLUT 在线分配次数 | 0 | 0 |

这里 `G=(k+1)^2*ell*N=12288`。经典 BSK 保存 `n*(G/2)` 个 Complex64，稀疏保存 `(c*n+b)*G` 个 u32，另有 `(c*n+b+1)` 个 usize 的 CSR 映射（17,992 B）。所以 payload 约增 54%，并非直接按 GGSW 份数增三倍；u64 的字节比例不同，不能套用此结论。稀疏 scratch 比经典多一份系数 GGSW、一份 Fourier GGSW 和 n 个指数，共 153,280 B。

BSK+KSK 生成也更贵：默认 RustFFT 为 52.873 / 183.057 ms，TfheFFT 为 52.374 / 178.435 ms。计时复用 generator，排除客户端、FFT table 与返回 key 的析构。在线收益适合重复使用同一 key 的低重量负载；一次性 key、大桶数或更小缓存机器需要重新核算。

### 复现与维护边界

```sh
taskset -c 2 cargo bench -p primus_tfhe_glwe_fourier --bench sparse_pbs -- \
  --warm-up-time 0.2 --measurement-time 1 --nresamples 1000
taskset -c 2 cargo +nightly bench -p primus_tfhe_glwe_fourier --bench sparse_pbs --features simd -- \
  --warm-up-time 0.2 --measurement-time 1 --nresamples 1000
```

h=128 的复现只需临时改变该基准的 `WEIGHT`，并用过滤器 `sparse_pbs/.*/BootstrapKeyswitch/.*/single`；不把它增加为持久矩阵。阶段诊断通过公开 `bucket`/`as_slice`、`Ggsw::write_fourier_form` 和外积接口重放上述流程；资源统计复用 `primus_test_allocations::measure`。CSV 的 `initial` 为首轮，`repeat` 为默认完整链复测，`tiling` 为默认分块对照；SIMD 分块在阶段首轮一并测量。

只保留一个完整链基准及此测量记录，临时分块、阶段和高重量诊断已删除；不新增普通 CI 统计测试。`just tfhe` / `just tfhe-simd` 均通过；Cargo 仍提示既有的跨包同名 `circuit_bootstrap` 示例输出路径冲突，本步未改动这些示例。上表为 `5102a4b` 参考实现的历史测量，后续底层优化见下节；下一步为 B5.1，不自动开放其他 sparse 组合。

### Native 加减切片与常数准备优化

B4.3 后续检查把 nightly/feature 的影响分开。不开 `simd` 时，编译器已为 Native wrapping 加减生成 AVX-512；开启后原手写分块使 `Polynomial::add_mul_monomial_assign` 未内联，在此负载中每次 BR 调用 `c*n*G/N=26208` 次独立函数，并重复处理动态长度/尾部。现在 Native `ReduceAddSlice` / `ReduceSubSlice` 的五个方法在两种 feature 下共用普通 wrapping 循环，恢复旋转累加内联；删除重复 SIMD 实现，不改多项式 API 或 TFHE 聚合顺序。其他 SIMD 算术保持原实现。

Fourier 常数 GGSW 批次只在相邻常数改变时重新准备层变换。复用限于一次调用，因此无需长期 cache、table/basis 失效标记或额外 context 成员；准备耗时依赖输入序列。缩放、FFT、每份独立采样及密文写入顺序保持原路径。

新增底层 `FourierGlweSecretKey::encrypt_ggsw_constant_batch_coeff_to`：共享一次边界检查，复用调用方提供的一份 Fourier GGSW，逐份逆变换写入最终系数存储。sparse keygen 将 selector/dummy 按最终桶顺序组成 `Zeroizing<Vec<T>>` 后调用该入口。h=32 的 u32 配置仅增加 8,992 B 临时 selector 数组，生成后擦除；BSK/evaluator 常驻存储不变。没有接入会改变浮点计算顺序的直接系数加密。

两项改变分别测量，避免把 Native 修改归入常数缓存收益。固定 CPU 2、nightly 1.100.0、`simd`、与上节相同 n=728 配置；两轮顺序为 before→after、after→before，均 0.5 s warmup、1000 resamples。Native 对照测 BK 单输出完整 PBS，30 samples、2 s measurement；keygen 对照在 Native 修改之后进行，10 samples、3 s measurement。均值/95% CI 见[追加 CSV](benchmarks/tfhe-b4.3-kernels.csv)，下表为 ms、每格 before→after。

| 修改 / FFT | 第一轮 | 第二轮 |
| --- | --- | --- |
| Native / RustFFT sparse PBS | 4.851→4.479 | 4.549→4.547 |
| Native / TfheFFT sparse PBS | 4.416→4.208 | 4.565→4.621 |
| 常数准备 / RustFFT sparse keygen | 189.177→183.553 | 186.872→185.379 |
| 常数准备 / TfheFFT sparse keygen | 186.283→181.123 | 186.449→179.984 |

Native 首轮下降约 5%–8%，反向复测为持平/慢约 1%，不能宣称完整 PBS 在各次运行中稳定加速；保留它的依据是恢复内联、去除重复分块处理及 96 行重复实现，并保留自动向量化。Sparse keygen 两轮均下降，约 0.8%–3.5%；经典 keygen 没有稳定收益，相关数据一并保留。生成 2248 份 GGSW 的采样、加密和逆变换仍占主体，不以“一次 keygen 必须快于一次 PBS”为目标，也不外推到其他参数/CPU。

既有 `constant_gadget` 差分测试补充相邻重复值、切换值及系数批次：u32/u64、两种 FFT 的输出和后续 RNG 状态与逐份普通多项式加密相同，覆盖空批次、非零工作区复用和新输出/scratch 拒绝边界。新增一个 Native 加减切片测试，以 u128 模运算核对偏移切片、回绕和向量尾部。TFHE 既有相位/零分配测试继续使用；没有新增持久 benchmark。`just tfhe` / `just tfhe-simd`、modulus/poly/lattice/GLWE 默认与 SIMD 的 check/Clippy/test、GLWE/modulus 严格 rustdoc 均通过。

## NTT 后续优化

2026-09-19，分别验证常数准备、Barrett 加减切片和直接系数域 GGSW，前一阶段作为后一阶段的基线。算法与接口变化：

- **常数准备**：原来每份常数 GGSW 先对 `(c,0,...)` 做完整 NTT，再逐系数乘各层 scalar。现在利用 `NTT(c)=(c,c,...)`，每层只做一次模乘并填充已有层缓冲，再复用普通 GGSW 的加密循环；不引入秘密值缓存或新 trait。适用于经典、ternary 和 sparse 的常数控制。
- **Barrett 加减切片**：五个方法在默认/SIMD 下共用 `compact::slice` 循环，保持规范剩余类语义，让编译器按实际切片长度向量化。原 SIMD 与默认版本的旋转累加均已内联，因此不是 Fourier 的失去内联问题。隔离替换这些切片后完整 sparse PBS 测得收益，保留此替换；未将瓶颈归因于某一条指令，也未改 NTT butterfly、模乘或其他 SIMD 内核。`U32NttTable` 原本就按 CPU 能力选 AVX-512/AVX2，不依赖 `simd` feature 才启用向量化。
- **系数域 GGSW**：新增 `NttGlweSecretKey::encrypt_ggsw_constant_batch_coeff_to`，复用系数域 GLWE 私有加密内核。噪声留在系数域，逐个采样 NTT mask、累加秘密乘积并逆变换，最后添加常数 gadget 对角项。相同 RNG 下与 NTT GGSW 后逆变换逐字一致；每个 GLWE 省一次正向 NTT，对角项也只改一个系数。sparse keygen 按桶直接写最终存储；只复用原 context 的 N 系数 scratch，不增加类型、分配或常驻 key/evaluator 空间。普通 NTT 输出接口保留。

### 测量口径与结果

Ryzen 9 9955HX3D、固定逻辑 CPU 2、boost/SMT 开启、CPU 未隔离。所有版本均用 nightly 1.100.0（2026-08-26）及仓库构建配置，避免把工具链差异算作 SIMD 差异。参数取当前 NTT `sparse_pbs`：u32、`q=132120577,n=728,h=32,N=1024,k=1,t=8,c=3,b=64`，BR 基数 `2^7`、三层，KS 基数 `2^2`、13 层；seed `0x50354252+728`，输入/LUT 同 P3.5 当前基准。

每阶段两轮 before→after、after→before，0.5 s warmup、2 s measurement、1000 resamples；keygen 10 samples，PBS 30 samples，Criterion 按样本数需要延长采集。BK 单输出补测用 3 s measurement。keygen 改用 `iter_batched(PerIteration)`，排除返回 key 析构，两个版本使用同一修正后的 harness；旧 NTT keygen 记录包含析构，不能直接与本表作优化比例比较。CSV 的均值/95% CI 与全部异常轮次见 [tfhe-ntt-kernels.csv](benchmarks/tfhe-ntt-kernels.csv)。

常数准备阶段，经典 keygen 在默认配置下降 1.8%–2.0%、SIMD 下降 2.4%–3.3%；sparse 变化为 −1.8%～+0.7%，没有稳定整体收益。保留它是因为消除了不必要的 NTT 和向量模乘，且保持精确输出和采样顺序。

Barrett 切片阶段仅在 SIMD 配置作实现对照，默认实现未变。以下为完整 sparse PBS，单位 ms，每格为 before→after：

| order / 输出 | 第一轮 | 第二轮 |
| --- | --- | --- |
| BK 单输出，补测 | 4.608→4.437 | 4.772→4.448 |
| BK 三输出 | 4.555→4.431 | 4.594→4.373 |
| KB 单输出 | 4.659→4.194 | 4.873→4.507 |
| KB 三输出 | 4.641→4.193 | 4.590→4.410 |

初测 BK 经典单输出基线异常升到 14.396 ms，三输出也到 7.323 ms，不据此声称大幅加速；初测 sparse BK 单输出还出现 5.430 ms，保留原数据并补测该负载。补测中 sparse 下降 3.7%/6.8%，经典为 −0.5%/+0.4%。其他表内 sparse 下降约 2.7%–10.0%；这些结果只支持本机本配置的选择，不保证消除所有参数下的 SIMD 退化。

本节性能对照使用 u32。[u64 补测](simd-u64.md)另外记录完整 PBS、keygen、modulus / Shoup
的结果与负向信号；不能直接推广本节的收益或宣称所有 u64 路径无退化。

最后单独比较直接系数域 GGSW 与“已优化常数准备的 NTT GGSW 后逆变换”：

| sparse keygen | 第一轮 ms | 第二轮 ms |
| --- | --- | --- |
| 默认 | 163.138→160.559 | 163.756→160.369 |
| SIMD | 164.783→156.813 | 164.867→157.792 |

默认下降 1.6%–2.1%、SIMD 下降 4.3%–4.8%。经典 keygen 不使用这个新入口，但默认控制项增加 1.4%–1.7%，SIMD 为 −1.0%～−0.1%；保留这个小幅退化信号，不声称所有负载都受益。各阶段比例不能相加，也未把“keygen 快于一次 PBS”作为目标。

### 验证与复现

扩展既有 `constant_gadget` 测试，覆盖 u32/u64、`UintNttTable` 与专用 u32/u64 表，比较普通多项式 GGSW、常数批次及系数批次的密文和后续 RNG 状态；包含空批次、dirty scratch 复用、系数输出与 level 数无关、错误长度和错误 scratch 在写入/采样前拒绝。Native 与 Barrett 加减切片合用一个 u128 oracle 测试，覆盖小模数、模数上界、偏移、回绕、空切片和向量尾部，没有增加统计测试或新的持久基准。

`just tfhe` / `just tfhe-simd` 及受影响 modulus/poly/NTT/factor/decompose/RNS/Barrett derive/lattice/GLWE 的默认与 SIMD check/Clippy/test、GLWE/modulus 严格 rustdoc 均通过；沿用完整 PBS 的相位、解码及零分配检查。非 x86 性能未测。

现有基准复现命令：

```sh
taskset -c 2 cargo +nightly bench -p primus_tfhe_glwe_ntt --bench sparse_pbs --features simd -- \
  'sparse_keygen|sparse_pbs' --warm-up-time 0.5 --measurement-time 2 --nresamples 1000
```

去掉 `--features simd` 得到同工具链默认配置。对照常数准备时保留旧的“常数完整 NTT→层缩放”；对照 Barrett 时只恢复五个加减切片到 `compact::simd`；对照系数输出时恢复按桶 NTT 加密后逐 GGSW 原地逆变换，其他阶段保持相同。每次迭代仍执行一个完整工作负载；保存两版可执行文件并交换顺序测量。

## P3.3 参考盲旋转实现与验证

[参考实现](../crates/primus_tfhe_glwe_ntt/src/sparse/blind_rotation.rs)提供
`SparseGlweBootstrappingKey::ntt_blind_rotate_lookup_table_to(input, lookup_table, output, ntt, context)`，
模数与 basis 取自 key。`SparseGlweBlindRotationContext::new(&key)` 一次建立全部 scratch；
无需客户端或 keygen 缓存，可用于相同输入维数和 gadget 布局的其他 sparse key。

公开入口在写入前检查输入、LUT、输出、工作区及 NTT 长度/模数。采用步长 1，使用
`RotationQuantizer::exponent_slice_to` 批量量化全部 `a_i` 到已有 `usize` 工作区，复用
`switch_map` 在循环前选择内核；`b` 单独量化并初始化 `(0, X^{-R(b)}P)`。
每桶从独立 dummy 复制初始化聚合 GGSW，累加所有旋转副本，
原地转 NTT，再做一次外积。输出与 scratch 交替使用，奇数桶数时最后复制回输出。
没有按秘密占用或公开指数跳过桶，外积次数严格为 `bucket_count`。
完整 PBS、两种 order 的 KS/提取与交错步长已在 P3.5 接入；CBS 不在本次支持范围。

[BR 集成测试](../crates/primus_tfhe_glwe_ntt/tests/sparse_blind_rotation.rs)使用同秘密经典对照和独立整数模切/单项式 oracle：N=16 遍历全部总指数，覆盖 q-1 回绕、奇偶桶数、空桶和多行 GGSW；N=256 使用截断 basis 与真实加密输入，覆盖分块尾部。检查相位/解码、scratch 复用、零在线分配，以及错误在写入前拒绝，不比较不同噪声密文的字节。

### 批量量化快速路径的取舍

`q_in == 2N` 且 `rotation_step == 1` 时，底层准备阶段已经选择 `Identity`。
步长大于 1 时，目标为 `2N/rotation_step`，仍须舍入后恢复步长；例如
`q_in=2N=16, step=4` 时 `2 -> 4`、`15 -> 0`，不能直接复制输入。

2026-09-17，在 Ryzen 9 9955HX3D、rustc 1.98.0、默认 feature/release、固定逻辑 CPU 2
上，用临时 Criterion 比较原实现与快速路径：`u32`，Native、Barrett `q=132120577`
和二次幂 `q=2N=2048`，批长 `16/512`、步长 `1/4`；准备和分配在计时外，
每次迭代量化一个切片。每组 50 samples、0.1 s warmup、0.7 s measurement，两轮交换版本顺序，
计时前逐项比较输出。步长 1 的独立分支使批长 512 的 Native/Barrett 分别快约 13%/5%，
但 Native、步长 4、批长 16 慢约 5%–6%；再加相等模数的直接转换分支，使 Native、
步长 1、批长 16 慢约 66%–70%。无分支的系数域左移替代乘法也使相等模数、步长 1、
批长 16 慢约 4%–5%；左移再加步长 1 分支的收益不稳定。因此保留原实现，
不新增相等模数标志或步长分支。临时原型和基准已删除，未据此推断完整 BR/PBS 性能。

## P3.4 聚合、表示与工作区测量

保留系数域 BSK、预先量化的 `alpha[n]` 和逐桶一次 NTT/外积，调整两处数据访问：

- 聚合先复制 dummy，再累加选择 GGSW，省去清零及最后一次模加。公开空桶也直接得到其 dummy。
- 聚合缓冲区原地转 NTT，下一桶覆盖初始化；不保留第二份 GGSW。累加按至多 16 KiB 的整多项式块遍历各副本，减少大 GGSW 的工作集；若单个多项式更大，则一块至少容纳一个多项式。小 GGSW 整块处理，尾块可较短。

没有新增公开 API、预计算 key 表或在线分配。每桶仍处理全部副本并执行一次外积，输出为规范系数 GLWE；复用 P3.3 的独立 oracle，将加密输入场景改为 `k=2`，覆盖跨块及较短尾块，测试数不增加。

### 方法与分项定位

2026-09-17，Ryzen 9 9955HX3D、固定逻辑 CPU 2、release、仓库编译配置。默认使用 rustc 1.98.0；SIMD 使用 nightly 1.100.0（2026-08-26）。采用上文两组 P3 参数、seed `0x5034_4252+n`，同一客户端分别生成经典/稀疏 BSK，四个输入加密 `0..4`，LUT 为 `(3*m+1)%8`。每次迭代处理一个输入，所有 key、NTT table、输入、输出及 scratch 在计时外建立；setup 检查两条路径的四个输出解码。

临时分项 Criterion 每次迭代执行一个输入的全部桶，聚合后保留的控制密文与各步真实 GLWE 作为 NTT/外积阶段输入。30 samples、0.2 s warmup、1 s measurement；两次默认配置测量的均值范围如下。独立阶段的缓存状态不同，三项之和不等于完整 BR 耗时。

| `(n,h,N)` | 原聚合 | GGSW NTT（含复制） | 外积（含 inverse NTT） |
| --- | --- | --- | --- |
| `(16,4,256)` | 9.19–9.22 µs | 9.18–9.56 µs | 12.6–13.0 µs |
| `(512,32,1024)` | 1.69–1.79 ms | 0.292–0.296 ms | 0.431–0.436 ms |

成本组的主要开销是读取及聚合 `cn=1536` 份 GGSW。`[-p,p,-p]` 连续切片原型将系数存储由 75 MiB 扩大至 225 MiB，聚合为 2.07–2.10 ms，未保留。逐多项式或固定四多项式分块会拖慢小参数组；按字节限制块大小则让小 GGSW 整块处理。延迟约简原型在大组未超过分块版本，且小组从约 8.95 µs 变为 10.75 µs，未保留。输入指数已预备并复用，不重复展开 `cn` 份旋转量；全旋转 NTT 预计算未实现。

### 完整原始 BR 对照

基线为 `a4ddb01` 的实现，两版本使用同一新增基准。Criterion 30 samples、0.3 s warmup、2 s measurement、10,000 resamples；每种配置两轮交换版本先后顺序。下表为最终代码的均值范围，经典列取当前版本中同一客户端的实际经典路径。一轮默认配置中连未修改的经典路径也从约 3.5 ms 波动至 6 ms 以上，整轮重跑，未用于表中比较。

| 配置 / `(n,h,N)` | 原稀疏 BR → 当前稀疏 BR | 当前经典 BR |
| --- | --- | --- |
| 默认 / `(16,4,256)` | 31.05–31.61 → 30.35–30.40 µs | 26.97–27.46 µs |
| 默认 / `(512,32,1024)` | 2.403–2.508 → 2.272–2.409 ms | 3.570–3.572 ms |
| SIMD / `(16,4,256)` | 33.08–33.29 → 33.18–33.48 µs | 26.49–26.58 µs |
| SIMD / `(512,32,1024)` | 2.609–2.617 → 2.555 ms | 3.498–3.506 ms |

默认小组两轮下降约 4.0%/2.1%，SIMD 大组下降约 2.1%/2.3%。默认大组变化为 +0.2%/−9.4%，SIMD 小组为 −0.3%/+1.2%，不作稳定加速结论。保留优化的主要收益是工作区减少，耗时改善只按上述测量范围解释。小组稀疏仍慢于经典；大组当前稀疏比同秘密经典少约 27%–36% 耗时，不能由外积次数比值推导倍数。经典路径照常跳过公开零旋转：小组四个输入均为 16 次有效 CMUX，大组分别为 511/510/512/512 次；稀疏始终执行 8/64 次外积。

历史复现入口（提交 `c424162`）：`cargo bench -p primus_tfhe_glwe_ntt --bench sparse_blind_rotation`。测量结果限于上述硬件、参数和固定输入，均为原始 BR，不含 KS、提取或完整 PBS。

### 内存边界

临时 allocator 统计同线程的请求字节数，不含 allocator 元数据、对象栈空间和进程 RSS。Keygen 测量从新建 generator 到返回稀疏 key，包含其工作区、转换后的 accumulator secret、PBC 临时数据；已有 context/table/client 在区间外。返回后保留值包含 key 的系数、映射和 basis。工作区单独从空构造后复用，在线测量不含调用方输出。

| `(n,h,N)` | BSK 返回后保留 | Keygen 峰值 | 原工作区 → 当前工作区 | 调用方 GLWE 输出 |
| --- | --- | --- | --- | --- |
| `(16,4,256)` | 688,620 B | 693,848 B | 31,104 → 18,816 B | 2,048 B |
| `(512,32,1024)` | 78,656,044 B | 78,677,192 B | 128,000 → 78,848 B | 8,192 B |

工作区分别减少约 39.5%/38.4%，构造分配从 8 次减为 7 次；两组在线分配次数和峰值增量均为零。基准测得的工作区大小与上文公式一致。密钥布局及常驻量未增加，未同时保存系数/NTT 两份 BSK。

P3.4 当时新增 `sparse_blind_rotation`，两组参数各比较经典/稀疏原始 BR，共四项；P3.5 已将其替换为完整 PBS 基准。分项、分配和表示选型的临时程序不进入 CI。上述功能和有限样本不认证安全性或完整链失败概率。

## P3.5 完整 PBS 接入与验收

### 接口与有效范围

`KeyGenerator::try_generate_sparse_server_key` 配对稀疏 BSK 和既有 GLWE KSK；
`ServerKey::bootstrapping_key()` / `into_parts()` 的 BSK 类型改为
`BootstrappingKey::{Classic, Sparse}`。原有生成入口继续生成经典 key。
Evaluator 将所选 key 引用与其 scratch 配对，只分配一套 BR 工作区，在线在 BR 入口分派一次。
LUT 编译、输出 codec、输入/输出检查、KS 与提取共用原路径。

普通 LUT 复用 key 中的步长 1 量化器，交错 LUT 在系数循环前按 `padded_output_count`
准备量化器；mask 和 body 使用相同步长。稀疏条件始终绑定实际 BR 的 small-LWE 秘密。
两种 order 的外部维数分别保持 `n` / `kN`，KS 的目标始终为补零 small 秘密。
兼容性检查绑定 sparse weight、模数、维数、布局与 basis，但不能验证实际秘密身份。

P3.5 的[完整 PBS 测试](../crates/primus_tfhe_glwe_ntt/tests/sparse_pbs.rs)覆盖同一客户端的
经典/稀疏对照，两种 order，普通和三输出四槽交错 LUT，`t_in=8 → t_out=16`，四个前半区消息，
解码/相位余量、步长切换复用、零分配及写入前拒绝。为覆盖截断误差，该测试 BR basis 为
`log_basis=7, levels=3`，其余采用小参数。现有 CBS fixture 增加稀疏 key 拒绝检查；
`TfheEvaluationError::UnsupportedSparseBootstrapping` 明确保留 gadget 尺度验收边界。
Fourier、稀疏三元和 NTRU 未新增支持。

### 完整性能与内存

2026-09-17，Ryzen 9 9955HX3D，固定逻辑 CPU 2，release；默认 rustc 1.98.0，
SIMD 为 nightly 1.100.0（2026-08-26）加 `simd` feature。使用上文两组参数，未改变安全/噪声假设。
每个 order 从 `StdRng` seed `0x5035_4252+n` 生成同一客户端的经典 key、稀疏 key，
再加密 `0..4` 四个输入；计时前验证全部输出。单输出为 `(3*m+1)%8`，三输出为
`(m+2*i)%8`。每次迭代执行一次完整 PBS（含 KS/提取），复用 evaluator 与输出。

Criterion：PBS 30 samples、keygen 10 samples，0.2 s warmup、1 s measurement、1,000 resamples。
各配置一轮，下面为点估计，不能视作跨机器或稳定尾延迟结论；大组稀疏路径的置信区间较宽，
例如默认 BK 单输出为 2.30–2.45 ms。BK/KB 分别指 `BootstrapKeyswitch` / `KeyswitchBootstrap`。

| 参数 / order | 默认单输出：经典 → 稀疏 | 默认三输出：经典 → 稀疏 | SIMD 单输出：经典 → 稀疏 | SIMD 三输出：经典 → 稀疏 |
| --- | --- | --- | --- | --- |
| 小参数 BK | 28.53 → 31.72 µs | 28.46 → 31.59 µs | 28.58 → 34.30 µs | 28.76 → 33.56 µs |
| 小参数 KB | 30.16 → 31.75 µs | 30.25 → 31.89 µs | 27.99 → 35.46 µs | 27.98 → 34.75 µs |
| 成本组 BK | 3.529 → 2.363 ms | 3.525 → 2.250 ms | 3.515 → 2.464 ms | 3.511 → 2.349 ms |
| 成本组 KB | 3.536 → 2.267 ms | 3.525 → 2.224 ms | 3.520 → 2.316 ms | 3.496 → 2.262 ms |

同一工作负载下，成本组稀疏完整 PBS 在本轮耗时约减少 30%–37%；小参数反而约慢 5%–27%。
三输出和单输出的接近耗时来自共享 BR/KS；不表示三个独立输入的吞吐。
经典 BR 保留公开零指数跳过：成本组 BK 普通/交错分别跳过 0/3 个，KB 为 1/4 个（每组 2048 个 mask 系数）；
小组均为零。稀疏 BR 固定处理全部桶。

完整 server key 生成包含 BSK、KSK 和结果释放，复用 generator，排除客户端与 NTT table。
两种 order 的生成算法相同，仅保留 BK 计时：

| 参数 | 默认：经典 → 稀疏 | SIMD：经典 → 稀疏 |
| --- | --- | --- |
| 小参数 | 0.311 → 1.122 ms | 0.310 → 1.122 ms |
| 成本组 | 32.24 → 118.26 ms | 31.50 → 115.84 ms |

下表为实际 allocator 请求字节，不含 allocator 开销/RSS。常驻包括 BSK、basis、映射及 KSK；
keygen 峰值将新建 generator 与临时缓冲区计入，已有 context/client 排除。
Evaluator 包含 BR、KS 和输入/中间密文工作区；不含调用方输出。两种 order 和默认/SIMD 数值相同。

| 参数 / key | BSK 系数 payload | Server key 常驻 B | Keygen 峰值 B | Evaluator 工作区 B |
| --- | --- | ---: | ---: | ---: |
| 小参数 / 经典 | 192 KiB | 202,824 | 209,992 | 14,916 |
| 小参数 / 稀疏 | 672 KiB | 694,800 | 701,968 | 27,332 |
| 成本组 / 经典 | 24 MiB | 25,272,512 | 25,342,144 | 61,444 |
| 成本组 / 稀疏 | 75 MiB | 78,762,696 | 78,832,328 | 114,692 |

Evaluator 构造分别为经典 12 / 稀疏 14 次分配；所有测量的在线普通/交错 `_to` 调用零分配。
稀疏 BSK 的映射额外占用成本组 12,808 B / 小组 456 B；没有保存第二份 NTT BSK。
调用方每个 LWE 输出另占 `4*(dimension+1)` B，三输出乘三。

常驻 [`sparse_pbs`](../crates/primus_tfhe_glwe_ntt/benches/sparse_pbs.rs) 替换四项原始 BR 基准，
只保留成本组的八项完整 PBS 和两项 keygen。当前 `DIMENSION=728`；后续计时见 [P4.0](benchmarks/tfhe.md#p40-阶段拆分)和 [P4.3](tfhe-mvb.md#8-p43-测量与应用选择)，上表仍为 n=512。复现上表需设回 512。运行当前基准：
`cargo bench -p primus_tfhe_glwe_ntt --bench sparse_pbs`；SIMD 使用 `cargo +nightly bench` 并加
`--features simd`。小参数仅替换该基准中的维数、重量、噪声和两组 basis 为上文小参数后测量；
诊断程序未保留为常驻 target，GitHub CI 不执行 benchmarks。

### 相位余量与匹配诊断

对上述固定输入，临时诊断按 `min(|phase-E(f(m))|, q-|phase-E(f(m))|)` 计算环形输出误差。
`q/(2*t_out)` 的保守整数解码半径为 8,257,535；普通每项四个输出、交错每项十二个输出。
默认/SIMD 的实际误差和内存记录一致。

| 参数 / order | 经典：普通 / 交错最大误差 | 稀疏：普通 / 交错最大误差 | 量化后相对输入中心最大偏移：普通 / 交错 |
| --- | ---: | ---: | ---: |
| 小参数 BK | 37,192 / 35,446 | 25,575 / 61,028 | 0 / 4 |
| 小参数 KB | 32,115 / 21,948 | 75,557 / 49,230 | 1 / 4 |
| 成本组 BK | 588,867 / 782,762 | 1,262,445 / 1,066,009 | 4 / 12 |
| 成本组 KB | 688,593 / 836,663 | 1,717,958 / 1,943,283 | 2 / 8 |

偏移以实际进入 BR 的密文逐系数量化计算，KB 包含前置 KS，单位为原始旋转指数；两条路径
在本样本中得到相同最大偏移。对应中心间半距为小组 32 / 成本组 128，交错步长为 4。
最小输出解码余量仍大于 6.31e6；这些有限点不提供尾概率或重复求值保证。

额外对每组固定非零索引 `i*n/h`、`i in 0..h`，使用生产映射/匹配实现、seed
`0x5035_4d41+n` 连续生成 64 个成功映射，各组总尝试次数均为 64，无重试。
这只统计映射阶段，不是 64 次大密钥加密，也不能据此宣称匹配不失败；八轮耗尽上界和条件分布仍沿用前文。

## B3.3 已有上层组合验收

[sparse_pbs.rs](../crates/primus_tfhe_glwe_ntt/tests/sparse_pbs.rs) 增加两项测试，均覆盖 BK/KB。
复用现有小型参数 `u32, q=132120577, N=256, n=16, h=4, k=1`；
BR basis 为 `7×3`，KS basis 为 `9×3`，加密噪声标准差为 `0.7`，
稀疏映射使用三个副本、八个桶。外部维数分别为 16/256。

- **Boolean**：`t=4`，seed=`0xB3030004`。给 false/true 输入分别加 `±floor(q/128)`
  的相位偏移，再复用共享真值表、NOT、MUX 和 `NAND → NOT → MUX → XOR` 门链。
- **双输入**：`t_in=15 → t_out=8`，seed=`0xB303000F`，`B=3, R=2`，
  `f(x,y)=x²+y`。对 `(0,0)、(2,1)、(1,1)` 加同号/异号受控误差，单位为
  `floor(q/(16*t_in))`；独立解密核对 `e_packed=e_x+3e_y+rho(x,y)`，
  包含非二次幂编码的非零舍入差。最大注入量约占普通输入半宽 `q/(2*t_in)` 的一半。
- **奇数全域**：复用双输入的密钥、evaluator 和输出缓冲，
  `f(m)=(m²+3)%8`。检查 `0、7、8、14、1`，覆盖零点回绕、两半域和末端；
  非中心点注入 `±floor(q/(8*t_in))`，约占折叠后输入半宽 `q/(4*t_in)` 的一半。

输入余量还需容纳逐系数量化及 KB 前置 KS 的误差，以上半宽是理想近似。
所有调用检查输出相位与解码，并从首次调用起验证零分配；`just tfhe` 和 `just tfhe-simd` 通过。
这是现有链的功能回归，不估计生产尾概率。未修改生产 API/内核，也未新增 benchmark；
稀疏 CBS、ternary 和其他后端仍沿用各自验收边界。

## 论文校勘与表示选择

### 旋转切片

对于长度 `N` 的 `p`，以 `[-p,p,-p]` 保存三段，`0<=r<2N` 的 `X^r p mod (X^N+1)` 对应：

```text
start = N - r       if r < N
        3N - r      otherwise
result = buffer[start .. start + N]
```

p.19 的第二段使用 `2N-r`，在 `r=N` 时给出 `p`，应为 `-p`。P3.1 用独立逐项乘单项式 oracle 复核了 `N=2,4,8,16` 的全部 60 个指数。P3.4 实测三倍存储的切片方案在成本参数组更慢，保留已有系数旋转/相加；临时脚本不作为常驻测试。

### 初始化与噪声表述

p.18 Algorithm 2 在 `Boot` 定义了 `P(X)`，但 `BlindRot` 初始化使用常数且未消费 `P`。Primus 必须按前述相位不变量从真实 LUT 初始化，不能照抄该伪码。论文的输入相位记号也不同，以本仓库 `b-<a,s>` 为准。

p.17 的聚合标准差仅写 `sqrt(|C_j|)*sigma`，按 Algorithm 2 显式添加的独立 dummy 应计为 `sqrt(|C_j|+1)*sigma`。其 `O(sigma_output)` 表述没有给出可直接使用的有限参数尾界；本轮采用逐项递推，保留生产失败概率问题。

### NTT 与空间换时间

每桶聚合后转换整个 GGSW，再用现有 NTT external product；这是一次**GGSW 变换**，包含 `(k+1)^2*ell` 个多项式 NTT，不是一个多项式 NTT。变换/外积边界保持现有规范模表示与 basis 顺序。

不默认预计算所有 `2N` 个旋转的 NTT 形式。论文一般二元实现的超大 key 已遇到带宽瓶颈；P3.4 按上述分项测量保留系数域 BSK 和逐桶 NTT。`[-p,p,-p]` 也会将对应系数存储扩大约三倍，不能只报告减少的算术次数。

## 未解决的研究问题

1. 固定重量 small-LWE、补零 KS 目标和相关 evaluation keys 的具体攻击估计与安全假设；成功条件下公开映射的影响不能仅凭熵或 `U^8` 消除。
2. 实际离散采样器、分解相关性、GLWE KS、重复求值及各 LUT 编码的完整尾界；普通 LUT 的实验结论不能自动推广到 CBS。
3. 安全目标是否需要增加复制数/桶数或采用其他 PBC；改变参数后须重算失败/噪声界并同步经典对照。

论文 Table 2 的 gate 倍数属于外部结果，功能 3-bit 项还包含标星的微基准估计，不作为 Primus 目标。§5 Binary-NTT shallow 使用 NTT 槽二元秘密、不同 RLWE 假设和乘法树，与本文系数二元稀疏秘密及 LWE→GGSW CBS 不同，见[候选清单](tfhe-next.md#6-保留但暂缓)。

底层恢复入口：[固定重量采样](../crates/primus_distr/src/common.rs)、[客户端秘密](../crates/primus_tfhe_glwe/src/key.rs)、[NTT keygen](../crates/primus_tfhe_glwe_ntt/src/key.rs)、[GGSW 加密](../crates/primus_glwe/src/secret_key/ntt/gadget.rs)、[basis 误差界](../crates/primus_decompose/src/primitive/basis.rs)、[外积](../crates/primus_lattice/src/ggsw/external_product.rs)与[工作区](../crates/primus_lattice/src/context/glwe_external_product.rs)。
