# NTRU 固定重量二元桶聚合

[B8 分步计划](tfhe-backend-plan.md#b8ntru-固定重量二元桶聚合-pbs)的恢复入口。
**B8.1–B8.2 NTT 桶聚合与完整 PBS 已接入。** 普通/ManyLUT 复用原有 evaluator；
sparse CBS/MVB 明确拒绝。下一步 B8.3 独立验证 Fourier，不自动启动。

## 1. 秘密身份与两次条件化

客户端候选是 `n` 维、重量恰为 `h` 的均匀二元向量，嵌入 `N` 长多项式
`f_client` 的前缀；`n..N` 为零。外部 LWE 必须使用同一个前缀。沿用
[generate_padded_pair](../crates/primus_ntru/src/secret_key/ntt/mod.rs)，逐候选检查
`f_client` 在 `R_q=Z_q[X]/(X^N+1)` 中可逆，最多 1024 次，失败返回错误。
不能为满足重量、可逆性或映射条件而翻转系数，也不能另采样一份 LWE 秘密。

设 `U_h` 是全部重量 `h` 支持集上的均匀分布，`A(S)` 表示该支持对应的多项式可逆。
在独立候选模型下，成功返回的秘密服从 `D_A=U_h | A`，不是未筛选的 `U_h`。
NTT 没有 Native 的偶重量禁令，但接受条件也不只由重量决定：

- `q=17,N=n=8,h=4`，70 个支持中 32 个可逆，38 个不可逆。
- `{0,1,2,3}` 可逆，`{0,1,2,4}` 不可逆；二者能通过坐标置换互相得到。
- 临时枚举核对 `f(3^(2k+1)) != 0 mod 17` 的独立根求值和现有 NTT 转换，结果一致。
  这说明不能假定 NTRU 接受集合具有任意坐标置换对称性；小环比例不代表实际参数的接受率。

固定已经接受的秘密后，复用 [BucketMap](../crates/primus_tfhe/src/sparse.rs)：
每个输入索引独立均匀选择 `c` 个不同桶，支持集匹配到互不相同的桶。匹配失败时只重采
公开映射，最多八次；耗尽就返回错误，不重采或修改客户端秘密。匹配和支持索引保持私有，
由 `Zeroizing` 管理，不进入公开 key。

令 `P_0(M)` 为映射提议分布，`E(S,M)` 为存在完整匹配。对固定 `n,h,c,b`，
`p_match=Pr_M[E(S,M)]` 对任意大小为 `h` 的 `S` 相同：将输入标签置换，同时置换
映射的输入行，保持 `P_0` 和匹配事件。因此，在独立随机数模型下，两步成功后的联合分布为

```text
Pr[S,M | success] = D_A(S) * P_0(M) * 1[E(S,M)] / p_match
```

有限重试仅将成功概率乘以 `1-(1-p_match)^8`，不进一步改变成功输出的秘密边缘分布
`D_A`；可逆性阶段成功概率另为 `1-(1-p_A)^1024`。但是公开映射仍与秘密相关：

```text
Pr[S | M,success] ∝ U_h(S) * 1[A(S)] * 1[E(S,M)]
```

这项推导只描述采样过程，不证明给定公开映射时的安全性。不能把 GLWE 未做环可逆筛选的
秘密/映射结论直接用于此处，也不能用秘密熵、八次重试或解密成功代替攻击估计。
局部匹配过程不保证恒时；固定客户端入口保留上述失败和重试契约。

## 2. 每桶控制与表示

对桶 `C_j`，设私有选择 `u_(j,i)` 恰好选中它负责的一个支持索引，或全零。
每个非零客户端系数在全部副本中恰好被选一次。独立加密

```text
K_(j,i) = NGSW_f_acc[u_(j,i)]
D_j     = NGSW_f_acc[1 - sum_i u_(j,i)]
G_j     = D_j + sum_(i in C_j) X^alpha_i K_(j,i)
```

`G_j` 明文是所选 `X^alpha_i`，未占用桶则为 `1`。区分三个角色：有公开条目且占用、
有条目但未占用、没有条目的公开空桶。后两者都需加密一的 dummy；占用桶的 dummy
虽然加密零，也必须参与计算。每个副本均独立加密，不能重复使用同一份 Enc(0)，
也不能在全部副本中直接加密原 `s_i`，否则重复旋转。

密钥存储为 `[bucket][entry...,dummy][level][coefficient]`：已有批量 NTT NGSW
常数加密后，逐多项式原地 inverse NTT。聚合先复制 dummy，再按每个公开指数旋转并
相加，整份聚合结果原地转 NTT，最后一次外积。下一桶覆盖同一聚合区；外积复用
初始化使用的 `NttNtruExternalProductContext`。不保存明文占用位或额外密文偏移数组。

NGSW 的每层相位是 `g_l*f_acc*M_j + e_(j,l)`；NLev[1] 的每层相位却是
`g_l + e_(I,l)`，两者不能混用。若原始加密行误差独立且方差为 `sigma_e²`，
聚合行误差方差为 `(|C_j|+1)*sigma_e²`，包括所有零 selector 和 dummy。
公开桶长度不等，最坏界不能用平均桶长替换。NTT 和系数旋转都是精确环运算，
没有 Fourier 的变换舍入项。

## 3. 独立的初始化预算和单桶预算

记 `phi_f(C)=f*C`，`D_l(x)` 为当前有符号 gadget digits，
`rho(x)=sum_l g_l*D_l(x)-x`，`eps=basis.approximate_error_bound()`，
`B=basis.basis_value()`。本实现的 digits 绝对值不超过 `B/2`。

先对已经旋转的编码 LUT `U=X^-beta P` 做 NLev[1] 外积：

```text
C_0 = sum_l D_l(U) * I_l
phi_f(C_0) = U + rho(U) + sum_l D_l(U)*e_(I,l)
||E_0||inf <= eps + N*(B/2)*sum_l ||e_(I,l)||inf
```

初始化残差前没有 `||f||1`，因为 NLev 的目标相位是 `g_l`。
它也不是 GLWE 平凡初始化的零误差。

对桶单项式 `M_j`，一次 NGSW 外积满足

```text
phi_f(C_(j+1)) = M_j*phi_f(C_j) + M_j*f*rho(C_j)
                + sum_l D_l(C_j)*e_(j,l)
```

单项式只置换并变号，保持已有相位误差的无穷范数。因此单桶新增误差保守界为

```text
Delta_j <= ||f||1*eps + N*(B/2)*sum_l ||e_(j,l)||inf
```

完整 BR 可用 `||E_0||inf + sum_j Delta_j` 作确定性上界，但它可能很松。
这里的行误差界从具体测试控制的独立系数相位恢复，不是高斯截断概率；
没有假设 digits 与此前累积误差独立。完整链还需计入第 6 节的量化和返回 KS。

## 4. 验证与参数诊断

[单桶回归](../crates/primus_tfhe_ntru_ntt/tests/sparse_bucket.rs)现在直接检查正式 sparse key，
用独立行相位恢复 selector，验证每个支持恰好在一个副本生效：

- u32/u64、`N=32,n=16,h=4,logB=8`，默认完整层数，`t=16,sigma=0.7,seed=0xB801`。
  accumulator 为 SparseTernary；模数分别为 `132120577` / `1125899906826241`。
- `(c,b)=(3,8)` 检查每个支持恰好选一次；`(1,17)` 保证有公开空桶。
  检查可逆生成、真实重量、零 padding，以及每个支持恰好在一个副本中生效。
- 独立整数负循环卷积求每个原始控制的行相位。聚合后的相位必须**精确等于**各行相位
  旋转相加，保护 dummy/加密零的噪声参与。测试使用零指数以及跨 `N`、`2N` 的指数。
- 单桶输出分别对照已加密输入的理想旋转和无噪声 LUT 的理想旋转，检查上述两个预算。
  小 fixture 的预算和须小于 `q/32`，避免空泛的大界；初始化、聚合/变换/外积均检查
  首调用零分配，并复用脏输出和工作区。普通测试无诊断输出或统计循环。

另做临时大参数诊断：`N=1024,n=728,h=32,c=3,b=64`，其余配置同上，
u32/u64 用 `U32NttTable/U64NttTable`。仅检查第一个占用桶、第一个未占用桶和最长桶，
每桶四组公开指数；各桶独立消费同一份初始化密文，**没有串联 64 个桶**。
2026-09-19 默认与 nightly SIMD 的以下整数结果完全一致：

| 类型 | 初始化最大误差 | 初始化预算 |
| --- | ---: | ---: |
| u32 | 6,948 | 786,436 |
| u64 | 3,604 | 1,572,866 |

| 类型 / 桶 | 公开条目数 / 占用 | 最大新增误差 | 最大单桶预算 | 含初始化的最大误差 |
| --- | --- | ---: | ---: | ---: |
| u32 / 0 | 35 / 是 | 60,341 | 6,162,364 | 60,706 |
| u32 / 1 | 35 / 否 | 58,974 | 6,031,292 | 62,811 |
| u32 / 35 | 43 / 是 | 64,133 | 6,424,508 | 64,731 |
| u64 / 0 | 39 / 是 | 93,929 | 12,714,974 | 94,587 |
| u64 / 1 | 32 / 否 | 98,781 | 10,486,750 | 98,625 |
| u64 / 30 | 47 / 是 | 109,047 | 13,894,622 | 108,217 |

各列分别取四组指数中的最大值，最大值不一定来自同一次调用。u32 的初始化加单桶
保守预算可超过小回归的 `q/32` 阈值，但实测仍满足推导界；这也是保守界不能直接当作
失败概率的例子。按此单桶界量级累加 64 次已无法给 u32 完整链提供有用余量。
第 6 节补充实际完整链和量化/KS；这些单桶结果不能批准任意参数。

小回归复现：`cargo test -p primus_tfhe_ntru_ntt --test sparse_bucket`。
大参数诊断采用同一代码，将 `N/DIM/WEIGHT` 改为 `1024/728/32`、映射配置改为 `(3,64)`，
选择上述三类桶；保留实际误差不超过预算的检查，以记录预算替代仅针对小 fixture 的
`q/32` 断言，release 模式运行。临时诊断和小环枚举已删除，未加入 CI。

## 5. 正式 API 与接入边界

- [`KeyGenerator::try_generate_sparse_server_key`](../crates/primus_tfhe_ntru_ntt/src/sparse.rs)
  和 context 转发入口接受已有客户端及 `copy_count/bucket_count`。构造先检查分布、
  `0<h<n<=N`、实际系数/重量、零 padding、表/模数和存储尺寸，再转换两份可逆秘密；
  这些拒绝不消耗 RNG。匹配失败只重采 map，错误保留在 family `KeyGenerationError` 中。
- `SparseNtruBootstrappingKey` 保存系数 NGSW 和公开 map；`ServerKey` 内部选择
  classic/sparse，共用 NLev initializer、basis 和返回 KSK。无第二套高层 evaluator 类型。
  `bucket()` 只公开索引和密文，dummy 永远位于末尾，不公开私有占用/选择信息。
- 普通/ManyLUT 以同一个 `RotationQuantizer` 处理 body 和全部 mask。工作区只分配
  所选算法需要的存储；初始化、桶外积和返回 KS 共用一个外积 context。每桶输出后交换
  两个 NTRU 缓冲，奇偶桶数均保证最终 accumulator 位于 `current`。
- CBS 工厂及 `try_from_parts` 都返回 `UnsupportedSparseBootstrapping`，MVB 工厂同样拒绝。
  初次交付只验收普通/ManyLUT；不继承经典 CBS/MVB 或其他上层组合的误差结论。
- Fourier 需独立验证。这里的 `h=32` 在 Native 环不可逆，B8.3 必须显式选择奇数重量，
  并重新检查逆元稳定性、系数恢复和 FFT 聚合误差；不能静默修改重量。

## 6. B8.2 完整链与误差

记 body/mask 的量化指数为 `beta/alpha_i`，二元秘密为 `s_i`。理想完整旋转为
`r=-beta+sum_i alpha_i*s_i (mod 2N)`，输出槽 `k` 的目标是 `(X^r P)_k`。
输入噪声及量化偏差先决定该槽是否仍落在正确消息的 LUT 区间，不能把它们直接当作
输出编码的加性噪声。ManyLUT 三输出的步长为四，body 和 mask 都使用该步长；
这里 `h=32` 的逐项最坏量化位移界为 `(h+1)*4/2=66` 个指数单位，已经超过
`N=1024,t_in=16` 的理想消息半间距 `N/t_in=64`；输入噪声另加。
因此八个输入成功只提供功能证据，不是全输入误差尾界。

设 BR 后密文为 `C`，返回 KSK 的第 l 行在 `f_client` 下相位为
`g_l*f_acc + e_(KS,l)`。则

```text
phi_f_client(KS(C)) = phi_f_acc(C) + f_acc*rho_KS(C)
                     + sum_l D_KS,l(C)*e_(KS,l)
```

compact extraction 在 client 的零 padding 前提下精确取出目标系数，不另加噪声。
最终误差包括 NLev 初始化、所有桶和返回 KS，不能从单桶数值推出完整失败概率。

持久 [完整链回归](../crates/primus_tfhe_ntru_ntt/tests/sparse_pbs.rs)：

- u32/u64、`N=256,n=16,h=4,seed=0xB802`，同一客户端对照经典链；普通和三输出，
  零/随机 mask，奇偶桶数 `(3,8)/(1,17)`，包含公开空桶。首调用和复用均零分配。
- 独立整数 LWE 点积检查最终相位，按量化后的完整旋转直接索引编译 LUT，检查符号、
  提取槽、相位误差及输出解码，不靠后端 decryptor 构成循环 oracle。
- 非法分布/重量、映射参数、存储溢出和不可逆秘密在 RNG 改变前拒绝；错误维数调用
  不写输出。独立有效 CBS 材料也不能绕过 sparse 拒绝边界。

大参数诊断合入 [sparse_pbs 基准](../crates/primus_tfhe_ntru_ntt/benches/sparse_pbs.rs)
的 setup：`N/n/h=1024/728/32,c=3,b=64,logB=8`（BR/KS 都保留完整层数），
所有噪声标准差为 `0.7`，accumulator 使用 SparseTernary。输入 Rounded `t=16`、
输出 Rounded `t=8`，函数为 `(m+2i)%8`；固定 seed `0xB802`，检查 padded 域全部八个
输入。每种字宽的 classic/sparse 使用同一可逆客户端及输入；计时 RNG 单独固定，
Criterion 自适应迭代次数不会改变后续 setup key。不同算法的控制加密噪声不同。

下节记录测得的完整误差和成本；测试未认证条件秘密/公开映射安全性或完整失败率。

## 7. B8.2 完整成本

2026-09-19，`7b7cea3` 加本步修改；Ryzen 9 9955HX3D，CPU 2，boost/SMT 开启，
CPU 未隔离。默认与 SIMD 均用 nightly 1.100.0（bff8e12ff，2026-08-26），串行计时，
20 samples、1 s warm-up、2 s measurement。在线迭代一次处理八个输入之一，复用 LUT、
输出和 scratch；server keygen 保持客户端及 KeyGenerator workspace 固定，包含 map、
全部控制、初始化、KSK 和最终密钥分配，析构移出计时。未把客户端采样算入 server keygen。

以下是 Criterion 样本均值（ms）；[CSV](benchmarks/tfhe-b8.2.csv)保存 95% 区间。
对照是同一低重量秘密下的算法选择，没有此前 sparse 完整链的性能基线。

| 字宽 / feature | 单输出 classic → sparse | 三输出 classic → sparse | server keygen classic → sparse |
| --- | ---: | ---: | ---: |
| u32 / 默认 | 1.880 → 0.664 | 1.875 → 0.635 | 23.465 → 74.996 |
| u32 / SIMD | 1.906 → 0.668 | 1.901 → 0.635 | 23.250 → 75.125 |
| u64 / 默认 | 10.826 → 4.624 | 10.838 → 4.657 | 56.943 → 188.251 |
| u64 / SIMD | 7.869 → 4.808 | 7.857 → 4.469 | 55.418 → 183.512 |

本组 sparse 在线比 classic 快约 **39%–67%**，server keygen 慢至 **3.20–3.31 倍**。
u32 开启 SIMD 的影响很小；u64 classic 明显受益，sparse 没有一致 SIMD 收益，
其单输出 SIMD 样本波动较大（均值 95% 区间约 4.609–5.062 ms）。未据此修改底层内核。

构造结束仍持有的请求堆字节（默认/SIMD 相同）：

| 字宽 / 算法 | server key | evaluator scratch | 单输出最大误差/q | 三输出最大误差/q |
| --- | ---: | ---: | ---: | ---: |
| u32 / classic | 8,970,312 | 21,504 | 1.372035e-3 | 1.662905e-3 |
| u32 / sparse | 27,666,064 | 39,616 | 8.172383e-4 | 2.441315e-3 |
| u64 / classic | 35,881,248 | 41,984 | 1.366631e-10 | 2.408935e-10 |
| u64 / sparse | 110,610,280 | 96,960 | 1.963887e-10 | 4.223537e-10 |

堆字节不含客户端、借用的 NTT table、LUT、调用方输入/输出、allocator 元数据或栈，
也不是 keygen 峰值。误差是 setup 八个输入的最终解密相位到预期编码的最大圆周距离；
默认/SIMD 完全一致，均小于输出 `t=8` 的半间距约 `q/16`。不将一次密钥样本的误差大小
当作噪声分布排序，尤其不声称 sparse 总比 classic 噪声小。

稀疏控制数为 `cn+b=2248`，经典为 `n=728`；加上公共初始化/KSK 后 key 约大 3.08 倍。
稀疏 BR 只有 `b=64` 次外积，但在线仍要读出并旋转累加所有控制。额外 scratch 为
一份 `L*N` 系数聚合区及 `n` 个旋转指数；外积工作区复用，不新增第二份。
所以保留显式算法选择，不按重量自动切换，不以 keygen 必须快于一次 PBS 为目标。

复现（默认和 SIMD 顺序执行）：

```sh
taskset -c 2 cargo +nightly bench -p primus_tfhe_ntru_ntt --bench sparse_pbs -- --warm-up-time 1 --measurement-time 2 --sample-size 20 --save-baseline b82-default --noplot
taskset -c 2 cargo +nightly bench -p primus_tfhe_ntru_ntt --bench sparse_pbs --features simd -- --warm-up-time 1 --measurement-time 2 --sample-size 20 --save-baseline b82-simd --noplot
```

本步验收通过 `just tfhe`（`RUSTDOCFLAGS=-D warnings`）、`just tfhe-simd`、
`cargo check --workspace --all-targets` 及默认/SIMD release 的 `ntru_ntt_sparse` 示例。
B8.2 到此完成；B8.3 Fourier 仍需独立验收，不能直接沿用本组偶数重量与精度结论。
