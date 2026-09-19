# Native 偶尺度 MVB：Fourier 实现与验证

**B5.2–B5.3 已完成两族 Fourier 正式接入。** 使用入口见
[GLWE README](../crates/primus_tfhe_glwe_fourier/README.zh_CN.md#固定尺度分解式-mvb) 与
[NTRU README](../crates/primus_tfhe_ntru_fourier/README.zh_CN.md#固定尺度分解式-mvb)。
接口与误差验收分别见 [B5.2](#b52正式接口与验收) / [B5.3](#b53ntru-接入与独立误差验收)；下一步 B5.4。

以下原型记录以 `1f6bab2` 为基线，覆盖 RustFFT/TfheFFT、Native u32/u64、小整数
差分因子和经典 binary BK 链。历史测量不代表任意因子/参数的精度或当前实现的耗时，
也不覆盖 NTRU 初始化。

## 表示与执行

沿用[整数恒等式](tfhe-mvb.md#精确恒等式)：`W_i=(1-X)p_i`、`V=A*S`，
`S=1+...+X^(N-1)`，并在构造期要求实际 `Delta=round(2^w/t_out)` 为偶数，
取整数 `A=Delta/2`。于是 `V*W_i=Delta*p_i mod (2^w,X^N+1)`。
只对无噪声的公开尺度除二，不对 BR 结果右移，不使用不存在的模逆元。

原型使用已有 raw `LookupTable::try_new` 编译未缩放的 `p_i`，保留负尾，
再按有符号整数差分构造 `W_i`；另编译相同 Scaled 输出的独立 PBS 参照。
B5.1 当时未修改 `FactorizedLookupTable::try_new`；其 Native 分支现已由 B5.2 接入。

```text
准备：W_i 的负系数保留为 Native 二补码
      forward_as_integer(W_i) -> 已准备整数 Fourier 因子
在线：经典 BR(input, V, step=1) -> 系数 GLWE
      write_fourier_form -> 共享 torus Fourier GLWE
      对每个因子：mul_fourier_polynomial_to -> write_torus_form
                  -> 环 KS -> compact LWE 提取
```

这些操作分别来自 [FFT](../crates/primus_fft/src/table.rs)、
[Fourier 公开乘法](../crates/primus_lattice/src/macros/fourier_ops.rs) 和
[经典 BR](../crates/primus_tfhe_glwe_fourier/src/blind_rotation.rs)。两种 FFT
均要求因子与密文使用同一 table 实例；未把 RustFFT 的顺序用于 TfheFFT。
密文前向变换带 `2^-w` 缩放，整数因子不带此缩放，逆变换只恢复一次 torus 尺度。

无需新增底层 trait、密钥类型或乘法内核。B5.2 复用这些原语及普通 evaluator
的 BR/KS 阶段，另持有共享 Fourier 结果，集中管理逐输出乘积 scratch。
原型的分散因子 Vec 和独立系数缓冲只是诊断布局，不作为正式 API/存储设计。

## 独立参照与边界

原型使用 `i128` 直接累加负循环卷积，最后转回 `u32/u64`；不调用 FFT、
`Polynomial` 乘法或模数约简内核作为 oracle。所测长度/系数范围不会溢出 `i128`。

- 精确整数卷积核对 `V*W_i` 与 raw Scaled LUT 的每个系数，复用现有几何，
  不复制或重新解释输入中心算法。
- 独立公开乘法：`N=16/1024/4096`，全字宽随机 torus 系数；稀疏因子
  `w[0]=18,w[N/2]=w[N-1]=-9`，以及稠密 `w[j]=j%7-3`。
- 完整链：每次 BR 后，对 GLWE 的每个 mask/body 分量分别做精确系数卷积；
  与真实 FFT 乘积比较，再用系数私钥独立计算两者相位。
- 精确乘积相位同时与 `W_i*phase(BR)` 对照，隔离公开乘法的数值误差；
  最后分别测 KS 前后相位、Scaled 解码及同编码独立 PBS。
- 输入侧按实际逐系数量化计算 `r=R(b)-sum(R(a_j)*s_j)`，直接检查该位置的
  raw LUT 值是否仍等于目标值，避免把输入位置错误算成输出噪声。
- 每个 FFT/字宽/输出尺度组合的首次完整调用均为零分配。普通测试/CI
  没有新增大型统计或 benchmark。

### 实际尺度

| 字宽 | `t_out` | `Delta` | `epsilon=t_out*Delta-2^w` | 原型处理 |
| --- | ---: | ---: | ---: | --- |
| u32 | 8 | 536870912 | 0 | 偶数，接受 |
| u32 | 10 | 429496730 | 4 | 偶数，接受 |
| u64 | 8 | 2305843009213693952 | 0 | 偶数，接受 |
| u64 | 10 | 1844674407370955162 | 4 | 偶数，接受 |
| u32 | 3 | 1431655765 | −1 | 奇数，拒绝 |
| u64 | 3 | 6148914691236517205 | −1 | 奇数，拒绝 |

因此应检查实际尺度奇偶，不能用“`t_out` 必须为二次幂”代替。
二补码转 `f64` 对本组整数因子精确；这不证明大于 `2^53` 的整数因子也能精确
表示，或小于该值便有足够的完整 FFT 精度。正式接口仍须说明因子表示与噪声预算。

## 完整负载与误差

固定参数：`n=728,d=1,N=1024,t_in=15,D=8,k=3`，small-LWE 为均匀 binary，
GLWE 为 `SparseTernary`；BR 分解 `logB=8,L=3`，KS 为 `logB=2,L=13`。
small-LWE 标准差 `3.2*2^w/16384`，GLWE 标准差为 **6.4 个整数单位**。
字宽之间不等噪声强度或等安全，不能直接用其相位数值比较参数优劣。

seed=`0x42353101`，每个 FFT/字宽独立以同 seed 生成客户端、经典 server key，
然后顺序加密 16 个输入 `m=sample%8`。同组 `t_out=8/10` 复用这些输入/密钥；
每个尺度有 48 个输出样本。三输出函数为：

```text
f0(m) = t_out - 1 - (m % t_out)
f1(m) = (m 为奇数 ? t_out - 1 : 0)
f2(m) = (m >= 3 ? 1 : 0)
```

| `t_out` | 各因子 nnz | 各因子 L1 | 各因子 L2² |
| --- | --- | --- | --- |
| 8 | 8 / 8 / 2 | 14 / 56 / 2 | 56 / 392 / 2 |
| 10 | 8 / 8 / 2 | 18 / 72 / 2 | 128 / 648 / 2 |

最大单个差分绝对值为 9。输入真实中心为
`0,137,273,410,546,683,819,956`，终止中心截到 1024；公共保守偏移区间
为 `[-34,33]`。实测最大绝对旋转偏差 u32 为 6、u64 为 12，所有实际位置检查通过。

[误差 CSV](benchmarks/tfhe-b5.1-noise.csv) 保存默认和 SIMD 的结果；两次诊断
数值一致。`public_product` 是独立随机卷积；`complete_mvb` 是真实链，
所有误差以整数 torus 单位计。`br` 比较整条相位多项式与实际旋转后的 V；
`coefficient_fft` 比较每个密文分量，`phase_fft` 比较其系数私钥下整条相位；
`product_phase/ks_increment/mvb_output/single_output` 只统计提取位置。
各阶段样本数不同，不将其 RMS 当成可相减的独立方差。

下表为默认配置、两种 FFT/两个输出尺度中观察到的最大绝对误差：

| 阶段 | u32 | u64 |
| --- | ---: | ---: |
| BR 相位 | 4352173 | 545790479636070 |
| 公开乘法新增的密文系数误差 | 0 | 262144 |
| 公开乘法新增的相位误差 | 0 | 5200406 |
| 乘后、KS 前的目标相位误差 | 49867664 | 7286987543124480 |
| KS 新增相位误差 | 2694 | 4459669539584 |
| 最终 MVB 输出相位误差 | 49867460 | 7284911321808896 |
| 独立 PBS 输出相位误差 | 3366650 | 442280411193344 |

u64 的新增公开乘法相位误差约不超过 `2.82e-13*q`，在本组中远低于 BR 与
分解误差；独立稠密 N=4096 卷积最大系数误差为 1819670，约 `9.86e-14*q`。
u32 所测乘法与 oracle 逐系数相同，不代表任意更大 N/范数都可逐位一致。

若公开乘法的各分量误差为 `delta_a_j,delta_b`，它增加的真实相位误差是
`eta_FFT=delta_b-sum(delta_a_j*s_j)`。因此应预算

```text
e_out = coeff_0(W_i*e_BR) + coeff_0(eta_FFT) + e_KS
```

而不是只看单个密文系数误差。保留 `||W_i||_1*||e_BR||_infinity` 的无条件界，
不假设 BR 系数或同组输出独立。

所有输出满足 `abs(epsilon*y+t_out*e_out)<q/2`，其中 `epsilon` 的非零偏差也
计入。记录 `margin=0.5-abs(epsilon*y+t_out*e_out)/q`：u32 最小为
**0.387518898118**，u64 为 **0.496050841659**，分别剩余约 77.50% / 99.21%
的解码半径。交替高低值函数明显放大噪声，不能把阈值小范数的余量套给所有 LUT。
这些有限样本不估计失败概率，也不认证参数安全性。

## 成本与复现

计时结果见 [CSV](benchmarks/tfhe-b5.1.csv)。2026-09-19，Ryzen 9 9955HX3D，
CPU 2、boost/SMT 开启、CPU 未隔离；rustc 1.98.0、Criterion 0.8.2、默认 feature、
仓库 `target-cpu=native`。预编译后串行两轮；每项 20 样本、预热 0.3 秒、目标
测量 2 秒，Criterion 对较慢负载可能延长。每次迭代处理一个输入的三个输出；
密钥、输入、程序、分配及诊断均在计时外，循环使用同一组 16 个输入。

- `mvb3`：一次 BR、一次 GLWE 前向 FFT、三次整数乘法/逆 FFT/KS/提取。
- `pbs3`：三次独立 PBS，函数、输入、密钥、Scaled 输出均相同。
- `postprocess3`：对已准备的共享 Fourier BR 结果做三次乘法/逆 FFT/KS/提取，
  不含 BR 及共享前向 FFT。
- `factor_fft3`：对已准备的三个系数因子做整数 FFT，不含 LUT 编译、差分和分配。

下表为两轮均值范围，不是置信区间：

| FFT / 字宽 / t_out | 完整 MVB 三输出 | 三次独立 PBS | 三输出后处理 | 三因子 FFT 准备 |
| --- | ---: | ---: | ---: | ---: |
| rustfft / u32 / 8 | 6.209–6.220 ms | 18.210–18.611 ms | 0.045–0.046 ms | 1.441–1.445 µs |
| rustfft / u32 / 10 | 6.156–6.182 ms | 18.187–18.697 ms | 0.045–0.046 ms | 1.439–1.444 µs |
| rustfft / u64 / 8 | 9.586–9.730 ms | 28.644–29.915 ms | 0.072–0.072 ms | 1.495–1.502 µs |
| rustfft / u64 / 10 | 9.574–9.773 ms | 28.296–28.748 ms | 0.072–0.072 ms | 1.491–1.505 µs |
| tfhe_fft / u32 / 8 | 5.256–5.299 ms | 15.481–15.565 ms | 0.039–0.039 ms | 1.028–1.052 µs |
| tfhe_fft / u32 / 10 | 5.188–5.349 ms | 15.493–15.827 ms | 0.039–0.039 ms | 0.923–0.931 µs |
| tfhe_fft / u64 / 8 | 8.706–9.033 ms | 26.136–27.030 ms | 0.066–0.067 ms | 1.069–1.098 µs |
| tfhe_fft / u64 / 10 | 8.742–8.827 ms | 26.147–26.361 ms | 0.065–0.066 ms | 1.072–1.092 µs |

这是候选算法的成本记录；未比较交错 ManyLUT，不据此推荐取代它。两轮采用相同
case 顺序；没有测 SIMD 延迟，也不把默认/SIMD 误差一致解释为性能相同。

原型只使用上述公开 API，以临时独立 Cargo 包连接当前 workspace；默认与 nightly
SIMD release 各执行一次完整诊断。正式接入前可按本节参数、函数和执行顺序重建
原型；两轮计时保存均值及 95% 区间，不保留临时程序、构建分支或 Criterion 原始样本。

## B5.1 实际验证

原型默认/SIMD release 诊断全部通过；补充输入平台检查后重跑，记录数值保持一致。
已有 `primus_fft --test negacyclic` 与 `primus_tfhe --test factorized_lookup_table`
的默认及 nightly SIMD 依赖配置回归通过；`primus_fft` 自身没有 SIMD feature，
其 nightly 命令启用 `primus_integer/simd`。格式、文档链接及 CSV 完整性检查通过。
没有修改生产 Rust 代码，未重复运行全 workspace 测试。

## B5.2：正式接口与验收

共享 `FactorizedLookupTable` 对 Native 检查实际尺度奇偶，奇尺度返回
`LookupTableError::OddFactorizationScale`；显式偶模数保持拒绝，奇数 q 分支保持原语义。
原有整数几何 oracle 扩充 Native 输出和非二次幂 `t_out=10`，包含空负尾及全部旋转，
仍只有两个共享编译测试。

Fourier context 提供 `compile_factorized_lookup_table_fn` / `factorized_evaluator`，
与 NTT 的调用习惯一致；显式准备可用 `FourierFactorizedLookupTable::new`。
预处理消费系数程序，保留 V 和一段连续 `Vec<Complex64>` 因子，不保留因子系数副本。
产物借用 context，执行时核对指针身份；相同参数不足以证明 table 表示相同。
字宽目前限定 u32/u64，准备 u16 会在变换前 panic。

工作区复用普通 evaluator，额外持有 `(d+1)*N/2` 复数的共享 BR 结果和 `N/2`
复数的乘积 scratch。逐分量点乘、逆 FFT 直接写回普通 evaluator 的系数 GLWE；
BK 逐输出 KS，KB 先切换输入再做共享 BR。空间不随输出数增长，普通 PBS 工作区不变。
无需增加密钥材料或向底层暴露内部 scratch；本步未重测完整性能，不把 B5.1
原型计时解释为该缓冲区布局的性能保证。

[两个后端测试](../crates/primus_tfhe_glwe_fourier/tests/factorized_pbs.rs)分别负责：

- 完整链：`n=8,d=2,N=128,t_in=15,t_out=10`，两种 FFT、u32/u64、两种 order；
  binary/ternary 按字宽和 FFT 配对覆盖，避免全笛卡尔积。固定 seed，消息 0/3/7，
  下降函数、交替 0/9、阈值三输出；与同 Scaled 编码的独立 PBS 对照，检查相位余量
  和首次/重复调用零分配。small-LWE 外部维数 8，KB 外部维数 256。
- 独立边界：单输出、跨 context、输入/输出长度、每项编译元数据、不同输出模数、
  奇尺度及 sparse key 拒绝。最后一项输出维数错误也须在任何输出写入前失败，随后仍可复用工作区。

默认两测试合计约 0.65 秒。没有新增统计测试或持久 benchmark。原有
[基本示例](../crates/primus_tfhe_glwe_fourier/examples/fourier_basic.rs)补充偶尺度 MVB，
复用两种 order 的 ternary 密钥、公钥输入及输出缓冲；不复制参数构造。

验证：`just tfhe` / `just tfhe-simd`，共享编译与后端聚焦测试，严格 rustdoc，
默认/SIMD release 基本示例。参数只用于功能验证，仍须自行预算因子放大与
`delta_b-sum(delta_a*s)` 的 FFT 相位误差。

**后续边界**：NTRU 初始化/KS 已由下文 B5.3 核对；Fourier sparse×MVB 当前明确拒绝，
其组合验收及与重复/交错 PBS 的应用成本比较归 B5.4。新接口不提供尾概率或安全认证。

## B5.3：NTRU 接入与独立误差验收

### 接口与工作区

以 `7707c22` 加本步实现为基线。NTRU Fourier 提供与其他 MVB 后端一致的
`compile_factorized_lookup_table_fn` / `factorized_evaluator`；共享 Native 编译器不再修改。
`FourierFactorizedLookupTable` 消费系数程序，保留 V 与连续整数 Fourier 因子，绑定同一
context；支持 u32/u64、两种 FFT 和现有 binary NGSW 控制，不增加密钥类型或底层 trait。

NTRU 在线链保持独立：

```text
NLev_f_acc[1] 初始化旋转后的 V → 一次 binary BR → 共享 Fourier NTRU
  → 每个整数因子 W_i：公开乘法 → 系数 NTRU → f_acc 到 f_client 的 KS → compact LWE
```

MVB evaluator 在普通工作区之外持有共享 Fourier NTRU 和一个 Fourier 乘积：共 N 个复数，
与输出数无关；乘积逆变换写回现有 `current`，KS 写入现有 `scratch`。
初始化、BR 及 KS 都使用原 server key，输出秘密和维数不变。公开程序占
`N*sizeof(T) + k*N/2*sizeof(Complex64)` 的元素存储，不保留因子系数副本。
不对带噪声的结果除二，也不将 KS 提前到因子乘法之前。

[两个聚焦测试](../crates/primus_tfhe_ntru_fourier/tests/factorized_pbs.rs)共用小功能参数
`n=8,h=3,N=128,t_in=15,t_out=10`，初始化/BR 与 KS 分解均为 `logB=8,L=3`，
三处加密噪声标准差为 0.7。两种 FFT、u32/u64 均检查消息 0/3/7/0、三种函数、
同 Scaled 单 PBS 对照、完整相位余量和首调用/复用零分配；另保留单输出、跨 context、
编译元数据、输入/全部输出维数及失败后复用。默认合计约 0.24 秒。
原基本示例复用 public-key 输入、同一 server key 和输出缓冲，演示 ManyLUT 与 MVB。

### NTRU 独立诊断

大参数诊断使用临时内部观测，不进入普通测试或增加公开访问器。以下参数和执行顺序
用于复现；正式调用的输出逐字与分阶段路径对照。每组先以 seed=`0x42353310` 生成一对
client/server key，再依次加密 16 个输入，消息 `m=j%8`；两种 FFT、u32/u64 分别重置 seed。

| 参数 | 取值 |
| --- | --- |
| Native 字宽、环与外部维数 | u32/u64；N=1024，n=728 |
| 客户端秘密 | 固定重量 binary h=33，剩余 N−n 系数补零 |
| Accumulator 秘密 | SparseTernary |
| 输入与输出 | Rounded t_in=15，D=8；unsigned Scaled t_out=10；k=3 |
| 输入噪声标准差 | `3.2*2^w/16384` |
| 初始化/BR 与 KS 噪声标准差 | 均为 0.7 个整数单位 |
| 初始化/BR、KS 分解 | 均为 logB=8、L=3 |
| 函数 | `9-m`、`9*(m%2)`、`[m>=3]` |
| 因子 `(nnz,L1)` | `(8,18)`、`(8,72)`、`(2,2)` |

h=33 满足 Native NTRU 所需的奇数重量，密钥生成仍检查可逆性与 Fourier 逆元稳定性。
低重量使用逐坐标经典 BR，不是桶聚合；本组不是 GLWE 的等安全/等噪声参数。
尤其两种字宽使用相同整数噪声与分解层数，不将数值大小直接解释为精度优劣。

记 `b̄=R(b)`、`A=sum(R(a_j)*s_j) mod 2N`，使用实际逐系数量化结果：

1. 单独执行正式 NLev 初始化外积，精确求相位 `f_acc*c_init`，减去 `X^-b̄ V` 得到
   `e_init`。随后执行正式 BR，减去 `X^(A-b̄)V` 得到 `e_shared`；
   `e_BR=e_shared-X^A e_init` 包含 BR 新增的控制加密、分解和数值误差。
2. 各因子分别计算 `u_i=coeff_0(W_i*X^A e_init)` 和 `v_i=coeff_0(W_i*e_BR)`。
   独立 i128 负循环卷积计算精确 `c_shared*W_i` 及其相位，核对乘法与取相位交换，
   并检查 `|u_i+v_i| <= ||W_i||_1*||e_shared||_infinity`。
3. 实际 FFT 乘法得到 `c_product`，令 `delta_c=c_product-exact(c_shared*W_i)`，
   核对新增相位误差 `eta_i=coeff_0(f_acc*delta_c)`。这使用系数秘密和精确整数卷积，
   不用 FFT 解密充当 oracle；本组长度与小整数因子在 i128 范围内。
4. 执行实际 KS/提取，外部 LWE 相位减去乘后相位，定义 `k_i`；核对最终误差
   `e_i=u_i+v_i+eta_i+k_i mod 2^w`，并确认实际旋转位置的理想 LUT 系数等于目标 Scaled 中心。
5. 每项输出用 Scaled 解码，与相同编码的独立 PBS 比较。分阶段密文与公开 MVB 完整调用
   逐字一致；所有完整输出相位误差小于 0.01q。

环境为 x86_64 Linux、仓库 `target-cpu=native`；默认 rustc 1.98.0（88d9e12ae），
SIMD nightly 1.100.0（bff8e12ff），后端 feature 为 `simd`。两次均使用 release 编译。
默认与 SIMD 诊断均通过，科学记数法保留小数点后九位的[误差摘要](benchmarks/tfhe-b5.3-noise.csv)
一致，只保存一份。初始化/BR/shared 各统计 16×N 个系数，后续各统计 16×3 个提取系数；
下表单位均为 q，RMS 未去均值。除 FFT 误差单列范围外，两种 FFT 在表中精度下一致。

| 误差阶段 | u32 RMS / 最大绝对值 | u64 RMS / 最大绝对值 |
| --- | ---: | ---: |
| 初始化 | 3.579e−7 / 7.632e−7 | 1.192e−8 / 1.192e−8 |
| BR 新增 | 1.482e−5 / 5.966e−5 | 2.191e−6 / 9.358e−6 |
| 共享初始化与 BR | 1.482e−5 / 6.010e−5 | 2.191e−6 / 9.346e−6 |
| 乘后初始化贡献 | 3.632e−6 / 8.116e−6 | 1.205e−7 / 2.146e−7 |
| 乘后 BR 贡献 | 2.766e−4 / 8.592e−4 | 2.858e−5 / 7.671e−5 |
| 公开 FFT 乘法相位误差 | 0 / 0 | (2.705–2.882)e−16 / (7.576e−16–1.057e−15) |
| KS 前 | 2.756e−4 / 8.577e−4 | 2.860e−5 / 7.671e−5 |
| KS 新增 | 8.060e−7 / 1.945e−6 | 4.297e−7 / 1.192e−6 |
| 完整 MVB | 2.757e−4 / 8.565e−4 | 2.859e−5 / 7.671e−5 |
| 同编码独立 PBS | 1.242e−5 / 3.654e−5 | 2.041e−6 / 5.364e−6 |

初始化贡献非零，已被因子放大，不能套用 GLWE 平凡初始化。u32 的零只表示本组
乘法在提取相位上未观察到差异；u64 的额外 FFT 误差非零。各项相关且统计对象不同，
不能将 RMS 直接相加；成功解码也不认证任意因子范数、参数或失败概率。

验证包括 `just tfhe` / `just tfhe-simd`、严格 rustdoc、默认/SIMD release 基本示例。
临时诊断已清理，无新增持久 benchmark；本步不测耗时，算法成本与 Fourier sparse×MVB
组合仍留给 B5.4，不以 GLWE 原型计时替代 NTRU 性能结论。
