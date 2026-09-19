# Native 偶尺度 MVB 原型

**B5.1 原型通过；公共 Fourier MVB 尚未接入。** 在 `1f6bab2` 上复用现有
GLWE Fourier 原语，验证了 RustFFT/TfheFFT、Native u32/u64、小整数差分因子与
经典 binary、BootstrapKeyswitch 完整链。下一步为 [B5.2](tfhe-backend-plan.md#b52glwe-fourier-mvb-正式接入)。
本结论不代表任意字宽、因子范数或噪声参数均可用，也不覆盖 NTRU 初始化。

## 表示与执行

沿用[整数恒等式](tfhe-mvb.md#精确恒等式)：`W_i=(1-X)p_i`、`V=A*S`，
`S=1+...+X^(N-1)`，并在构造期要求实际 `Delta=round(2^w/t_out)` 为偶数，
取整数 `A=Delta/2`。于是 `V*W_i=Delta*p_i mod (2^w,X^N+1)`。
只对无噪声的公开尺度除二，不对 BR 结果右移，不使用不存在的模逆元。

原型使用已有 raw `LookupTable::try_new` 编译未缩放的 `p_i`，保留负尾，
再按有符号整数差分构造 `W_i`；另编译相同 Scaled 输出的独立 PBS 参照。
`FactorizedLookupTable::try_new` 未修改，原型也验证它仍拒绝 Native。

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

本轮无需新增底层 trait、密钥类型或乘法内核。B5.2 应复用这些原语及普通 evaluator
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

## 实际验证

原型默认/SIMD release 诊断全部通过；补充输入平台检查后重跑，记录数值保持一致。
已有 `primus_fft --test negacyclic` 与 `primus_tfhe --test factorized_lookup_table`
的默认及 nightly SIMD 依赖配置回归通过；`primus_fft` 自身没有 SIMD feature，
其 nightly 命令启用 `primus_integer/simd`。格式、文档链接及 CSV 完整性检查通过。
没有修改生产 Rust 代码，未重复运行全 workspace 测试。

## B5.2 的边界

- 可以接入 Native 偶尺度构造、两种 FFT 的整数因子准备与 GLWE 完整 evaluator；
  奇数尺度明确报错，奇数 q 的既有分支保持原契约。
- 本轮验证的是 u32/u64、N=1024 的经典 binary BK 三输出，以及 N≤4096 的
  独立小整数乘法；不能由此开放任意精度保证。KB/ternary 在 B5.2 独立验收。
- NTRU 初始化/KS 在 B5.3 核对；sparse×MVB、更多输出及与交错算法的成本选择
  留给 B5.4。没有新增安全认证或噪声尾界结论。
- 公共构造器、README 支持矩阵和生产代码本步不变；正式公开支持由后续工程步骤交付。
