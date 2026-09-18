# GLWE Fourier CBS：误差、成本与使用

B1.1–B1.3 已完成。公开工作流见 [English README](../crates/primus_tfhe_glwe_fourier/README.md#circuit-bootstrapping) / [中文 README](../crates/primus_tfhe_glwe_fourier/README.zh_CN.md#circuit-bootstrapping)。本文记录当前 Native 实现与 B1.3 的固定参数测量，不提供生产安全或失败概率参数。

## 1. 执行链与示例

```text
外部 LWE → [KB 的前置环 KS + 提取] → gadget-scale ManyLUT BR
→ 每层完整 RevHomTrace 投影 → GLev → scheme switch → Fourier GGSW
```

BK（`BootstrapKeyswitch`）的 CBS 输入维数为 n，KB（`KeyswitchBootstrap`）为 kN。
两者输出均留在 accumulator 私钥下；CBS 不执行普通 BK PBS 的后置 KS。
普通 server key 与附加 CBS key 必须来自同一 client，并使用同一个 FFT table 实例。

[可运行示例](../crates/primus_tfhe_glwe_fourier/examples/circuit_bootstrap.rs) 将 LWE bit 转为 GGSW 控制，
选择两条非恒定 GLWE 消息之一；覆盖两种 order、复用工作区与 `1→0` 控制。
CMUX 之后的 GLWE 仍属于 accumulator 私钥，不能直接交给外部 small-LWE decryptor。

```sh
cargo run --release -p primus_tfhe_glwe_fourier --example circuit_bootstrap
```

三层 GGSW 使用四列交错 LUT。ManyLUT 的消息尾部通常非零，不能直接替换为要求零尾的 partial expansion。
按当前决定保留逐系数 RevHomTrace，暂不实施共享正向展开树或 automorphism 优化。

## 2. 误差应按哪些边界计算

设 `q=2^64`，GLWE 相位 `φ(C)=b−Σ a_i*s_i`，第 j 层输出尺度为 `Δ_j`。
所有误差以相对于预期相位的模 q 居中距离计；旋转偏差另以物理 `2N` 指数单位计，两者不能相加。

| 阶段 | 需要计入的误差与条件 |
| --- | --- |
| 输入与旋转量化 | 原始 LWE 噪声；KB 前置 KS 的分解、密钥和 FFT 误差；逐系数量化后秘密加权的旋转偏差。必须留在正确消息的平台内，平台错位不是小的输出加性噪声 |
| BR | 每次外积的近似分解、GGSW 密钥噪声和 FFT 数值误差，沿盲旋转累积。交错 LUT 的 rotation step 是补齐后的层数 |
| RevHomTrace | 每层投影先乘 `X^-j`，再按 `3,5,…,N+1` 做 `H=floor(C/2); C=H+Auto(H)`。除二逐密文系数取无符号代表元，包含 wrap 后的负值；必须计入取整、trace KS 与 FFT 误差 |
| Scheme switch | body row 继承投影 GLev 并变换到 Fourier；mask row 与加密的 `-s_i` 做外积，包含输入误差与秘密多项式的卷积、scheme-switch 分解残差、密钥噪声与 FFT 误差 |
| CMUX 消费 | 两条候选密文的噪声、按输出 basis 分解候选差值的残差，以及分解 digits 与所有 GGSW 行/层误差的卷积。只检查 GGSW 的最小尺度不足以证明任意后续 CMUX 正确 |

Native 的 `floor(x/2)` 不是模逆元，也不是对 Fourier 复数除二。不能将整个过程写成
“最后的相位误差除以 N”；unsigned wrap、逐级取整和随后引入的 KS 误差都必须保留。
NTT 的模逆元路径有另一套误差行为，不继承本文测量。

令投影相位为 `mΔ_j+e_j(X)`，则 scheme-switch mask row 的目标为 `−s_i*mΔ_j`，
其输入误差项为 `−s_i*e_j`，另外还有外积误差。可用
`||s_i*e_j||∞ ≤ ||s_i||₁ ||e_j||∞` 作保守估计，但不能把不同输出/行/层当作独立样本。
共享 BR 与 evaluation key 会使误差相关。

### 测量方法

基线实现为 `a8efb77`，参数与 RNG seed 固定在[共享 profile](../crates/primus_tfhe_glwe_fourier/examples/support/circuit_bootstrap.rs)。
每种 FFT/order 生成一组配套密钥，再加密八个输入 `0,1,0,1,…`。独立诊断逐系数执行
wrapping 整数负循环卷积计算 `b−a*s`，不调用 FFT 解密作为相位 oracle：

1. 用实际小 LWE 与真实 binary 秘密计算量化旋转指数；KB 先执行实际输入 KS。
2. BR 相位与按该指数旋转的精确 LUT 多项式比较，遍历 N 个系数；另检查指数相对输入消息中心的偏差。
3. 各投影 GLWE 与常数目标 `mΔ_j` 比较，包含全部非目标系数。
4. Fourier GGSW 转回系数域，检查每行、每层、每个系数：body 目标为 `mΔ_j`，mask 目标为 `−s_i*mΔ_j`。这项测量包含观察输出所需逆 FFT 的舍入。
5. 用所得 GGSW 对两条真实加密的非恒定消息执行 CMUX，检查全部系数解码及相位误差。候选消息为 `(i+offset) mod 4`，offset 为 0/1；在八个输入之后采样候选密文。

手工串联的 BR→projection→scheme switch 与完整 evaluator 的 Fourier 输出逐元素一致。
统计为各阶段的累计误差，不将两组 RMS 相减来冒充某个内核的独立误差贡献。
临时分项诊断已删除；持久保留 profile、[逐层统计 CSV](benchmarks/tfhe-b1.3-noise.csv)、
现有[独立相位/CMUX 测试](../crates/primus_tfhe_glwe_fourier/tests/circuit_bootstrap.rs)和基准的计时前检查。

## 3. 固定参数与观测余量

| 项目 | 配置 |
| --- | --- |
| 字宽、模数、消息 | u64、Native `q=2^64`、unsigned Rounded `t=4`，输入 bit 0/1 |
| Small LWE | n=728、UniformBinary、σ=`3.2*q/16384` |
| Accumulator | k=1、N=1024、UniformTernary、σ=6.4 |
| BR / 环 KS basis | `(logB=8, levels=6)` / `(8,6)` |
| 输出 / trace / scheme-switch basis | `(8,3)` / `(8,7)` / `(10,5)`；附加密钥 σ=6.4 |
| 输出尺度顺序 | `2^40, 2^48, 2^56`，与 `scalar_iter()` 从低层到高层的顺序一致 |
| Seed | `StdRng::seed_from_u64(0x4231_3300)` |

这些 basis 的逐系数近似分解残差界分别是：BR/KS `2^15`、trace `2^7`、scheme switch `2^13`；
它们不是完整运算误差界。下游 CMUX 使用输出 basis 时残差界为 `2^39`，还须计入秘密和 digit 卷积。

最小尺度 `Δ_min=2^40=1,099,511,627,776`。下表 GGSW 数值只统计最小尺度那一层，
包含两行和所有系数；其余尺度与 RMS 见 CSV。

| FFT / order | 最大旋转偏差 | 投影最小层最大误差 | GGSW 最小层最大误差 | GGSW 误差 / Δ_min | CMUX 最大相位误差 |
| --- | ---: | ---: | ---: | ---: | ---: |
| RustFFT / BK | 32 | 44,586,216,279 | 103,134,265,344 | 9.38% | 450,069,622,926,632 |
| RustFFT / KB | 44 | 11,092,955,829 | 70,086,033,408 | 6.37% | 497,146,759,486,280 |
| TfheFFT / BK | 32 | 24,118,096,738 | 70,683,197,440 | 6.43% | 318,891,658,035,632 |
| TfheFFT / KB | 44 | 20,610,411,471 | 66,036,695,040 | 6.01% | 290,507,292,871,728 |

相邻输入中心相距 512 个物理指数单位，step=4；所测偏差严格小于半间距 256，均处于正确平台。
全体 GGSW 观测误差均小于诊断阈值 `Δ_min/4`，最差值距该阈值约 2.66 倍。
CMUX 的模 4 Rounded 解码半径为 `2^61`，最差观测误差小于其 0.022%，全部消息正确。
这些比值是固定样本的余量，不是尾概率、所有密钥上的保证或通用 CMUX 参数选择规则。

默认/SIMD 下上述逐阶段最大值、RMS、旋转偏差及分配统计相同，因此 CSV 不重复两份相同统计。
本轮成本/噪声 profile 仅为 binary；ternary 的功能覆盖来自 B1.2 测试，不据此推断相同噪声或成本。

## 4. 在线时间与操作数

2026-09-18，AMD Ryzen 9 9955HX3D，固定逻辑 CPU 2；默认和 SIMD 均使用
`rustc 1.100.0-nightly (bff8e12ff 2026-08-26)`、仓库 `target-cpu=native`，Criterion 0.8.2。
每项 20 samples、1 s warm-up、3 s measurement、10,000 resamples。
部分完整 CBS 的线性采样自动将测量延长至约 3.2–3.5 s。

[基准](../crates/primus_tfhe_glwe_fourier/benches/circuit_bootstrap.rs) 每轮只计算一次 CBS 或一个阶段，
复用密钥、LUT、输出和工作区。完整 CBS 交替使用两个输入；分项使用 bit=1 的真实中间结果。
Setup、解密预检及分配均不计时。只有 BK 测阶段，避免复制两种 order 共同的后处理负载。

均值如下；[计时 CSV](benchmarks/tfhe-b1.3.csv) 保留 95% CI。单位为 ms，每格为默认 / SIMD：

| FFT | 完整 CBS BK | 完整 CBS KB | BR | 三层投影 | Scheme switch |
| --- | ---: | ---: | ---: | ---: | ---: |
| RustFFT | 16.514 / 16.480 | 16.258 / 16.607 | 15.787 / 15.393 | 0.416 / 0.411 | 0.0273 / 0.0271 |
| TfheFFT | 14.909 / 15.053 | 14.692 / 15.994 | 14.113 / 14.513 | 0.379 / 0.375 | 0.0227 / 0.0223 |

BR 占主要成本，投影约 0.4 ms，scheme switch 约 0.02–0.03 ms。分项独立计时、输入池与缓存状态不同，
不能相加后当作完整 CBS 的精确拆账。SIMD 的完整 KB 组波动更大，例如 TfheFFT 的均值 95% CI 为
15.690–16.362 ms；本轮不声称 SIMD 提升或某种 order 更快，也没有“旧 Fourier CBS”对照实现。

每次最多 n=728 次 binary BR 外积（跳过公开零指数）；三层投影使用 `3*log2(1024)=30` 次
automorphism+KS；scheme switch 使用 `k*levels=3` 次外积，以及 body row 的 `(k+1)*levels=6` 次前向 FFT。
KB 额外包含一次环 KS 和提取。不同基的外积成本不同，不能仅用次数比较阶段耗时。

```sh
taskset -c 2 cargo +nightly bench -p primus_tfhe_glwe_fourier --bench circuit_bootstrap -- --sample-size 20 --warm-up-time 1 --measurement-time 3 --nresamples 10000 --save-baseline b1_3_default --noplot
taskset -c 2 cargo +nightly bench -p primus_tfhe_glwe_fourier --bench circuit_bootstrap --features simd -- --sample-size 20 --warm-up-time 1 --measurement-time 3 --nresamples 10000 --save-baseline b1_3_simd --noplot
```

原始样本在 `target/criterion/fourier_cbs*/{complete,blind_rotation,project_3,scheme_switch}/b1_3_{default,simd}/`；
清理 target 后可用相同 profile/命令重建，CSV 保存本轮摘要。

## 5. 密钥、scratch 与输出

令 `F=N/2`、复数占 16 B，排除结构体与索引表时 Fourier 密钥 payload 为：

| 对象 | 复数元素数 | 本 profile payload |
| --- | --- | ---: |
| Binary BSK | `n*(k+1)^2*l_br*F` | 136.5 MiB |
| 环 KSK（输入/输出维数均为 k） | `k*(k+1)*l_ks*F` | 96 KiB |
| Trace keys | `log2(N)*k*(k+1)*l_trace*F` | 1,120 KiB |
| Scheme-switch key | `k*(k+1)^2*l_ss*F` | 160 KiB |
| 调用方 Fourier GGSW 输出 | `(k+1)^2*l_out*F` | 96 KiB |

线程局部分配计数得到以下构造后净请求字节数，四种 FFT/order、默认/SIMD 均相同。
包含 Vec capacity、basis 和 trace 置换表，排除 allocator 元数据、栈上对象、共享 context/client、输入和生成时临时工作区；不是 RSS 或峰值。

| 持有对象 | 字节 |
| --- | ---: |
| 普通 server key | 143,229,216 |
| 附加 CBS key | 1,479,560 |
| 普通 evaluator | 138,952 |
| CBS evaluator（含其内部 LUT） | 304,840 |
| 调用方 GGSW 输出 | 98,304 |

CBS 比普通 evaluator 增加 **162 KiB**：trace scratch 73 KiB、scheme-switch scratch 33 KiB、
三层系数 GLev 48 KiB、内部 LUT 8 KiB。输出另由调用方持有；示例中的 CMUX 和解密工作区不属于 CBS。
当前 CBS 复用整个普通 evaluator，因此 BK 也持有其中未用于 CBS 后置 KS 的缓冲；本步不重构该布局。
首次及后续 `circuit_bootstrap_to` 均测得零次堆分配。

## 6. 验证与边界

保留现有小 fixture 的两种 order × 两种 FFT × binary/ternary 功能测试、独立相位 oracle、CMUX 和零分配检查。
本步不增加普通测试数量；新增一个应用示例和十项 Criterion 工作负载，重型诊断不进入 CI。
默认/SIMD 阶段验证使用 `just tfhe` / `just tfhe-simd`，另运行底层 GLWE/NTRU 测试；严格 rustdoc 与示例单独验证。

尚无生产安全或尾概率认证；稀疏 CBS、其他字宽/参数的噪声余量、非 x86 性能不由本轮结果覆盖。
下一步骤按[后端补齐计划](tfhe-backend-plan.md)由用户指定。
