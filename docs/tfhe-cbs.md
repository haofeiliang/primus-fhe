# GLWE Fourier CBS：误差、成本与使用

B1.1–B1.3 经典 CBS 和 [B6.3 稀疏 CBS](#7-b63-fourier-sparse-cbs)已完成。公开工作流见 [English README](../crates/primus_tfhe_glwe_fourier/README.md#circuit-bootstrapping) / [中文 README](../crates/primus_tfhe_glwe_fourier/README.zh_CN.md#circuit-bootstrapping)。第 1–2 节说明 Native 契约，第 3–6 节保留 B1.3 的历史测量，第 7 节记录当前稀疏接入与 profile。不提供生产安全或失败概率参数。

## 1. 执行链与示例

```text
外部 LWE → [KB 的前置环 KS + 提取] → gadget-scale ManyLUT BR
→ 每层完整 RevHomTrace 投影 → GLev → scheme switch → Fourier GGSW
```

BK（`BootstrapKeyswitch`）的 CBS 输入维数为 n，KB（`KeyswitchBootstrap`）为 kN。
两者输出均留在 accumulator 私钥下；CBS 不执行普通 BK PBS 的后置 KS。
通过 `Some(config)` 配套生成普通与 CBS 材料，
`context.circuit_bootstrap_evaluator(&server)` 绑定参数和附加密钥。高级 `try_from_parts`
组合仍须由调用方保证同一 client 和同一 FFT table 实例。

[可运行示例](../crates/primus_tfhe_glwe_fourier/examples/circuit_bootstrap.rs) 将 LWE bit 转为 GGSW 控制，
选择两条非恒定 GLWE 消息之一；覆盖两种 order、复用工作区与 `1→0` 控制。
`evaluator.allocate_output()` 分配控制，`evaluator.cmux_to(...)` 复用绑定的 basis/FFT/scratch；
`context.accumulator_client(&client)` 准备环私钥表示并加解密系数域候选，示例无需手工变换秘密。
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

B1.3 基线实现为 `a8efb77`，当时的参数与 RNG seed 见第 3 节；[共享 profile](../crates/primus_tfhe_glwe_fourier/examples/support/circuit_bootstrap.rs)现已切换到第 7 节的 fixed-weight 配置。
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
三层系数 GLev 48 KiB、内部 LUT 8 KiB。输出另由调用方持有。以上为 B1.3 构造测量；
B1.6 的 CMUX/外积复用 scheme-switch 缓冲，不再单独准备消费 scratch。
`AccumulatorClient` 的私钥变换、密文变换缓冲、FFT engine 及加解密 scratch 单独归客户端；
最新高层构造与完整消费成本见 [B1.7 对照](tfhe-api-costs.md)，不用历史数值替代当前测量。
当前 CBS 复用整个普通 evaluator，因此 BK 也持有其中未用于 CBS 后置 KS 的缓冲；本步不重构该布局。
首次及后续 `circuit_bootstrap_to` 均测得零次堆分配。

## 6. 验证与边界

保留现有小 fixture 的两种 order × 两种 FFT × binary/ternary 功能测试、独立相位 oracle、CMUX 和零分配检查。
本步不增加普通测试数量；新增一个应用示例和十项 Criterion 工作负载，重型诊断不进入 CI。
默认/SIMD 阶段验证使用 `just tfhe` / `just tfhe-simd`，另运行底层 GLWE/NTRU 测试；严格 rustdoc 与示例单独验证。

B1.3 未覆盖稀疏 CBS，后续独立验收见第 7 节。尚无生产安全或尾概率认证，其他字宽/参数的余量和非 x86 性能不由这些结果覆盖。
NTT sparse CBS 的独立原型与接入边界见 [B6.1](tfhe-sparse-cbs.md)，不替代 Fourier 的组合验证。
下一步骤按[后端补齐计划](tfhe-backend-plan.md)由用户指定。

## 7. B6.3 Fourier sparse CBS

**独立原型通过后正式接入。** u64 Native，RustFFT/TfheFFT、BK/KB 均支持固定重量 binary
稀疏 server key。CBS 使用普通 evaluator 已有的 sparse BR 绑定，共用原 trace、scheme-switch
和消费 scratch；没有新建公共类型或改变数值 kernel。`try_generate_sparse_server_key`
增加 `Option<CircuitBootstrapConfig>`，返回 `KeyGenerationError`，通过 `SparseBootstrapping`
保留底层错误；`None` 保持普通 PBS 用法，未携带 CBS 材料时返回 `MissingCircuitBootstrapKey`。
无消费者的 `UnsupportedSparseBootstrapping` 已删除。

### 参数与独立诊断

原型基线 `7c72e16`。沿用第 3 节的 u64/Native、N=1024、t=4、accumulator UniformTernary、
BR/KS `(8,6)`、trace `(8,7)`、scheme switch `(10,5)` 及所有噪声参数，唯一秘密分布变化是
small-LWE `n=728,h=32` 固定重量 binary，稀疏映射 `c=3,b=64`。输出对照 `(8,3)` / `(9,3)`。
这不是与 UniformBinary 等安全性的声明，也不覆盖 u32、其他 h/basis 或更多输出层。

每个 `(FFT,order,seed)` 重置 RNG，seeds 为 `0x42363301/0x42363302`，依次生成 client、
经典普通 server、稀疏普通 server、共用独立 CBS key、四个输入 `1,0,1,0`、两个加密候选
`i mod 4` / `(i+1) mod 4`。两种输出 basis 复用相同密钥；输出先 `(8,3)` 后 `(9,3)`。
普通 KS 密钥各自采样；共享的 trace/scheme-switch 材料使用同一 accumulator 秘密与 FFT 表。

公开 sparse CBS 检查在原型阶段保持拒绝；完整链由已有 raw BR、投影及 scheme-switch 原语
串联。经典原型与公开 evaluator 的 Fourier 输出逐元素相同。全部相位以独立 wrapping 整数
负循环卷积 `b−a*s` 计算；观察 Fourier GGSW 时先逆 FFT，统计包含该观察过程的舍入。

- **BR 与旋转**：按实际量化指数和真实 small 秘密旋转 LUT，核对三个输出槽的 `bit*g_l`；
  对比完整 N 系数的相位误差。KB 使用实际前置 KS 的输出。
- **聚合 FFT**：首个输入上重建全部 64 桶的系数聚合，包括所有加密零与 dummy；逐多项式
  做 Fourier 往返，统计全 GGSW 系数差，以及最高 body 层的独立相位差。
  这是聚合转换误差，未将原有 selector 加密/转换误差从完整 BR 误差中扣除。
- **逐级 Native halving**：首个输入的三个投影分别重放 `3,5,…,N+1` 的十级 trace，
  使用真实 trace automorphism keys；最终每层密文与公开投影逐元素相同。
  每级验证下式的精确相等，并独立比较 automorphism/KS 输出与 `Auto(phase(H))`。
- **输出与消费**：检查每个 GGSW 行/层的全部系数、非恒定 CMUX 解码及相位；完整
  CBS→CMUX 首次和复用调用均零分配。输入 1→0 必须覆盖旧控制。

对 `H=floor(C/2)`、逐系数余数 `R=C mod 2`，Native 环内有

```text
2*phase(H) - phase(C) = -phase(R) = -R_b + Σ R_ai*s_i  (mod 2^64)
```

观测该奇偶修正项最大绝对值为 3；这不是一般上界，也不说明相位可以直接除二。
模 `2^64` 上从 `2*phase(H)` 不能唯一恢复 `phase(H)`。将理想 LUT 相位逐级无符号除二并做
相同 automorphism 时，中间相位差可出现约 `q/2` 的代表元分支；它不能当成独立的小噪声项。
完整逐密文系数重放和最终常数投影检查保留了这些分支。独立 trace KS/FFT 的每级最大误差
为 1,820,276,224；聚合 FFT 全系数最大差为 10,752，代表 body 层相位最大差为 228,564。
这些量不能与累计阶段 RMS 相减或简单相加作为完整误差界。

[统计 CSV](benchmarks/tfhe-b6.3-noise.csv)保留默认/SIMD 两组。`br`、`projected`、`ggsw`、
`cmux` 按两 seed × 四输入合并；后者同密钥相关，count 不是独立失败概率样本数。
`halve_defect`、`trace_ks_fft`、`trace_phase_vs_ideal_halving` 只取首输入、输出 `(8,3)`，
合并两 seed × 三个输出层，`level=0..9` 表示 trace 步数，`row=all`；最后一种是上述相位模型
偏差，不能解释为纯数值噪声。聚合 FFT 项合并两 seed 的全部桶，phase 项只取最高 body 层。
其余 `row/level` 是 GGSW 行/gadget 层；所有均值/RMS 使用居中整数距离，最大值未去均值。

默认使用 rustc 1.98.0，SIMD 使用 nightly 1.100.0，版本同 B6.2。RustFFT 的统计相同，
TfheFFT/KB 存在数值差异，两组均满足下面的验收阈值；不将差异单独归因于某个 SIMD 内核。
临时程序与 trace 访问器已删除；复现应按上述生成次序和逐级公式恢复诊断，常驻 profile
与基准只保留正式入口、首 seed 和输出 `(8,3)`。

### 最小 gadget 尺度

沿用经典 Fourier 诊断阈值：每行/层 `<g_l/4`，CMUX `<q/64` 并全部正确解码。
跨 FFT/order/seed/default/SIMD 的最低 gadget 层最大误差如下，阈值仅针对这些固定样本：

| 输出 logB / L | 最小尺度 | 经典最大误差 | 稀疏最大误差 | 结果 |
| --- | ---: | ---: | ---: | --- |
| 8 / 3 | 1,099,511,627,776 | 86,657,728,512 | 109,628,620,800 | 通过 |
| 9 / 3 | 137,438,953,472 | 86,753,148,928 | 93,910,466,560 | 最小层未通过 |

保留 `(8,3)`，尺度为 `2^40,2^48,2^56`。稀疏最低层最差约为尺度的 9.97%，
该配置稀疏 CMUX 最大相位误差为 647,338,813,009,184，约占模 4 解码半径的 0.0281%。
`(9,3)` 的 CMUX 也全部解码正确，但最小层没有所需余量，因此未纳入通过配置。
公开参数构造不硬编码样本阈值，完整噪声尾界和稀疏映射条件分布的安全性仍需独立评估。

### 正式回归与成本

现有 CBS 测试入口数量保持不变，补充两种 FFT/order 的稀疏链、bundled/独立绑定、独立整数
相位、非恒定 CMUX/外积、首调用零分配及参数/形状/采样前错误检查。
原 sparse PBS 中的 CBS 拒绝测试改为缺少材料检查，完整绑定边界由 CBS 测试承担。
现有 CBS 示例通过 `--sparse` 选择算法，两种模式均保持同一求值工作流。

现有 CBS benchmark 从十项调整为八项完整调用：两种 FFT × 两种 order × 经典/稀疏；
历史阶段数据保留在第 4 节，不再重复计时共同后处理。当前 profile 取本节首 seed、
`n/h/N=728/32/1024` 和输出 `(8,3)`，复用同 client 与 CBS key。计时前检查每行/层、CMUX、
首调用/复用零分配并报告构造资源；这些大参数检查不加入普通 CI 测试。

2026-09-19，AMD Ryzen 9 9955HX3D、CPU 2、仓库 `target-cpu=native`；默认 rustc 1.98.0、
SIMD nightly 1.100.0，版本同原型；Criterion 0.8.2、20 samples、1 s warm-up、2 s measurement、
10,000 resamples、Flat sampling。串行测量，计时期间不编译；CPU 未隔离/锁频，powersave、
boost/SMT 开启。均值及 95% CI（ms）：

| FFT / order / key | 默认 | SIMD |
| --- | ---: | ---: |
| RustFFT / BK / classic | 16.843 [16.761, 16.933] | 17.129 [17.022, 17.245] |
| RustFFT / BK / sparse | 16.449 [16.402, 16.495] | 18.617 [18.431, 18.812] |
| RustFFT / KB / classic | 16.073 [16.049, 16.101] | 16.807 [16.722, 16.885] |
| RustFFT / KB / sparse | 18.204 [18.161, 18.249] | 18.039 [17.748, 18.452] |
| TfheFFT / BK / classic | 14.710 [14.659, 14.765] | 15.233 [15.162, 15.323] |
| TfheFFT / BK / sparse | 18.188 [18.145, 18.234] | 18.389 [18.195, 18.653] |
| TfheFFT / KB / classic | 15.441 [15.076, 15.833] | 15.243 [15.223, 15.265] |
| TfheFFT / KB / sparse | 18.673 [18.536, 18.814] | 18.173 [18.153, 18.192] |

**本参数组没有稳定的稀疏加速。** 默认 RustFFT/BK 约快 2%，其余七组稀疏调用慢约 7%–24%。
稀疏 BR 虽只做 64 次桶外积，但每次读取/聚合 2,248 份系数 GGSW 并执行 64 次聚合 FFT；
经典 BR 为最多 728 次已有 Fourier 控制外积。接入保留显式算法选择，未做自动替换或新的内核
优化，也没有用这轮非交替计时定位具体性能瓶颈。样本位于
`target/criterion/fourier_cbs*/{classic,sparse}/b6_3_{default,simd}/`；常用命令在基准头部，
复现本表使用上述 Criterion 参数与同名 baseline。

两 FFT/order/default/SIMD 的构造后净请求字节一致：

| 对象 | 经典 | 稀疏 |
| --- | ---: | ---: |
| 普通 server key | 143,229,216 B | 442,091,368 B |
| 独立 CBS key | 1,479,560 B | 1,479,560 B |
| CBS evaluator（含 LUT/FFT engine） | 304,840 B | 703,880 B |
| 调用方 Fourier GGSW 输出 | 98,304 B | 98,304 B |

普通 server 构造时 KeyGenerator 的初始 scratch 在计数窗口外，CBS key 的临时 generator 在
窗口内构造并释放；表内扣除临时释放，包含 Vec capacity，排除栈、共享 context/client、allocator
元数据及未释放在窗口外的生成 scratch。它不是 RSS/峰值。稀疏 server 约为经典的 3.09 倍；
workspace 多 399,040 B，用于系数/Fourier 聚合与指数等已有 sparse BR 缓冲。

验证通过：`just tfhe`、`just tfhe-simd`、改动包的严格 rustdoc、经典与 `--sparse` 两种 release
示例，以及默认/SIMD 的八项基准和 setup 检查。本地 Markdown 链接/新增锚点检查通过。
底层数值实现最终无改动；没有保留临时统计测试或 trace 访问器。
