# TFHE 历史测量索引

本目录 CSV 保存历史摘要；算法契约见 [TFHE 总览](../tfhe.md)，P3 / MVB / ternary 的方法及数据分别见 [稀疏 PBS](../tfhe-sparse-pbs.md)、[MVB](../tfhe-mvb.md#8-p43-测量与应用选择) 与 [Ternary T1](../tfhe-ternary.md#t1-测量与取舍)。源码或参数变化后按当前任务复测，不以历史数据声明当前性能。

共同边界：Ryzen 9 9955HX3D、x86_64 Linux，仓库构建配置；CPU 未隔离，boost/SMT 开启，计时串行。默认 rustc 1.98.0、Criterion 0.8.2；SIMD 若列出则为 nightly 1.100.0（2026-08-26）。耗时 CSV 为均值及 95% 置信区间（ns），不能当作 Criterion 原始样本或跨后端等安全参数比较。

## P1.1 初始基线

2026-09-15，生产编译算法与 `7526ada` 相同；[tfhe-p1.1.csv](tfhe-p1.1.csv) 含 10 项构造、18 项在线 PBS。固定 CPU 0、默认 features、10 samples、1 s warm-up、3 s measurement。依赖为 rand 0.10.2、RustFFT 6.4.1、tfhe-fft 0.10.1。

- 构造：u32、N=1024，Native / Barrett q=132120577，t/k 为 4/4、16/1、16/4、16/16、255/4；计入验证、几何、分配、填充与析构。
- 在线：四后端 `benches/pbs.rs`，seed=42、N=1024、t=4，GLWE n=512、NTRU n=800；覆盖两种 GLWE order、两种 FFT，复用 key/LUT/scratch/输出。ID 的 k1 是 GLWE 维数，输出数看 many_4。
- 复现：分别运行共享 `lookup_table` 与四后端 `pbs` 基准，后者筛选 `complete_pbs_(reused_output|many_4_reused_outputs)$`。先在对应旧源码 `--save-baseline p1_1`，再在新源码 `--baseline p1_1`，避免覆盖。

## P1.M 接口与 codec

2026-09-16，基线 `21f278a`；[tfhe-p1.m.csv](tfhe-p1.m.csv) 的 23 项 codec 使用 `modulus_before`，18 项 PBS 使用重新采集的 `p1_m_before`。环境、CPU 0、负载沿用 P1.1；10 samples、1 s warm-up，codec 测 2 s，PBS 测 3 s。计时早于消息统一为 T 的最终接口调整。

批量 codec 变化 −14.99%～+2.75%；Native 单值加法编码 0.795→0.973 ns（+22.44%）。通用提升/符号 helper 原型约 +30%，未保留。完整 PBS −4.39%～+3.34%，无一致加速。RingContext 超 trait 调整后另测 23 项：批量 −2.06%～+1.41%，Native 单值加法编码 0.976 ns（−0.01%）；未重测完整 PBS。

复现入口为 `primus_encoding --bench plaintext_codec` 与 P1.1 的 PBS 筛选。原样本目录为 `target/criterion/**/{modulus_before,p1_m_before,p1_m_pair_after,ring_final}/`；未测 SIMD 性能。

## 固定模数对内核优化

2026-09-16，基线 `eef21a0` 加 P1.R 旋转域边界修改，CPU 2、默认 features。微基准/codec 20 samples，PBS 10 samples，均 0.5 s warm-up、2 s measurement；setup、预计算和分配不计时。[modulus-switch.csv](modulus-switch.csv) 保留算术对照及两轮融合原型。

入口为 `primus_modulus/benches/modulus_switch.rs` 的标量/512 系数批量、23 项 codec，以及 GLWE NTT/TfheFftTable 两种 order、单/4 输出的 8 项完整 PBS。

| 工作负载 | 前 → 后 ns | 变化 |
| --- | --- | --- |
| 512 Native u32 → 2048 | 14.82 → 14.70 | −0.8% |
| 512 u64，128 → 131 | 597.67 → 239.20 | −60.0% |
| 512 Barrett u32 → 2048 | 723.84 → 126.80 | −82.5% |
| 512 Barrett u64 → 2048 | 738.73 → 181.56 | −75.4% |
| 512 Barrett u64 → Native | 1343.70 → 215.55 | −84.0% |
| 4096 Barrett u32 解码 | 5815.76 → 1009.40 | −82.6% |
| 4096 Barrett u64 窄乘积解码 | 5887.85 → 1388.89 | −76.4% |

标量 u32 Barrett 旋转 +16.9%、128→131 +19.2%，u64 对应旋转/Native 扩张为 −8.9%/−36.6%；16 项移位居中编码约 +10%，4096 项精确编码约 +5%～6%。8 项完整 PBS −6.4%～+0.8%，无一致整体收益。

将 CMUX 融入 quantizer 批量回调的原型，两轮无稳定收益；第二轮 −1.1%～+3.9%，第一轮有大离群。两轮均使用窄分子特化前的同版算术，单独比较循环融合。ELF text 为 NTT +5,852 B、Fourier −2,848 B。原型及额外入口已删除。未测 SIMD/NTRU 性能、构造成本或非 x86。

## P1.2 构造与控制流

2026-09-16，首版与 `ea2d6a4` 比较，[tfhe-p1.2.csv](tfhe-p1.2.csv) 含 10 项耗时与分配。CPU 0、环境/采样/负载沿用 P1.1；每次构造并释放一个 LUT。多输出分配从 k+1 次/累计 8192 B 降为一次 4096 B，耗时降约 68%～87%；单输出仍一次分配，约增加 1 ns。

主循环重整独立比较见 [tfhe-p1.2-flow.csv](tfhe-p1.2-flow.csv)：当时未提交源码的 SHA-256 前缀为 `bdc360afcbca46e6` → `768bbaaff5e3a5c2`，同配置两组基线为 `p1_2_flow_before/after`。部分 case 增 0.2～6 ns，其余降 0.4～14 ns，无整体加速结论。尾部 helper 未内联时 Native 16 输出约慢 11%，恢复 inline 后约 147 ns，保留该局部选择。

分配计数不进入计时；累计请求量不是峰值 RSS。此步未改在线 PBS，也未重测在线性能。

## P1.R 居中原型

2026-09-16，以 `u32`、均匀二元秘密验证三个配对路径：原始量化、仅居中、居中并向负方向 shift 半个虚拟单位。临时原型只修正 body，mask 和 LUT 保持不变；没有加密零样本、在线随机舍入或额外堆分配。原型不作为公共 API 保留。

**可复现的整数计算：** 取未做末端模约简的 `u_i=round(p*a_i/q)`，累积 `E=Σ(q*u_i-p*a_i)`；令 `h=0` 表示仅居中、`h=1` 表示附加 shift，则 `c=round((E-h*q)/(2p))`，`b'=(b+c) mod q`。所有 round 均为 nearest ties-up，包括有符号 `c`。对 Native 输入，`Δ=q/p` 为整数，可改为累积源尺度残差 `d_i=Δ/2-((a_i+Δ/2) mod Δ)`，再计算 `c=round((Σd_i-h*Δ)/2)`。原型以 `i64` 累积所测 `u32` 参数，不能直接推广为任意字宽实现。

- **独立 oracle：** 小显式模数穷举加 Native 固定 seed 随机输入，共 343,668 个修正结果与独立 `i128` 有理数公式一致。
- **LUT 反例：** 固定 half-shift 的零噪声反例见[设计决定](../tfhe.md#p1r-取整策略取舍)。
- **误差实验：** `N=1024,n=512,t=16,k=1/3`，分别使用 Native `q=2^32` 和 Barrett `q=132120577`。每组 65,536 条零输入噪声 LWE；每 1,024 条重新采样一把均匀二元秘密，共 64 把；使用 `StdRng`，seed 为 `0x50315200+k`。误差以虚拟旋转单位计，相对于真实编码相位；按当前 LUT 检查读取值。数据见 [量化统计](tfhe-p1.r-quantization.csv)。

| 量化路径 | Native 方差，k=1 / 3 | Barrett 方差，k=1 / 3 |
| --- | --- | --- |
| 原始 | 21.474 / 21.390 | 21.477 / 21.390 |
| 仅居中 | 10.692 / 10.715 | 10.692 / 10.715 |
| 居中 + shift | 10.712 / 10.692 | 10.711 / 10.692 |

居中将所测方差约减半，标准差约为原来的 `0.707`。Shift 将均值移到约 `-0.5`，未进一步降低方差；它的作用是槽位对齐。`k=3` 两种模数的原始路径均有 30 次 LUT 读取错误，两个居中路径均为 0；`k=1` 三种路径均为 0。这里不含加密噪声、BR 和 KS 噪声，有限样本的零错误也不是生产失败概率结论。

**性能方法：** Ryzen 9 9955HX3D，固定逻辑 CPU 2，rustc 1.98.0、默认 feature，沿用仓库编译配置，Criterion 0.8.2。`n=512,N=1024,t=8,k=1/3`，固定 seed 42，`BootstrapKeyswitch`；计时不含 key/LUT 构造和输出分配。量化负载为整条 513 系数 LWE（居中路径包含额外 mask 扫描）；完整负载为 body 修正加现有 PBS。Fourier 使用 `TfheFftTable`、Native u32、LWE/GLWE σ=3.2、BSK `(logB=8,l=3)`、KSK `(2,13)`；NTT 使用 Barrett `132120577`、LWE σ=`3.2*q/16384`、GLWE σ=6.4、BSK `(7,3)`、KSK `(2,13)`。每种后端/输出数量/修正模式均在计时外检查全部四个输入消息的解密结果。均值及 95% 置信区间见 [计时数据](tfhe-p1.r-centered.csv)。

每项 20 个样本、0.5 秒预热、2 秒测量；Native `k=1` 量化组因首次波动较大按同配置复测。下表每格依次为原始 / 仅居中 / 居中 + shift：

| 后端 / 输出数 | 整条 LWE 量化（μs） | 完整 PBS（ms） |
| --- | --- | --- |
| Native Fourier / k=1 | 0.806 / 0.817 / 0.816 | 3.528 / 3.520 / 3.528 |
| Native Fourier / k=3 | 0.806 / 0.819 / 0.817 | 3.565 / 3.521 / 3.551 |
| Barrett NTT / k=1 | 0.773 / 1.530 / 1.581 | 3.580 / 3.565 / 3.556 |
| Barrett NTT / k=3 | 0.852 / 1.592 / 1.592 | 3.535 / 3.531 / 3.534 |

Native 的额外位运算扫描成本较小；Barrett 的量化成本接近翻倍，但绝对增加约 `0.8 μs`，只占所测完整 PBS 的约 `0.02%`。完整 PBS 本轮未观察到明确的开销增加；均值差异不作为加速结论，也不外推至其他参数或稀疏 BR。

原型未保留为公开 API；固定重量稀疏秘密、NTRU/CBS 和生产失败概率不在本次测量范围。正式接入条件只在[设计决定](../tfhe.md#p1r-取整策略取舍)维护。

## P1.4 最终对照

2026-09-16，重建 `21f278a` 与 `d5da1cb` 加维护资产修改比较，相同锁文件、编译配置与 PBS 参数。CPU 2、默认 features；首轮 10 samples、1 s warm-up、3 s measurement，复测 20 samples、逐 case 交替版本与先后顺序。

[tfhe-p1.4.csv](tfhe-p1.4.csv) 的 initial 含 28 项等价对照及 11 项新增 k=3；paired 复测两项单输出构造和 18 项 PBS；rustfft_recheck 重测波动较大的两项。新增 case 不造旧版分母。

构造 u32、N=1024、D=ceil(t/2)，Native / Barrett q=132120577，raw 输出 `13*input+column`，计入构造/析构但不计模数 setup。八项多输出下降 61.6%～85.6%；单输出交替复测 Native 79.55→96.28 ns、Barrett 97.00→120.57 ns，增加 16.7/23.6 ns。全部仅一次 4096 B 结果分配。

在线复用 key/LUT/evaluator/输出，GLWE n=512、NTRU n=800、N=1024，其余见对应版本 fixture。首轮 18 项 −2.33%～+5.54%；交替复测 NTT 约 +0.9%～+3.3%，Fourier 多数 −2.4%～+1.7%，无稳定整体加速，保留 NTT 小幅退化信号。NTRU RustFFT 异常轮旧版约 4.3～4.5 ms，重测恢复双方约 2.7 ms，变化 −0.31%/+0.42%。新增九项三输出为 2.122～4.173 ms。

复现筛选 `^(lut_compile/|.*complete_pbs_(reused_output|many_[34]_reused_outputs)$)`；原样本为 `target/criterion-p1.4/{before,after}/**/{p1_4,p1_4_recheck,p1_4_rustfft_recheck}/`。未测 SIMD 性能、非 x86 或生产失败率。

维护资产精简的历史结果：PBS 调用 501→147、CBS 26→10，Criterion 166→97 项。按 CI 的 `CARGO_BUILD_RUSTFLAGS=''`、本机两个 nextest 线程，七包默认测试 0.908→0.547 s、nightly all-features 0.887→0.539 s；均仍 41 项测试，不含编译，也不是 GitHub runner 总时长。CI 未选择 benches，基准删减不计作 CI 提速。

## P4.0 阶段拆分

基线 `683a44c`，前后独立 Criterion 可执行文件，CPU 2，默认/SIMD；沿用四后端 pbs 单输出/三输出 fixture，另测 sparse_pbs 的 n=728、h=32、N=1024，两种 order、经典/稀疏。setup 不计时。[tfhe-p4.0.csv](tfhe-p4.0.csv) 的 52 组首轮对照：

| 负载 | 默认变化 | SIMD 变化 |
| --- | --- | --- |
| 四后端普通/三输出，各 18 项 | −1.99%～+1.98% | −3.89%～+1.55% |
| n728 经典/稀疏，各 8 项 | −8.65%～+1.09% | −1.76%～+5.06% |

首轮先 before 后 after，0.2 s warm-up、1 s measurement、1000 resamples；普通 10 samples、稀疏参数组 30 samples。SIMD KB 经典单输出/交错的 +4.77%/+5.06% 追加两轮，0.5 s warm-up、3 s measurement、30 samples，交换顺序后为 +1.88%/+1.35%、−2.08%/−1.75%。未重现稳定退化，保留阶段拆分；不以单轮差异宣称加速。

## P3 与 P4.3

- P3.2–P3.5 的分项、BR、完整 PBS、keygen、内存和相位诊断只在[稀疏专项](../tfhe-sparse-pbs.md)维护，历史成本组为 n=512。
- [tfhe-p4.3.csv](tfhe-p4.3.csv)、[resources](tfhe-p4.3-resources.csv)、[noise](tfhe-p4.3-noise.csv) 的 n=728 MVB 负载、测量方法和 KS 对照只在 [MVB 专项](../tfhe-mvb.md#8-p43-测量与应用选择)维护。

清理 target 后须用对应源码、参数与等价 harness 重建 Criterion 基线；CSV 是持久摘要。所有测量均有具体功能/噪声边界，不是方案排名或安全认证。
