# Fourier MVB：B5.4 组合与成本验收

基线为 `be7a06c` 加本步 GLWE sparse×MVB 接入。此前的
[表示与独立误差验收](tfhe-mvb-fourier.md)分别核对 GLWE 及 NTRU；本页比较两族 Fourier
后端**各自内部**的完整算法成本。NTT 的既有结果见 [GLWE](tfhe-mvb.md#8-p43-测量与应用选择)
和 [NTRU](tfhe-mvb-ntru.md)，不将历史 NTT 耗时当作本轮跨后端对照。

## 1. 等价负载与参数

一次调用从一个加密分数生成 k 个阈值标志：
`f_i(m) = [m >= floor((i+1)D/(k+1))]`。两组 `D/k=8/3、64/17`，
输入为 Rounded `t_in=2D`，三条算法都输出 unsigned Scaled `t_out=2`。
独立 PBS 和交错 ManyLUT 用 raw 编译器写入同样的 Scaled 中心，不替换输出编码。

- `D=8,k=3`：交错布局占 4 槽，重复 PBS、交错和 MVB 均可执行。
- `D=64,k=17`：交错布局需要 32 槽，只有 `N/32=32<D` 个位置，构造明确拒绝。
  该负载只比较重复 PBS 和 MVB，不记录交错的虚拟耗时。
- 编译器生成的每个因子均验证为 `nnz=2、L1=2、L2²=2`，Native 尺度 `Delta=q/2`
  为偶数。共同多项式在加密/BR 前取整数 `Delta/2`。

| 参数 | GLWE Fourier | NTRU Fourier |
| --- | --- | --- |
| 字宽、环长度、BR small 维数 | u32/u64，N=1024，n=728 | u32/u64，N=1024，n=728 |
| Client/small 秘密 | 固定重量 binary h=32 | 固定重量 binary h=33，补零至 N |
| Accumulator 秘密 | d=1，SparseTernary | SparseTernary |
| 输入 small-LWE 噪声标准差 | `3.2*q/16384` | `3.2*q/16384` |
| Accumulator 加密噪声标准差 | 6.4 个整数单位 | 0.7 个整数单位 |
| BR 分解 | logB=8，L=3 | logB=8，L=3，初始化共用 |
| KS 分解 | logB=2，L=13 | logB=8，L=3，KS 噪声标准差 0.7 |
| 秘密域/执行顺序 | BK 外部 n；KB 外部 dN | 固定 f_client → f_acc → f_client |

GLWE 在每组内复用同一个 client，同时生成经典与 sparse server key；sparse 使用
`c=3、buckets=64`。NTRU h=33 满足 Native 可逆性所需的奇数重量，生成仍检查可逆性和
逆元稳定性；它使用经典逐坐标 BR。本组参数不是生产参数，也不是两族等安全对照。
相同整数噪声在两种字宽下的相对强度不同，不能用误差数值直接比较安全性。

为控制基准数量，采用以下配对；功能测试另检查数值/API 契约，不补全计时笛卡尔积：

| 后端/顺序 | u32 | u64 |
| --- | --- | --- |
| GLWE BK，经典/稀疏 | RustFFT | TfheFFT |
| GLWE KB，经典/稀疏 | TfheFFT | RustFFT |
| NTRU，经典 | RustFFT | TfheFFT |

每个 fixture 重置 `StdRng`，seed=`0x42353400+D`。GLWE 依次生成 client、经典 key、
sparse key，再加密输入；NTRU 生成配对 key 后加密。计时池为 `0、D/4−1、D/2、D−1`。
每次 Criterion 迭代轮换一个输入并生成全部输出，包含初始化（NTRU）、BR、乘法、KS 和提取；
keys/LUTs/outputs/evaluator 全部提前准备。每条路径计时前解密核对整个输入池。

## 2. Sparse 组合与误差

GLWE 的 `FactorizedEvaluator` 已允许固定重量 sparse binary key，复用普通 evaluator 的
BR 分派，没有新增 sparse MVB 内核或额外 key。经典 binary/ternary 保持原接口。
原有两个聚焦测试在 binary fixture 内复用同一 client/program 检查经典和 sparse；
覆盖两种 order、两种 FFT、u32/u64、非二次幂输出尺度、首调用零分配和跨调用复用。
只增加这组组合覆盖，没有新增普通统计测试；两测试默认合计约 0.9 秒。

独立于计时的临时诊断使用同一 fixture/seed，输入池改为按 `m=0..D` 各重新加密一次。
所有三条算法共享输入，直接按外部秘密解密并相对预期 Scaled 中心取居中误差；
每条 D=8 路径有 24 个输出样本，D=64 有 1088 个。测量在线分配包含首次调用，全部为零。
因子范数由共享系数编译器逐个核对。默认/SIMD 的科学记数法九位小数摘要相同，
[误差 CSV](benchmarks/tfhe-b5.4-noise.csv)保留一份，含均值、未去均值 RMS 和最大绝对值。

下表是各类型所测 order/域中的**观测最大 MVB 误差**，单位为 q：

| 后端 | u32 经典 | u32 稀疏 | u64 经典 | u64 稀疏 |
| --- | ---: | ---: | ---: | ---: |
| GLWE | 1.290e−3 | 2.046e−3 | 9.807e−6 | 1.699e−5 |
| NTRU | 6.082e−5 | — | 9.537e−6 | — |

全部样本正确解码，误差远小于本组二元 Scaled 的 q/4 解码半径。此结果包含 sparse 的
加密零/dummy 聚合误差及其因子放大，不认证正式尾概率；也不能由 L1=2 推断任意高范数
因子可用。输出共享 BR，误差有相关性。NTRU 的初始化、FFT 和 KS 分项见
[B5.3](tfhe-mvb-fourier.md#b53ntru-接入与独立误差验收)，不套用 GLWE 平凡初始化模型。

## 3. 常驻资源

[资源 CSV](benchmarks/tfhe-b5.4-resources.csv)统计构造窗口内的成功分配、累计申请、释放
及剩余请求字节，包含 Vec capacity；排除 allocator 元数据、栈、借用 context/table 和
窗口外 keygen scratch，不是 RSS。临时转化缓冲的释放已扣除，默认/SIMD 结果一致。
NTRU 诊断把 client/server 生成分开以归属内存，采样顺序与配对生成相同。

| 对象 | u32 字节 | u64 字节 |
| --- | ---: | ---: |
| GLWE 经典 server key | 71,860,416 | 71,860,608 |
| GLWE sparse server key | 110,724,872 | 221,218,760 |
| GLWE 经典普通 / MVB evaluator | 103,268 / 127,844 | 138,952 / 163,528 |
| GLWE sparse 普通 / MVB evaluator | 256,548 / 281,124 | 341,384 / 365,960 |
| NTRU server key | 17,940,552 | 17,940,624 |
| NTRU 普通 / MVB evaluator | 46,080 / 62,464 | 58,368 / 74,752 |

MVB 不增加 key。GLWE 在 d=1 时额外 24,576 字节，NTRU 额外 16,384 字节，均与输出数无关。
Sparse 的在线收益需要与更大的 key 和普通 BR 工作区一起考虑。

| 程序 | u32：D8/k3 → D64/k17 | u64：D8/k3 → D64/k17 |
| --- | ---: | ---: |
| 独立 PBS，含外层 Vec | 12,456 → 70,584 B | 24,792 → 140,488 B |
| 交错 | 4,096 B → 容量不足 | 8,192 B → 容量不足 |
| 已准备 MVB | 28,672 → 143,360 B | 32,768 → 147,456 B |

两族使用同样的程序布局。MVB 准备后只有 V 与一段 Fourier 因子，u32 因子转换为复数后
占用大于系数 LUT；无需假定预处理会节省程序空间。输出密文和外层 Vec 另计，
按外部维数随 k 线性增长，详见 CSV。

## 4. 完整时间

每格为 **默认 / SIMD** 的均值，单位 ms；95% bootstrap 置信区间及完整配置见
[计时 CSV](benchmarks/tfhe-b5.4.csv)。BK/KB 的 FFT 配对见第 1 节，`—` 表示交错容量不足。

| 后端 / order / 字宽 / key | D / k | 重复 PBS | 交错 ManyLUT | MVB |
| --- | --- | ---: | ---: | ---: |
| GLWE / BK / u32 / classic | 8 / 3 | 18.301 / 18.565 | 6.080 / 6.138 | 6.311 / 6.134 |
| GLWE / BK / u32 / classic | 64 / 17 | 105.705 / 105.584 | — | 6.352 / 6.932 |
| GLWE / BK / u32 / sparse | 8 / 3 | 12.228 / 12.602 | 4.617 / 4.072 | 4.345 / 4.133 |
| GLWE / BK / u32 / sparse | 64 / 17 | 71.771 / 76.293 | — | 4.561 / 4.715 |
| GLWE / BK / u64 / classic | 8 / 3 | 26.007 / 26.389 | 8.663 / 8.810 | 8.910 / 8.729 |
| GLWE / BK / u64 / classic | 64 / 17 | 154.205 / 148.229 | — | 9.092 / 9.019 |
| GLWE / BK / u64 / sparse | 8 / 3 | 27.577 / 26.774 | 9.032 / 9.072 | 9.100 / 9.231 |
| GLWE / BK / u64 / sparse | 64 / 17 | 156.192 / 151.420 | — | 9.672 / 9.333 |
| GLWE / KB / u32 / classic | 8 / 3 | 15.875 / 16.174 | 5.308 / 5.151 | 5.426 / 5.361 |
| GLWE / KB / u32 / classic | 64 / 17 | 97.027 / 94.660 | — | 5.281 / 5.489 |
| GLWE / KB / u32 / sparse | 8 / 3 | 13.062 / 11.985 | 4.277 / 3.968 | 4.622 / 4.024 |
| GLWE / KB / u32 / sparse | 64 / 17 | 72.817 / 73.153 | — | 4.333 / 4.386 |
| GLWE / KB / u64 / classic | 8 / 3 | 28.557 / 28.412 | 9.495 / 9.360 | 9.505 / 9.765 |
| GLWE / KB / u64 / classic | 64 / 17 | 162.655 / 160.785 | — | 9.695 / 9.737 |
| GLWE / KB / u64 / sparse | 8 / 3 | 26.474 / 27.075 | 8.838 / 9.004 | 9.703 / 8.962 |
| GLWE / KB / u64 / sparse | 64 / 17 | 152.152 / 152.264 | — | 9.008 / 8.741 |
| NTRU / u32 | 8 / 3 | 7.408 / 7.437 | 2.492 / 2.472 | 2.480 / 2.494 |
| NTRU / u32 | 64 / 17 | 42.001 / 41.648 | — | 2.615 / 2.504 |
| NTRU / u64 | 8 / 3 | 11.055 / 10.799 | 3.680 / 3.610 | 3.672 / 3.619 |
| NTRU / u64 | 64 / 17 | 62.275 / 61.084 | — | 3.787 / 3.742 |

本组低范数阈值负载的取舍：

- **17 输出**：同后端内 MVB 相对重复 PBS，GLWE 均值比为 15.2–18.4 倍，NTRU 为
  16.1–16.6 倍；这是本轮完整调用的观测比值，不是理论加速上界。此时交错容量不足，
  MVB 的共享 BR 有明确价值。
- **3 输出**：MVB 与交错大体接近，部分配置更慢；两者均省去重复 BR。
  交错能容纳且噪声预算合适时，无需仅为了多输出切换成 MVB。MVB 还需要因子范数、
  FFT 精度和较大的程序存储预算。
- **Sparse**：本组 u32 MVB 比同 order 的经典路径快；u64 BK 的 sparse 在两种 feature
  下均更慢，KB 的收益也不一致。u64 sparse key 约 221 MB，经典约 72 MB；不能只按
  少做 external product 来推断完整收益，也不能把 u32 结论推广到 u64。
- **SIMD**：各路径既有改善也有退化；例如 u32 经典 BK 的 17 输出 MVB 为
  6.352 / 6.932 ms。此次未改数值内核，工具链也不同，不据此引入新的 SIMD 策略。

保留重复、交错与 MVB 的显式入口。本步没有增加自动算法选择，也未重测构造/keygen
耗时；这些均在在线计时之外。资源表补充其常驻成本，不能代替预处理时间。


## 5. 使用与复现

常驻基准为 [GLWE mvb](../crates/primus_tfhe_glwe_fourier/benches/mvb.rs) 和
[NTRU mvb](../crates/primus_tfhe_ntru_fourier/benches/mvb.rs)，命令见文件头。
2026-09-19 测量采用 Ryzen 9 9955HX3D、x86_64 Linux、CPU 2，仓库 `target-cpu=native`；
默认 rustc 1.98.0（88d9e12ae），SIMD nightly 1.100.0（bff8e12ff），Criterion 0.8.2。
每项 20 样本、预热 1 秒、测量 2 秒、Flat sampling；两后端和 feature 串行测量，
测量期间不并行编译。CPU 未隔离或锁频，governor 为 powersave，boost/SMT 开启；
置信区间不含跨运行漂移。
默认/SIMD 使用不同工具链，不把小差异直接归因于手写向量化。

临时诊断与分配计数器在计时前从基准移除；复测诊断可按第 1–3 节，将输入池改为
完整前半域并记录各构造对象的申请/释放，以及各路径输出相位；不要把统计插入计时循环。

[GLWE](../crates/primus_tfhe_glwe_fourier/examples/fourier_mvb_thresholds.rs) 与
[NTRU](../crates/primus_tfhe_ntru_fourier/examples/ntru_fourier_mvb_thresholds.rs) 示例使用
n=728、N=1024，将一个 `0..64` 分数转换为 17 个阈值标志，复用所有在线缓冲。
这些是 Scaled t_out=2 的**数值标志**。本组 Delta=q/2 恰好与 Rounded t=2 的中心一致，
但不能直接交给 Boolean t=4 门，也不是原 t_in=128 的编码；同样 t=2 的普通前半域
也只接受消息 0。若继续同态计算，下一步必须明确接受这种编码与整个 0/1 域。
其他 t_out（如 10）还要把 Scaled 与 Rounded 中心差计入下一次输入误差。

验证包括默认/SIMD TFHE 检查、严格 rustdoc、两示例的默认/SIMD release 执行、
完整域诊断与计时前输入池校验。稀疏 CBS、稀疏 ternary 和正式噪声尾界不在本步范围内。
