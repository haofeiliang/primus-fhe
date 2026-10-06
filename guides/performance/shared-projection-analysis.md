# CBS 与 one-hot 的共享投影研究

[性能取舍与测量方法](README.zh_CN.md)

2026-10-05 测量，2026-10-06 更新取舍；基线 `09e5f1b8`。保留原投影的成本研究、任意尾部相位推导，以及已撤回的 NTRU one-hot/完整高精度 LUT 一级共享实验。

结论：**一级共享实现已撤回，生产路径恢复各输出独立完成 reverse trace。** 整理后实验版的 sparse 完整 LUT 成对测量中位改善约 0.8%，classic 未确认稳定收益且有回退点；不足以抵偿额外 2N 系数、移位/访存、公开接口及共享误差契约的维护成本。相关测试扩展和 API 文档一并撤回，只保留推导、oracle 与测量记录。普通 CBS 不变，两级共享不继续。

## 原实现的成本，而非旧 BR 比例

在 Ryzen 9 9955HX3D、rustc 1.98.1 / LLVM 22.1.8、仓库 `target-cpu=native` 下，用 CPU 4 测 GLWE/NTRU CBS、NTRU nonzero one-hot、完整 LUT，再用 CPU 8 复测完整 LUT。未启用 nightly `simd`。Fourier 测 TFHE FFT；RustFFT 编译但没有计时。普通 GLWE CBS 仅测 `BootstrapKeyswitch` order，不代表另一 order 或其他参数。

每个配置先保存无插桩可执行文件，再在隔离副本中插桩。只在四个后端 CBS evaluator 和两个 NTRU one-hot evaluator 的 `trace_key().project_prefix_coefficients*` 调用外包围 `Instant`，累积线程本地整数计数；在每次完整请求外另计时。计时内不打印、不分配。统计只取 Criterion 正式采样阶段，投影占比为 `sum(projection_ns)/sum(request_ns)`，不是不同运行的时间相减。该范围包含 prefix 移位和 reverse trace，不包含 one-hot 外层 selector 移位、BR 或 scheme switch。

Criterion 每次迭代仍是一项完整请求，10 samples、warm-up 0.15 s、measurement 0.6 s；样本太慢时 Criterion 自行延长。普通 CBS 保留其原采样模式，LUT 保留 Flat 模式。先完成编译再计时。未启用硬件计数器（当前 perf 无可用事件）；这些短测量用于确定研究优先级，不用于发布速度结论。无插桩与插桩运行也有频率、缓存及代码生成波动，不能把它们的差值当作探针的纯开销。

全部 72 个配置的无插桩 Criterion 点估计、插桩点估计、内部平均阶段时间和调用数在 [CSV](data/shared-projection-measurements.csv)。`baseline_ms` / `probe_ms` 是两个可执行文件的 Criterion 点估计；`projection_ms` / `total_probe_ms` 是探针累计时间除以请求数，`share` 单位为百分比，`calls` 是每请求的 prefix 投影调用数。

| 消费者 | 当前投影占完整请求的比例 |
| --- | ---: |
| GLWE 普通 CBS，CPU 4，两字宽/NTT/TFHE FFT/classic/sparse | 1.29%–2.16% |
| NTRU 普通 CBS，同上 | 3.95%–6.85% |
| NTRU nonzero one-hot，同上 | 10.49%–17.41% |
| 完整 LUT，CPU 4，同上并含三种表 | 8.26%–20.87% |
| 完整 LUT，CPU 8，同上并含三种表 | 6.56%–19.54% |

完整 LUT 的几个 sparse 点如下；普通映射为 `x*x+3*x+7`，shared 映射沿用 bench 中的跨输出重复表。

| 后端 | 表 | CPU 4 完整基线 / 投影 ms | CPU 8 完整基线 / 投影 ms |
| --- | --- | ---: | ---: |
| NTT u32 | 普通 | 47.333 / 8.259 | 47.725 / 7.806 |
| NTT u64 | 普通 | 36.315 / 4.317 | 39.595 / 4.076 |
| TFHE FFT u32 | 普通 | 43.359 / 8.532 | 44.392 / 8.023 |
| TFHE FFT u64 | 普通 | 34.181 / 3.917 | 35.061 / 3.772 |
| NTT u32 | shared | 31.984 / 6.279 | 32.325 / 5.894 |
| NTT u64 | shared | 21.154 / 3.245 | 22.466 / 3.064 |

这些测量保留已有双输入 BR、delta_0 省略、重复多项式/跨输出复用、chunk 剪枝、公开提升和完整返回。普通/dense 表每次请求有 25 次 prefix 投影，shared 表有 19 次；每次 prefix 调用产生 L 个系数密文，不是仅做一次自同构。LUT 的计时外解密、phase-error 和在线零分配检查全部通过；CBS/one-hot 的原有实际 CMux 检查也通过。

参数直接沿用基线的 [GLWE](../../test-support/tfhe/src/parameters/glwe.rs)、[NTRU](../../test-support/tfhe/src/parameters/ntru.rs) profiles 和 [LUT fixture](../../crates/primus_tfhe_ntru_lut/benches/support/mod.rs)：N=1024、h=32、CBS/one-hot n=728，LUT n=800、c8/d5/o8、每 chunk 两位、sparse r3/B64。NTRU 外部 q=2^24；GLWE 的 LWE 与环使用同一模数。NTT Q 为 998244353 / 1125899906826241，Fourier Q=2^word_bits。GLWE 输出 L=3/2，NTRU 输出 L=4/3（u32/u64）；BR/trace/SS 保持各自既有完整层数和噪声。密钥 seed=42，独立输入 seed=43；dense 映射 seed=42。不应用尚未推广的 sparse 参数候选，不更改分解或噪声来增加投影占比。

复现完整基线的入口（CPU 8 将 `4` 替换为 `8`，只跑 LUT）：

```sh
taskset -c 4 cargo bench -p primus_tfhe_ntru_lut --bench pipeline --features ntt,rustfft,tfhe-fft -- 'lookup/(ntt|tfhe_fft)/u(32|64)/(classic|sparse)/.*/evaluate$' --warm-up-time 0.15 --measurement-time 0.6 --sample-size 10 --noplot
taskset -c 4 cargo bench -p primus_tfhe_ntru_ntt -p primus_tfhe_ntru_fourier --bench circuit_bootstrap --features rustfft,tfhe-fft -- 'ntru/(ntt|tfhe_fft)/u(32|64)/(cbs/.*/complete|one_hot/.*/nonzero)$' --warm-up-time 0.15 --measurement-time 0.6 --sample-size 10 --noplot
taskset -c 4 cargo bench -p primus_tfhe_glwe_ntt -p primus_tfhe_glwe_fourier --bench circuit_bootstrap --features rustfft,tfhe-fft -- 'glwe/(ntt|tfhe_fft)/u(32|64)/cbs/.*/BootstrapKeyswitch/complete$' --warm-up-time 0.15 --measurement-time 0.6 --sample-size 10 --noplot
```

实际采样将编译和运行分开，并执行保存的可执行文件；上面的命令给出同一 bench/filter/参数入口。阶段诊断需在上述调用边界临时加探针；本轮探针和隔离编译目录在记录结果后删除，不增加生产 feature 或 CI benchmark。

## 输出、尺度和剩余 trace

在 `R_Q = Z_Q[X]/(X^N+1)` 中，N=2^n，记 `sigma_d(P)=P(X^d)`，`d_k=2^k+1`。`Pi_r` 直接保留下标为 `N/r` 倍数的系数；`Pi_1` 只留常数。

奇模数下定义理想相位映射 `H_k=(I+sigma_dk)/2`。自同构在理想相位上交换，因此

```text
H_n ... H_(k+1) = Pi_(2^k),
H_n ... H_1 (X^-i P) = Pi_1(X^-i P).
```

可按从最高 degree 向下逐项消去奇位置证明第一式。它是**完成剩余所有级之后**的系数投影，不是对中间误差独立做实数除二；也不表示近似分解的 ciphertext key switch 是线性的。

普通 CBS 提取 `i=l`，目标相位为 `g_l*b`；one-hot 提取 `i=l-r*S mod 2N`，S=N/M，目标为 `g_l*[r=m]`。`i>=N` 按负半环取符号，不能先把 i 无符号截成 `i mod N`。Gadget scalar `g_l` 沿用 output basis 的顺序和尺度；投影不额外乘 N 或改变 basis。只生成消费者实际需要的 selector/level，普通和 sparse 的区别只在前置 BR。

多项式的其他消息系数可以全部非零。当前每个输出独立执行完整 reverse trace 正确；要求零尾的 prefix expansion 不能直接替换它。

## 共享前 h 级，而后完成各自投影

`C` 是同一 BR 结果。先保存 `(g=1,C)`，每级 k=1..h 对每个当前节点执行：

```text
D_g      = halve(C_g)
C_g      = D_g
C_(d_k*g)= EvalAuto_(d_k)(D_g)
```

`halve` 在 NTT 中乘 `2^-1 mod Q`，在 Fourier 中逐个系数执行 unsigned floor(c/2)。存储系数密文，已有 auto key 仍按原布局/表使用。早期节点按 g 标识其理想相位的 automorphism 分支，不表示它没有噪声。

对每个目标 i，用全部 `2^h` 个节点组合

```text
Z_i = sum_g X^(-g*i) C_g
```

再依次执行 degree `2^(h+1)+1,...,N+1` 的归一化 reverse trace。理想相位中每一对节点贡献 `(I+sigma_dk)`，因为 `sigma_d(X^-i P)=X^(-di)*sigma_d(P)`；故组合正好是 `H_h...H_1(X^-i P)`。剩余 trace 完成常数投影，任意尾部都被消去。

一级版本最简单：`D=halve(C)`、`A=EvalAuto_3(D)`，每个输出从 `X^-i D + X^(-3i) A` 开始，接着做 degree 5,...,N+1。不能写成 `X^-i*(D+A)`，也不能每个输出仍从 degree 3 开始而重复归一化。

现有 `apply_reverse_partial_to(retained_coefficient_count=2^h)` 正是剩余这些 degree 的数学操作；它保留 2^h 个均匀位置。这里这些位置的**消息**除常数外已被早期组合消去，但密文和噪声没有零尾假设。已撤回的一级原型曾复用其内部 trace kernel，从 degree 5 开始；当前生产路径仍独立完成每个输出的完整 trace。

## NTT 误差：投影有界，但输出相关

设 `e_(k,g)` 是共享节点的实际自动同构相位误差，g 为归一化前节点的标签。它包括近似分解和求值密钥误差；不假定换输入后误差与基线相同。共享前 h 级后，输出相位精确为

```text
Pi_1(X^-i Phi(C))
 + sum_(k<=h,g) Pi_(2^k)(X^(-d_k*g*i) e_(k,g))
 + sum_(k>h)   Pi_(2^k)(e_(k,i)).
```

每个早期误差都沿自己的后续分支复制并组合，剩余所有 H 将它变成上式的系数选择。因此模逆不会在最终误差中留下未经抵消的 `e/2 mod Q`；错误地省略剩余 trace 才会破坏这个结论。晚期误差仍可能占据非目标位置，与现有 reverse trace 一致。

若同一级每次 auto 的相位误差有统一系数上界 B_k，则一个输出的新增误差上界为

```text
sum_(k<=h) 2^(k-1)*B_k + sum_(k>h) B_k.
```

这是条件性的确定性预算，不是 Gaussian 方差/尾概率。h=1 的项数与原实现相同；h=2 比原实现多一个第 2 级误差项。不能以减少全批次 auto 次数推断每个输出的误差更小。

多个输出会取用同一个 e 的不同或相同系数；one-hot 下相差 N/2 的提取位置尤其会复用同一组系数并改变符号。不能假设 selectors、gadget levels 或后续 CMux 分支独立，也不能未经分析按平方和开根号预算。

## Fourier：系数减半及秘密加权的 parity

Native Q=2^w 没有模逆二。对当前 canonical ciphertext C_g，令 p 为逐系数 parity，`2*floor(C_g/2)=C_g-p`。对应的相位修正为：

- NTRU：`rho = f*p`。
- GLWE：`rho = p_b - sum_j p_aj*s_j`。

以上 NTT 相位式在 native 域需再减去

```text
sum_(k<=h,g) Pi_(2^(k-1))(X^(-g*i) rho_(k,g))
 + sum_(k>h) Pi_(2^(k-1))(rho_(k,i)).
```

这些 rho 必须取**实际共享节点/实际后续输出**的 parity；不能套用原逐输出路径的 parity，也不能把 floor 跨过加法或带负号的单项式移位。半模数的 lift 歧义在每个完整剩余 trace 中抵消，最终式为 native 模数下的精确等式。e 另包含实际 FFT 舍入和 key-switch 相位误差。

NTRU 的每项 rounding 系数界可用 `||f||_1`，GLWE 可用 `1+sum_j ||s_j||_1`，按上述各事件个数相加；不假设 parity 独立或无偏。h=1 保持项数，h=2 增加一个早期 rounding 项。这样只建立投影的预算形式，还没有证明代表性参数的解密余量。

后续 NTRU scheme switch 将投影误差再乘 f，另有分解残差乘 f² 和 scheme-switch/FFT 误差，见[现有相位契约](../../crates/primus_ntru/src/scheme_switch/fourier.rs)。进入多项式选表/旋转后还要计公开多项式范数、分解误差和相关性。只检查 projection 常数位置或单个 selector 的解码都不够。

## 计算、密钥与工作区取舍

同一 BR 的 K 个系数输出，原实现 K*n 次 auto；共享 h 级需要 `2^h-1 + K*(n-h)` 次。输出组合从每项一次移位变为每项 `2^h` 个带符号移位及加法，还增加读写，不能把 auto 数差当作时间收益。

| N=1024 的输出数 K | 原 auto 数 | h=1 | h=2 |
| --- | ---: | ---: | ---: |
| 3 个 gadget 层 | 30 | 28 | 27 |
| 4 个 gadget 层 | 40 | 37 | 35 |
| nonzero one-hot，L=3 / K=9 | 90 | 82 | 75 |
| 完整 one-hot，L=3 / K=12 | 120 | 109 | 99 |
| 完整 one-hot，L=4 / K=16 | 160 | 145 | 131 |

h=1 对投影 auto 最多省约 9%，乘当前完整 LUT 占比，理想化完整节省大约 0.5%–2%；h=2 大约 1%–4%，尚未扣组合与缓存成本。K 是同一 BR 真正需要的系数数，不能把整个 LUT 的 25 次 prefix 调用当成一次共享；它们跨多个输入密文。双输入 BR 的两个结果也不能直接共用这棵树。

不新增求值密钥，复用现有 degree 3、5,... keys。保守资源方案是新增 `2^h` 个系数密文槽来保留共享节点，输出、auto/变换 scratch 沿用现有缓冲。NTRU N=1024 时 h=1 为 8/16 KiB，h=2 为 16/32 KiB（u32/u64）；GLWE k=1 再乘 2。实际可否借用已有槽取决于生命周期，不默认合并同尺寸 scratch。节点必须跨 selector 的 scheme switch 保持有效，不能被它覆盖；可逐个 selector 产生 L 个投影并马上消费，避免存放所有输出。与已有 pair BR 状态分开预算。

## Oracle 与进入原型的条件

运行 [shared_projection_oracle.py](tools/shared_projection_oracle.py)：

```sh
python3 guides/performance/tools/shared_projection_oracle.py
```

本轮通过 **28128 个精确输出相位检查**：N=8/16/32、Q=257 和 2^8/2^32/2^64、NTRU/双 mask GLWE、共享深度 0..3、全部 2N 带符号目标及重复/selector 下标、dense 非零尾/奇偶与 wrap 边界、有无注入误差。奇模数另逐一验证每个消息单项式。Oracle 用 schoolbook 环乘法和直接系数选择作为参照，不调用 Rust trace/NTT/FFT；理想自动同构加已知误差，native 路径实际对密文系数 floor-halving，比较完整相位多项式而非只看常数。

它验证消息、移位、归一化与相关误差的代数，不模拟真实 gadget 分解或 FFT 精度，也不认证安全参数；小环不受生产 PolyLength 下界限制。脚本按需运行，不加入普通 CI。

实现验收限定 NTRU one-hot/完整 LUT 的 h=1：复用现有 key，保护节点生命周期和零在线分配，同时保留 delta_0 省略、剪枝及 pair BR。下节给出真实 gadget/FFT、CMux/LUT 和无插桩完整请求的结果。h=2 需要增加的 auto/rounding 项预算与独立收益证据；本轮不实现更深通用树，也不增加公开策略。


## 一级原型与完整流程测量（已撤回）

### 原型结构与空间

以下描述用于解释历史测量，相关类型和方法已删除，不能作为当前 API 使用说明。原型曾以 `prepare_projection` 在调用方的 2N 系数中保存 D/A，返回借用生成 key 和系数的投影对象；连续投影入口按模 2N 的带符号下标输出完整 N 系数块，允许任意消息尾部。

原型中的两个 NTRU one-hot evaluator 各保留一块独立的 2N 系数缓冲。对 selector r，从 `-r*S mod 2N` 连续生成 L 层后立即 scheme switch，D/A 跨 selector 保持不变。Rust 借用保证不能在准备结果存活时覆盖它们；临时 auto/变换 scratch 则继续复用。没有改动 LUT 的选表、剪枝、selector 省略或 pair BR，也未更改普通 CBS。

N=1024 时，额外堆空间为 u32 **8192 B** / u64 **16384 B**，key 不增加。以 sparse 普通表的 evaluator 构造为例：NTT u32 从 587268 到 595460 B，NTT u64 从 857608 到 873992 B；两个 FFT 引擎的 u32 从 1264192 到 1272384 B、u64 从 1212032 到 1228416 B。完整请求在线分配仍为零。这些是分配计数器的堆字节，不包含结构体元数据、共享 context 或服务端 key。

### 原型的正确性与误差验证

- 复用现有小参数 trace 测试，加上两段带符号下标、跨 2N 连续投影、非零尾部、空批次和写入前拒绝非法输出布局。独立 schoolbook 相位参照检查全部系数；没有增加大型普通测试。
- 现有 one-hot 测试验证全部/非零/joint 输出、pair 与单项结果、每层尺度、CMux/公开多项式消费和零分配；完整 LUT 测试继续覆盖剪枝、两字宽及两个 FFT 引擎。
- 另在临时诊断中，对基线/候选、seed 42/4242、消息 0..3、全部 selector 和全部层检查 **5376 个完整行相位**，并检查 **768 次实际 CMux 消费**。NLEV 与 `g_l*delta` 比较，NGSW 系数行与 `g_l*f*delta` 比较；所有系数误差小于相应 `g_l/2`，CMux 全部系数解码正确。不是仅检查常数项。

两 seed、两 BR、全部 selector/层合计的最大系数误差与该行 gadget scalar 的比值如下。它们是本轮 fixture 的观测值，不能当作尾概率或安全参数认证，也不证明共享一定减噪。

| 后端 | NLEV：基线 → 共享 | NGSW：基线 → 共享 |
| --- | ---: | ---: |
| NTT u32 | 5.534% → 5.534% | 8.867% → 8.867% |
| NTT u64 | 0.678% → 0.678% | 1.396% → 1.256% |
| RustFFT u32 | 0.585% → 0.592% | 1.531% → 1.728% |
| TFHE FFT u32 | 0.585% → 0.592% | 1.531% → 1.728% |
| RustFFT u64 | 0.000064% → 0.000071% | 0.001215% → 0.000989% |
| TFHE FFT u64 | 0.000061% → 0.000072% | 0.000934% → 0.000968% |

撤回前的整理版原型通过四个相关 crate 的 all-targets check/Clippy（`-D warnings`）及严格 rustdoc；普通和 nightly SIMD `nextest --lib --tests` 各 **78 项通过**。性能使用 stable 默认算术配置；SIMD 这里只作正确性验证。

### 测量方法与结果

硬件/工具链与前述基线相同，CPU 4/8 固定亲和性。基线固定为 `09e5f1b8`，候选保留相同参数、feature、seed 和所有 LUT 优化。保存各版本可执行文件，先编译再计时，不并发跑性能任务。每次 Criterion 迭代只做一个完整请求；setup、错误检查和分配诊断都在计时外。

[完整请求 CSV](data/shared-projection-implementation-measurements.csv) 保留所有成对测量，`change_pct=100*(shared/baseline-1)`，负数表示更快。`candidate` 是相同代数的私有原型，`final` 是整理后的借用接口版本，两者现均已撤回；二者分别与原基线比较，不能把两列混为一个二进制，也不代表当前生产实现。各轮协议：

| 轮次 | 覆盖 | warm-up / measurement / samples |
| --- | --- | --- |
| r1 | CPU 4 nonzero one-hot；CPU 4/8 完整 LUT，三引擎、两字宽、两 BR、三种表 | 0.3 s / 1 s / 20 |
| r2 | CPU 4/8，NTT/TFHE FFT，两字宽、两 BR、三种表，逐配置交替顺序 | 0.3 s / 2 s / 20 |
| r3 | 整理版原型，CPU 4/8，NTT/TFHE FFT，两字宽、两 BR、普通/shared 表 | 0.3 s / 2 s / 20 |
| r4 | 延长复测：TFHE FFT 两字宽 shared 表；NTT u32 普通/shared 表；两 CPU、两 BR | 0.6 s / 5 s / 30 |
| r5a～r5d | CPU 8 NTT u32 classic/shared，基线/最终版按 AB、BA、AB、BA 顺序 | 0.6 s / 5 s / 30 |

r1 的 CPU 4 先基线后候选，CPU 8 反序；后续逐配置交替。CSV 是 Criterion 点估计，未保留完整采样分布，不能据此宣称每个小差异都统计显著。classic 完整请求没有一致的加速幅度；r3 还出现 -14.06% 和 +5.96% 等大幅变化，r2 也有 +7.04% 点，不将这些作为优化收益。保留所有点，并延长对应类别的成对复测，不筛除异常结果。

原型 r1/r2 的 60 组 sparse 完整 LUT 成对结果中 57 组更快，变化中位数 -1.72%；整理版原型 r3/r4 的 24 组中 19 组更快，中位数 **-0.79%**。这些集合有重复配置、不同采样时长和选择性复测，数字仅描述本轮样本，不能作为跨配置平均加速比或显著性结论。没有用初版原型结果替代整理版原型测量。

整理版原型 r4 的 sparse 延长复测如下；u32 NTT 普通表 CPU 4 仍接近持平，没有宣称所有路径更快。

| sparse 配置 | CPU 4：基线 → 共享 ms（变化） | CPU 8：基线 → 共享 ms（变化） |
| --- | ---: | ---: |
| NTT u32 普通 | 47.548 → 47.687（+0.29%） | 47.393 → 46.824（-1.20%） |
| NTT u32 shared | 32.172 → 31.497（-2.10%） | 33.564 → 32.093（-4.38%） |
| TFHE FFT u32 shared | 31.051 → 30.569（-1.55%） | 31.849 → 31.540（-0.97%） |
| TFHE FFT u64 shared | 22.445 → 22.285（-0.71%） | 23.600 → 23.423（-0.75%） |

CPU 8 的 NTT u32 classic/shared 在 r4 为 +6.02%，r5a～r5d 为 -5.58%、+6.42%、+4.90%、-0.80%；两版绝对时间均有明显跨进程波动。这一路没有确认稳定收益，也无法将回退点直接归因于共享投影。这些点作为未解决的性能限制保留在记录中。虽然投影阶段确有减少，完整请求收益偏小，无法支撑新增空间和接口复杂度，因此撤回整个实现，不增加按 CPU/BR 选择的策略分支。


额外阶段探针只比较 CPU 4 的 sparse 完整 LUT，NTT/TFHE FFT、两字宽、三表：投影从基线到原型减少 **5.36%～12.02%**。该范围在两侧都包括 selector 移位；候选还包括共享准备、组合及剩余 trace，排除 BR/SS。例如 NTT u32 普通表 8.376 → 7.603 ms，TFHE FFT u32 普通表 8.539 → 7.616 ms。探针调用次数由 25/19 变成 33/25，是额外计入每个输入一次共享准备；不是新增 selector。此计时边界比前述成本研究多包含外层 selector 移位，不能直接混用比例。完整收益以无插桩 CSV 为准。

历史测量使用以下现有 bench 入口。当前执行会测到恢复后的原实现；候选源码与临时二进制已清理，命令本身不能重现已撤回候选。若以后重新研究，须重建原型并重新获取相邻基线：

```sh
taskset -c 4 cargo bench -p primus_tfhe_ntru_lut --bench pipeline --features ntt,rustfft,tfhe-fft -- 'lookup/(ntt|rustfft|tfhe_fft)/u(32|64)/(classic|sparse)/.*/evaluate$' --warm-up-time 0.3 --measurement-time 2 --sample-size 20 --noplot
taskset -c 8 cargo bench -p primus_tfhe_ntru_lut --bench pipeline --features ntt,rustfft,tfhe-fft -- 'lookup/tfhe_fft/u(32|64)/(classic|sparse)/.*/shared_middle_chunk/evaluate$' --warm-up-time 0.6 --measurement-time 5 --sample-size 30 --noplot
```

结论只覆盖这里的参数和负载。更大的 M、不同输出 basis、长 CMux 树以及其他秘密/噪声组合，仍须按上面的相关误差契约重新预算；不推广到 GLWE CBS 或两级共享。临时探针、诊断和隔离构建在记录后清理，未给普通 CI 增加基准或大型统计测试。
