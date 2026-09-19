# u64 SIMD 补测

## 结论与修改边界

2026-09-19 补测了此前未记录的 u64 性能。`modulus` / `factor` 既有微基准已经包含
u64；此前 sparse PBS 的完整链测量使用 u32，本轮另外构造了 u64 fixture。
首次补测只记录结果；随后完成了 Native 旋转定位和 Shoup 原地乘法的定向验证，
最终选择与新增测量见文末“内核收尾”。

| 操作 | 结果与选择 |
| --- | --- |
| Native / Barrett 加减 | 当前普通循环在固定长度切片上通常更快，保留已暂存实现；不能宣称所有旋转切片都不退化，见下文 |
| u64 Barrett 乘法、乘加 | 手写 SIMD 比普通循环快约 45%–53%，保留 SIMD |
| u64 Barrett 点积 | 手写 SIMD 快约 50%–52%，保留 SIMD |
| u64 Shoup 原地乘法 | 首测手写 SIMD 慢 6.7%–9.1%；同 feature 的源码对照确认普通循环快约 6%–7%，已定向替换 |
| Shoup 其他入口 | u64 多数接近；u32 大切片的乘加/乘减仍受益于 SIMD，不能整体替换 `common::simd` |
| Native 取负、乘法、乘加 | 结果随操作、长度和轮次变化，本轮不足以支持统一替换 |

修改以具体操作为单位；Shoup 已同时检查 u32、尾部和实际消费者。
不要因为存在 SIMD feature，就要求所有操作都手动分块；
也不要把加减的结果推广到 widening multiplication、Barrett 约简或整个 `factor` crate。

## 方法

- Ryzen 9 9955HX3D，固定逻辑 CPU 2、串行运行；boost / SMT 开启，CPU 未隔离。
  两种 feature 均使用 nightly `1.100.0 (bff8e12ff 2026-08-26)`、仓库
  `target-cpu=native` 配置、Criterion 0.8.2。每轮交换版本运行顺序。
- 微基准复用 `slice_arithmetic`、`slice_moduli`、`barrett_slice` 和 `shoup_factor`，
  覆盖 N=1024/1025/4096，Barrett / Shoup 的 q=1125899906826241。
  Shoup 和 scalar multiplication 的乘数为 17，预计算、分配在计时外。
  点积及逐项乘法测 N=1024/4096；Native `add_to` 单独测 N=4096。
- 临时旋转基准每次调用一次 `add_mul_monomial_assign`，指数按
  `(exponent + 37) & (2*N - 1)` 变化，覆盖 Native / Barrett、N=1024/4096。
  计时前以 u128 系数 oracle 检查 0、1、N−1、N、N+1、2N−1 的回绕与符号。
- 初测微基准为 20 samples、0.1 s warm-up、0.4 s measurement；不确定的加减、旋转
  延长到 0.3 / 1 s。完整 PBS 为 20 samples、0.2 / 1 s，NTT sparse 复测为
  0.5 / 3 s；keygen 为 10 samples、Flat sampling、0.2 / 1 s。
  Criterion 在不足以采满样本时延长实际测量。
- 每次迭代一个工作负载；PBS 复用 key、输入、输出和 evaluator；keygen 包含 BSK+KSK，
  排除客户端生成与返回 key 的析构。没有增加 CI 测试数量或持久基准目标。

[CSV](benchmarks/simd-u64.csv) 保留全部轮次的均值及轮内 95% CI，单位为 ns；
初测负向结果没有删除。轮内区间不能解释跨进程布局、调频等系统差异。

### 对照版本

| CSV variant / comparison | 含义 |
| --- | --- |
| `current-default` / `current-simd`，`other-kernels` | 同一当前源码关闭/开启 SIMD；比较尚未改写的乘法、取负、factor 等入口 |
| `before-simd` / `current-simd`，`add-sub`、`rotation`、`pbs`、`keygen` | 旧加减与旧常数 keygen，对照当前整组优化，均开启 SIMD |
| `*-recheck` | 使用相同可执行文件延长测量，不筛掉初测结果 |
| `isolate-simd` / `current-simd`，`add-sub-only-pbs` | 两边都使用新 keygen，仅比较旧/新加减，隔离完整链中的加减影响 |
| `factor-u32-control` | 对 Shoup 的 u32 乘法、乘加、乘减补充相同 feature 对照 |

旧实现取自 `5102a4b`，其余源码保持本轮开始时已暂存的版本。`before-simd` 恢复的文件是：
modulus 的 `native/{slice,simd}.rs`、`barrett/slice.rs`；GLWE 的
`secret_key/ntt/{batch,coefficient,context,gadget}.rs`、`secret_key/fourier/batch.rs`；
两个 GLWE TFHE 后端的 `sparse/key.rs`。`isolate-simd` 只恢复前三个 modulus 文件。
因此整组 keygen 收益不能全部归因于加减，也不能与前次 u32 分阶段百分比相加。

## 加减与旋转：保留负向信号

固定长度切片的普通循环通常有收益：Barrett N=1024/1025 初测两轮快约 16%–35%；
Native 同长度初测曾反向波动，延长测量后，加减原地入口快约 19%–21%，`sub_to` 快约 12%。
N=4096 的 Barrett `add_to/sub_to` 延长测量为 −2.3%～+1.7%，接近持平。

但旋转切片不能由整段加减推断。以下是延长测量的均值，单位 ns：

| 旋转累加 | 第一轮旧→新 | 第二轮旧→新 |
| --- | --- | --- |
| Native N=1024 | 59.73→59.00 | 60.98→53.82 |
| Native N=4096 | 331.96→341.40 | 333.60→340.34 |
| Barrett N=1024 | 57.04→61.09 | 63.75→57.14 |
| Barrett N=4096 | 342.11→344.67 | 344.14→344.51 |

Native N=4096 的微基准四轮均有约 2%–4% 的负向信号，延长测量仍慢 2.0%/2.8%；
首次补测没有将这项判为已解决。两版旋转函数在该基准中均内联，不能归因于恢复内联。
后续补充了对齐控制和 N=4096 完整 PBS，候选方案未优于当前取舍，详见文末；
最终没有为 Native 增加按长度或整数类型的热路径分派。

## 完整 PBS 与 keygen

临时 fixture 从两个后端的 `benches/sparse_pbs.rs` 转为 u64：NTT 使用 `U64NttTable`、
q=1125899906826241；Fourier 使用 Native u64，small-LWE sigma 相应按 2^64 缩放。
其余布局保持 n=728、h=32、N=1024、k=1、t=8、c=3、64 桶，
NTT BR 为 7×3、Fourier BR 为 8×3、KS 为 2×13；seed 为 `0x5035_4252 + 728`。
同一客户端生成 classic / sparse key；普通 LUT 为 `(3*m+1)%8`，三输出为 `(m+2*i)%8`。
每次 setup 检查两种 order、两种 LUT 下四个加密输入的解密结果，
**计时只测 BootstrapKeyswitch**。这是保持分解布局的成本检查，没有重新认证 u64 参数的失败率。

整组优化初测中，NTT classic PBS 约快 0.5%–1.1%；RustFFT sparse 普通/三输出快约
2.5%–3.5%；TfheFFT sparse 单输出快约 3.3%–4.1%，三输出两轮为 +1.3%/−1.1%。
NTT sparse 出现 +0.2%～+4.7% 的负向信号；延长测量仍为 +0.3%～+4.4%，
所以进一步保留新 keygen，仅恢复旧加减进行隔离：

| sparse PBS，ms | 第一轮旧加减→新加减 | 第二轮旧加减→新加减 |
| --- | --- | --- |
| NTT 单输出 | 10.031→10.002 | 10.020→9.910 |
| NTT 三输出 | 9.863→10.071 | 9.967→9.876 |
| RustFFT 单输出 | 9.122→8.818 | 9.904→8.788 |
| TfheFFT 单输出 | 9.051→8.858 | 9.122→9.252 |

隔离对照没有重现稳定的 NTT 加减退化；不能将整组初测的全部差异归因于加减。
RustFFT 第二轮旧版耗时也明显高于其余轮次，不据此声称 11% 的稳定收益。
保留当前加减实现，但不宣称 u64 全路径无退化或统一加速。

整组 keygen 优化结果如下，单位 ms：

| keygen | 第一轮旧→新 | 第二轮旧→新 |
| --- | --- | --- |
| NTT classic | 62.689→58.942 | 63.259→58.903 |
| NTT sparse | 223.870→198.198 | 222.964→198.014 |
| RustFFT classic | 64.046→61.452 | 62.315→60.578 |
| RustFFT sparse | 276.294→279.132 | 274.790→273.652 |
| TfheFFT classic | 61.749→61.855 | 61.970→64.767 |
| TfheFFT sparse | 275.247→272.345 | 274.606→272.308 |

NTT classic 快约 6%–7%，sparse 快约 11%；Fourier 的变化较小或受轮次影响，
保留 TfheFFT classic 第二轮 +4.5% 的负向结果。

## factor 与代码生成

Shoup u64 原地乘法三种长度、两轮均是普通循环更快；其他三个入口的 SIMD 相对变化为
−5.6%～+3.5%。u32 控制组 N=4096 的 SIMD 乘加快 9%–11%、乘减快 12%–15%，
不支持把全部 factor 切片替换为普通循环。

检查本次可执行文件，Shoup u64 原地乘法的两种实现都含标量 `mulx` 与向量
`vpmullq/vpsubq/vpminuq`；手写 SIMD 版本还带有不同的分块、展开和尾部代码。
Rust 源码使用 `Simd` 不能保证所有指令都是 SIMD，普通循环也不等于标量机器码。
源码分析覆盖了 Shoup scalar/SIMD、共享切片 kernel 和整数 widening-mul 路径；
这里的结论不覆盖 BarrettFactor、Lazy factor 全族、其他 CPU 或编译器版本。

## 复现与验证

现有微基准可直接筛选 u64；两版都使用同一 nightly，交换顺序复测：

```sh
taskset -c 2 cargo +nightly bench -p primus_modulus --bench slice_arithmetic -- \
  '/u64/' --sample-size 20 --warm-up-time 0.1 --measurement-time 0.4 --noplot
taskset -c 2 cargo +nightly bench -p primus_factor --bench shoup_factor -- \
  '/u64/' --sample-size 20 --warm-up-time 0.1 --measurement-time 0.4 --noplot
```

加 `--features simd` 比较 SIMD；Barrett 逐项乘法和点积改用 `barrett_slice`，
筛选 `barrett/slice/u64/(mul|dot_product)/(1024|4096)/`。
完整 u64 PBS 需按上文参数转换既有 sparse fixture；不要直接运行其 u32 默认参数并标为 u64。
旧/新源码对照应分别保存可执行文件，保持 fixture、工具链和 feature 不变。

本轮计时前的 u128 旋转 oracle、完整 PBS 解密检查通过；另运行当前实现的
`slice_add_sub` 与 `constant_gadget`，在同一 nightly 默认/SIMD 下验证 u32/u64
数值边界、系数/变换表示及 RNG 消费。没有把历史 workspace 测试当作本轮结果。

## 内核收尾

### Native：保留普通循环，撤回未获收益的原型

保持同一 nightly / SIMD 配置及 CPU 2，输入和输出显式按 64 字节对齐，并分别测
零偏移和偏移一个系数的切片。u64、N=4096 的普通循环仍比旧 SIMD 慢约 3%–4%，
说明之前的差异不能仅归因于分配地址。两版微基准均内联；生成的主循环、尾部处理及
重叠检查不同，但没有将全部差值归因于某一条指令。

依次试验了以下写法，均未保留：

- `for_each` 改为 `for`：生成的 u64 旋转指令相同。
- u64 使用八元素普通数组分块：N=4096 约 2.4 µs，明显慢于约 0.33 µs 的原循环。
- 仅恢复 SIMD u64 的 `reduce_add_slice_assign` / `reduce_sub_slice_assign`：
  微基准恢复至约 0.32–0.34 µs，但完整 PBS 再次出现独立旋转函数调用。
- 在上述 SIMD 原型上强制内联旋转函数：独立调用消失，完整消费者仍无一致收益。
  两轮 RustFFT sparse PBS 的单输出在 N=1024 慢 5.8%/5.4%，三输出慢 2.5%/3.4%；
  N=4096 单输出慢 7.5%/0.7%，三输出慢 8.1%/0.3%。TfheFFT 也没有一致优势。

因此保留原普通循环，接受已记录的 N=4096 微基准差异，不为它增加特殊分派或强制内联。
这是一项基于完整消费者的取舍，不表示所有 u64 内核均无退化。

完整 PBS 沿用上文 u64 fixture，另外将 N 改为 4096；覆盖两种 FFT、BK order、
classic / sparse、单输出 / 三输出。密钥、LUT、输出及工作区在计时外构造，每次 setup
检查四个实际加密输入。最终原型另补 N=1024 的 sparse 单/三输出。
普通旋转初测 20 samples、0.2/0.6 s，末轮 0.3/0.8 s；PBS 20 samples、
0.5/2 s（N=1024 warm-up 0.3 s）。所有组两轮交换版本顺序，保留异常轮次。

### Shoup：只替换 u64 原地规范乘法

SIMD 配置中的 `ShoupFactor<T>::factor_mul_slice_assign` 在 `T::BITS == 64` 时
复用已有 `common::slice` 循环，其余字宽继续使用原 SIMD 内核。该选择在单态化时折叠，
没有运行时 CPU 检测、逐系数分派、新 trait 或公开 API 变化。
`mul_to`、lazy、乘加、乘减及 Barrett 算术均不变。

两边都开启 SIMD，仅切换这个方法，20 samples、0.2/0.6 s。单位 ns：

| u64 长度 | 第一轮 SIMD→普通循环 | 第二轮 SIMD→普通循环 |
| --- | --- | --- |
| 1024 | 329.46→307.69 | 329.36→307.60 |
| 1025 | 331.86→309.01 | 331.02→309.25 |
| 4096 | 1327.23→1229.67 | 1312.23→1229.32 |

改动入口快 6.3%–7.4%；u32 原地乘法控制项为 +0.0%～+2.5%，实现未切换。
u64 内核的生成代码明显缩短，未将该收益外推到其他 factor 方法或整个 PBS。

实际消费者选用已有 `primus_glwe / primitives` 的 NTT `expand_partial/8`，
其规范化步骤调用这个 Shoup 方法；参数为 `(k,N)=(1,1024)/(2,4096)`、q=1125899906826241，
完整复用密钥、输出和 scratch。首测整体变化为 +0.5%/+0.8% 与 +3.1%/+1.1%。
增加未修改的 `trace` 控制后，复测使用 20 samples、0.5/3 s：

| 消费者 | 第一轮耗时变化 | 第二轮耗时变化 |
| --- | --- | --- |
| k1 N1024，部分展开 | +1.7% | +0.2% |
| k1 N1024，trace 控制 | −0.1% | +0.3% |
| k2 N4096，部分展开 | −0.4% | +2.6% |
| k2 N4096，trace 控制 | +0.1% | +2.5% |

整体没有稳定收益；后一轮大参数控制项也同幅变慢，不能把全部差异归因于 Shoup。
保留内核改善，并记录消费者的小幅负向结果，不宣称完整调用等时或加速。

### 数据与验证

[收尾 CSV](benchmarks/simd-u64-followup.csv)保留 392 项均值和 95% CI。
`current` / `native-before` 为本轮前的普通循环；`old-native` 为旧 Native SIMD；
`native-chunks` 为数组分块；`native-fix` 为仅恢复 u64 原地 SIMD；
`native-inline` 再强制内联，三种原型均已撤回。
`factor-before` / `factor-after` 只对照 Shoup 方法，使用相同 Native 实现；
NTT 消费者不依赖 Native 运算。临时 harness 不加入 CI。

既有 Shoup 切片测试改为确定性的 u32/u64 共用测试，以独立 u128 乘积取模作 oracle，
覆盖两个字宽的模数上界、0/1/q−1 因子、空切片、偏移和向量尾部，继续检查 lazy 范围；
不增加测试数量。Native 源码恢复到本轮开始状态，不保留原型代码或新增 benchmark 目标。

最终源码通过 modulus / factor / poly / lattice / GLWE / NTRU 六包默认与 nightly SIMD 的
`check --all-targets`、Clippy `-D warnings`、测试，以及 `just tfhe` / `just tfhe-simd`。
格式与 diff 检查通过。既有跨包同名 `circuit_bootstrap` 示例的输出路径警告仍存在。
