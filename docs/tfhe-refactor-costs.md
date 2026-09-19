# TFHE R1–R4 整理成本

本文件只记录已测的结构调整，实施范围见 [R1–R4 计划](tfhe-refactor-plan.md)。
数据保存于 [tfhe-r1.csv](benchmarks/tfhe-r1.csv)，不能据此推断其他参数或在线 PBS 的性能。

## R1：LUT 共享构造

2026-09-20，基线 `cba9c01`，对照 R1 工作区。CPU 为 Ryzen 9 9955HX3D，
x86_64 Linux、rustc 1.98.0、Criterion 0.8.2、默认 features，沿用仓库
`target-cpu=native`。固定逻辑 CPU 0，计时期间不运行编译或测试；未关闭 boost/SMT。

### 方法

将基线 GLWE family 源码复制成临时独立包，保留原包名；同一个测量入口分别链接基线和
当前 family，生成两个程序。两者使用相同且本轮未改的底层算法。调用实际的 `compile_lookup_table_fn`
或 `compile_interleaved_lookup_table_fn`，每次构造并析构一个 LUT。
参数、codec 和 Criterion setup 在计时外；参数引用、输出 codec、输出数和结果经 `black_box`。
不把手写简化版流程或同时装入两个重命名 crate 的程序作为最终基线，避免它们改变对照条件。

- `u32, N=1024`；Native 或 Barrett `q=132120577`。
- `(t_in, output_count)` 为 `(16,1)`、`(16,3)`、`(255,4)`；`t_out=512`。
- 单输出函数为 `m`，多输出为 `m+j`；GLWE 维数 1、small-LWE 维数 4、
  binary、sigma=0.7、BR/KS basis `(8,None)`、BR→KS。这里只构造参数和 LUT，不生成密钥。
- 每项 30 samples、0.5 s warm-up、1 s measurement、10,000 次 bootstrap resampling。
  三轮前后顺序为旧→新、新→旧、旧→新；每轮均重新采样，不复用首次计时作为固定分母。

比较程序的运行参数为：

```text
taskset -c 0 <comparison-binary> --bench --save-baseline <round-and-version> \
  --sample-size 30 --warm-up-time 0.5 --measurement-time 1 --nresamples 10000 --noplot
```

临时比较程序已清理，不增加 CI 测试或持久 bench target。
复测时按上述参数分别实例化两个版本的 family 构造入口；每项的每轮均值与 95% 区间见 CSV。

### 结果与取舍

下表采用三轮均值的中位数，单位 ns；百分比是两列中位数之比，不是独立的统计置信区间。

| 模数 | t / 输出数 | 基线 | R1 | 变化 |
| --- | --- | ---: | ---: | ---: |
| Native | 16 / 1 | 98.02 | 92.67 | −5.5% |
| Native | 16 / 3 | 238.39 | 226.97 | −4.8% |
| Native | 255 / 4 | 1357.05 | 1417.00 | +4.4% |
| Barrett | 16 / 1 | 145.21 | 141.88 | −2.3% |
| Barrett | 16 / 3 | 253.41 | 251.73 | −0.7% |
| Barrett | 255 / 4 | 1750.12 | 1703.89 | −2.6% |

共享构造消除了两族的重复检查/编码实现，但**并非所有构造负载都更快**。
Native `255/4` 三轮分别变化 −0.5%、+4.6%、+4.5%，中位数约多 0.06 μs；保留这项已测成本。
小负载也受构建和代码布局影响，不能将单轮差异解释为稳定的算法收益。

保留共享实现、薄构造入口和输出检查/编码 helper 的 `#[inline]`，避免不必要的调用。
没有为匹配微基准增加特化类型、额外缓存或更改 LUT 填充算法。
曾观察到未内联输出 helper 时 Native 大域构造约慢 9%；最终对照采用补齐内联后的版本。
代码布局会影响这些短负载，剩余差异的确切微架构原因尚未定位。

raw 编译器、结果布局和分配策略未改。聚焦测试验证普通、交错、odd-full 的构造
只分配最终多项式，并保留中心、符号、回调顺序、输出编码和错误边界。
本轮没有测量 u64/SIMD 构造或完整 PBS/CBS/MVB 时间，也不声称它们加速。

### 既有 raw 基准

另将 `cba9c01` 的原名 `primus_tfhe` 包及未改的 `benches/lookup_table.rs` 单独构建，
与当前版本分别运行相同的固定 CPU/采样参数。命令为
`cargo bench -p primus_tfhe --bench lookup_table --no-run`，随后对生成的程序使用上面的 Criterion 参数。
CSV 的 `raw` 行保存全部 12 项前后结果，输出为 `13*m+j`，与 rounded family 负载不同。

这组单轮短负载差异为约 −8.0%～+7.2%，不是零回退证明。raw 编译源码没有变更，
本次未定位这些构建间差异的原因，也不将其解释为算法加速或劣化。
R1 保留去重收益及上述构造成本限制；若后续应用频繁重建 LUT，应按实际编译环境复测。
