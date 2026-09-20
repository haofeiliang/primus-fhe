# TFHE R1–R4 整理成本

本文件只记录已测的结构调整，实施范围见 [R1–R4 计划](tfhe-refactor-plan.md)。
数值对照保存于 [R1 CSV](benchmarks/tfhe-r1.csv) 和 [R2 CSV](benchmarks/tfhe-r2.csv)，
R3 测试资产的数量与耗时直接记录在本文末节；不能据此推断未测参数、后端或平台的性能。

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

## R2：evaluator 所有权与工作区

直接基线为 `618768d`。仍使用上述 Ryzen 9 9955HX3D、逻辑 CPU 0 和仓库
`target-cpu=native` 配置；默认用 rustc 1.98.0，SIMD 用
rustc 1.100.0-nightly（2026-08-26）。同一 feature 内对照，不把不同工具链之间的差异归因于 SIMD。

### 保留的所有权与检查边界

- MVB/CBS 消费普通 evaluator，只构造额外缓冲区；回收时保留原 PBS 分配。
  `bootstrapper_mut()` 返回按值传递的不透明借用，只实现已有两个 PBS trait；
  交换这个借用不会交换内部 evaluator。共享 trait 对 `&mut B` 的转发无需虚调用或堆分配。
- GLWE 独立 BR→KS CBS 不构造 KS 工作区；其普通 PBS 借用为 `None`，转回普通
  evaluator 时显式分配缺失资源。KS→BR 保留前置 KS；从普通 evaluator 转入的 CBS
  保留完整资源。用户无需同步内部模式或 basis。
- GLWE BR、scheme-switch 和输出控制消费通过一次作用域借用共用外积缓冲。
  `with_rebound` 在正常返回和 unwind 时恢复布局，ternary 合成控制继续绑定原 BR basis。
- NTRU 的私有枚举同时持有控制材料与对应 scratch。CBS 的 trace 使用明确的 `2N`
  系数 scratch 和已有 BR 外积工作区；Fourier 路径无需变换输入专用的排列缓冲。
  现有 owning trace/automorphism 接口仍支持原来的用途，投影算法不变。
- GLWE Fourier sparse+CBS 先完成检查和 map-only 重试，再变换一次 accumulator 秘密供两者使用，
  在生成 KSK 前释放；私有选择记录和临时秘密保留原有擦除行为。NTT 的同类原型经完整计时后撤回，
  保持原生成实现；原因见下文。

### 测量方法

从基线完整源码与当前源码分别构建同名包和既有 `pbs`、`circuit_bootstrap`、`mvb` 基准，
保留独立可执行文件。在线计时复用所有输出/工作区，setup、验证和密钥生成在计时外；
计时期间不运行编译或测试。未关闭 boost/SMT，因此小比例变化仍需反向复测。

```text
cargo bench -p <backend> --bench <pbs|circuit_bootstrap|mvb> --no-run
cargo +nightly bench -p <backend> --bench <pbs|circuit_bootstrap|mvb> --features simd --no-run
taskset -c 0 <binary> --bench <filter> --noplot \
  --sample-size 15 --warm-up-time 0.5 --measurement-time 1.5 --nresamples 10000
```

首轮使用 10 samples、0.3 s warm-up、1 s measurement，顺序为旧→新；反向复测采用上面的设置。
PBS 选择 `complete_pbs_reused_output`；MVB 选择 k=3 的 `factorized`；GLWE CBS 覆盖两种 order
和 classic/sparse，NTRU CBS 选择 `N=1024, log_basis=10`。字宽、FFT 和秘密分布随既有基准标签记录。

完整 sparse+CBS keygen 在原 CBS 基准上临时添加测量入口：复用相同 client/context/generator，
调用 `try_generate_sparse_server_key(client, 3, 64, Some(cbs_config), rng)`，用
`iter_batched(..., BatchSize::PerIteration)` 将返回密钥析构排除在计时外。GLWE NTT 使用既有
u64 CBS 配置；Fourier 使用 `examples/support/circuit_bootstrap.rs`。两者都是
`n/h/N=728/32/1024`，不改变已记录的功能/成本参数性质。keygen 首轮用 10 samples、0.5 s warm-up、2 s measurement，反向复测用 1 s warm-up、3 s measurement。
构造分配通过现有 `primus_test_allocations` 计数，持有字节是申请量减释放量，不含 allocator 元数据、
context/table、server key 或调用方输出。临时入口不进入 CI 或持久 benchmark target。

### 构造与持有资源

下表是独立 CBS 构造，`u64,N=1024`。GLWE 的 n/h=728/32，NTRU 的外部维数为 64，
BR/trace/SS `log_basis=10`、输出 `(8,2)`；这是功能/成本参数，不是等安全参数比较。
Fourier 两种 FFT 在这个 N 下的请求量相同。分配次数包含构造临时量；字节只统计构造结束仍持有的堆内存。

| 后端 / order / BR | 分配次数：旧→新 | 持有字节：旧→新 |
| --- | ---: | ---: |
| GLWE NTT / BR→KS / classic | 26→16 | 288456→198656 |
| GLWE NTT / BR→KS / sparse | 28→18 | 458120→368320 |
| GLWE NTT / KS→BR / classic | 26→22 | 288456→254664 |
| GLWE NTT / KS→BR / sparse | 28→24 | 458120→424328 |
| GLWE Fourier / BR→KS / classic | 28→18 | 304840→215040 |
| GLWE Fourier / BR→KS / sparse | 31→21 | 703880→614080 |
| GLWE Fourier / KS→BR / classic | 28→24 | 304840→271048 |
| GLWE Fourier / KS→BR / sparse | 31→27 | 703880→670088 |
| NTRU NTT | 15→10 | 108544→82944 |
| NTRU Fourier | 18→12 | 133120→99328 |

GLWE 共享外积节省 33 KiB；独立 BR→KS CBS 另外省去 56,008 B 的 KS 工作区。
从已有普通 evaluator 消费转入时刻意保留 KS 资源，只获得前一项节省。
NTRU NTT/Fourier 分别节省 25/33 KiB，Fourier 额外省去仅供变换域输入使用的排列缓冲。
已有测试覆盖首调用、脏 scratch、PBS/MVB/CBS 交替和回收零分配；独立 GLWE BR→KS 的显式恢复例外有单独断言。

### 在线时间与 scratch 取舍

初轮默认/SIMD 各 40 项完整负载，变化范围分别为 −5.43%～+2.99%、−3.24%～+4.23%。
初轮 GLWE Fourier CBS 的过滤器未命中，后续反向轮补测全部八项；没有用未运行的数据作分母。
反向轮共默认 31 项、SIMD 30 项，覆盖全部 CBS、Fourier 完整 PBS 和选定 MVB/ternary 负载。
CSV 中 `online` 的 round=1 是初版 R2，round=2 使用最终借用接口；算术相同。
NTT keygen 撤回后的 GLWE NTT PBS/CBS/k=3 MVB 另列 `online_final`，避免把原型当作最终构建。
该最终轮各 10 项，默认 −1.35%～+1.27%、SIMD −0.88%～+2.40%；CBS 子集分别为
−0.82%～+1.27%、−0.40%～+2.40%，与前一轮的方向变化也保留在数据中。

- GLWE Fourier CBS 反向轮变化为默认 −4.48%～+2.30%、SIMD −2.32%～+1.91%；GLWE NTT 同轮为默认 −2.11%～+0.16%、SIMD −1.01%～−0.05%。保留外积共享及按用途分配，不声称 CBS 普遍加速。
- NTRU Fourier CBS 反向轮 RustFFT/tfhe-fft 分别为默认 +0.25%/+0.09%、SIMD +1.23%/−0.60%。保留显式系数 scratch 和共享外积。
- **NTRU NTT SIMD CBS 保留了小幅回退**：初轮 +2.95%、反向轮 +2.34%（约 0.758→0.776 ms），默认反向轮约 +0.14%。不能将其写成时间持平。

针对最后一项，另在相同 R2 源码中只恢复 NTT CBS 的 owning trace context，比较三个独立程序。
每项 20 samples、1 s warm-up、2 s measurement、10,000 resamples，顺序分别为
基线→共享→独立、独立→共享→基线，结果如下（ms）：

| 轮次 | R1 基线 | R2 共享 trace scratch | R2 独立 trace scratch |
| --- | ---: | ---: | ---: |
| 1 | 0.7566 | 0.7721 | 0.7756 |
| 2 | 0.7560 | 0.7762 | 0.7729 |

共享相对独立分别为 −0.45%、+0.43%，恢复独立工作区未消除相对基线的回退。
因此保留确定的 25 KiB 资源收益；剩余构建间差异尚未定位，不能归因于 scratch 共享，
也不能因隔离结果而忽略整体成本。没有保留尝试过、但未改善结果的额外 `#[inline]`。

其他在线项目也有方向相反的复测结果，例如 NTRU tfhe-fft u64 PBS 默认从初轮 +2.36% 变为 −1.66%。
各均值的 Criterion 区间只描述一次运行的采样误差，不覆盖 boost、调度、构建或代码布局差异。
本步保留清晰所有权和内存收益，不作完整 PBS/MVB 普遍加速或零回退承诺。

### 完整 sparse+CBS keygen

下表列出两轮完整生成的耗时变化。NTT 行是**已撤回原型**，Fourier 行是保留实现。

| 后端 | 默认：首轮 / 复测 | SIMD：首轮 / 复测 | 决定 |
| --- | ---: | ---: | --- |
| NTT | +1.22% / +1.68% | +2.93% / +2.76% | 撤回秘密变换复用 |
| Fourier RustFFT | +0.45% / +0.85% | −13.40% / −5.40% | 保留 |
| Fourier tfhe-fft | +0.09% / +0.28% | −5.22% / −5.23% | 保留 |

NTT 进一步做两轮隔离：只把 `key.rs` 和 `sparse/key.rs` 恢复为 `618768d`，保留其余 R2。
SIMD 三方完整生成时间分别为（基线 / 共享秘密原型 / 恢复生成代码）：
`408.639 / 418.944 / 408.736 ms`、`409.499 / 433.752 / 409.540 ms`。
第二轮共享原型波动更大，但恢复原代码在两轮均回到基线，故撤回对应更改及私有准备类型。
以后如重新尝试，应先解释整个生成内核的退化，不能仅以少一次 NTT 作为验收依据。

Fourier 删除了一次重复秘密变换，未增加长期秘密缓存或改变 RNG/重试顺序。
完整生成的变化还受代码生成、分配布局和测量环境影响，不能把约 5% 的 SIMD 差异全部归因于一次 FFT；
默认配置也没有时间改善证据。保留去重与测得的限制，不声称加速在线 PBS。

### 数据与验证边界

[R2 CSV](benchmarks/tfhe-r2.csv) 保存每轮均值、95% 区间及相对变化，单位 ns。
`trace_isolation` 用同版独立 scratch 作分母；`keygen_isolation` 用同版恢复原生成代码作分母，
其余 baseline/online/keygen 行用 R1 基线。临时诊断不进入 CI，也不增加持久 bench target。

TFHE 七包的默认/SIMD 测试各 87 项、workspace all-targets、严格 Clippy/rustdoc 和两个修改过的
release 示例通过；下层 lattice/GLWE/NTRU 默认/SIMD 各 89 项及严格 Clippy/rustdoc 通过。
撤回 NTT keygen 后补跑该后端默认/SIMD 测试和 all-targets Clippy。
TFHE 测试数未增加，下层仅新增一项 unwind 恢复测试；现有数值/分配测试承担交替执行的覆盖。
未测非 x86、生产安全参数、任意 N/basis 或全部算法组合；不以这些结果证明噪声尾界或恒时性。

## R3：测试资产整理

2026-09-20，直接基线 `ba85493`，对照 R3 工作区。环境为同一台 Ryzen 9 9955HX3D、
x86_64 Linux，默认 rustc 1.98.0，SIMD nightly 1.100.0（2026-08-26），cargo-nextest 0.9.143。
沿用仓库 `target-cpu=native`，未绑定 CPU、未关闭 boost/SMT；计时期间没有另开编译或测试任务。

两版分别连续运行三次以下命令；SIMD 将 `cargo nextest` 替换为 `cargo +nightly nextest`，
并加 `--features simd`。数据取 nextest 的 Summary 时间，仅包含测试执行，不包含编译或文档构建。

```sh
cargo nextest run --offline --test-threads 2 \
  -p primus_tfhe -p primus_tfhe_glwe -p primus_tfhe_glwe_ntt -p primus_tfhe_glwe_fourier \
  -p primus_tfhe_ntru -p primus_tfhe_ntru_ntt -p primus_tfhe_ntru_fourier
```

| 配置 | 测试数：旧→新 | 基线三次 / s | R3 三次 / s | 中位数：旧→新 / s |
| --- | ---: | --- | --- | --- |
| 默认 | 87→86 | 5.184 / 5.095 / 5.112 | 5.180 / 5.102 / 5.094 | 5.112→5.102 |
| SIMD | 87→86 | 5.096 / 5.040 / 5.038 | 5.055 / 5.033 / 5.042 | 5.040→5.042 |

两份后端 CBS 参数错误矩阵合并为家族测试，非法 CBS 配置在密钥生成消耗 RNG 前拒绝的检查
保留在后端。GLWE `many_lut` 测试更名为 `pbs`，数值函数体不变；其余独立相位、selector/dummy、
非恒定 CMUX、不同表示与首调用零分配覆盖不变。测试整理减少维护重复，本机运行时间基本持平。
这里没有采用 GitHub CI 的 CPU、构建缓存或 flags，也未测在线算法时间，不声称 CI 或 PBS 加速。
上述计时在后续默认 codec 入口补充前完成；接口迁移后的测试数量仍为 86 项，未重新计时。

七包共 19 个持久 benchmark target，未增删独立负载。GLWE NTT 的历史 n=512 PBS 参数
由公共 `boolean_parameters()` 移入 `benches/support/mod.rs`，参数值、基准名称和计时工作不变，
不将这个成本 fixture 当作安全参数推荐。模块迁移只调整路径、导入和必要的 crate 内可见性。
GLWE CBS 示例更名为 `ntt_circuit_bootstrap` / `fourier_circuit_bootstrap`，消除联合构建的
输出冲突；仅更名，不影响上面的 nextest 负载或统计，两个新入口另行执行 release 验证。
