# TFHE 基准

[English](README.md) | 简体中文

`primus_tfhe_benchmarks` 是放在生产 crates 之外、不发布的 workspace 工具。四个具体 TFHE 后端与 NTRU 高精度查表共享[算术参数](src/parameters/mod.rs)、注册规则和报告。这些参数没有经过安全性或失败概率评估。

## 快速开始

在仓库根目录运行，日常只需选择运算：

```sh
just bench pbs          # 普通 PBS
just bench sparse       # 固定重量 classic/sparse PBS 对比
just bench cbs          # 普通 CBS 的 classic/sparse 对比
just bench one-hot      # NTRU one-hot：完整/紧凑输出
just bench mvb          # D8/k3：三条路径，classic/sparse
just bench lut-create   # 高精度 LUT 创建（含释放）
just bench lut          # 高精度 LUT 同态求值：classic/sparse
```

运算名必填，单独的 `just bench` 不会隐式运行 PBS。默认串行运行**四个后端的常用 u64 用例**；`one-hot`、`lut`、`lut-create` 运行支持它们的 NTRU NTT 和 NTRU Fourier。先统一编译，再由一个 Criterion 进程依次测量。PBS 选 binary shortint；LUT 选八个输入/输出 chunk 的多项式示例。参数和计时策略与完整入口相同。

需要只跑一个后端时，指定第二个参数；Fourier 默认 RustFFT：

```sh
just bench sparse ntru-ntt
just bench sparse glwe-fourier
just bench lut ntru-fourier
```

在命令后加 `--list` 只列出用例，加 `--test` 只做正确性检查。需要 SIMD 时加 `--simd`（自动选择 nightly）；需要另一个 FFT 引擎时加 `--fft tfhe-fft`。

终端直接显示结果。以下章节用于选择完整矩阵、自定义采样或保存多轮报告；日常运行无需填写 package、feature 或长 ID。没有安装 just 时，可用 `python3 benchmarks/tfhe/tools/measure.py quick pbs`。

## 完整 Cargo 入口

在 workspace 根目录运行，先列出 ID，再选择测量对象：

```sh
cargo bench -p primus_tfhe_benchmarks --bench pbs --features glwe-ntt -- --list
cargo bench -p primus_tfhe_benchmarks --bench pbs --features glwe-ntt -- \
  'binary/boolean/KeyswitchBootstrap/complete/glwe/ntt/u32$' --test
cargo bench -p primus_tfhe_benchmarks --bench pbs --features ntru-fourier,rustfft -- \
  'binary/shortint_2_2/complete/ntru/rustfft/u64$'
cargo bench -p primus_tfhe_benchmarks --bench high_precision_lut --features lut,ntru-ntt -- \
  '/create_lut_and_drop/'
```

`--list` 不生成密钥。`--test` 执行正确性检查和一次 smoke，不做统计采样；去掉后才开始测量。优先指定 target，`--benches` 也会选择昂贵的 setup 与论文诊断。

## Features

默认不启用后端。没有可用后端时不注册案例。

| Feature | 选择范围 |
| --- | --- |
| `glwe-ntt`、`glwe-fourier` | 对应 GLWE 后端 |
| `ntru-ntt`、`ntru-fourier` | 对应 NTRU 后端；启用 LUT 时也使用该表示 |
| `lut` | 高精度查表，配合 NTRU 后端 |
| `rustfft`、`tfhe-fft` | 为已选 Fourier 依赖配置引擎 |
| `ntt` / `fourier` | 对应表示的两个后端和 LUT；Fourier 仍需引擎 |
| `validation` | 显式 `validate_parameters` 诊断 bin 与公开 LUT 编译器 |
| `simd` | 仅向已选后端传播 SIMD，需要 nightly |

同时启用两种 FFT 引擎时，RustFFT 为主引擎，每个家族的 PBS 增加一个 TFHE-FFT shortint 对照项。这是控制矩阵大小的选择，不是引擎性能排名。单引擎可以独立编译运行。

## Targets

| Target | 一次计时迭代 |
| --- | --- |
| `pbs` | Dense binary/ternary PBS，显式区分 GLWE order |
| `sparse_pbs` | 相同固定重量参数的 classic/sparse 完整 PBS |
| `cbs` | 普通 CBS，或 NTRU one-hot 的完整 M / 紧凑 M−1 输出 |
| `mvb` | 独立 PBS、ManyLUT、factorized MVB 生成相同 k 个阈值 |
| `high_precision_lut` | 分别计时 `create_lut_and_drop` 和完整 `evaluate` |
| `setup` | 密钥生成，或具名的原始 BR/KS 阶段 |
| `sparse_paper` | 论文原始/候选参数及适配后的返回路径 |

同一运算的各后端进入同一个 Criterion group，可生成 HTML 对照。ID 将工作负载放在 `family/engine/word` 前面；不同 order、输出契约和参数仍保留区别。相同 n/N 不代表等安全性，完整矩阵及数值契约见 [BENCHMARKS.md](BENCHMARKS.md)。

独立的 `primus_tfhe/lookup_table` 基准仍在原库。

## 源码组织

`benches/<operation>.rs` 是按 feature 注册的入口；同名目录放具体后端，方便并排阅读同一负载的实现：[PBS](benches/pbs/glwe_ntt.rs)、[CBS](benches/cbs/ntru_ntt.rs)、[MVB](benches/mvb/ntru_ntt.rs)、[高精度查表](benches/high_precision_lut/ntt.rs)。

- [Workload](src/benchmark.rs) 集中共享尺寸、配对的 sparse 映射配置、阈值函数和路径矩阵；数值参数仍放在 `src/parameters/`。
- [Case](src/measurement.rs) 为 Criterion 和元数据提供同一个显式 ID，注册代码不再解析历史名称。
- 各运算将拥有型 fixture 的构造与测量分开；`LazyCell` 在选中 callback 后才初始化，evaluator 在局部借用这些所有者。论文请求需要更新输入/输出缓冲，因此保留可变缓存。
- MVB 的 independent、interleaved、factorized 各有独立计时方法。NTRU 普通/one-hot CBS 共用密钥、输入及候选密文的构造，selector 校验与计时分开。NTT/Fourier 内核和模数角色仍显式保留。

新增用例时先更新 workload/profile 和保留矩阵，再明确分开准备、正确性检查及 `b.iter` 内的真实负载。避免用后端 trait 或注册宏隐藏所测运算。

## 测量与报告

测量版本 **2** 默认 30 个样本、3 秒预热、5 秒请求采样时长，使用 flat sampling。样本数和时长可通过 Criterion CLI 覆盖。一次迭代执行一个真实请求；独立 PBS 做 k 次调用，是因为实际需要 k 个输出。MVB/LUT 吞吐量按输出密文计数，延迟始终为整个请求。表创建包含 drop；keygen 使用 `iter_batched` 将返回密钥的释放放到计时外。

选中案例后才缓存创建密钥和输入。借用它们的 evaluator、输出缓冲区在每个 callback 内构造，在该 callback 的计时循环中复用。Setup、验证、元数据均在计时外。元数据记录实际数值参数，MVB 分别记录输入、输出明文模数；报告会拒绝与缺少这些字段的旧 MVB 记录严格配对，尽管负载和计时未变。测量版本 2 保持当前 fixture 生命周期和采样策略。

已启用 Criterion HTML。标准库实现的[小型执行脚本](tools/measure.py)先构建并冻结 Cargo 返回的二进制，再串行启动 Linux CPU 绑核进程。细节可运行 `--help`：

```sh
python3 benchmarks/tfhe/tools/measure.py build --features glwe-ntt --target sparse_pbs \
  --output target/benchmark-results/artifacts-A
python3 benchmarks/tfhe/tools/measure.py run \
  --build target/benchmark-results/artifacts-A/build.json --cpu 4 --rounds 3 --label A \
  --case 'sparse_pbs:sparse_pbs/fixed_weight/KeyswitchBootstrap/classic/complete/glwe/ntt/u64' \
  --case 'sparse_pbs:sparse_pbs/fixed_weight/KeyswitchBootstrap/sparse/complete/glwe/ntt/u64'
python3 benchmarks/tfhe/tools/report.py target/benchmark-results --output target/benchmark-summary
```

选择当前机器允许使用的 CPU。每次运行保存源码快照标识、dirty patch/未跟踪文件归档、lockfile 摘要、工具链与 feature、CPU 拓扑/频率策略、可执行文件摘要、实际案例参数。不同源码标识使用独立构建目录；run/CPU/round/case 独立目录避免覆盖 Criterion `new/base`。HTML 保留在各案例的 `criterion/`，CSV 与 Markdown 保留逐进程结果。工具不会并行执行 PBS/CBS，也不会在采样时构建。最终相位误差诊断仍显式启用：`PRIMUS_LUT_DIAGNOSTICS=1` 配合 `--test`。

报告不自动宣称加速。用 `--baseline-label A --candidate-label B` 配对同案例的版本结果。显式 `--pair BASE_ID CAND_ID --comparison algorithm` 允许其他参数一致时比较 BR/MVB 算法；`--comparison arithmetic` 允许数值参数不同，并列出差异，不代表等安全性。正百分比表示变慢。缺失、失败、重复配对，参数、CPU、feature 不匹配，以及 FFT 布局变化都保留。现有 FFT API 不暴露内部选中的算法；报告记录策略与排列指纹，并标注此限制，不把布局相同等同于计划相同。进程内区间不能代表跨进程重复性，不合并不同 CPU 或轮次。

## 验证与资产归属

教学 examples 和普通小参数 tests 留在所属库。Boolean 共享真值表放在 [`primus_tfhe/tests/common`](../../crates/primus_tfhe/tests/common/boolean.rs)，通过测试模块引用，不再使用独立辅助包。迁入的大参数诊断和 benchmark 使用同一参数源，默认只列出 profile：

```sh
cargo run --release -p primus_tfhe_benchmarks --bin validate_parameters \
  --features validation,ntru-ntt -- ntru/ntt/u32
cargo run --release -p primus_tfhe_benchmarks --bin validate_parameters \
  --features validation,glwe-fourier,tfhe-fft -- --list
python3 -m unittest discover -s benchmarks/tfhe/tools -p 'test_*.py'
cargo clippy -p primus_tfhe_benchmarks --all-targets \
  --features validation,ntt,fourier,rustfft,tfhe-fft -- -D warnings
```

使用 `--help` 查看帮助。`--list`、`--all` 与非空子串筛选三选一；未知选项、多余参数和无匹配的筛选都会报错。无参数只列出 profile，`--all` 才运行所有已编译 profile。普通 nextest 使用 `--lib --tests`，诊断设为 `test=false`，Criterion 不作为测试运行器。Workspace 的 `just`/`tfhe` 编译并 lint 这些入口，nightly all-features 也检查 SIMD。CI 不运行大参数诊断或性能采样。详见[测试指南](../../guides/development/testing.md)。

[测量版本 2 初始基线](../../guides/performance/tfhe-benchmark-schema2.md)：六种负载各三个独立进程，用于验证测量流程，不代表生产优化收益。
