# 测试、示例与基准运行

本指南区分编译检查、普通测试、doctest、示例执行和性能测量。运行入口以 [justfile](../../justfile) 为准，包、target 与所需 features 以各 crate 的 `Cargo.toml` 为准。库的选择和组合见[开发导航](README.zh_CN.md)。

## 常用验证入口

需要 Rust、Clippy、rustfmt、`cargo-nextest` 和 `just`。普通命令使用当前工具链；SIMD 命令使用 nightly。

| 入口 | 范围 |
| --- | --- |
| `just fmt-check` / `just fmt` | 检查格式 / 写入格式化结果 |
| `just check [package] [features]` | all-targets 编译，包括所选 features 允许的示例和基准 |
| `just lint [package] [features]` | all-targets Clippy，警告视为错误 |
| `just test [package] [features]` | nextest 普通测试，显式使用 `--lib --tests` |
| `just test-doc [package]` | doctest，与 nextest 分开执行 |
| `just simd [package]` | nightly、all-features 的 Clippy 与普通测试 |
| `just tfhe` / `just tfhe-simd` | 所有 `primus_tfhe*` 包的 Clippy 与普通测试；前者选择 NTT 和双 FFT，后者使用 nightly、all-features |
| `just` | 格式检查、workspace Clippy 与普通测试，选择 `ntt,fourier,rustfft,tfhe-fft` |
| `just ci` | 在 `just` 之上执行 doctest 和可选依赖隔离编译 |
| `just ci-nightly` | workspace 全 features 的 Clippy、普通测试、doctest、严格 private rustdoc 和 SIMD-only 编译 |

上表可选的 `package` 默认为 `*`，也接受包名或加引号的 Cargo glob。单独调用 `check`、`lint`、`test` 时，`features` 默认空字符串，即只使用各包的默认 features；它们不会自动选择 `just` 的 NTT/双 FFT 组合。例如：

```sh
just test primus_lattice ntt,rustfft,tfhe-fft
just test-doc primus_lattice
just tfhe
```

all-targets 只编译或 lint 示例与基准，不执行它们。nextest 不执行 doctest；`test-doc` recipe 使用默认 features，需选其他 features 时直接调用 `cargo test -p <package> --doc --features <features>`。普通测试保持 `--lib --tests`，避免混入 Criterion target。

[开发 profile](../../Cargo.toml) 设置 `opt-level=1`，test profile 继承它；release/bench 使用默认配置。需要验证 release 下的检查或数值行为时，对相关普通测试另加 `--release`。[GitHub CI](../../.github/workflows/ci.yml) 分 stable/nightly 两个 job；示例执行和性能采样按需进行，不加入普通 CI 的大参数运行。

## Features 与独立消费者

| 包或能力 | 默认与选择方式 |
| --- | --- |
| `primus_fft` | 默认不启用 FFT 引擎；用 `rustfft`、`tfhe-fft` 或两者 |
| `primus_lattice`、`primus_glwe`、`primus_ntru` | 按需选择 `ntt`、`rustfft`、`tfhe-fft`；FFT 引擎 feature 同时启用 Fourier 能力 |
| 两个 TFHE Fourier 后端 | 默认 RustFFT；加 `--features tfhe-fft` 启用双引擎；用 `--no-default-features --features tfhe-fft` 单选 TFHE-FFT |
| `primus_tfhe_ntru_lut` | 默认 NTT 和 RustFFT；用 `--no-default-features --features ntt`、`rustfft` 或 `tfhe-fft` 单选；不选后端仍可编译公开 LUT |

稳定工具链上的其他可选功能包括 `primus_data/aligned-vec`、integer/lattice 的 `serde`、`primus_modulus/derive`、`primus_distr/high_precision` 及 lattice/encoding 的 `rns`。独立包验证须显式选择需要的功能，不能依赖其他 workspace 消费者合并 features。

```sh
cargo nextest run -p primus_fft --lib --tests --features rustfft,tfhe-fft
cargo check -p primus_tfhe_ntru_lut --lib --no-default-features
cargo check -p primus_tfhe_ntru_fourier --lib --no-default-features --features tfhe-fft
```

Cargo 会跳过缺少 `required-features` 的 target，测试内部也可能按 feature 条件编译。`--all-targets` 不等于启用全部 features；空运行不能记为数值验证。需要查看当前选择的普通测试时使用 `cargo nextest list -p <package> --lib --tests --features <features>`，该命令可能先编译测试。

依赖或 feature 边界变化时，可在 workspace 外的临时 Cargo 包复用一个相关 example，只声明它直接使用的普通依赖与选定后端。用独立 `[workspace]` 隔离，并通过 `cargo tree -e normal,features` 核对依赖、执行示例验证结果；不要带入 dev-dependencies。`--lib --no-default-features` 编译与独立消费者验证分别检查库自身和实际组合。

SIMD feature 使用 nightly；`primus_ntt` 的 x86 intrinsic 分派另外受 CPU 能力控制，不要求 Cargo `simd`。本机通过只代表实际选中的内核，不代表其他 CPU 或架构也执行过。

## 测试与示例的职责

普通测试使用能保护目标契约的小参数，保留字宽、模数/舍入边界、必要的 SIMD 块与尾部，以及不同变换的数值差异。优先固定 seed 和独立 oracle；不通过挑选成功 seed 或放宽阈值掩盖失败。基础契约在所属 crate 验证，TFHE 测试验证公开接口的端到端组合，避免重复底层覆盖。

示例用代表性参数展示推荐工作流，基准测量指定负载；两者的尺寸不自动成为普通测试要求。TFHE 示例使用 u64，从后端 `experimental` 配置开始。这些配置的适用操作和证据限制见[参数目录](tfhe-parameters.md)，不据有限样本解密成功推断安全性或失败概率。

例如，运行普通 PBS 和高精度查表流程：

```sh
cargo run --release -p primus_tfhe_glwe_ntt --example ntt_basic
cargo run --release -p primus_tfhe_ntru_lut --example ntt_lookup
```

其他操作的示例见各后端 README。当前 Fourier 示例明确使用 RustFFT，需要 `rustfft` feature；切换 bench/test 的 FFT 引擎不会自动改写示例中的引擎类型。

## TFHE benchmarks

四后端的基准位于各自 `benches/`，每个文件就地组织参数和准备工作。选择一个包与操作：

```sh
just bench primus_tfhe_glwe_ntt pbs
just bench-smoke primus_tfhe_ntru_fourier one_hot
```

`just bench <package> <target> [Cargo options…]` 执行 Criterion 测量；`bench-smoke` 追加 `-- --test`，执行构造、请求和校验，不做统计采样。Smoke 仍有密钥生成和大参数运算成本，不能把它的耗时当作求值延迟。

一次测量四后端的普通 u64 PBS（Fourier 使用默认 RustFFT）：

```sh
cargo bench -p 'primus_tfhe_*_ntt' -p 'primus_tfhe_*_fourier' --bench pbs -- 'classic_dense/u64$'
```

| target | 一次迭代的负载 |
| --- | --- |
| `pbs` | 一次完整 LWE→LWE PBS；提供 dense classic u32/u64 与 fixed-weight classic/sparse u64 |
| `many_lut` | 一次盲旋转及多项 LWE 返回 |
| `mvb` | 一次完整 factorized MVB，返回多项阈值结果 |
| `cbs` | 自定义谓词的 CBS，再用输出控制实际 CMux |
| `one_hot`（仅 NTRU） | 生成非零 NGSW selectors，再执行多路 CMux |

Fourier 引擎按前面的 feature 规则选择；关闭默认 feature 后若不选引擎，Fourier bench 会报错。具体函数、消息空间和参数见[当前基准配置](tfhe-parameters.md#current-backend-benchmarks)及各文件。固定重量 classic/sparse 在同一后端使用相同参数，仅更换算法；dense classic 属于另一参数组，不能把两组时间差解释成算法加速。跨后端的噪声、分解和返回路径也不同。

密钥生成、公开程序编译、加密、工作区/输出分配和解密校验均在计时之外。每次迭代处理一个完整请求，throughput 不按输出数放大；测量的是固定输入、预分配材料反复求值的延迟。Criterion 过滤器只控制采样，**不会跳过 `bench_function` 外的准备和校验**。

比较时固定 CPU、工具链、features、参数和完整负载，不混用不同核型的结果。构建、smoke 和正式采样分别记录；Criterion 提供统计输出，历史测量及其适用范围见[性能指南](../performance/README.zh_CN.md)。

## High-precision LUT benchmarks

高精度 LUT 分开测量公开表创建和同态求值：

```sh
cargo bench -p primus_tfhe_ntru_lut --bench lookup_create -- 'c4_'
cargo bench -p primus_tfhe_ntru_lut --bench lookup_evaluate -- 'c4_'
```

| target | 计时范围 | 计时外准备 |
| --- | --- | --- |
| [lookup_create](../../crates/primus_tfhe_ntru_lut/benches/lookup_create.rs) | 一次 `HighPrecisionLookupTable::try_new` 的检查、分配、完整枚举/编码/存储及 drop | 随机函数、codec 与几何；不生成密钥 |
| [lookup_evaluate](../../crates/primus_tfhe_ntru_lut/benches/lookup_evaluate.rs) | 一次 `evaluate_to`：one-hot CBS、完整选表树、低位旋转、模数切换与 LWE KS | context、随机函数、LUT、密钥、加密、输出/workspace 分配及解密校验 |

`lookup_create` 分别测量 Q50/native64 编码，可加 `--no-default-features` 运行；不会为两个 FFT 引擎重复相同的公开编译。`lookup_evaluate` 默认测 NTT 和 RustFFT，按前面的 feature 规则单选或增加引擎。每次迭代创建一张完整表或求值一个完整请求。

将过滤器换成 `c5_`、`c6_`，或去掉它测量所有尺寸。对于 `lookup_evaluate`，**即使只采样 c4，也会准备 c5/c6 并校验求值**；最大公开表的系数存储为 512 MiB，此外还有随机映射、密钥、工作区和变换表。`lookup_create` 被过滤的 case 仍生成随机函数，但不创建其 LUT。`--list` 同样会执行计时外准备，只看名称时直接阅读基准文件。Smoke 也执行这些大尺寸工作，不放入普通 CI。

随机完整函数、classic BR、完整选表树及具体几何保持固定，输入 chunk 数决定表的尺寸。配置、内存和输入保护界见[高精度基准参数](tfhe-parameters.md#random-high-precision-lut-benchmark)。这组负载与教学示例不同，不能互换性能或噪声结论。
