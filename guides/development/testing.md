# 测试、基准与契约归属

本指南区分普通测试、编译检查、示例执行和性能测量，并提供后续精简测试的覆盖入口。包和 target 由 [workspace](../../Cargo.toml) 与 Cargo metadata 决定；运行时用例由 nextest 清单决定，不能用源码中的 `#[test]` 数量替代宏展开后的清单。

存储、布局、语义迭代器和工作区的使用入口见[库使用导航](README.zh_CN.md)。

## 验证入口

| 入口 | 范围与执行方式 |
| --- | --- |
| `just fmt-check` | 只检查格式 |
| `just check` / `just lint` | 默认 features，全 workspace、all-targets；编译/检查 examples 和 benches，不执行它们 |
| `just test` | 默认 features，全 workspace 的 library/proc-macro 单元测试及集成测试；显式 `--lib --tests` |
| `just test-doc` | 全 workspace doctests；nextest 不执行 doctest |
| `just test-simd` | justfile 列出的六个算术包及其 SIMD features，显式 `--lib --tests` |
| `just tfhe` / `just tfhe-simd` | 八个 TFHE crate 和两组 test support；具体 check/lint/test/doc/example 范围见 [justfile](../../justfile) |
| `just bench-smoke <package> <target> [Cargo options…]` | release/bench profile，单个 Criterion binary 启动一次，以 `--test` 执行 setup 和工作负载断言，不做统计采样 |
| `just bench-smoke-simd <package> <target> [Cargo options…]` | 对提供 `simd` feature 的包使用 nightly，其余语义相同 |

普通测试不使用 nextest `--all-targets`。`harness=false` 的 Criterion binary 也会被 nextest 枚举；注册前的密钥生成及整组验证可能在枚举时执行，并随着 nextest 逐条启动基准而反复执行。基准 smoke 保留这些 fixture 检查，但独立于普通测试运行。

```sh
# 只验证一个包的普通测试。
cargo nextest run -p primus_tfhe_ntru_lut --lib --tests

# 一个 benchmark target，一个进程；额外参数在 --test 之前传给 Cargo。
just bench-smoke primus_tfhe_ntru_lut pipeline
just bench-smoke primus_lattice rns_glev --features rns
just bench-smoke-simd primus_tfhe_ntru_lut pipeline

# 真实性能采样使用 benchmark 自己记录的命令。
cargo bench -p primus_tfhe_ntru_lut --bench pipeline
```

不要把 smoke 的耗时当作 kernel 延迟；它包含参数构造、密钥生成、验证和一次工作负载执行。性能测量的参数、CPU、工具链和 feature 必须保持可比，编译/初始化成本单独记录。过滤某个基准条目也不保证其注册前的 setup 会被跳过。

[CI](../../.github/workflows/ci.yml) 的普通测试同样显式选择 `--lib --tests`，保留 stable 默认和 nightly 全 feature 两个范围；all-target Clippy、doctest 及严格 rustdoc 独立执行。全 feature 普通测试和 doctest 的本地命令为：

```sh
cargo +nightly nextest run --workspace --lib --tests --all-features
cargo +nightly test --workspace --all-features --doc
```

`just ci` 组合默认 workspace 与局部 SIMD/TFHE 验证，仍不等同于 GitHub 的全 feature 矩阵。它包含 `test-doc`，不运行 benchmark smoke；需要验证基准 fixture 时显式运行对应 target。Examples 的编译检查不等于运行，其中两个 NTRU 查表示例由 `tfhe` / `tfhe-simd` 执行，其余按示例文档选择运行。

## 测试参数与 CI 成本

普通测试优先选择能覆盖目标契约的最小合适参数，包括密文端到端测试。小 LWE 维数、小环和小消息域可以减少密钥生成、变换与穷举成本；不要求普通测试跟随示例/基准采用 n≈800、N=1024/2048。

- 缩小几何和样本数时保留目标字宽、modulus 类型、分解/舍入边界及秘密分布。小尺寸不等于只能用小模数，u32/u64 的溢出和 lazy range 边界仍须独立覆盖。
- SIMD lane/尾部、按长度分派的 NTT/FFT kernel 等要求特定尺寸时，用能触达该路径的最小尺寸。确需实际大尺寸或参数组验证时，保留少量有明确理由的案例，并标明所属入口和运行成本。
- 默认 CI 保留必要回归；大型参数扫描、统计诊断和性能采样单独运行。不能未经替代覆盖就把慢测试标为 ignored，或用成功的 seed、放宽误差阈值掩盖失败。
- 示例/基准使用各自的代表性参数，修改 fixture 后执行对应 smoke；它们不替代普通测试中的独立数学和错误边界验证。

精简时记录每项大尺寸案例实际保护的路径，而非只比较测试函数数量。上述是参数选择原则；当前用例清单及数值实现不会因指南变更而自动调整。

## 可复现的清单

```sh
# target 种类、required-features、包 features；不执行测试或 benchmark。
cargo metadata --no-deps --format-version 1 > /tmp/primus-targets.json

# 单独计量构建：binaries-only 不调用各 binary 枚举用例。
cargo nextest list --workspace --lib --tests --list-type binaries-only \
  --message-format json > /tmp/primus-test-binaries.json

# 复用同一批二进制枚举，避免把编译时间算入枚举时间。
cargo nextest list --binaries-metadata /tmp/primus-test-binaries.json \
  --message-format json > /tmp/primus-tests.json
```

改变工具链、features、profile 或源码后重新生成二进制清单，不能继续复用旧清单。全 feature 清单在第一条 nextest 命令使用 `cargo +nightly` 和 `--all-features`，第二条也使用同一 nightly nextest。

审查 JSON 时同时检查：`rust-suites` 的 `kind` 仅为 `lib`、`proc-macro`、`test`；`testcases` 没有 Criterion `::bench/` 名称；`test-count` 与实际执行结果一致。若将来增加需要运行的 binary/example 自测，须明确其测试归属并更新选择范围，不能因为 `--lib --tests` 已存在就静默漏掉。

2026-09-27 的入口分离清单如下。用例数指命名测试函数，其中可能包含多个参数/消息；不表示独立数学边界的数量，也不设为必须维持的阈值。

| 项目 | 默认 workspace | nightly 全 features |
| --- | ---: | ---: |
| Library/proc-macro targets | 29 | 29 |
| 可用的 integration targets | 135 | 136 |
| 含实际用例的测试 binaries | 141 | 144 |
| 普通测试用例 | 374 | 387 |
| Criterion binaries/条目进入普通测试 | 0 | 0 |

Cargo 声明总计 67 个 bench targets、21 个 examples，其中 `primus_tfhe*` 占 20 个 bench targets、16 个 examples；这些是文件/target 数，不能与普通测试用例相加。当前所有 bench/example 的 metadata 均为 `test=false`，源文件中没有独立测试函数；本次分离未删除或改写任何普通测试。原 CI 的隐式选择与新的显式选择分别得到完全相同的 164/165 个 binary ID 和可执行文件路径。

## Feature 与字宽范围

- `simd` 需要 nightly。全 feature 验证覆盖提供该 feature 的各层；`just simd` 仅覆盖 justfile 指定的算术包。单次全 feature 通过不能替代默认分派路径的运行。
- `primus_modulus/derive` 启用 `derives` 集成测试和 `derived_mac` 基准；默认 workspace 不启用它。`primus_distr/high_precision` 增加高精度 CDT 覆盖。
- `primus_lattice/rns`、`primus_encoding/rns` 及 `primus_data/aligned-vec` 在默认 workspace 中可由其他成员依赖启用。独立包运行不能假定这种 feature 合并；`rns_glev`、`rns_ggsw`、`bfv_rns` 等基准需要对应的 required-features。
- 算术、模数、变换和基础同态层具有 u32/u64 及必要的较小字宽、多 limb 验证；每个运算的具体字宽从所属测试入口确认，不能从包内出现某个类型名推断全部路径均被覆盖。普通 PBS 有 u32/u64 路径；CBS/one-hot 的字宽覆盖不均，高精度 LUT 的密文求值当前只验证 u64。该限制仍需在参数和使用资产整理中处理。

## 契约与主要 setup 归属

以下是精简工作的导航，不是完成了每个测试的独立性复审。默认入口保留这些测试，后续合并/删除时须逐项给出替代覆盖或删除理由；缺少本地用例的 trait/辅助包可以由实际消费者承担验证。

| 层及包 | 普通测试承担的契约 | 主要 setup 与检查入口 |
| --- | --- | --- |
| `primus_data` | 存储访问、借用及 aligned 后端 | 小数组/容器；[integration.rs](../../crates/primus_data/tests/integration.rs) |
| `primus_integer`、`primus_gcd` | 进借位、移位/除法、多 limb、SIMD 尾部、逆元 | 确定性边界和整数 oracle；[integer/tests](../../crates/primus_integer/tests)、[xgcd.rs](../../crates/primus_gcd/tests/xgcd.rs) |
| `primus_reduce`、`primus_modulus`、`primus_factor`、`primus_barrett_derive` | 模数范围、约简、signed 编码、模切、预计算与派生实现 | 标量/切片输入与常量派生；[modulus/tests](../../crates/primus_modulus/tests)、[factor/tests](../../crates/primus_factor/tests)；trait 经消费者验证 |
| `primus_distr` | 采样支持集、秘密分布、批次/RNG、高精度 CDT | 固定 RNG 和 sampler 构造；[tests](../../crates/primus_distr/tests)，统计型资产另行评估 |
| `primus_poly`、`primus_ntt`、`primus_fft` | 负循环算术、单项式/自同构、变换顺序、Fourier packing/归一化、擦除 | 多项式 oracle、NTT 表和两个 FFT plan；[poly/tests](../../crates/primus_poly/tests)、[ntt/tests](../../crates/primus_ntt/tests)、[fft/tests](../../crates/primus_fft/tests) |
| `primus_decompose`、`primus_rns`、`primus_encoding` | 舍入/分解残差、CRT/DCRT/limb、编码与 padding | basis、模数链和整数 oracle；[decompose/tests](../../crates/primus_decompose/tests)、[rns/tests](../../crates/primus_rns/tests)、[encoding/tests](../../crates/primus_encoding/tests) |
| `primus_lattice` | 布局、外积/CMux、提取符号、RNS 算术、分配和借用恢复 | 显式构造 gadget/多项式及小环 oracle；[tests](../../crates/primus_lattice/tests) |
| `primus_lwe`、`primus_glwe`、`primus_ntru`、`primus_glwe_rns` | 密钥域、加解密、KS、trace/packing、scheme switch、擦除 | 秘密/求值密钥生成、相位 oracle、变换表；各包的 [LWE](../../crates/primus_lwe/tests)、[GLWE](../../crates/primus_glwe/tests)、[NTRU](../../crates/primus_ntru/tests)、[RNS GLWE](../../crates/primus_glwe_rns/tests) 测试 |
| `primus_tfhe`、`primus_tfhe_glwe`、`primus_tfhe_ntru` | 共享 LUT 几何/编码、稀疏分桶、家族参数和客户端 | 公开 LUT/basis；客户端测试另生成秘密；[共享](../../crates/primus_tfhe/tests)、[GLWE 家族](../../crates/primus_tfhe_glwe/tests)、[NTRU 家族](../../crates/primus_tfhe_ntru/tests) |
| 四个 `primus_tfhe_{glwe,ntru}_{ntt,fourier}` 后端 | PBS、Boolean、MVB、CBS、classic/sparse 的实际消费；NTRU one-hot 与独立 LWE 返回 | 小尺寸密钥/表、各后端的 `pbs`、`boolean`、`factorized_pbs`、`circuit_bootstrap`、`sparse_*` tests；NTT/Fourier 及秘密/order 差异分别保留 |
| `primus_tfhe_ntru_lut` | chunk 表分区与编码、选择/旋转/返回、错误前不写入、在线零分配 | [编译整数 oracle](../../crates/primus_tfhe_ntru_lut/tests/lookup_table.rs)、[小域密文穷举](../../crates/primus_tfhe_ntru_lut/tests/evaluation.rs)，后者含多组密钥 setup |
| `primus_tfhe_test_support`、`primus_test_allocations` | 共享 fixture/oracle、在线分配计数 | 由 [TFHE 消费者](../../test-support/tfhe/src) 和 [计数消费者](../../test-support/allocations/src) 验证；不额外生成机械测试 |

基准中的核心算术断言有以下普通测试入口，分离后仍会运行：

- 分解 scalar/batch 等价、配对单项式旋转、RNS 外积与 hybrid KS：分别见 [decompose tests](../../crates/primus_decompose/tests)、[monomial.rs](../../crates/primus_poly/tests/monomial.rs)、[rns_arithmetic.rs](../../crates/primus_lattice/tests/rns_arithmetic.rs)、[ksk.rs](../../crates/primus_glwe_rns/tests/ksk.rs)。
- 首次融合残差及 reverse trace：见 [phase_contracts.rs](../../crates/primus_ntru/tests/phase_contracts.rs) 和 [trace.rs](../../crates/primus_ntru/tests/trace.rs)，包含 NTT 模逆与 native 减半的不同 oracle。
- PBS/ManyLUT、MVB、CBS→CMux、one-hot 完整/紧凑 selectors：见各后端 `pbs.rs`、`factorized_pbs.rs`、`circuit_bootstrap.rs`，以及 NTRU [NTT one_hot.rs](../../crates/primus_tfhe_ntru_ntt/tests/one_hot.rs) / [Fourier one_hot.rs](../../crates/primus_tfhe_ntru_fourier/tests/one_hot.rs)。查表完整链路由上述 LUT tests 验证。

普通测试不等价于基准的每一个大尺寸参数组。基准中的已知结果、相位余量和在线分配断言继续保护该 fixture；修改其参数、分解或 kernel 时运行对应 smoke。benchmark 参数预算、setup 重复及条目精简需要逐项处理，不能仅靠移出默认入口宣称已经优化。

## 成本记录方法

分别记录构建、枚举、运行和 smoke，不把一次带编译运行与另一轮缓存运行直接比较。可用 `/usr/bin/time` 记录 wall time 与进程 RSS，用 nextest 汇总观察执行阶段及慢用例；其进程 RSS 不是所有并行子进程的内存总峰值。缓存记录区分 `target/debug`、`target/release`、Criterion 数据和剩余磁盘空间。

2026-09-27 的本地普通测试基线使用 Ryzen 9 9955HX3D、仓库 `target-cpu=native`、nextest 0.9.143；stable 1.98.0 和 nightly 1.100.0。测试 profile 通过环境临时设为 `opt-level=1`，显式保留 debug assertions 与 overflow checks，`CARGO_INCREMENTAL=0`；未修改仓库/CI profile，以下数字不代表默认未优化 CI 的耗时。

| 阶段 | stable 默认 | nightly 全 features |
| --- | ---: | ---: |
| 生成 binaries-only 清单（含构建） | 49.56 s | 49.14 s |
| 复用二进制枚举 | 0.15 s | 0.15 s |
| 缓存就绪的命令运行总耗时 | 1.67 s | 1.64 s |
| nextest 汇总的测试执行阶段 | 1.347 s | 1.339 s |

本次没有重新执行旧的全 workspace Criterion 逐条枚举/运行，也没有删减普通测试；因此只确认负载分离后的当前成本，不据历史包含 benchmark 的 2076/2155 项推算测试提速比例。后续比较须使用相同 profile、工具链、features、线程数、缓存和机器条件，并保留独立契约清单。
