# 测试、基准与契约归属

本指南区分普通测试、编译检查、示例执行和性能测量，并记录各层独立契约的覆盖入口。包和 target 由 [workspace](../../Cargo.toml) 与 Cargo metadata 决定；运行时用例由 nextest 清单决定，不能用源码中的 `#[test]` 数量替代宏展开后的清单。

存储、布局、语义迭代器和工作区的使用入口见[库使用导航](README.zh_CN.md)。

## 验证入口

使用 Rust、Clippy、rustfmt、`cargo-nextest` 和 `just`；普通命令使用当前工具链，GitHub 的 stable job 由 workflow 选择 stable，SIMD 入口显式使用 nightly。仓库不提交 Cargo.lock，命令不使用 `--locked`，允许 Cargo 按需生成或更新本地锁文件。

| 入口 | 范围 |
| --- | --- |
| `just` | 格式检查、当前工具链的 all-targets Clippy、普通测试 |
| `just ci` | 上述默认验证、doctest 和必要的可选依赖编译检查；沿用当前工具链，CI 中为 stable |
| `just ci-nightly` | nightly 全 features 的 all-targets Clippy、普通测试、doctest、严格/private rustdoc 和 SIMD-only 库编译检查 |
| `just fmt-check` / `just fmt` | 检查格式 / 写入格式化结果 |
| `just check [package]` / `just lint [package]` | 当前工具链的 all-targets 编译 / Clippy `-D warnings` |
| `just test [package]` / `just test-doc [package]` | 当前工具链的普通测试 / doctest；nextest 不执行 doctest |
| `just simd [package]` | nightly 全 features 的 Clippy 和普通测试 |
| `just tfhe` / `just tfhe-simd` | 对 `primus_tfhe*` 执行 Clippy 和普通测试，分别使用当前工具链/default features 和 nightly/all features |
| `just bench-smoke <package> <target> [Cargo options…]` | 显式选择一个 Criterion target，以 `--test` 执行工作负载及断言，不做统计采样 |

可选 package 默认为整个 workspace，接受包名或加引号的 Cargo glob。普通测试始终显式使用 `--lib --tests`，避免 Criterion 进入 nextest 枚举/执行；all-targets 只编译和 lint 示例、基准。Clippy 已承担编译检查，组合入口不再重复全库 `cargo check`。

```sh
just ci                                    # 当前工具链；GitHub 中为 stable
just ci-nightly                            # 单独验证 nightly
just test primus_tfhe_ntru_lut
just simd 'primus_tfhe*'
just bench-smoke primus_tfhe_ntru_lut pipeline
just bench-smoke primus_lattice rns_glev --features rns
# 示例与性能测量直接使用其 README/源码中的 Cargo 命令。
cargo run --release -p primus_tfhe_ntru_lut --example ntt_lookup
cargo bench -p primus_tfhe_ntru_lut --bench pipeline
```

Nightly 基准 smoke 的显式命令为 `cargo +nightly bench -p <package> --bench <target> --features simd -- --test`。所有 smoke 和示例执行都由维护者按改动选择，CI 不生成密钥运行大参数工作负载，也不自动执行全量性能采样。Smoke 耗时包含构造、密钥生成和断言，不能当作 kernel 延迟。

### Profile、feature 隔离与 CI

[开发 profile](../../Cargo.toml) 在 `[profile.dev]` 中设置 `opt-level=1`，test profile 自动继承，因此普通 `cargo build`、`cargo run` 和测试都使用基础优化。调试信息、debug assertions、overflow checks 和本地 incremental 保持默认开启。CI 单独用 `CARGO_INCREMENTAL=0` 禁用增量产物，不影响本地配置。Release/bench profile 保持原样；复查 release 拒绝路径仍需显式运行 `cargo nextest run … --release`。

[GitHub CI](../../.github/workflows/ci.yml) 只有 stable、nightly 两个独立 job，分别调用 `just ci` 和 `just ci-nightly`；它们可以并行运行，各自使用对应工具链的缓存。严格文档只在 nightly 全 features 下构建一次，doctest 在两个配置都运行。使用 Cargo/nextest 按可用 CPU 自动选择的并发；空 `RUSTFLAGS` 覆盖本机 native 配置，缓存使用 rust-cache 默认策略。这里不承诺冷构建或特定 runner 的完成时限。

Feature 边界只增加五条库编译命令，不再单独重复运行五组测试：

- stable 分别以 `--lib --no-default-features` 检查 data、lattice、encoding，避免其他成员或 dev-dependencies 的 feature 合并掩盖可选依赖关闭时的问题。
- stable 合并编译 modulus/derive 与 distr/high_precision；RNS、aligned-vec 的启用路径已由默认 workspace 的实际消费者编译并运行。
- nightly 合并编译 modulus/lattice/encoding 的 SIMD-only 库，不启用 derive/RNS。该组合与全 features 分开，保留弱可选依赖关闭时的检查。

小参数数值契约继续由默认/全 feature 普通测试负责。大参数诊断、示例配置切换和基准 fixture 验证按下面的维护入口显式执行。

## 测试参数与 CI 成本

代表性大尺寸配置见 [TFHE 参数矩阵](tfhe-parameters.md)。使用 `cargo run --release -p primus_tfhe_test_support --example validate_parameters` 手动验证；加 `-- ntru/ntt/u32` 可在密钥生成前筛选后端和字宽。Nightly SIMD 使用 `cargo +nightly run --release -p primus_tfhe_test_support --example validate_parameters --features simd`。这是参数与误差余量诊断，不加入普通 nextest，也不是性能采样；配置构造器与各后端诊断分开维护。

`test-support` 的职责入口见 [TFHE support](../../test-support/tfhe/src/lib.rs) 和[分配计数](../../test-support/allocations/src/lib.rs)。参数验证按家族/表示拆分，检查清单见 [validation 模块](../../test-support/tfhe/examples/validation/mod.rs)；入口只选择参数组和 seed。每组检查用简短注释说明目标契约、预期结果来源和输入选择理由，复杂部分解释模数/编码、gadget 相位和误差预算；示例文件说明用途及运行方式。后端的密钥生成、变换和相位提取保持显式，共享辅助函数集中真正相同的 oracle 或计量逻辑，避免引入统一后端框架。普通测试继续使用小参数；产品示例专注推荐用法，大参数诊断集中在这个独立入口。

例如，Boolean 公共构造、输入维度及 NOT 输出维度由 [primus_tfhe/tests/boolean.rs](../../crates/primus_tfhe/tests/boolean.rs) 的独立测试验证，无需密钥或加密；四个后端的 Boolean 集成测试保留真实 PBS 输出维度拒绝、输出不变和拒绝后正常求值。`test-support` 只共享需要真实后端参与的真值表/门链断言，不因多个调用方就把公共层自己的测试搬进辅助库。

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

2026-09-28 的全库验收清单如下。用例数指命名测试函数，其中可能包含多个参数/消息，不表示独立数学边界的数量，也不设为必须维持的阈值。

| 项目 | stable 默认 | nightly 全 features |
| --- | ---: | ---: |
| Library/proc-macro targets | 29 | 29 |
| 可用的 integration targets | 138 | 139 |
| 含实际用例的测试 binaries | 143 | 146 |
| 普通测试用例 | 370 | 381 |
| Criterion binaries/条目进入普通测试 | 0 | 0 |

整个 workspace 声明 65 个 bench targets、28 个 examples；其中 TFHE 产品 crate 有 18 个 bench targets、22 个 examples，最近全量验收在默认/SIMD 下各执行过 382 个 Criterion 工作负载和 22 个示例；这不是每次 CI 的负载。这些 target/工作负载数不能与普通测试用例相加。`test-support` 参数诊断属于剩余六个 examples 之一，始终按需显式执行。

入口分离时（2026-09-27）普通测试为 374/387 项；当时有 67 个 bench targets、21 个 examples，TFHE 产品部分为 20/16。后续整理既删除重复 setup/循环，也迁移测试并补齐错误边界和字宽。保留/替代关系见以下各层索引；净用例数只作辅助记录，不把合并循环当作工作量下降。

## Feature 与字宽范围

- `simd` 需要 nightly。全 feature 验证覆盖提供该 feature 的各层；`just simd` 默认对整个 workspace 执行 Clippy 与普通测试。单次全 feature 通过不能替代默认分派路径的运行。
- 调用通用 API 的测试同时用于默认/SIMD 配置，不为它另建同义的 `simd_*` 测试。只有直接使用 SIMD 专属类型或接口才条件编译整个测试；普通测试可局部条件编译 `LANE_COUNT` 等参数。启用 feature 不保证实际触达 SIMD：例如 Barrett 点积需要至少 `16 * LANE_COUNT` 个元素，选择输入时保留分派点两侧、完整块和尾部。单纯转发标准库切片分块的方法不单独测试。
- `primus_modulus/derive` 启用 `derives` 集成测试和 `derived_mac` 基准；默认 workspace 不启用它。`primus_distr/high_precision` 增加高精度 CDT 覆盖。
- `primus_lattice/rns`、`primus_encoding/rns` 及 `primus_data/aligned-vec` 在默认 workspace 中可由其他成员依赖启用。独立包运行不能假定这种 feature 合并；`rns_glev`、`rns_ggsw`、`bfv_rns` 等基准需要对应的 required-features。
- 算术、模数、变换和基础同态层具有 u32/u64 及必要的较小字宽、多 limb 验证；每个运算的具体字宽从所属测试入口确认，不能从包内出现某个类型名推断全部路径均被覆盖。普通 PBS 和高精度密文求值有 u32/u64 路径；CBS/one-hot 的专用相位测试侧重 u64，u32 的实际消费由高精度求值和双字宽基准 smoke 补充。FFT 底层谱运算 fixture 使用 u32，u64 转换 oracle 及上层 Fourier 密文消费另行保留，不将转换测试称作完整谱运算覆盖。

## 契约与主要 setup 归属

以下是各层契约归属的导航，具体删减与保留理由见后续各层小节。以后合并/删除时仍须给出替代覆盖或删除理由；缺少本地用例的 trait/辅助包由实际消费者承担验证。

| 层及包 | 普通测试承担的契约 | 主要 setup 与检查入口 |
| --- | --- | --- |
| `primus_data` | 存储访问、借用及 aligned 后端 | 小数组/容器；[integration.rs](../../crates/primus_data/tests/integration.rs) |
| `primus_integer`、`primus_gcd` | 进借位、移位/除法、多 limb、SIMD 尾部、逆元 | 确定性边界和整数 oracle；[integer/tests](../../crates/primus_integer/tests)、[xgcd.rs](../../crates/primus_gcd/tests/xgcd.rs) |
| `primus_reduce`、`primus_modulus`、`primus_factor`、`primus_barrett_derive` | 模数范围、约简、signed 编码、模切、预计算与派生实现 | 标量/切片输入与常量派生；[modulus/tests](../../crates/primus_modulus/tests)、[factor/tests](../../crates/primus_factor/tests)；trait 经消费者验证 |
| `primus_distr` | 采样支持集、秘密分布、批次/RNG、高精度 CDT | 固定 RNG 和 sampler 构造；[tests](../../crates/primus_distr/tests)，统计型资产另行评估 |
| `primus_poly`、`primus_ntt`、`primus_fft` | 负循环算术、单项式/自同构、变换顺序、Fourier packing/归一化、擦除 | 多项式 oracle、NTT 表和两个 FFT plan；[poly/tests](../../crates/primus_poly/tests)、[ntt/tests](../../crates/primus_ntt/tests)、[fft/tests](../../crates/primus_fft/tests) |
| `primus_decompose`、`primus_rns`、`primus_encoding` | 舍入/分解残差、CRT/DCRT/limb、编码策略与舍入 | basis、模数链和整数 oracle；[decompose/tests](../../crates/primus_decompose/tests)、[rns/tests](../../crates/primus_rns/tests)、[encoding/tests](../../crates/primus_encoding/tests) |
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

普通测试不等价于基准的每一个大尺寸参数组。基准中的已知结果、相位余量和在线分配断言继续保护该 fixture；修改其参数、分解或 kernel 时运行对应 smoke。TFHE 的保留/合并、延后 setup 及实测范围见[基准职责](../../crates/primus_tfhe/BENCHMARKS.md)和[基准记录](tfhe-benchmarks.md)，不以移出普通测试代替基准本身的整理。

## 基础库的聚焦覆盖

以下入口适用于 `data/integer/gcd/reduce/modulus/factor/barrett_derive/distr`。每项测试说明目标契约与 oracle；非平凡内部函数及测试辅助逻辑说明输入选择、数值前提或算法原因。机械转发无需复述实现。

| 契约 | 维护入口与保留理由 |
| --- | --- |
| 存储绑定、整数和 GCD | [Data](../../crates/primus_data/tests/integration.rs) 在存储绑定测试中直接使用所有权构造器并验证读写，不重复验证标准库迭代器或 aligned-vec 自身对齐；[整数测试](../../crates/primus_integer/tests) 保留跨 limb 进借位、移位和独立整数 oracle；[GCD](../../crates/primus_gcd/tests/xgcd.rs) 保留小字宽穷举和宽字整数 oracle |
| 各模数的切片加减 | [slice_add_sub.rs](../../crates/primus_modulus/tests/slice_add_sub.rs) 集中 u32/u64 的 Native、PowOf2、Compact、Barrett、Uint 覆盖，使用 u128 oracle、偏移切片和边界哨兵；各 modulus 文件保留不同的构造、标量、乘法、求逆及一元操作契约 |
| 原生与派生 Barrett | [原生内核](../../crates/primus_modulus/src/barrett/native.rs) 直接比较可用的 AVX-512 实现，避免通常分派遮住另一个实现；[派生消费者](../../crates/primus_modulus/tests/derives.rs) 编译并验证生成代码。保留模数位宽、IFMA 上界、32 元素分派点、vector 尾部及累加器复用；无独立执行路径的千元素重复不进入普通测试 |
| 模数切换 | [modulus_switch.rs](../../crates/primus_modulus/tests/modulus_switch.rs) 按比值、二次幂、窄/宽中间值及 native 输出选择案例，再验证各模数类型的接入。精确整数舍入 oracle 和小字宽 reciprocal 修正穷举保留，不展开类型与模数的完整笛卡尔积 |
| 预计算乘法 | [MultiplyFactor](../../crates/primus_factor/tests/multiply_factor.rs) 用固定边界及固定 seed 验证 32/52/64 位商精度、最大合法模数和 lazy range；[ShoupFactor](../../crates/primus_factor/tests/shoup_factor.rs) 保留 reset、逐 lane 因子、全字宽乘数、融合操作及标量尾部，不再单独重复随机标量乘法 |
| trait 与宏边界 | `primus_reduce` 经 modulus/factor 等真实消费者验证；derive 的成功展开由上述消费者负责，[解析/校验测试](../../crates/primus_barrett_derive/src/lib.rs) 直接验证结构形状、类型、字面量溢出及模数边界，无需为每个拒绝案例重启 rustc |
| 采样和统计 | [采样测试](../../crates/primus_distr/tests) 保留支持集、固定重量、表示转换、精确阈值、RNG 消耗和错误前不写入；批次长度共享不变的 Gaussian 表。统计函数只使用小型确定性 [stats fixture](../../crates/primus_distr/tests/stats.rs)；大型经验分布诊断留在 [check_gaussian](../../crates/primus_distr/examples/check_gaussian.rs) / [compare_samplers](../../crates/primus_distr/examples/compare_samplers.rs)，不进入普通 CI |

这八个包的默认验证需另加 `aligned-vec`、`derive`、`high_precision` 才覆盖全部 stable 可选路径；nightly 再用 `--all-features` 覆盖 SIMD。以下命令在 Bash 中运行：

```bash
packages=(-p primus_data -p primus_integer -p primus_gcd -p primus_reduce
          -p primus_modulus -p primus_factor -p primus_barrett_derive -p primus_distr)
cargo nextest run "${packages[@]}" --lib --tests
cargo nextest run "${packages[@]}" --lib --tests \
  --features primus_data/aligned-vec,primus_modulus/derive,primus_distr/high_precision
cargo +nightly nextest run "${packages[@]}" --lib --tests --all-features
```

原生指令测试受 CPU feature 检测约束；本机可用内核的通过不代表其他架构已经执行。Doctest 和 all-targets 检查按上文单独运行。

## 多项式、变换、分解与编码的聚焦覆盖

以下六包按数学契约和实际分派选择尺寸；普通 API 测试在默认和 SIMD 配置下复用，不按 feature 复制同义测试。模数类型按数值角色选择：native 使用 `NativeModulus`，显式二次幂使用 `PowOf2Modulus`，满足位宽限制的一般模数使用 Barrett，超出其范围使用 Uint。

| 范围 | 保留的独立验证与尺寸理由 |
| --- | --- |
| 多项式 | [配对旋转](../../crates/primus_poly/tests/monomial.rs) 使用逐系数散射 oracle：短环穷举指数、长区间验证三个分量顺序，空批次单独调用一次；[Fourier 算术](../../crates/primus_poly/tests/fourier.rs) 使用手算复数结果，不重复测试消费自身后转发到 assign 的包装；[CRT 采样](../../crates/primus_poly/tests/crt_random.rs) 从同一组 signed 样本独立计算各 limb，并核对 RNG 消耗 |
| NTT | [ntt.rs](../../crates/primus_ntt/tests/ntt.rs) 用 N=2/8、q=17 的直接多项式求值固定根选择、bit-reversed 排列和逆归一化；U32 保留 16/32/64 的 scalar/SIMD 分派、偏移切片和 lazy 范围；U64 保留三种模数位宽和 8/16/64，另以 2048/4096/8192 覆盖 AVX-512 基例及两层递归，不能统一缩成小环 |
| 两个 FFT 后端 | [负循环卷积](../../crates/primus_fft/tests/negacyclic.rs) 用有符号整数 O(N²) oracle 验证 packing 和乘积归一化；短环验证 offset 切片与并发独立 workspace；[擦除](../../crates/primus_fft/tests/zeroize.rs) 保留短缓冲区和 N=1024 的后端工作存储；TFHE-FFT 私有测试强制不同 plan base size，避免依赖自动 planner 恰好选中某种谱排列 |
| torus 转换 | [roundtrip.rs](../../crates/primus_fft/tests/roundtrip.rs) 对 u32/u64 使用浮点 round、饱和有符号转换和 unsigned wrapping 作为独立 oracle；保留所有浮点指数、代表性尾数和正负舍入/饱和边界，不再追加十万次随机比特扫描 |
| 分解 | [primitive oracle](../../crates/primus_decompose/tests/primitive_approx_signed_basis_oracle.rs) 保留小模数穷举、native 半步舍入、digit 范围及层序；[多 limb 分解](../../crates/primus_decompose/tests/big_uint.rs) 保留跨 limb、drop/carry 边界、固定 stride 1/2/4 和 fallback 3 的批次差分，边界之外仅少量固定 seed 输入 |
| RNS | [base.rs](../../crates/primus_rns/tests/base.rs) 从 u128 同时构造 modulus-major 和 value-major 预期值，覆盖跨 u64 limb 边界；[converter](../../crates/primus_rns/tests/converter.rs) 保留 fast 与 exact 不同 lift、scratch 复用；[hybrid](../../crates/primus_rns/tests/hybrid.rs) 保留裁剪基后的固定分区、mod-up 流式输出和多 P mod-down。65 元素的 scaled batch 保留 native 分派及尾部 |
| 编码 | [plaintext_codec.rs](../../crates/primus_encoding/tests/plaintext_codec.rs) 按 q/t 策略选择案例，保留 u16/u32/u64、奇偶模数、窄/宽中间值、Rounded/Scaled 和 centered/unsigned 区别；仅小域穷举，大域取中心两侧和端点；[BFV RNS](../../crates/primus_encoding/tests/bfv_rns.rs) 单独验证 floor scale、噪声恢复及输出前检查。LUT 的 padding 属于 TFHE 消费者，不在此层重复验证 |

六包独立运行命令如下；`primus_fft` 自身没有 `simd` feature，两个后端都会参与。`primus_ntt` 的 x86 intrinsic 分派由 CPU 决定，不要求 Cargo `simd`。本机通过只说明本机选中的 kernel；不能据此声称 AVX2、DQ32 或其他架构都执行过。

```bash
packages=(-p primus_poly -p primus_ntt -p primus_fft
          -p primus_decompose -p primus_rns -p primus_encoding)
cargo nextest run "${packages[@]}" --lib --tests
cargo +nightly nextest run "${packages[@]}" --lib --tests --all-features

# 防止其他 workspace 成员合并 feature 后掩盖独立包的问题。
cargo nextest run -p primus_encoding --lib --tests --features rns
cargo +nightly nextest run -p primus_encoding --lib --tests --features simd
```

同一 package/feature 选择也用于 `check --all-targets`、`clippy --all-targets -- -D warnings`。六包的 stable 可选功能是 encoding/rns；derive 与 high_precision 的归属和运行命令见前一节。Doctest 和严格 rustdoc 独立运行。

## 密文表示与算术层的聚焦覆盖

`primus_lattice` 的[测试索引](../../crates/primus_lattice/tests/README.md)区分原始密文布局、算术及资源契约。测试构造确定性数值，不在此层重复秘密采样和加解密 fixture。

| 契约 | 维护入口与精简边界 |
| --- | --- |
| 布局与存储 | [layout.rs](../../crates/primus_lattice/tests/layout.rs) 检查 size 拒绝、ABox 消费后保留分配、偏移 slice 写回、串行工作区 rebind 拒绝/异常恢复及 RNS limb 宽度相容性；不测试 aligned-vec 本身或迭代器计数 |
| 共享算术与 gadget 布局 | [arithmetic.rs](../../crates/primus_lattice/tests/arithmetic.rs) 以 65 元素和偏移哨兵覆盖向量/尾部；[RNS](../../crates/primus_lattice/tests/rns_arithmetic.rs) 保留两模数的不同因子与 row/level/component 顺序。[明文和对角注入](../../crates/primus_lattice/tests/plaintext_and_gadget.rs) 使用 N=4、独立扁平索引 oracle，每个共享宏保留一个包装类型，Fourier 的复数契约单独验证 |
| 多项式乘法与旋转 | [polynomial_products.rs](../../crates/primus_lattice/tests/polynomial_products.rs) 保留 NTRU 单多项式和 GGSW 批次遍历，NTT 的 N=32 保留向量长度；八个指数覆盖符号/环绕和脏 scratch 后零指数。CRT 以 N=4 穷举八个指数；配对旋转的纯转发不重复 [poly 的独立穷举](../../crates/primus_poly/tests/monomial.rs)。[Fourier](../../crates/primus_lattice/tests/fourier.rs) 的 N=8 整数卷积 oracle 保留两个 FFT 后端 |
| 外积与 CMux | [external_product.rs](../../crates/primus_lattice/tests/external_product.rs) 保留 NLev/NGSW 的层序、控制与输出不同层数、变换域/系数域输出、短输出拒绝前不写入及非零→零复用。[ternary_cmux.rs](../../crates/primus_lattice/tests/ternary_cmux.rs) 保留 ±1/0 控制、两种分解深度、NTT/Fourier 及 Fourier 的 u32/u64 和两个 FFT 后端，指数按边界选择 |
| 提取 | [extraction.rs](../../crates/primus_lattice/tests/extraction.rs) 保留手算样本顺序、NTRU `c*f` 与 GLWE `b-a*s` 的整数卷积 oracle、完整/部分秘密、native/显式模数逆提取、padding 和 packed 拒绝；它们各自保护不同的符号或布局契约 |
| 首次融合与在线分配 | 首次融合的秘密和分解残差由 [NTRU phase contracts](../../crates/primus_ntru/tests/phase_contracts.rs) 验证；在线计数由这些消费者及四后端 PBS/CBS/高精度 LUT 测试承担。本层保留资源复用断言，不对每个数学样本重复计数，也不把指针相等当作零临时分配证明 |

默认、独立 RNS、nightly SIMD/RNS 及 release 拒绝契约分别验证：

```sh
cargo nextest run -p primus_lattice --lib --tests
cargo nextest run -p primus_lattice --lib --tests --features rns
cargo +nightly nextest run -p primus_lattice --lib --tests --all-features
cargo nextest run -p primus_lattice --lib --tests --release --features rns
```

默认和扩展配置复用同一套测试；无需为普通测试单独标记 SIMD。按同一 feature 范围运行 all-targets 编译/Clippy，doctest 单独运行。改变实际算术或资源接口时，额外验证受影响的 GLWE/NTRU/RNS/TFHE 消费者；纯测试整理无需重新运行全 workspace 数值矩阵。

## 加密与求值原语的聚焦覆盖

`primus_lwe`、`primus_glwe`、`primus_ntru`、`primus_glwe_rns` 验证秘密、编码和求值密钥共同决定的相位关系。普通功能测试使用小参数：LWE 的 65 维仍跨过向量块并留下尾部；环测试以 N=32 或更小的专用 fixture 为主。保留原有字宽、密文模数和分解精度，RNS 仍使用约 100/150 位的 Q，不把多 limb 算术缩成单字算术。

| 契约 | 维护入口与精简边界 |
| --- | --- |
| LWE 加密与批次 | [raw.rs](../../crates/primus_lwe/tests/raw.rs)、[public_key.rs](../../crates/primus_lwe/tests/public_key.rs) 保留独立整数相位、噪声与 RNG 消耗 oracle，signed/encoded 秘密、公钥矩阵及两种 embedding 各有职责；[batch.rs](../../crates/primus_lwe/tests/batch.rs) 保留 tile=8 前后、空输入、偏移哨兵和部分写入边界；[packed.rs](../../crates/primus_lwe/tests/packed.rs) 保留空/部分/满载及全部提取位置。显式二幂模数使用 PowOf2Modulus |
| LWE key switch | [key_switch.rs](../../crates/primus_lwe/tests/key_switch.rs) 保留不同秘密表示、批次与逐 key-entry 求和的差分，输出前及采样前拒绝独立验证；不以端到端解密成功替代密钥条目符号检查 |
| GLWE 加密与 gadget | [NTT 秘密测试](../../crates/primus_glwe/tests/ntt_glwe_secret_key.rs) 保留系数域/NTT 域相同 RNG 下的密文与相位差分、精确噪声、截断解密；[Fourier](../../crates/primus_glwe/tests/fourier_glwe_secret_key.rs) 保留 native u32/u64 和工作区复用。固定重量大于 N 的秘密仍按完整 kN 采样。公钥、gadget、constant batch、CMux、改变维数的 KS、scheme switch 在各自文件验证 |
| GLWE trace 与 packing | [trace_packing.rs](../../crates/primus_glwe/tests/trace_packing.rs)、[packing_key_switch.rs](../../crates/primus_glwe/tests/packing_key_switch.rs) 保留完整/部分投影、系数选择与独立 signed/encoded LWE 秘密；非二元秘密的 automorphism 用整数卷积恢复原秘密下的相位。资源拒绝见 [boundaries.rs](../../crates/primus_glwe/tests/boundaries.rs) |
| NTRU 密钥与返回链 | [secret_key.rs](../../crates/primus_ntru/tests/secret_key.rs) 保留两种表示的编码入口和脏密文复用，NTT 噪声幅度按固定 seed 精确重放；[padded_secret_key.rs](../../crates/primus_ntru/tests/padded_secret_key.rs) 区分可逆性、奇偶限制与 Fourier 数值稳定性。[lwe_key_switch.rs](../../crates/primus_ntru/tests/lwe_key_switch.rs) 保留 Q→q 整数舍入、样本提取符号及独立、无需可逆的 LWE 输出秘密 |
| NTRU 相位与归一化 | [phase_contracts.rs](../../crates/primus_ntru/tests/phase_contracts.rs) 的 N=8 小域验证首次融合的分解残差、密钥误差和 reverse trace；NTT 模逆与 Fourier/native 有理逆及舍入分别有 oracle。[trace.rs](../../crates/primus_ntru/tests/trace.rs) 保留完整/部分 trace、展开和公开拒绝。GLWE/NTRU 的 N=32 ternary CMux 只取符号、环绕、内部指数和脏 scratch 后零指数；旋转索引穷举由多项式层负责 |
| RNS 加密与求值 | [glwe.rs](../../crates/primus_glwe_rns/tests/glwe.rs) 将 sampler×明文模数全组合收敛为代表性配对，复用四条编码入口的输出；保留未缩放 CRT 公钥输入和 BFV 明文乘法的缩放语义。参数当前共享一种 modulus 类型，Barrett fixture 使用非二幂的奇/偶 t。[expand.rs](../../crates/primus_glwe_rns/tests/expand.rs) 按 CRT/DCRT 分开，同一密钥比较串行/本地双线程的完整/部分展开，并解密核对每个输出；工作区及脏输出跨轮复用 |
| RNS 分解与 KS | [glev.rs](../../crates/primus_glwe_rns/tests/glev.rs)、[ext_prod.rs](../../crates/primus_glwe_rns/tests/ext_prod.rs) 保留多字宽分解和公钥 GGSW 消费；[auto.rs](../../crates/primus_glwe_rns/tests/auto.rs) 固定非恒等 automorphism，[trace.rs](../../crates/primus_glwe_rns/tests/trace.rs) 保留 CRT/DCRT/reverse 的模逆归一化。[ksk.rs](../../crates/primus_glwe_rns/tests/ksk.rs) 区分 classic 与 hybrid，后者保留三个 Q limb、P 基及不等长分区；内部系数域参考差分和 mixed-domain mod-down 仍就地测试 |
| 秘密擦除与资源 | [GLWE zeroize](../../crates/primus_glwe/tests/zeroize.rs)、[NTRU zeroize](../../crates/primus_ntru/tests/zeroize.rs) 观察释放前存储，保留失败构造、重试、变换后秘密/逆、显式擦除失效及工作区复用。RNS 私有工作区的双缓冲擦除留在内部测试；公共 domain 构造拒绝放 [parameter.rs](../../crates/primus_glwe_rns/tests/parameter.rs)。首次融合及在线分配计数继续由真实消费者验证 |

不在本层重复底层 add/sub/neg/scalar kernels 的多份加解密往返。多项式算术 oracle、BFV 的缩放乘法、带噪声求值密钥的相位关系各自保留；省略某个操作之前的普通解密检查，不省略该操作结果的检查。测试不要求单独标记 SIMD，默认和全 feature 运行同一套契约：

```bash
packages=(-p primus_lwe -p primus_glwe -p primus_ntru -p primus_glwe_rns)
cargo check "${packages[@]}" --all-targets
cargo nextest run "${packages[@]}" --lib --tests
cargo clippy "${packages[@]}" --all-targets -- -D warnings
cargo +nightly check "${packages[@]}" --all-targets --all-features
cargo +nightly nextest run "${packages[@]}" --lib --tests --all-features
cargo +nightly clippy "${packages[@]}" --all-targets --all-features -- -D warnings
cargo nextest run "${packages[@]}" --lib --tests --release
```

Release 验证公开拒绝和擦除失效不依赖 debug assertions；doctest 按同样 package/feature 范围单独运行。本机 SIMD 通过只代表当前 CPU 上实际分派到的路径。这里不执行大参数统计、bench 或示例，也不替代 TFHE 消费者的端到端验证。

## TFHE 流程与共享辅助代码的聚焦覆盖

八个 `primus_tfhe*` crate 的普通测试区分公共几何、家族参数和后端密文消费。优先使用 N=32/64/128 的功能参数；GLWE 普通 PBS 和 NTRU sparse PBS 的 ManyLUT fixture 保留 N=256，因为按步长 4 量化时，非零 LWE mask 项的舍入误差会累加，需要足够宽的平台。不能只按 gadget 输出数量决定最小 N，也不能通过挑 seed 或放宽误差阈值缩小测试。

| 契约 | 所属层与默认用例 |
| --- | --- |
| LUT 编译、padding、量化和奇数全域 | [公共 lookup_table.rs](../../crates/primus_tfhe/tests/lookup_table.rs) 用独立整数/负循环旋转 oracle 检查中心、guard、碰撞及奇数折叠边界，保留小域穷举；[factorized_lookup_table.rs](../../crates/primus_tfhe/tests/factorized_lookup_table.rs) 保留独立卷积和 odd delta。家族 LUT 测试只补输入/输出 codec 绑定 |
| 参数、client 与秘密表示 | [GLWE](../../crates/primus_tfhe_glwe/tests/parameters.rs)、[NTRU](../../crates/primus_tfhe_ntru/tests/parameters.rs) 拥有配置、噪声及 CBS basis/ring/capacity 拒绝；NTRU 的 native/显式模数构造验证集中于此，不在两个后端复制。家族 `client.rs`/NTRU `key.rs` 保留 signed/encoded 秘密、public client、失败前不写入和非法消息检查 |
| PBS、ManyLUT、双输入和奇数全域消费 | 四后端的 `tests/pbs.rs` 保留 u32/u64、实际输出编码、分配与形状拒绝；GLWE 保留两种 order，Fourier 保留两个 FFT 实现。奇数全域的加密输入取 0、1、折叠两侧、末值及复用后的零；逐位置几何由公共 oracle 穷举 |
| Boolean、独立 client/server 与盲旋转 | 四后端 `boolean.rs`/`context.rs` 保留真实密钥消费；[共享 Boolean driver](../../test-support/tfhe/src/boolean.rs) 只复用真值表和连用电路。GLWE `blind_rotation.rs` 比较直接指数和量化输入；NTRU PBS 保留首项为零、后续非零和首次融合的相位回归 |
| 稀疏与 MVB | GLWE 的 `sparse_key.rs`/`sparse_blind_rotation.rs`/`sparse_pbs.rs` 区分映射、密钥条目和实际求值；NTRU `sparse_bucket.rs`/`sparse_pbs.rs` 保留首桶、空桶、单桶和多桶差异。四后端 `factorized_pbs.rs` 保留超过 interleaved 容量的输出数，以及公开 LUT 与密钥/表绑定。公共 sparse 匹配与有限重试 oracle 留在其私有 kernel 测试 |
| CBS 与 one-hot | 四后端 `circuit_bootstrap.rs` 检查 gadget 层次相位及 CMux/外积消费；[公共 one_hot.rs](../../crates/primus_tfhe_ntru/tests/one_hot.rs) 穷举 guard、padding 和反周期符号。两 NTRU 后端的 `one_hot.rs` 以 N=64 验证完整/紧凑批次等价、selector 0、三层尺度、实际消费及错误后复用 |
| 高精度查表与独立返回秘密 | [编译 oracle](../../crates/primus_tfhe_ntru_lut/tests/lookup_table.rs) 完整检查表分区和系数；[evaluation.rs](../../crates/primus_tfhe_ntru_lut/tests/evaluation.rs) 保留 NTT/RustFFT/TFHE-FFT × u32/u64 × classic binary/ternary。小域完整求值，大域取各表边界、每个 chunk 的非零 digit、前导零及末值；保留 d=0、d=c、公密混合 CMux 层、满系数环和不同输入/输出 chunk 数。NTRU 后端 `lwe_return.rs` 验证 Q→q 与独立且无需可逆的 LWE 秘密 |
| 分配与共享参数 | [CountingAllocator](../../test-support/allocations/src/lib.rs) 保持每线程计数，不把 worker 或进程内存算入；公共编译的正分配计数和后端在线零分配测试直接消费它，不新增标准库转发测试。[参数模块](../../test-support/tfhe/src/parameters/mod.rs) 服务代表性诊断/基准，与普通测试的小参数分开；产品示例就地构造参数以便阅读 |

显式二幂外部 LWE 模数使用 `PowOf2Modulus`；Fourier accumulator 仍使用 `NativeModulus`。u32 NTT 的高精度流程使用适合 CBS 的 prime 998244353，三层输出分解采用 log basis=4；u64 保留其独立模数与精度，不能直接缩窄常量。

支持与拒绝各有用例：GLWE CBS 覆盖 classic binary/ternary 及 sparse、两种 order；NTRU 普通 PBS 支持 classic/sparse，CBS、MVB、one-hot/高精度流程只支持 classic binary/ternary，相应 sparse 绑定被拒绝。缺失 CBS 材料、错误输出形状、参数/表不匹配和无效容量继续由实际边界验证。

默认与 nightly 全 feature 复用同一套测试，不给普通测试加 SIMD gate。TFHE 快捷入口只组合 Clippy 和普通测试；示例和 benchmark smoke 独立运行：

```sh
just tfhe
just tfhe-simd
cargo run --release -p primus_tfhe_ntru_lut --example ntt_lookup
just bench-smoke primus_tfhe_ntru_lut pipeline
# 显式复查 release 的拒绝/输出保持契约。
cargo nextest run -p 'primus_tfhe*' --lib --tests --release
```

大参数扩展入口是 [validate_parameters](../../test-support/tfhe/examples/validate_parameters.rs)，不加入默认测试。它验证 [参数矩阵](tfhe-parameters.md) 的 n≈800、N=1024/2048，保留两个固定 seed、raw phase 误差预算和全部后端/字宽；支持在密钥生成前按名称筛选。Boolean PBS 的消息为 0→1→0，不重复其与 midpoint/末值相同的 1；CBS、one-hot、完整查表和阈值诊断仍保留各自的边界输入与复用。

```sh
cargo run --release -p primus_tfhe_test_support --example validate_parameters
cargo run --release -p primus_tfhe_test_support --example validate_parameters -- ntru/ntt/u32
```

## 成本记录方法

分别记录构建、枚举、运行和 smoke，不把一次带编译运行与另一轮缓存运行直接比较。可用 `/usr/bin/time` 记录 wall time 与进程 RSS，用 nextest 汇总观察执行阶段及慢用例；其进程 RSS 不是所有并行子进程的内存总峰值。缓存记录区分 `target/debug`、`target/release`、Criterion 数据和剩余磁盘空间。

在同一台 Ryzen 9 9955HX3D（32 个逻辑 CPU）、相同 `target-cpu=native`、stable 1.98.0 / nightly 1.100.0、nextest 0.9.143 下复测。两次都使用 opt-level=1、debug assertions/overflow checks 开启、`CARGO_INCREMENTAL=0`、默认自动并发、不绑核。2026-09-27 的 profile 由环境设置，2026-09-28 初次验收时写入 Cargo.toml；随后只保留 opt-level=1，本地 incremental 恢复默认开启。下表保留的是禁用 incremental 时的历史测量，不能直接代表当前本地配置。运行前单独生成 binaries-only 清单；以下每个值都是单轮观察，不是统计基准。

| 阶段 | 9/27 默认 | 9/28 默认 | 9/27 全 features | 9/28 全 features |
| --- | ---: | ---: | ---: | ---: |
| 生成 binaries-only 清单（含构建） | 49.56 s | 31.17 s | 49.14 s | 30.22 s |
| 枚举已构建的二进制 | 0.15 s | 0.19 s | 0.15 s | 0.14 s |
| 缓存就绪的普通测试命令 | 1.67 s | 2.24 s | 1.64 s | 2.20 s |
| nextest 汇总的执行阶段 | 1.347 s | 1.908 s | 1.339 s | 1.902 s |
| 构建命令 max RSS（KiB） | 1,316,140 | 946,332 | 1,388,092 | 922,140 |
| 枚举命令 max RSS（KiB） | 53,652 | 53,176 | 48,192 | 46,980 |
| 测试命令 max RSS（KiB） | 63,688 | 65,464 | 53,732 | 53,468 |

这不是冷构建对比：依赖和历史产物的缓存状态不同，构建时间/资源下降不能直接归因于精简。缓存测试执行并未整体变快；最长的 TFHE-FFT 高精度用例由约 1.12 s 变为 1.74 s，同期增加了 u32 完整求值覆盖，具体输入和 setup 也已变化。保留独立契约，不能为了回到旧数字删除字宽或放宽阈值。各层重复尺寸/setup 的减少与整个 workspace 的总时间分开解释；没有重跑旧的含 Criterion 普通入口来制造夸大对比。

收缩 CI 前的同次本机全量验收中，原两个 full 命令分别 11.27 / 12.55 s；22 个示例分别 20.99 / 22.68 s，382 条 Criterion smoke 分别 136.97 / 137.44 s，均包含当次缓存状态下的 Cargo 检查/构建。两种配置普通测试全部通过，doctest 各 21 passed、2 个既有 ignored；smoke 通过不表示测过所有可切换的示例源码配置。该全量入口及批量脚本已删除，以上 smoke 成本不再计入每次 CI。

收缩后的入口于同机重新验证：`just ci` / `just ci-nightly` 分别 39.27 / 39.45 s，包含恢复本地 incremental 后约 32.73 / 31.67 s 的测试重编译；普通测试分别 370/381 项通过，执行阶段约 1.90/1.92 s。它们不运行示例/基准，GitHub 分为两个 job。这些本机数据没有模拟 GitHub 的 CPU、缓存或编译 flags，不能直接与此前预编译后的 full 时间比较。

维护时按上面的清单命令将 JSON 和 `/usr/bin/time` 结果存放在本地临时目录，记录实际工具版本、profile、CPU、并发、缓存和执行范围。普通测试用例数、基准数量和代码行数都是辅助指标，不能替代成本及覆盖内容。GitHub runner、其他架构和 CPU 分派路径必须以各自实际运行结果为准。
