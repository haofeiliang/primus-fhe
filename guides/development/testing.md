# 测试、基准与契约归属

本指南区分普通测试、编译检查、示例执行和性能测量。包和 target 由 [workspace](../../Cargo.toml) 与 Cargo metadata 决定；实际用例由 nextest 清单决定。库接口与工作区入口见[开发导航](README.zh_CN.md)。

所有 `primus_tfhe*` 的原有普通测试和基准已经移除，后续依据示例与接口重新设计；底层库测试仍保留。TFHE 当前的编译、Clippy、doctest 和示例运行各自只验证其实际范围，不能算作已恢复端到端回归覆盖。

## 验证入口

使用 Rust、Clippy、rustfmt、`cargo-nextest` 和 `just`。普通命令使用当前工具链；GitHub stable job 选择 stable，SIMD 使用 nightly。仓库不提交 Cargo.lock，命令不使用 `--locked`。

| 入口 | 范围 |
| --- | --- |
| `just` / `just ci` | 格式、all-targets Clippy、现有普通测试；CI 另做 doctest 和可选依赖编译检查 |
| `just ci-nightly` | 全 features 的 Clippy、现有普通测试、doctest、严格 private rustdoc、SIMD-only 编译 |
| `just fmt-check` / `just fmt` | 检查格式 / 写入格式化结果 |
| `just check [package] [features]` / `just lint [package] [features]` | all-targets 编译 / Clippy；可选逗号分隔 features |
| `just test [package] [features]` / `just test-doc [package]` | 普通测试 / doctest；nextest 不执行 doctest |
| `just simd [package]` | nightly 全 features 的 Clippy 和现有普通测试 |
| `just tfhe` / `just tfhe-simd` | TFHE 库和示例的 Clippy，分别使用稳定 feature 组合和 nightly/all-features；当前不运行普通 TFHE 测试 |
| `just bench <package> <target> [Cargo options…]` | 运行所属 crate 的一个 Criterion target |
| `just bench-smoke <package> <target> [Cargo options…]` | 用 `--test` 执行一个 Criterion target，不做统计采样 |

package 默认整个 workspace，接受包名或加引号的 Cargo glob。默认 feature 组合为 `ntt,fourier,rustfft,tfhe-fft`。普通测试显式使用 `--lib --tests`，避免 Criterion 进入 nextest；all-targets 编译和 lint 示例、现有基准，不执行它们。Clippy 已承担编译检查，组合入口不再重复全库 check。

```sh
just ci
just ci-nightly
just test primus_lattice ntt,fourier,rustfft,tfhe-fft
just tfhe
just bench-smoke primus_lattice rns_glev --features rns
cargo run --release -p primus_tfhe_ntru_lut --example ntt_lookup --features ntt
```

示例和性能采样按改动显式选择，不加入普通 CI 大参数运行。Smoke 包含构造、密钥生成与断言，不能当作 kernel 延迟。没有可用后端或 Cargo 跳过 required-features target 时，不能把空运行记为数值验证。

### Profile、feature 隔离与 CI

[开发 profile](../../Cargo.toml) 设置 `opt-level=1`，test profile 继承它；调试信息、断言、overflow checks 和本地 incremental 使用默认值。CI 的 `CARGO_INCREMENTAL=0` 不影响本地。Release/bench profile 保持默认；需要验证 release 拒绝边界时，显式给普通测试加 `--release`。

[GitHub CI](../../.github/workflows/ci.yml) 分 stable/nightly 两个 job，各有工具链缓存。严格文档在 nightly 构建一次。空 `RUSTFLAGS` 覆盖本机 native 配置以便复用 runner 缓存；不承诺特定运行时限。少量 `--lib` 命令验证无后端、NTT、Fourier、derive/high_precision 和 SIMD-only 组合，避免 dev-dependencies 或 workspace feature 合并掩盖缺失依赖。

### 独立消费者复查

修改依赖或 feature 边界后，在 workspace 外的临时 Cargo 包复制所需 example，只声明它直接使用的普通依赖和选定后端 feature。临时 manifest 使用独立 `[workspace]`；不要复制 dev-dependencies 或测试辅助模块。

```sh
cargo run --manifest-path /tmp/primus-consumer/Cargo.toml
cargo tree --manifest-path /tmp/primus-consumer/Cargo.toml -e normal,features
```

纯 LWE/公共 LUT 编译应不带 NTT/FFT；NTT PBS/RNS 不带 FFT；Fourier PBS 只带选定引擎。SIMD 仅传播到选定能力，不自动选择另一表示或 FFT 引擎。数值执行与依赖树分别确认结果和依赖隔离。临时消费者核验后删除，不增加常驻框架。

## 测试参数与 CI 成本

普通测试使用能保护目标契约的小参数。代表性示例配置见 [TFHE 参数指南](tfhe-parameters.md)，它们不自动成为普通测试要求。

- 缩小几何和样本时保留字宽、modulus 类型、舍入/分解边界与秘密分布；小环不代表只能用小模数。
- SIMD 分派、完整块、尾部及变换路径用最小可覆盖尺寸；大参数案例需要独立理由。
- 固定 seed 和独立 oracle；不挑成功 seed，不用放宽阈值掩盖失败。
- 示例展示用法，基准测量工作负载；两者都不能替代数学和错误边界回归。

## 可复现的清单

```sh
cargo metadata --no-deps --format-version 1 > /tmp/primus-targets.json
cargo nextest list --workspace --features ntt,rustfft,tfhe-fft --lib --tests --list-type binaries-only \
  --message-format json > /tmp/primus-test-binaries.json
cargo nextest list --binaries-metadata /tmp/primus-test-binaries.json \
  --message-format json > /tmp/primus-tests.json
```

改变工具链、features、profile 或源码后重新生成。核对实际 `test-count` 和 target kind，不能将源码中的 `#[test]` 数量等同于宏展开后的用例数，也不把 Criterion、examples 与普通测试相加。

## Feature 与字宽范围

- SIMD 使用 nightly。默认与 SIMD 复用通用 API 测试；只有专属类型才需要条件编译。启用 feature 不保证触达分派，需保留相关长度边界。
- `primus_modulus/derive` 与 `primus_distr/high_precision` 有独立可选覆盖。
- integer/lattice 的 `serde` 默认关闭，可显式运行两包的 serde 测试；nightly all-features 已覆盖。
- lattice/encoding 的 `rns` 和 data 的 `aligned-vec` 可能由 workspace 消费者合并启用，独立包运行不能依赖这种合并。
- 底层保留 u32/u64 及必要的小字宽、多 limb 测试；TFHE 示例固定 u64，当前不提供普通 TFHE 双字宽回归保证。

### 变换后端、FFT 引擎与 target 覆盖

lattice、GLWE/NTRU 的 `ntt` / `fourier` 控制表示、转换、运算和工作区；`rns` 启用 DCRT 所需 NTT。两个 TFHE family 无具体后端，四个后端 crate 固定选择对应表示。FFT 默认仅公共接口和 torus 转换，`rustfft` / `tfhe-fft` 显式选择实现。

现有底层混合对照测试与示例用 `required-features` 声明要求，缺少时 Cargo 会跳过；TFHE 的 `just tfhe` 编译 NTT 和双 FFT 能力以及现有示例，不等于实际执行全部引擎。FFT 底层可按需分开复查：

```sh
cargo nextest run -p primus_fft --lib --tests
cargo nextest run -p primus_fft --lib --tests --features rustfft
cargo nextest run -p primus_fft --lib --tests --features tfhe-fft
cargo nextest run -p primus_fft --lib --tests --features rustfft,tfhe-fft
```

## 契约与主要 setup 归属

基础类型、算术、表示及密码原语的测试留在拥有其契约的 crate，详细入口如下。TFHE 原有普通测试已删除；未来分别恢复共享几何/参数边界和真实后端消费，不重复整套底层测试或为测试新增生产接口。

## 基础库的聚焦覆盖

以下入口适用于 `data/integer/gcd/reduce/modulus/factor/barrett_derive/distr`。每项测试说明目标契约与 oracle；非平凡内部函数及测试辅助逻辑说明输入选择、数值前提或算法原因。机械转发无需复述实现。

| 契约 | 维护入口与保留理由 |
| --- | --- |
| 存储绑定、整数和 GCD | [Data](../../crates/primus_data/tests/integration.rs) 在存储绑定测试中直接使用所有权构造器并验证读写，不重复验证标准库迭代器或 aligned-vec 自身对齐；[整数测试](../../crates/primus_integer/tests) 保留跨 limb 进借位、移位和独立整数 oracle；[GCD](../../crates/primus_gcd/tests/xgcd.rs) 保留小字宽穷举和宽字整数 oracle |
| 各模数的切片加减 | [slice_add_sub.rs](../../crates/primus_modulus/tests/slice_add_sub.rs) 集中 u32/u64 的 Native、PowOf2、Compact、Barrett、Uint 覆盖，使用 u128 oracle、偏移切片和边界哨兵；各 modulus 文件保留不同的构造、标量、乘法、求逆及一元操作契约 |
| 原生与派生 Barrett | [原生内核](../../crates/primus_modulus/src/barrett/native.rs) 直接比较可用的 AVX-512 实现，避免通常分派遮住另一个实现；[派生消费者](../../crates/primus_modulus/tests/derives.rs) 编译并验证生成代码。保留模数位宽、IFMA 上界、32 元素分派点、vector 尾部及累加器复用；无独立执行路径的千元素重复不进入普通测试。[点积边界](../../crates/primus_modulus/tests/barrett_modulus.rs) 用 u128 oracle 验证运行时/派生 Barrett 的跨模数输入界，以及 16 项和 SIMD 完整块/尾部 |
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
| NTT | [ntt.rs](../../crates/primus_ntt/tests/ntt.rs) 用 N=32/64、q=257 的直接多项式求值固定根选择、bit-reversed 排列和逆归一化；U32/U64 用 32/64 检查运行时分派、偏移切片和 lazy 范围；私有 kernel 测试直接调用 scalar，覆盖 U32 及 U64 两种乘法位宽，不依赖宿主 CPU；U64 保留三种模数位宽，另以 2048/4096/8192 覆盖 AVX-512 基例及两层递归，不能统一缩成小环 |
| 两个 FFT 后端 | [负循环卷积](../../crates/primus_fft/tests/negacyclic.rs) 用有符号整数 O(N²) oracle 验证 packing 和乘积归一化；短环验证 offset 切片与并发独立 workspace；[擦除](../../crates/primus_fft/tests/zeroize.rs) 保留短缓冲区和 N=1024 的后端工作存储；TFHE-FFT 私有测试强制不同 plan base size，避免依赖自动 planner 恰好选中某种谱排列 |
| torus 转换 | [roundtrip.rs](../../crates/primus_fft/tests/roundtrip.rs) 对 u32/u64 使用浮点 round、饱和有符号转换和 unsigned wrapping 作为独立 oracle；保留所有浮点指数、代表性尾数和正负舍入/饱和边界，不再追加十万次随机比特扫描 |
| 分解 | [primitive oracle](../../crates/primus_decompose/tests/primitive_approx_signed_basis_oracle.rs) 保留小模数穷举、native 半步舍入、digit 范围及层序；[多 limb 分解](../../crates/primus_decompose/tests/big_uint.rs) 保留跨 limb、drop/carry 边界、固定 stride 1/2/4 和 fallback 3 的批次差分，边界之外仅少量固定 seed 输入 |
| RNS | [base.rs](../../crates/primus_rns/tests/base.rs) 从 u128 同时构造 modulus-major 和 value-major 预期值，覆盖跨 u64 limb 边界；[converter](../../crates/primus_rns/tests/converter.rs) 用独立小整数 CRT 求和核对单项/批量/paired fast 入口，保留 exact 居中 lift、源模数大于目标模数及 scratch 复用；[hybrid](../../crates/primus_rns/tests/hybrid.rs) 保留裁剪基后的固定分区、mod-up 流式输出和多 P mod-down。65 元素的 scaled batch 保留 native 分派及尾部 |
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
| 布局与存储 | [layout.rs](../../crates/primus_lattice/tests/layout.rs) 检查 PolyLength 的支持范围/单位派生、size 拒绝、ABox 消费后保留分配、偏移 slice 写回、串行工作区 rebind 拒绝/异常恢复及 RNS limb 宽度相容性；不测试 aligned-vec 本身或迭代器计数 |
| 共享算术与 gadget 布局 | [arithmetic.rs](../../crates/primus_lattice/tests/arithmetic.rs) 以 65 元素和偏移哨兵覆盖向量/尾部；[RNS](../../crates/primus_lattice/tests/rns_arithmetic.rs) 保留两模数的不同因子与 row/level/component 顺序。[明文和对角注入](../../crates/primus_lattice/tests/plaintext_and_gadget.rs) 使用 N=4、独立扁平索引 oracle，每个共享宏保留一个包装类型，Fourier 的复数契约单独验证 |
| 多项式乘法与旋转 | [polynomial_products.rs](../../crates/primus_lattice/tests/polynomial_products.rs) 保留 NTRU 单多项式和 GGSW 批次遍历，NTT 的 N=32 保留向量长度；八个指数覆盖符号/环绕和脏 scratch 后零指数。CRT 以 N=4 穷举八个指数；配对旋转的纯转发不重复 [poly 的独立穷举](../../crates/primus_poly/tests/monomial.rs)。[Fourier](../../crates/primus_lattice/tests/fourier.rs) 的 N=8 整数卷积 oracle 保留两个 FFT 后端 |
| 外积与 CMux | [external_product.rs](../../crates/primus_lattice/tests/external_product.rs) 保留 NLev/NGSW 的层序、控制与输出不同层数、变换域/系数域输出、短输出拒绝前不写入及非零→零复用。[ternary_cmux.rs](../../crates/primus_lattice/tests/ternary_cmux.rs) 保留 ±1/0 控制、两种分解深度、NTT/Fourier 及 Fourier 的 u32/u64 和两个 FFT 后端，指数按边界选择 |
| 提取 | [extraction.rs](../../crates/primus_lattice/tests/extraction.rs) 保留手算样本顺序、NTRU `c*f` 与 GLWE `b-a*s` 的整数卷积 oracle、完整/部分秘密、native/显式模数逆提取、padding 和 packed 拒绝；它们各自保护不同的符号或布局契约 |
| 首次融合与资源复用 | 首次融合的秘密和分解残差由 [NTRU phase contracts](../../crates/primus_ntru/tests/phase_contracts.rs) 验证；四后端 PBS/CBS/高精度 LUT 保留复用后的数值结果断言，不把指针相等当作零临时分配证明 |

双引擎、独立 RNS、nightly SIMD/RNS 及 release 拒绝契约分别验证：

```sh
cargo nextest run -p primus_lattice --lib --tests --features ntt,rustfft,tfhe-fft
cargo nextest run -p primus_lattice --lib --tests --features rns,rustfft,tfhe-fft
cargo +nightly nextest run -p primus_lattice --lib --tests --all-features
cargo nextest run -p primus_lattice --lib --tests --release --features rns,rustfft,tfhe-fft
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
| RNS 分解与 KS | [glev.rs](../../crates/primus_glwe_rns/tests/glev.rs)、[ext_prod.rs](../../crates/primus_glwe_rns/tests/ext_prod.rs) 保留多字宽分解和公钥 GGSW 消费；[auto.rs](../../crates/primus_glwe_rns/tests/auto.rs) 在 CRT/DCRT 上分别验证 identity、`degree=N+1` 与一般奇数 automorphism，复用密文及已绑定 evaluator，并与独立明文 scatter 比较，[trace.rs](../../crates/primus_glwe_rns/tests/trace.rs) 保留 CRT/DCRT/reverse 的模逆归一化。[domain.rs](../../crates/primus_glwe_rns/tests/domain.rs) 拒绝所有自同构/trace/展开绑定的异布局、有序 Q、radix 与层数；[expand.rs](../../crates/primus_glwe_rns/tests/expand.rs) 比较串行/双 worker 的完整、部分及单输出展开，覆盖拒绝前不写入。池 guard 的 unwind 归还就地测试。[ksk.rs](../../crates/primus_glwe_rns/tests/ksk.rs) 区分 classic 与 hybrid，后者保留三个 Q limb、P 基及不等长分区；内部系数域参考差分和 mixed-domain mod-down 仍就地测试 |
| 秘密擦除与资源 | [GLWE zeroize](../../crates/primus_glwe/tests/zeroize.rs)、[NTRU zeroize](../../crates/primus_ntru/tests/zeroize.rs) 观察释放前存储，保留失败构造、重试、变换后秘密/逆、显式擦除失效及工作区复用。[RNS zeroize](../../crates/primus_glwe_rns/tests/zeroize.rs) 观察 DCRT 秘密转换中途 unwind 的释放前擦除；私有工作区的双缓冲擦除留在内部测试，公共 domain 构造拒绝放 [parameter.rs](../../crates/primus_glwe_rns/tests/parameter.rs)。首次融合及工作区复用后的数值结果由真实消费者验证 |

不在本层重复底层 add/sub/neg/scalar kernels 的多份加解密往返。多项式算术 oracle、BFV 的缩放乘法、带噪声求值密钥的相位关系各自保留；省略某个操作之前的普通解密检查，不省略该操作结果的检查。测试不要求单独标记 SIMD，默认和全 feature 运行同一套契约：

```bash
packages=(-p primus_lwe -p primus_glwe -p primus_ntru -p primus_glwe_rns)
cargo check "${packages[@]}" --all-targets --features ntt,rustfft,tfhe-fft
cargo nextest run "${packages[@]}" --lib --tests --features ntt,rustfft,tfhe-fft
cargo clippy "${packages[@]}" --all-targets --features ntt,rustfft,tfhe-fft -- -D warnings
cargo +nightly check "${packages[@]}" --all-targets --all-features
cargo +nightly nextest run "${packages[@]}" --lib --tests --all-features
cargo +nightly clippy "${packages[@]}" --all-targets --all-features -- -D warnings
cargo nextest run "${packages[@]}" --lib --tests --features ntt,rustfft,tfhe-fft --release
```

Release 验证公开拒绝和擦除失效不依赖 debug assertions；doctest 按同样 package/feature 范围单独运行。本机 SIMD 通过只代表当前 CPU 上实际分派到的路径。这里不执行大参数统计、bench 或示例，也不替代 TFHE 消费者的端到端验证。

## TFHE 流程与共享辅助代码的聚焦覆盖

当前保留四后端及 LUT 的 26 个示例、公开 rustdoc 和底层密码原语测试。原有 TFHE 单元/集成测试、集中 benchmark 包、参数诊断 CLI 和报告脚本均已移除。测试待示例驱动的接口收敛后重新设计；编译成功和示例结果不补足这段时间的回归覆盖。

恢复时按独立契约选择少量小参数测试：共享 LUT/旋转 oracle、家族配置边界、PBS/ManyLUT/MVB 输出编码、CBS/one-hot 实际消费、q/Q 返回及高精度 chunk 组合。NTT/Fourier、u32/u64、classic/sparse 等差异在真正拥有差异的层验证，不复制大型参数矩阵。

未来 TFHE 基准放回所属后端或 LUT crate 的 `benches/`，单个文件就地组织 helper。基准使用推荐公开工作流，不为阶段拆时新建公开资源入口、共享 support crate 或自动分析框架。完整请求是主要测量对象；LUT 创建和在线求值分别计时，setup 不混入在线延迟。历史结果见[性能记录](../performance/README.zh_CN.md)，旧命令须在报告对应版本运行。

## 成本记录方法

分别记录构建、枚举、运行和 smoke，不把一次带编译运行与另一轮缓存运行直接比较。可用 `/usr/bin/time` 记录 wall time 与进程 RSS，用 nextest 汇总观察执行阶段及慢用例；其进程 RSS 不是所有并行子进程的内存总峰值。缓存记录区分 `target/debug`、`target/release`、Criterion 数据和剩余磁盘空间。

维护时按上面的清单命令将 JSON 和 `/usr/bin/time` 结果存放在本地临时目录，记录实际工具版本、profile、CPU、并发、缓存和执行范围。普通测试用例数、基准数量和代码行数都是辅助指标，不能替代成本及覆盖内容。GitHub runner、其他架构和 CPU 分派路径必须以各自实际运行结果为准。
