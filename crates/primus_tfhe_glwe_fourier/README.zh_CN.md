# primus_tfhe_glwe_fourier

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

基于原生环面和 Fourier 变换的 GLWE TFHE 后端。提供 PBS、ManyLUT、分解式 MVB、Boolean 门和 CBS，两种 PBS 顺序均支持 classic binary/ternary 或 sparse fixed-weight binary 盲旋转。见[操作与编码选择](../primus_tfhe/README.zh_CN.md#选择同态操作)和 [GLWE 参数/密钥域](../primus_tfhe_glwe/README.zh_CN.md)。

## 快速开始

```sh
cargo run -p primus_tfhe_glwe_fourier --release --example fourier_basic
```

[basic 示例](examples/fourier_basic.rs)将加密输入组合成 `z=2*x+y`，计算 `score=min(z,6)`，再直接对该密文执行第二次 PBS，得到 `price=2*score+[score>=4]`。它使用 `Word = u64`、消息模数 t=32，复用密钥、LUT、evaluator 和缓冲。源码标明客户端/服务端阶段，只解密最终结果。反馈须满足 padded 输入范围及噪声预算，消息模数相同并不足够。

## 实验配套参数

```rust
use primus_tfhe_glwe_fourier::{experimental, TfheContext};
use primus_fft::RustFftTable as Table;

let config = experimental::CLASSIC_PBS_U64;
// Context 使用 config.messages；构造前修改 output_modulus 即可覆盖默认输出域。
let context = TfheContext::<u64, Table>::try_from_pbs_config(config)?;
```

从 [experimental](src/experimental.rs) 选择操作配置。`PbsConfig` 包含 BR/KS、PBS 顺序及输入输出消息；`CbsConfig` 添加 CBS gadget，使用 `TfheContext::try_from_cbs_config`。这些算术教学参数的**安全性及失败概率尚未评估**，数值选择与噪声角色见[家族指南](../primus_tfhe_glwe/README.zh_CN.md#实验配套参数)。

`PbsMessageConfig::new(t_in)` 默认输入输出消息模数相同，`.with_output_modulus(t_out)` 可独立修改输出。创建 PBS context 前设置 `config.messages`，CBS 则设置 `config.pbs.messages`；客户端和编译器据此派生编码。同钥消息覆盖见[选择输出编码](../primus_tfhe/README.zh_CN.md#选择输出编码)。

## 操作示例

示例均使用 u64，在请求循环外准备可复用状态。替换快速开始命令中的示例名即可运行其他流程。

| 流程 | `experimental` 配置 | 完整示例 |
| --- | --- | --- |
| 两次连续 PBS | `CLASSIC_PBS_U64` | [fourier_basic](examples/fourier_basic.rs) |
| `admin OR (member AND NOT revoked)` | `CLASSIC_PBS_U64`，消息 4→4 | [fourier_boolean](examples/fourier_boolean.rs) |
| 使用 sparse BR 的相同评分流程 | `SPARSE_PBS_U64` | [fourier_sparse](examples/fourier_sparse.rs) |
| ManyLUT grade/flag，再做密文组合 | `CLASSIC_MANY_LUT_U64` | [fourier_many_lut](examples/fourier_many_lut.rs) |
| CBS 谓词 → CMux → 环加法 | `CLASSIC_CBS_U64` | [fourier_circuit_bootstrap](examples/fourier_circuit_bootstrap.rs) |
| 使用 sparse BR 的相同 CBS 流程 | `SPARSE_CBS_U64` | [fourier_sparse_circuit_bootstrap](examples/fourier_sparse_circuit_bootstrap.rs) |
| 同一输入产生 17 个数值阈值标志 | `CLASSIC_THRESHOLD_MVB_U64` | [fourier_mvb_thresholds](examples/fourier_mvb_thresholds.rs) |

普通 PBS/ManyLUT 和 MVB 使用 `context.try_generate_keys(rng)`。从 `client.external_lwe_secret_key()` 取得外部秘密，绑定到 `context.encryptor`；PBS/ManyLUT 用 `pbs_decryptor` 解密，MVB 的 Scaled 输出用 `mvb_decryptor`。公钥输入使用 `public_encryptor`，客户端无需 LUT 或手工 codec。

ManyLUT 通过 `pbs_lookup_table_compiler` / `compile_interleaved_fn` 编译，使用 `context.evaluator` 求值。示例从 t_in=16 映射到 t_out=8，再组合返回的 grade/flag 密文；它们不能直接反馈给编码不同的输入 PBS。MVB 使用 `compile_mvb_fn` 和 `mvb_evaluator`，保留完整输入分辨率，但因子范数会放大噪声。其 Scaled 标志不是 Boolean 门密文，见[共享 MVB 契约](../primus_tfhe/README.zh_CN.md#固定尺度分解式-mvb)。

CBS 使用 `context.try_generate_circuit_bootstrap_keys(rng)`、`compile_cbs_fn` 和 `circuit_bootstrap_evaluator_with_lookup_table`。示例编译 `[m>=2]`，选择加密费用方案后加上加密附加费用。`accumulator_client(client.glwe_secret_key(), t_ring)` 以 Scaled 编码加密候选，候选的 t_ring=8 独立于外部消息域。环系数不是独立 SIMD 槽。CMux 要求整个输入域上的函数均为 bit、秘密配对且候选兼容，见 [CBS 契约](../primus_tfhe/README.zh_CN.md#cbs-输出与消费)。普通 PBS 可复用 CBS 组合中的 `server.server_key()`。

## 参数与表示

输入、累加器和返回密文共用 q。`PbsOrder::BootstrapKeyswitch` 的外部秘密是小 LWE 秘密（维数 n），`KeyswitchBootstrap` 则是展平的环秘密（维数 kN）。`context.allocate_lwe_ciphertext()` 使用所选外部维数。Basic 示例使用 BR→KS，MVB 示例使用 KS→BR。必需 KS 及其独立噪声见[家族指南](../primus_tfhe_glwe/README.zh_CN.md#参数与外部密钥域)。

本后端只支持 `NativeModulus<T>`，不支持 `PowOf2Modulus` 环。`RustFftTable` 和 `TfheFftTable` 均支持 u32/u64。

变换域密钥、数据和 evaluator 须使用**同一个 FFT 表实例**，长度相同不能证明表示一致。除加密、分解和密钥切换噪声外，还须计入 FFT 近似误差，详见 [Fourier 契约](../primus_fft/README.zh_CN.md)。

分解式 MVB 要求实际 Scaled 输出尺度 `round(2^BITS/t_out)` 为偶数；奇数尺度返回 `LookupTableError::OddFactorizationScale`。因子按有符号整数变换，不做环面缩放；须预算其放大和 FFT 误差。见 [MVB 契约](../primus_tfhe/README.zh_CN.md#固定尺度分解式-mvb)。

Sparse BR 须在 `config.method` 中显式选择 `BlindRotationMethod::Sparse`；仅使用固定重量秘密仍可运行 classic BR。Sparse 要求 binary 重量 `0<h<n`、`copy_count>=1`、`bucket_count>=max(copy_count,h)`。两种顺序均支持 PBS、ManyLUT、MVB 和 CBS。PBS 配置可用，不代表 CBS 输出精度或 CMux 噪声余量充分。

重复请求保留 context、密钥和已编译程序，`_to` 方法复用 evaluator scratch 及调用方输出；并发请求需要独立的可变 evaluator。MVB 程序保持与其 context 绑定。独立材料组合及逐调用借用契约见 [KeyGenerator](src/key.rs)、[Evaluator](src/evaluator.rs) 和 [CircuitBootstrapEvaluator](src/circuit_bootstrap/evaluator.rs)，默认流程无需手工组合资源。

## Features

默认启用 RustFFT。普通依赖已启用 `fourier`，单独使用不引入 NTT；可选 `simd` 启用依赖中的 nightly SIMD 算术，不选择 FFT 引擎。

| Cargo 参数 | 可用引擎 |
| --- | --- |
| 默认 | RustFFT |
| `--no-default-features --features tfhe-fft` | 仅 TFHE-FFT |
| `--features tfhe-fft` | 两者均可用，由具体表类型选择 |
| `--no-default-features` | 不含具体引擎的泛型 API |

示例导入 `primus_fft::RustFftTable as Table`，并在 [Cargo.toml](Cargo.toml) 声明 `required-features = ["rustfft"]`；只添加 `--features tfhe-fft` 不会切换引擎。仅用 TFHE-FFT 运行示例时，须将导入改为 `primus_fft::TfheFftTable as Table`，对应 target 的 `required-features` 改为 `["tfhe-fft"]`，再使用 `--no-default-features --features tfhe-fft`。

基准已经分别实例化每个启用的引擎，选择引擎无需修改基准源码。

## 基准

```sh
cargo bench -p primus_tfhe_glwe_fourier --bench pbs
```

| Target | 计时请求 |
| --- | --- |
| [pbs](benches/pbs.rs) | 一次完整 PBS；dense u32/u64、fixed-weight classic/sparse u64 |
| [many_lut](benches/many_lut.rs) | 一次双输出 grade/flag ManyLUT，u64 |
| [mvb](benches/mvb.rs) | 一次 17 输出阈值 MVB，u64 |
| [cbs](benches/cbs.rs) | 一次谓词 CBS 加 CMux，u64 |

每次迭代使用已准备的密钥、LUT 和缓冲测量一个服务端请求，准备和解密校验不计时。ManyLUT/CBS 基准不包含示例后续的密文算术。只有 fixed-weight classic/sparse PBS 配对仅改变 BR 算法，dense 用例使用不同参数。计时范围与比较限制见[基准指南](../../guides/development/testing.md#tfhe-benchmarks)。

仅测量 TFHE-FFT：

```sh
cargo bench -p primus_tfhe_glwe_fourier --bench pbs --no-default-features --features tfhe-fft
```

保留默认 features 并添加 `--features tfhe-fft`，可分别测量两个引擎。

## 进一步阅读

[API 源码](src/lib.rs) · [共享编码与错误](../primus_tfhe/README.zh_CN.md) · [数值契约](../../guides/development/bootstrapping-contracts.md) · [性能说明](../../guides/performance/README.zh_CN.md)
