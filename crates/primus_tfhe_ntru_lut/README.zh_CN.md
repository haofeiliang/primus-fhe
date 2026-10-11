# primus_tfhe_ntru_lut

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

对独立加密的 NTRU-TFHE chunks 计算有限函数。One-hot CBS 选择公开表，加密旋转选择其中的系数，再返回外部 LWE 秘密。推荐配置使用 classic binary BR，也支持 classic ternary 和显式选择的 sparse 固定重量 binary BR。

## 快速开始

```sh
cargo run --release -p primus_tfhe_ntru_lut --example ntt_lookup
cargo run --release -p primus_tfhe_ntru_lut --example fourier_lookup
```

[NTT](examples/ntt_lookup.rs) 和 [Fourier](examples/fourier_lookup.rs) 示例将 16 位输入映射为 16 位分段费用。源码区分客户端/服务端阶段，复用密钥、表、evaluator 和缓冲，并检查分段点及域边界。两者均使用 u64 系数，库也支持 u32。

## 实验配套参数

从 `experimental::NTT_CLASSIC_LOOKUP_U64` 或 `FOURIER_CLASSIC_LOOKUP_U64` 开始。它们组合 n800/h32/N1024 one-hot CBS、必需返回 KS 和八个输入/八个输出两位 chunks。`coefficient_chunk_count: None` 选择 d=5，`Some(d)` 可覆盖分区；输入输出数量独立。这些算术教学配置的**安全性与失败概率尚未评估**，见[参数指南](../../guides/development/tfhe-parameters.md#scope-of-paired-parameter-entries)。

`NttHighPrecLutContext::try_from_config` / `FourierHighPrecLutContext::try_from_config` 准备操作参数、编码和变换表；密钥、公开函数编译和可变 evaluator 状态分别准备：

```rust,no_run
use primus_ntt::U64NttTable;
use primus_tfhe_ntru_lut::{NttHighPrecLutContext, experimental};
use rand::{SeedableRng, rngs::StdRng};

let context = NttHighPrecLutContext::<u64, U64NttTable, _>::try_from_config(
    experimental::NTT_CLASSIC_LOOKUP_U64,
)?;
let fee = |x: u64| {
    if x < 16_384 {
        x / 4
    } else if x < 49_152 {
        4_096 + (x - 16_384) / 2
    } else {
        20_480 + (x - 49_152)
    }
};
let table = context.compile_fn(fee)?; // 公开、离线；不使用秘密。

// Client：只有配套生成需要两类秘密；在线客户端仅借用外部秘密 s。
let mut rng = StdRng::seed_from_u64(42);
let (client, server) = context.try_generate_keys(&mut rng)?;
let encryptor = context.encryptor(&client)?;
let decryptor = context.decryptor(&client)?;
let mut input = encryptor.allocate_input();

// Server：接收公开 context/table、计算密钥和加密 chunks。
let mut evaluator = context.evaluator(&server, &table)?;
let mut output = evaluator.allocate_output();
for (value, expected) in [(16_383u64, 4_095u64), (49_152, 20_480)] {
    encryptor.encrypt_to(value, &mut input, &mut rng)?;
    evaluator.evaluate_to(&input, &mut output);
    let result: u64 = decryptor.decrypt(&output)?;
    assert_eq!(result, expected);
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

Fourier 使用 `FourierHighPrecLutContext<u64, RustFftTable, _>` 和对应实验常量。客户端工厂不接收 LUT 或手工 codec：输入/返回 chunks 使用 q，表系数使用 Q。API 处理 chunk 提取、padding 加密和拼接，不对单个高精度 LWE 做同态拆分。

`compile_fn(|x: W| -> W)` 的明文整数类型 W 独立于系数类型 T。完整输入输出位宽须能被 W 容纳，结果须属于输出域，超出位数直接拒绝。编译会为每个输出 chunk 再调用一次纯函数。超过单个机器字的输出可使用 `compile_chunks_fn(|x, output| digit)`、`encrypt_chunks_to` 和 `decrypt_chunks_to`；原始 chunk 切片按低位在前排列。分块解码失败可能已写入前缀，应丢弃该结果。见[客户端契约](src/client.rs)。

## 编码与表分区

令 `M=2^tau>=2`，chunk 使用明文模数 `t=2*M` 和 `0..M` 内的 unsigned digit。输入输出共用 tau，但数量独立且均为正。`ChunkFormat` 提供 `split_to`、`join` 和 `chunk` 明文转换，`context.chunk_format()` 返回已准备格式。位数用 u32，数量和索引用 usize。

| 布局量 | 含义 |
| --- | --- |
| `input_chunk_count` = c | `x=sum_i m_i*M^i` 中的输入 chunk 数 |
| `output_chunk_count` = o | 独立指定的输出 chunk 数 |
| `coefficient_chunk_count` = d | 选择系数的低位 chunk 数，`0<=d<=c` |
| `entries_per_polynomial()` = K = M^d | 每个多项式中使用的系数数量，K<=N |
| `polynomials_per_output()` = P = M^(c-d) | 每个输出 chunk 的存储多项式数量 |
| `input_value_count()` = M^c | 编译时枚举的完整输入域 |

将输入写成 `x=p*K+z`。输出 chunk j 的多项式 p 在系数 z 存放 `E_Q(F(x,j))`，K..N 补零，其中 `E_Q(v)=round(Q*v/(2*M))`。`F(x,j)` 须属于 `0..M`。编译按输出 j 优先、x 升序枚举，每对调用一次。值域及存储限制内可支持任意有限映射；有符号数或定点数的解释由 digit 映射约定。

`polynomial(j,p)` 借用 N 个系数。全部 `o*P*N` 个系数按 `[output][prefix][coefficient]` 连续保存，包括相同多项式和重复输出。M=4、c=3、d=1、N=64 时，每个输出有 16 个多项式，各含四个表项及 60 个零；输入 6 选择多项式 1 的系数 2。

完整输入域大小须能用 usize 表示，因此 `tau*c < usize::BITS`；这是实现中的枚举限制，不是论文约束。编译在分配或调用回调前检查总位宽、元素数和字节大小，但不保证实际可用内存。公开表存储随 c-d 指数增长，占 `o*P*N*sizeof(T)` 字节。

### 选择系数 chunk 数

固定 N、M、c 时，从 `d=min(c, floor(log2(N)/tau))` 开始，让 M^d 接近 N。d 每增加一，公开存储缩小 M 倍，每个输出多一次旋转乘积，同时减少选表运算；应根据完整求值时间和噪声余量选择。

`h=c-d>0` 时，每个输出执行 `P+P/M-1` 次选表乘积，分为 `(P-1)/(M-1)` 组，再做 d 次旋转乘积。首层通过全部 M 个 NLEV selectors 提升，后续层使用 M-1 个 NGSW selectors。h=0 时，唯一公开多项式先经一次 NLEV[1] 提升，再做 d 次旋转。所有输出都执行完整树，包括常量/重复表。推导与共享误差条件见[数值指南](../../guides/development/bootstrapping-contracts.md#fixed-complete-high-precision-lookup)。

## 求值与工作区

用 `context.try_generate_keys(rng)` 生成完整组合，不传入函数；用 `context.evaluator(&server, &table)` 绑定密钥和已编译表，分配一次输出后复用 `evaluate_to`。Evaluator 借用这些所有者，在构造时分配缓冲，在线求值无额外分配。并发 evaluator 需要各自的可变状态。

c=d 时 context 提供提升材料：classic 使用 initializer，sparse 使用按 BR basis/noise 生成的独立 NLEV[1]。c>d 时首层公开选表已完成提升。配套配置采用固定重量秘密，可在创建 context 前选择 sparse：

```rust,ignore
use primus_tfhe::BlindRotationMethod;

let mut config = experimental::NTT_CLASSIC_LOOKUP_U64;
config.one_hot.pbs.algorithm =
    BlindRotationMethod::Sparse { copy_count: 3, bucket_count: 64 };
let context = NttHighPrecLutContext::<u64, U64NttTable, _>::try_from_config(config)?;
```

密钥组合可服务其他几何、编码及材料相容的表，函数值不改变 lift 需求。资源须匹配 N/q/Q 和实际秘密，Fourier 还要求同一个 FFT table 实例。输入输出形状在写入前检查。返回依次执行逐系数 Q→q、提取及到外部秘密的 KS。

显式组合可使用 `backend_context()` 和底层 [NTT](src/ntt.rs) / [Fourier](src/fourier.rs) evaluator。公开 lift 视图将 NLEV[1] 与生成参数配对。c=d 时显式 lift 优先于 classic initializer，必须通过验证；c>d 忽略多余 lift。它可采用不同 basis/noise，但必须在对应环秘密和变换下编码一；元数据不能证明这些事实或足够的分解精度。

## 数值限制

数据表为每个逻辑输入/输出 chunk 存放一个值，输入误差容忍由此前的 [one-hot 保护区](../primus_tfhe_ntru/README.zh_CN.md#one-hot-cbs)提供，不依靠重复数据表项。保护区须预算加密/逐坐标舍入误差，最终解码还须预算 CBS、选表、旋转及 Q→q/KS 误差。Fourier 额外包含 trace 减半和 FFT/转换误差，融合求和不保证与逐项转换后的密文系数相同。共享 selectors 会使输出误差相关；形状检查和示例成功不建立失败概率，见[数值指南](../../guides/development/bootstrapping-contracts.md)。

## Features

默认 features 为 `ntt,rustfft`。Features 不改变回调顺序、系数编码或完整表布局。

| Feature | 启用内容 |
| --- | --- |
| `--no-default-features` | 无密钥、变换或 evaluator 的公开编译与检查 |
| `ntt` | NTT context、服务端组合和 evaluator |
| `fourier` | 不包含具体 FFT 引擎的泛型 Fourier 工作流 |
| `rustfft` / `tfhe-fft` | `fourier` 及所选 FFT 实现 |
| `simd` | 已选依赖中的 nightly SIMD，不选择 evaluator/引擎 |

纯编译使用 `HighPrecisionLookupTable::try_new(poly_length, ring_modulus, input_codec, config, function)`，仅需 N/Q、Rounded 输入 q/t 和 chunk 几何。启用后端时，`HighPrecLutParameters::try_from_config` 可先于变换编译，再移入对应 context。

`--no-default-features --features ntt` 仅选择 NTT，`--no-default-features --features tfhe-fft` 仅选择 TFHE-FFT。Fourier 示例导入 `RustFftTable` 且要求 `rustfft`；切换时须同时修改表导入及 [Cargo.toml](Cargo.toml) 中该 target 的 `required-features`。仅添加 `--features tfhe-fft` 会启用另一引擎，不会切换该示例。

## 基准

```sh
cargo bench -p primus_tfhe_ntru_lut --bench lookup_create -- 'c4_'
cargo bench -p primus_tfhe_ntru_lut --bench lookup_evaluate -- 'c4_'
```

`lookup_create` 测完整公开表创建，**包含分配与 drop**，随机映射在计时外准备。`lookup_evaluate` 测一次完整同态请求，密钥、表、输入和缓冲均已准备。它使用 classic BR，默认测 NTT/RustFFT，`--features tfhe-fft` 额外测 TFHE-FFT。

两者均使用 M=16、d=3、N=4096 和四个输出 chunk。过滤器 `c4_`、`c5_`、`c6_` 对应 16、20、24 位输入，输出保持 16 位，公开存储为 2/32/512 MiB。Criterion 仅过滤计时，其他 case 的计时外准备和检查仍执行。见[基准命令与成本](../../guides/development/testing.md#high-precision-lut-benchmarks)及[实验数值配置](../../guides/development/tfhe-parameters.md#random-high-precision-lut-benchmark)。
