# primus_tfhe_ntru_lut

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

对已加密的 NTRU-TFHE chunks 执行高精度查表，串联 one-hot CBS、公开及密文表选择、负向旋转和独立 LWE 返回。

## 实验配套参数

`experimental::NTT_CLASSIC_LOOKUP_U64` / `FOURIER_CLASSIC_LOOKUP_U64` 组合 n800/h32/N1024 one-hot CBS、其必需返回 KS 和八个输入/八个输出两位 chunks。`coefficient_chunk_count: None` 默认得到 d=5；`Some(d)` 可显式选择其他分区。输入、输出 chunk 数独立。这些算术教学配置没有经过安全性或失败概率评估，见[参数指南](../../guides/development/tfhe-parameters.md#scope-of-paired-parameter-entries)。

`NttHighPrecLutContext::try_from_config` / `FourierHighPrecLutContext::try_from_config` 准备完整操作、q/Q 编码和一份变换表，不生成密钥或求值工作区。若需要先于变换离线编译，使用 `HighPrecLutParameters::try_from_config` 及其编译方法，再将该 owner 移入对应 Context。CBS/BR/返回公共状态与 sampler 只有一份，移动时不 clone，也不增加 Arc。

## 工作流

两个后端支持 classic binary/ternary 和 sparse 固定重量 binary 查表。推荐直接提供纯整数函数与完整整数输入输出，由库处理 chunk 提取、padding 加密和拼接：

```rust,no_run
use primus_ntt::U64NttTable;
use primus_tfhe_ntru_lut::{NttHighPrecLutContext, experimental};
use rand::{SeedableRng, rngs::StdRng};

let context = NttHighPrecLutContext::<u64, U64NttTable, _>::try_from_config(
    experimental::NTT_CLASSIC_LOOKUP_U64,
)?;
let function = |x: u64| (x*x + 3*x + 7) & 0xffff;
let table = context.compile_fn(function)?; // 公开、离线；不使用秘密。

// Client：只有配套生成需要两类秘密；在线客户端仅借用外部秘密 s。
let mut rng = StdRng::seed_from_u64(42);
let (client, server) = context.try_generate_keys(&table, &mut rng)?;
let encryptor = context.encryptor(&client)?;
let decryptor = context.decryptor(&client)?;
let mut input = encryptor.allocate_input();

// Server：接收公开 context/table、计算密钥和加密 chunks。
let mut evaluator = context.evaluator(&server, &table)?;
let mut output = evaluator.allocate_output();
for value in [43981u64, 0] {
    encryptor.encrypt_to(value, &mut input, &mut rng)?;
    evaluator.evaluate_to(&input, &mut output);
    let result: u64 = decryptor.decrypt(&output)?;
    assert_eq!(result, function(value));
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

Fourier 使用 `FourierHighPrecLutContext<u64, RustFftTable, _>` 与对应实验常量。完整示例为 [ntt_lookup.rs](examples/ntt_lookup.rs) 和 [fourier_lookup.rs](examples/fourier_lookup.rs)，输入输出均为 16 位，复用同一 evaluator 与密文存储执行两次请求。五个低 chunk 填满 N=1024 个系数，三个高 chunk 在 64 个多项式间选表。示例固定 u64 系数，库与测试继续支持 u32。

`compile_fn(|x: W| -> W)` 将明文整数 W 与密文系数 T 分开。完整输入输出位宽必须能被 W 容纳，超出输出域的结果直接报错，不截断。编译仍为 output-major：同一纯函数会为每个输出 chunk 再计算一次，不保留全域明文缓存。昂贵函数可以显式预先准备值。`compile_chunks_fn(|x, output| digit)` 保留 digit 回调，支持超过一个整数容量的输出。客户端同样提供 `encrypt_chunks_to` / `decrypt_chunks_to`，使用调用方已有 digit 切片。

Encryptor/decryptor 工厂不接收 LUT 或函数，根据完整操作准备编码：输入、返回 chunks 使用 q，公开表系数使用 Q。整值加解密不分配 digit 缓冲，输入密文分配显式执行。加密前先验证完整数量、维数、整数容量与输入范围，失败时不写入或消耗 RNG。解密会拒绝 padding 半区的 digit，不将其掩码为合法值。`decrypt_chunks_to` 遇到非法解码 digit 时可能已写入前缀，应丢弃该部分结果。密文本身仍不携带秘密/编码身份。

```sh
cargo run --release -p primus_tfhe_ntru_lut --example ntt_lookup --features ntt
cargo run --release -p primus_tfhe_ntru_lut --example fourier_lookup --features rustfft
```

## 编码与表分区

要求明文模数 `t=2*M`，其中 `M=2^tau>=2`。输入与输出 chunks 共用 tau，数量独立指定且均为正。两个密文切片都按低位在前排列：`x=sum_i m_i*M^i`。输入已经分别加密，API 不对单个高精度 LWE 做同态拆分。

`ChunkFormat::new(tau)` 统一派生 `bits()`、`radix()`、`mask()` 和 `plaintext_modulus()`；用后者构造 Rounded codec。`bit_count(count)` 以 u32 返回各自的总位宽，超出范围时拒绝。编译器从 codec 派生相同格式，通过 `table.chunk_format()` 取得，编译时无需再传第二份位宽。格式本身不持有缓冲或 codec。`table.chunk_bits()` 和 `LookupTableStats::input_bits/output_bits` 同样使用 `u32`，编译在分配或调用回调前拒绝超过 `u32::MAX` 的总位宽。Chunk 数量、表长度和索引仍使用 `usize`。

明文机器字使用 `chunks.split_to(value, &mut digits)` 覆盖复用的低位在前切片，再用 `chunks.join(&digits)` 组合。工具拒绝容量超限、截断和非法 digit，允许恰好填满机器字。`chunks.chunk(value, index)` 提取单项 digit，超出机器字部分按零扩展，可用于表回调。机器字转换为可选功能：回调仍可分别提供总位宽超过 u64 或其他单个机器字的输出 digits；LUT 独立保留完整输入枚举与存储上限。

令 `c=input_chunk_count`、`d=coefficient_chunk_count`、`o=output_chunk_count`，要求 `0<=d<=c`、`M^d<=N`。低 d 个 chunks 选择系数，其余高位 chunks 选择多项式。各布局量的含义为：

| 布局量 | 含义 |
| --- | --- |
| `chunk_bits()` = tau | 每个输入/输出 chunk 的统一位宽 |
| `input_value_count()` = M^c | 完整输入可能的取值总数 |
| `entries_per_polynomial()` = K = M^d | 每个多项式中用于存放 LUT 表项的系数个数 |
| `polynomials_per_output()` = P = M^(c-d) | 每个输出 chunk 的逻辑多项式数量，不受存储去重影响 |
| `unique_polynomial_count()` = U | 跨输出共享的实际存储多项式数量 |
| N | 每个多项式实际分配的系数个数，包括补零区域 |

将输入拆成 `x=p*K+z`。对于输出 chunk j，第 p 个多项式的第 z 个系数存放 `E_Q(F(x,j))`，系数 `K..N` 补零。其中 `E_Q(v)=round(Q*v/(2*M))`，乘法在舍入之前。`F(x,j)` 返回目标函数结果的第 j 个 chunk，必须位于 `0..M`。编译按输出优先、再按 x 升序枚举，每对 `(x,j)` 恰好调用一次。在值域及存储限制内可以编译任意有限映射；整数、有符号数或定点数的解释由调用方的 chunk 编码和回调决定。

例如 `M=4, c=3, d=1, N=64` 时，有 64 种输入，每个输出对应 16 个多项式，每个多项式放 4 个表项。多项式 0 存放输入 0..3，多项式 1 存放输入 4..7，以此类推。输入 6 选择多项式 1 的系数 2。每个多项式其余 60 个系数均为零。

`polynomial(j,p)` 返回逻辑输出 j、前缀 p 对应的 N 个系数。相同编码多项式跨输出共享存储，`unique_polynomial_count()` 返回其实际数量。存储包含 U*N 个系数与编译后的选择计划。全等分支删除选择；相同输入 chunk 的相同有序选择可跨输出共享节点。物理池顺序和节点索引属于内部实现。

输入取值总数本身必须能用 `usize` 表示，即 `tau*c < usize::BITS`；这是完整枚举的索引限制，并非论文约束。调用回调前仍检查最坏情况 `o*P*N` 存储及索引长度，但多项式池按需增长。这些检查不保证指数级表一定有足够物理内存可分配。

### 选择系数 chunk 数

固定 N、M、c 时，可从 `d=min(c, floor(log2(N)/tau))` 开始，让 M^d 尽量接近 N。d 每增加 1，公开表的最坏存储量缩小 M 倍，每个输出多一次旋转乘积；最佳选择仍取决于实测时间与噪声余量，计算公式见[阶段说明](IMPLEMENTATION.md#stage-and-buffer-layout)。

编译各个候选 d 后，`table.stats()` 给出输入/输出位数、逻辑/唯一多项式数、需要 one-hot 的 chunk 数、NLEV/NGSW selector 数、选择节点数、公开提升数和同时存活的结果 slot 数。这些数量反映剪枝及跨输出共享，不预测延迟或噪声；`public_lift_count > 0` 等价于 `needs_public_lift()`。

`table.estimate_workspace(output_levels)?` 接收拟用 CBS 输出的 `DecompositionLevelCount`，返回 `ntt_bytes` 与 `fourier_bytes`，与 evaluator 构造共用缓冲长度计算。它是**部分估算**，只统计 LUT 直接持有的 selectors、旋转 controls/factors、结果 slots、current/product 及 Fourier 转换/gadget-one 缓冲。它不含 BR/CBS/one-hot 工作区（包括 sparse 的额外输入状态）、LWE 返回工作区、变换引擎、密钥、公开表/计划、调用方输入输出、分配器开销及构造临时空间；比较 d 时仍需实测总内存与时间。

## 求值与工作区

`context.try_generate_keys(&table, rng)` 生成一份 BR/CBS/返回组合，只补充执行计划实际需要的 lift。Classic 借用已有 initializer；sparse 仅在 `table.needs_public_lift()` 为真时，按 BR 的 basis/noise 生成独立 `NLEV[1]`。BR、CBS 和 lift 共用已接受的环秘密变换/逆元，不生成第二份 BR 或变换表。普通 sparse PBS/CBS/one-hot 不受影响。

使用 sparse 查表时，在创建高精度 Context 前修改 one-hot PBS 的算法：

```rust,ignore
config.one_hot.pbs.algorithm =
    BlindRotationMethod::Sparse { copy_count: 3, bucket_count: 64 };
let context = NttHighPrecLutContext::<u64, Table, _>::try_from_config(config)?;
let table = context.compile_fn(function)?;
let (client, server) = context.try_generate_keys(&table, rng)?;
let mut evaluator = context.evaluator(&server, &table)?;
```

服务端组合可复用于布局、编码和材料需求兼容的其他公开表。最初未生成 lift 的 sparse 组合，绑定后来需要 lift 的表时会报错，不在线生成材料；含 lift 的组合也可绑定不需要它的表。实际秘密与变换身份仍须一致，元数据不能证明这些条件。

显式组合使用 `backend_context()` 借用原 NTRU 环境，通过 `server.into_parts()` 移出完整 `CircuitBootstrapServerKey` 和可选拥有型 lift。`NttPublicLiftKey` / `FourierPublicLiftKey` 将拥有型变换域 NLEV 与生成它的 `NlevParameters` 配对；`NttPublicLift` / `FourierPublicLift` 是借用视图。原有 `NttLookupTableEvaluator` / `FourierLookupTableEvaluator` 构造器与 `try_from_parts` 保留。独立 lift 可以选择其他 basis/noise，默认工作流不隐式重建或重新解释它。

底层公开编译仍可用 `HighPrecisionLookupTable::try_new(poly_length, ring_modulus, input_codec, config, function)`，仅需 N/Q 与输入 q/t。启用后端后也可通过 `try_from_parameters` 复用已有 PBS 参数；两者都不需要密钥或变换。底层 evaluator 绑定检查 N/q/Q 和 one-hot 容量；完整 Context 额外要求匹配自己的 chunk 数、分区与 t。需要 Lift 时，显式材料优先于 classic initializer；没有 Lift 的计划忽略多余 lift。检查证明布局与公开域相容，不证明秘密身份、lift 编码为一或完整噪声余量。

每次调用对低位 chunks 及编译计划实际使用的高位 chunks 执行 one-hot CBS。全等分支省去选择，重复子树只计算一次。公开选择用完整 NLEV selectors 同时提升多项式，加密选择用非零 NGSW selectors；同一 chunk 需要两种表示时共享 BR 与投影。完全不依赖高位的输出使用绑定的 NLEV[1] 提升，公密混合选择也可能需要它。因此，全剪枝表和 c=d 仍需要该材料。每个不同的根仍需低位旋转与返回；重复根在同一 evaluator 内的后续操作完全相同，直接复制已完成的输出。

Sparse 求值在单线程内将这些仍需处理的输入 chunks 两两分组，再依次投影并消费结果。单个输入或奇数尾项沿用普通路径。至少需要两个 chunk 时，构造额外保留一个 BR aggregate、累加器和指数向量，共 `(L_BR+1)*N*sizeof(T) + n*sizeof(usize)` 字节；变换、外积和投影 scratch 仍共享。调度不减少 BR 次数，也不新增 selector 批次；公开求值接口不变。

共享节点复用同一密文及其误差，输出误差存在相关性；根相同且后续操作相同时，复用完整输出密文。剪枝保持明文映射，但改变误差传播路径。完整选择、旋转及返回公式见[实现说明](IMPLEMENTATION.md#stage-and-buffer-layout)。

每组选表在变换域累加所有乘积后只逆变换一次。Fourier 的舍入结果可能与逐个乘积分别转换后求和不同；编码函数保持不变，结果仍需留出足够的解码余量。

数据 LUT 为每个逻辑输入/输出 chunk 编码一个函数值，相同多项式共享存储。容忍输入相位误差的重复保护区位于此前的 one-hot CBS 测试多项式；后续选择和旋转带来加性密文误差，仍需解码余量。

Evaluator 借用 context、server key 和 table，并在构造时分配全部缓冲。复用 `allocate_output()` 的结果与 `evaluate_to`，在线无额外分配；所有 chunk 数量和 LWE 维数在写入前检查。资源必须匹配 N/q/Q，表的 t 决定 one-hot 几何；密钥须实际配套；Fourier 还要求相同 FFT table 实例。每个并发 evaluator 持有独立可变工作区。

返回链路对每个多项式独立执行逐系数 Q→q 和相位提取，再切换到外部 LWE 秘密。NTT 逐项返回，仅分配 scalar 返回缓冲；Fourier 仅分配 `LweReturnBatchWorkspace`，通过独立 `LweReturnEvaluator` 批量执行 key switch，只保留一小块中间 LWE，每次提取后即可覆盖多项式缓冲；输出近似 q 下的 chunk 编码，双重舍入与返回误差须纳入预算。

## 数值限制与进一步阅读

输入须满足 [one-hot 保护区](../primus_tfhe_ntru/README.zh_CN.md#one-hot-cbs)，包含加密、编码与逐坐标量化误差。CBS 和每次选择/旋转外积继续引入误差，Fourier 还包含原生 trace 减半及 FFT 舍入；公开提升分解必须能解析 LUT 尺度。形状校验和功能测试不能认证安全性、生产参数或失败概率。

[参数指南](../../guides/development/tfhe-parameters.md)记录示例选择与验证范围，[测试指南](../../guides/development/testing.md)说明独立契约的覆盖，[实现说明](IMPLEMENTATION.md)记录算法和内部缓冲布局。

## Features

使用 `--no-default-features` 时，提供 `ChunkFormat`、`HighPrecisionLookupTable`、`LookupTableConfig`、相关错误及公开多项式访问，无需变换或 evaluator。`try_new` 接收 `PolyLength`、累加 Q、输入 codec 和 chunk 配置；普通依赖不包含 LWE/GLWE/NTRU/TFHE 材料或变换 crate。统计与两种工作区估算均无需启用后端。编译保留完整的不可变选择计划，回调顺序、系数编码和表布局不随 feature 改变。

| Feature | 启用内容 |
| --- | --- |
| `ntt` | NTT Context、服务端组合与 evaluator，不选择具体 FFT 引擎 |
| `fourier` | Fourier Context、服务端组合与 evaluator，不选择具体 FFT 引擎 |
| `rustfft` / `tfhe-fft` | `fourier` 与选定的 FFT 实现 |
| `simd` | 已启用算术依赖中的 nightly SIMD，不会激活 evaluator 或 FFT 引擎 |

默认 feature 为 `ntt,fourier`，不选择具体 FFT 引擎。所有 feature 可以叠加。`LookupTableError::OneHot` / `Evaluation` 只在启用 `ntt` 或 `fourier` 时可用。

NTT 示例要求 `ntt`；Fourier 示例要求其选定引擎。求值测试按实际启用的 NTT/FFT 实现运行，两个字宽的既有用例保持不变；`high_precision_lut` 比较 u64 NTT 与主 Fourier 引擎（启用 RustFFT 时优先选它）。`ntt`、`rustfft`、`tfhe-fft` 可独立启用；NTT 加一个 FFT 引擎注册全部 18 项。未选择可用后端时，target 提示所需 feature，不注册任何 ID。完整验证使用 `just tfhe`，纯编译或单后端可分别运行：

```sh
cargo test -p primus_tfhe_ntru_lut
cargo test -p primus_tfhe_ntru_lut --no-default-features --features ntt
cargo test -p primus_tfhe_ntru_lut --no-default-features --features rustfft
cargo test -p primus_tfhe_ntru_lut --no-default-features --features tfhe-fft
```

## 基准

```sh
# 创建并释放一个公开的高精度 LUT。
cargo bench -p primus_tfhe_benchmarks --bench high_precision_lut --features lut,ntru-ntt,ntru-fourier,rustfft -- '/create_lut_and_drop/'
# 使用已准备的 LUT 和工作区，同态求值全部输出 chunk。
cargo bench -p primus_tfhe_benchmarks --bench high_precision_lut --features lut,ntru-ntt,ntru-fourier,rustfft -- '/evaluate/'
```

18 项工作负载保留 polynomial、dense、shared 三种表、classic/sparse 成对求值，以及 Q50/Native64 各自的创建。创建计时包含分配、系数填充和释放；求值计时不包含密钥生成、公开 LUT 创建、输入加密和工作区分配。设置 `PRIMUS_LUT_DIAGNOSTICS=1` 并使用 `--test`，可从同一 fixture 显式获取相位误差报告；普通计时只保留结果校验。详见[基准说明](IMPLEMENTATION.md#benchmark-fixture)。

原有 ID 使用多项式示例；包含 `/dense_seed42/` 的 ID 使用相同参数下的固定稠密映射。用 `dense_seed42` 过滤可只运行该负载，用 `c8_d5_o8/evaluate/` 可只测多项式示例的同态求值。

`/shared_middle_chunk/` 诊断映射把每个输出 digit 都设为 `(m_0+m_6) mod 4`，用于隔离越过 chunk 5 的公开选择、省略 chunks 5 和 7 的高位 CBS，以及相同最终输出的复用。它是专门的共享负载，与完整位宽的算术函数不同。
