# primus_tfhe_ntru_lut

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

对已加密的 NTRU-TFHE chunks 执行高精度查表，串联 one-hot CBS、公开及密文表选择、负向旋转和独立 LWE 返回。

## 实验配套参数

启用 `ntt` / `fourier` 后，`experimental::NTT_CLASSIC_LOOKUP_U64` / `FOURIER_CLASSIC_LOOKUP_U64` 是 `HighPrecLutConfig` 常量，组合 n800/h32 的 NTRU `CbsConfig`（`one_hot`）、独立 `key_switching` 和 c8/d5/o8 的 `layout`。`config.try_chunk_format()?` 从 one-hot 的 t=8 派生 tau=2，避免另设一份可能冲突的 chunk 位宽。`config.try_prepare()?` 准备 BR 与必要返回状态；密钥生成使用 `config.one_hot.blind_rotation.algorithm` 与 `config.one_hot.gadget`。不创建闲置 CMux 候选 codec。

`parameters.pbs_codecs(PbsMessageConfig::new(config.one_hot.input_modulus))?` 准备 chunk 编码：输入/返回使用 q24，LUT 输出使用 Q。`config.layout` 中输入输出数量独立，公开函数由调用方提供。这些仅为 16 位算术教学配置，安全性与失败概率尚未评估；修改函数或分区后须重新确定完整预算，见[参数指南](../../guides/development/tfhe-parameters.md#scope-of-paired-parameter-entries)。默认的纯编译功能不启用配置或密钥依赖。

## 工作流

[NTT](../primus_tfhe_ntru_ntt/README.zh_CN.md) 和 [Fourier](../primus_tfhe_ntru_fourier/README.zh_CN.md) 均支持 classic binary/ternary 和 sparse fixed-weight binary 查表。使用 `generator.try_generate_server_key(&client, blind_rotation, Some(cbs_config), rng)` 生成求值材料，算法选择 `BlindRotationAlgorithm::Classic` 或 `Sparse { copy_count, bucket_count }`；CBS 材料为必需项。客户端生成 chunks，再用 `encrypt_padded` 分别加密。基础示例固定 classic BR，保留一条八 chunk 工作流；sparse/public-lift 用法见下文[求值与工作区](#求值与工作区)。

`HighPrecisionLookupTable::try_new(poly_length, ring_modulus, &input_codec, config, function)` 仅用 N、Q 和 codec 的 q/t 编译公开表，不需要 TFHE 参数、秘密或变换。启用 `ntt` 或 `fourier` 后，`try_from_parameters(parameters, &input_codec, config, function)` 可从已有参数取得 N/Q/q，并在编译前检查 codec 的 q。两个入口共用同一编译实现，均不需要密钥或变换表。回调接收 `(完整输入索引, 输出 chunk 索引)`，返回一个 digit。用 `NttLookupTableEvaluator::try_new(context, server_key, table)` 或 `FourierLookupTableEvaluator::try_new(context, server_key, table)` 绑定资源，调用一次 `allocate_output()`，随后重复调用 `evaluate_to(input_chunks, output_chunks)`。输出逐个使用 `context.decryptor(client.external_lwe_secret_key(), codecs.output_codec())` 解码。表拥有 chunk 编码，密钥不依赖 t。Evaluator 借用 context、服务端密钥和表，求值不需要客户端秘密。

先用 `NTT_CLASSIC_LOOKUP_U64` 准备 context 与服务端密钥；八个两位 chunks 表示一个 16 位输入。以下片段计算 `(x*x+3*x+7) mod 65536`，返回八个 chunks：

```rust,ignore
use primus_tfhe_ntru_ntt::PbsMessageConfig;
use primus_tfhe_ntru_lut::{
    HighPrecisionLookupTable, NttLookupTableEvaluator, experimental,
};

let config = experimental::NTT_CLASSIC_LOOKUP_U64;
let chunks = config.try_chunk_format()?;
let codecs = context.parameters()
    .pbs_codecs(PbsMessageConfig::new(config.one_hot.input_modulus))?;
let table = HighPrecisionLookupTable::try_from_parameters(
    context.parameters(),
    codecs.input_codec(),
    config.layout,
    |x, output| {
        let x = x as u64; // 明文中间结果可能超出 u32。
        let value = (x * x + 3 * x + 7) % 65536;
        chunks.chunk(value, output)
    },
)?;
let mut evaluator = NttLookupTableEvaluator::try_new(&context, &server, &table)?;
let mut output = evaluator.allocate_output();
evaluator.evaluate_to(&encrypted_chunks, &mut output);
```

完整可运行工作流见 [ntt_lookup.rs](examples/ntt_lookup.rs) 和 [fourier_lookup.rs](examples/fourier_lookup.rs)。它们使用 n=800/N=1024，以八个两位 chunks 加密 16 位输入，并返回八个 chunks 的 16 位结果。低五个输入 chunks 选择系数，高三个选择 64 个候选多项式之一；输出 chunk 数仍可独立设置。输入 `0b10_10_10_11_11_00_11_01` 返回 `0b10_00_01_01_10_01_01_11`，随后零输入返回 7，两次请求复用同一个 evaluator 和缓冲。

两个示例固定 `Word = u64`，从 `experimental` 取得对应的 `HighPrecLutConfig`。Chunk 位宽从 one-hot 输入 t 派生，输入输出数量及分区取自 `config.layout`，公开函数显式编写。配置准备 BR/返回状态，`config.one_hot.gadget` 用于 CBS 密钥生成。Prime/native Q 与独立 PowOf2 q=2^24 记录在[参数指南](../../guides/development/tfhe-parameters.md)，库测试与诊断继续覆盖 u32。NTT 使用 `U64NttTable`；Fourier 选择 RustFFT。需要 TFHE-FFT 时，同时切换 `Table` 导入、target 的 `required-features` 和 `--features tfhe-fft`。

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

两个 evaluator 独立持有各自后端的公共 `BootstrapResources` 与 one-hot 操作状态；表选择、旋转与 CBS 依次借用同一外积工作区，Fourier 还复用其中同一个 FFT engine。返回绑定独立于 one-hot：NTT 只分配 scalar 返回缓冲，Fourier 只分配 batch 返回缓冲。

两个 evaluator 均可通过 `try_new(context, server_key, lookup_table)` 绑定完整 `ServerKey`。独立 lift 使用 `try_with_public_lift(context, server_key, lookup_table, (nlev_view, &nlev_parameters))`。高级调用方可用 `try_from_parts(context, blind_rotation_key, return_key, circuit_key, public_lift, lookup_table)` 借用分开的材料，此处 `public_lift` 为可选项。可用 `ServerKey::into_parts()` 移出组件而不复制密文缓冲。此流程输出 LWE，始终需要 Q→q、f→s 返回密钥；独立 CBS/one-hot 则无需该密钥。各项材料在绑定时检查，实际秘密和变换身份仍由调用方保证。

`table.needs_public_lift()` 表示剪枝后的选表计划是否包含显式 `Lift`。各绑定入口共用同一选择规则：显式 lift 优先，否则需要时借用 classic initializer 及其 BR 参数。Sparse 计划包含 `Lift` 却没有独立材料时返回 `MissingPublicLiftKey`。无 `Lift` 的计划忽略多余材料，不予保留。One-hot evaluator 不暴露 BR controls。

`NttPublicLift` / `FourierPublicLift` 是 NTT/Fourier NLEV[1] 视图和生成时使用的 `NlevParameters` 的借用元组别名，没有新增 owner 或构造器。Evaluator 检查 N、Q 和变换域存储长度，随后使用该材料自己的 basis，允许其不同于 BR/CBS。材料必须使用相同 accumulator 秘密和变换表示（Fourier 使用同一 table 实例）；所声明的明文、basis 和噪声预算仍由调用方保证。

Sparse 要求固定重量 binary 外部秘密与匹配的 CBS 参数，可沿用查表示例的 n=800、h=32、N=1024、q24。调用方使用同一 context/编码编译公开表并加密输入 chunks。以下 NTT 片段接收这些已准备的值，避免复制整套参数：client 生成计算密钥，并按表的实际需要生成 NLEV[1]；server 绑定材料并返回密文。

```rust,no_run
use primus_modulus::PowOf2Modulus;
use primus_ntt::U64NttTable as Table;
use primus_tfhe::{BlindRotationAlgorithm, CbsGadgetConfig, LweCiphertext};
use primus_tfhe_ntru::ClientKey;
use primus_tfhe_ntru_ntt::{KeyGenerator, TfheContext};
use primus_tfhe_ntru_lut::{HighPrecisionLookupTable, NttLookupTableEvaluator as LookupEvaluator};
use rand::rngs::StdRng;

// 完整展示 setup 和一次密文请求；后续请求继续复用
// server 段创建的 evaluator 与输出缓冲。
fn sparse_setup_and_request(
    context: &TfheContext<u64, Table, PowOf2Modulus<u64>>,
    client: &ClientKey<u64>,
    cbs_config: CbsGadgetConfig,
    table: &HighPrecisionLookupTable<u64>,
    inputs: &[LweCiphertext<u64>],
    rng: &mut StdRng,
) -> Vec<LweCiphertext<u64>> {
    // Client：为自己的固定重量 binary LWE 秘密生成计算材料。
    let mut generator = KeyGenerator::new(context);
    let server_key = generator.try_generate_server_key(
        client,
        BlindRotationAlgorithm::Sparse { copy_count: 3, bucket_count: 64 },
        Some(cbs_config),
        rng,
    ).unwrap();
    // 这里使用 BR 的 basis 和行噪声（查表示例中 sigma=0.7）。
    // 独立的 NlevParameters 可以选择其他提升 basis/噪声预算。
    let lift_parameters = context.parameters().blind_rotation();
    let lift = table.needs_public_lift().then(|| {
        generator.try_generate_public_lift_key(
            client.accumulator_ntru_secret_key(), lift_parameters, rng,
        ).unwrap()
    });

    // Server：接收计算密钥/提升密文、公开参数/表，以及输入密文 chunks。
    let mut evaluator = match &lift {
        Some(key) => LookupEvaluator::try_with_public_lift(
            context, &server_key, table, (key.as_view(), lift_parameters),
        ),
        None => LookupEvaluator::try_new(context, &server_key, table),
    }.unwrap();
    let mut outputs = evaluator.allocate_output();
    evaluator.evaluate_to(inputs, &mut outputs);
    // 后续请求复用此 evaluator，并覆盖同一输出缓冲。
    outputs // 只将结果密文交回 client 解密。
}
```

Fourier 对应替换为 `primus_fft::RustFftTable as Table`、`primus_tfhe_ntru_fourier::{KeyGenerator, TfheContext}` 和 `FourierLookupTableEvaluator as LookupEvaluator`。使用 Fourier 的 Native64 环参数，外部仍为 `PowOf2Modulus<u64>`，全部材料由同一 FFT 表实例生成。Evaluator 借用期间须保留 key/lift 的 owner；重复请求不应重新调用整个 setup 函数。

这是同一累加秘密下的独立 one 加密，不对 sparse 首桶求和派生，后者具有不同的误差分布。生成前检查环和秘密，Fourier 使用 context 的 FFT 表。普通 sparse PBS/CBS/one-hot 不承担此材料的生成或存储成本。

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

默认 features 为空，提供 `ChunkFormat`、`HighPrecisionLookupTable`、`LookupTableConfig`、相关错误及公开多项式访问，无需变换或 evaluator。`try_new` 接收 `PolyLength`、累加 Q、输入 codec 和 chunk 配置；普通依赖不包含 LWE/GLWE/NTRU/TFHE 材料或变换 crate。统计与两种工作区估算均无需启用后端。编译保留完整的不可变选择计划，回调顺序、系数编码和表布局不随 feature 改变。

| Feature | 启用内容 |
| --- | --- |
| `ntt` | `NttLookupTableEvaluator` 及 NTT 依赖，不引入 FFT |
| `fourier` | `FourierLookupTableEvaluator` 及通用 FFT 接口，不引入 NTT 或具体 FFT 引擎 |
| `rustfft` / `tfhe-fft` | `fourier` 与选定的 FFT 实现 |
| `simd` | 已启用算术依赖中的 nightly SIMD，不会激活 evaluator 或 FFT 引擎 |

所有 feature 可以叠加。`LookupTableError::OneHot` / `Evaluation` 只在启用 `ntt` 或 `fourier` 时可用。

NTT 示例要求 `ntt`；Fourier 示例要求其选定引擎。求值测试按实际启用的 NTT/FFT 实现运行，两个字宽的既有用例保持不变；`pipeline` 比较 u64 NTT 与主 Fourier 引擎（启用 RustFFT 时优先选它）。`ntt`、`rustfft`、`tfhe-fft` 可独立启用；NTT 加一个 FFT 引擎注册全部 18 项。未选择可用后端时，target 提示所需 feature，不注册任何 ID。完整验证使用 `just tfhe`，纯编译或单后端可分别运行：

```sh
cargo test -p primus_tfhe_ntru_lut
cargo test -p primus_tfhe_ntru_lut --features ntt
cargo test -p primus_tfhe_ntru_lut --features rustfft
cargo test -p primus_tfhe_ntru_lut --features tfhe-fft
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
