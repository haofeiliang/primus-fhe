# primus_tfhe_ntru_lut

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

对已加密的 NTRU-TFHE chunks 执行高精度查表，串联 one-hot CBS、公开及密文表选择、负向旋转和独立 LWE 返回。

## 工作流

使用 [NTT](../primus_tfhe_ntru_ntt/README.zh_CN.md) 或 [Fourier](../primus_tfhe_ntru_fourier/README.zh_CN.md) 的 classic binary/ternary context，通过 `context.try_generate_keys(Some(cbs_config), rng)` 生成配对密钥。拒绝 sparse 密钥和缺失 CBS 材料。客户端生成 chunks，再用 `encrypt_padded` 分别加密。

`HighPrecisionLookupTable::try_new(parameters, &input_codec, config, function)` 编译公开表。回调接收 `(完整输入索引, 输出 chunk 索引)`，返回一个 digit。用 `NttLookupTableEvaluator::try_new(context, server_key, table)` 或 `FourierLookupTableEvaluator::try_new(context, server_key, table)` 绑定资源，调用一次 `allocate_output()`，随后重复调用 `evaluate_to(input_chunks, output_chunks)`。输出逐个使用 `context.decryptor(client.external_lwe_secret_key(), &input_codec)` 解码。表拥有 chunk 编码，密钥不依赖 t。Evaluator 借用 context、服务端密钥和表，求值不需要客户端秘密。

对于 u32、`t=8`、`N=1024` 的 context，八个两位 chunks 表示一个 16 位输入。以下片段计算 `(x*x+3*x+7) mod 65536`，返回八个 chunks：

```rust,ignore
use primus_tfhe_ntru_lut::{
    HighPrecisionLookupTable, LookupTableConfig, NttLookupTableEvaluator,
};

let input_codec = primus_encoding::RoundedCodec::new(8u32, context.parameters().external_lwe().cipher_modulus());
let table = HighPrecisionLookupTable::try_new(
    context.parameters(),
    &input_codec,
    LookupTableConfig {
        input_chunk_count: 8,
        output_chunk_count: 8,
        coefficient_chunk_count: 5,
    },
    |x, output| {
        let x = x as u64; // 明文中间结果可能超出 u32。
        let value = (x * x + 3 * x + 7) % 65536;
        ((value >> (2 * output)) & 3) as u32
    },
)?;
let mut evaluator = NttLookupTableEvaluator::try_new(&context, &server, &table)?;
let mut output = evaluator.allocate_output();
evaluator.evaluate_to(&encrypted_chunks, &mut output);
```

完整可运行工作流见 [ntt_lookup.rs](examples/ntt_lookup.rs) 和 [fourier_lookup.rs](examples/fourier_lookup.rs)。它们使用 n=800/N=1024，以八个两位 chunks 加密 16 位输入，并返回八个 chunks 的 16 位结果。低五个输入 chunks 选择系数，高三个选择 64 个候选多项式之一；输出 chunk 数仍可独立设置。输入 `0b10_10_10_11_11_00_11_01` 返回 `0b10_00_01_01_10_01_01_11`，随后零输入返回 7，两次请求复用同一个 evaluator 和缓冲。

两个示例默认使用 `type Word = u32`；改为 u64 时修改此别名，NTT 示例还需将 `U32NttTable as Table` 导入改为 `U64NttTable as Table`。Fourier 示例默认 RustFFT，改用 `TfheFftTable as Table` 可选择 TFHE-FFT；修改后执行同一运行命令。每个文件的本地 `parameters()` 与 `circuit_config()` 直接构造 `TfheConfig` / `CircuitBootstrapConfig`，展示尺寸、噪声、对应字宽的分解、prime/native 环模数和独立的 PowOf2 q=2^24，数值选择见[参数矩阵](../../guides/development/tfhe-parameters.md)。

```sh
cargo run --release -p primus_tfhe_ntru_lut --example ntt_lookup
cargo run --release -p primus_tfhe_ntru_lut --example fourier_lookup --features rustfft
```

## 编码与表分区

要求明文模数 `t=2*M`，其中 `M=2^tau>=2`。输入与输出 chunks 共用 tau，数量独立指定且均为正。两个密文切片都按低位在前排列：`x=sum_i m_i*M^i`。输入已经分别加密，API 不对单个高精度 LWE 做同态拆分。

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

固定 N、M、c 时，可从 `d=min(c, floor(log2(N)/tau))` 开始，让 M^d 尽量接近 N。d 每增加 1，公开表的最坏存储量缩小 M 倍，每个输出多一次旋转乘积；最佳选择仍取决于实测时间与噪声余量。精确操作数见[阶段说明](IMPLEMENTATION.md#stage-and-buffer-layout)。

## 求值与工作区

两个 evaluator 独立持有各自后端的公共 `BootstrapResources` 与 one-hot 操作状态；表选择、旋转与 CBS 依次借用同一外积工作区，Fourier 还复用其中同一个 FFT engine。返回绑定独立于 one-hot：NTT 只分配 scalar 返回缓冲，Fourier 只分配 batch 返回缓冲。

两个 evaluator 均可通过 `try_new` 接收完整 `ServerKey`，或通过 `try_from_parts(context, blind_rotation_key, return_key, circuit_key, lookup_table)` 借用独立材料。可用 `ServerKey::into_parts()` 移出组件而不复制密文缓冲。此流程输出 LWE，始终需要 Q→q、f→s 返回密钥；独立 CBS/one-hot 则无需该密钥。三类材料在绑定时检查，实际秘密和变换身份仍由调用方保证。

每次调用对低位 chunks 及编译计划实际使用的高位 chunks 执行 one-hot CBS。全等分支省去选择，重复子树只计算一次。公开选择用完整 NLEV selectors 同时提升多项式，加密选择用非零 NGSW selectors；同一 chunk 需要两种表示时共享 BR 与投影。完全不依赖高位的输出用 initializer 的 BR basis 直接提升。每个不同的根仍需低位旋转与返回；重复根在同一 evaluator 内的后续操作完全相同，直接复制已完成的输出。

共享节点复用同一密文及其误差，输出误差存在相关性；根相同且后续操作相同时，复用完整输出密文。剪枝保持明文映射，但改变误差传播路径。完整选择、旋转及返回公式见[实现说明](IMPLEMENTATION.md#stage-and-buffer-layout)。

每组选表在变换域累加所有乘积后只逆变换一次。Fourier 的舍入结果可能与逐个乘积分别转换后求和不同；编码函数保持不变，结果仍需留出足够的解码余量。

数据 LUT 为每个逻辑输入/输出 chunk 编码一个函数值，相同多项式共享存储。容忍输入相位误差的重复保护区位于此前的 one-hot CBS 测试多项式；后续选择和旋转带来加性密文误差，仍需解码余量。

Evaluator 借用 context、server key 和 table，并在构造时分配全部缓冲。复用 `allocate_output()` 的结果与 `evaluate_to`，在线无额外分配；所有 chunk 数量和 LWE 维数在写入前检查。资源必须匹配 N/q/Q，表的 t 决定 one-hot 几何；密钥须实际配套；Fourier 还要求相同 FFT table 实例。每个并发 evaluator 持有独立可变工作区。

返回链路对每个多项式独立执行逐系数 Q→q 和相位提取，再切换到外部 LWE 秘密。NTT 逐项返回，仅分配 scalar 返回缓冲；Fourier 仅分配 `LweReturnBatchWorkspace`，通过独立 `LweReturnEvaluator` 批量执行 key switch，只保留一小块中间 LWE，每次提取后即可覆盖多项式缓冲；输出近似 q 下的 chunk 编码，双重舍入与返回误差须纳入预算。

## 数值限制与进一步阅读

输入须满足 [one-hot 保护区](../primus_tfhe_ntru/README.zh_CN.md#one-hot-cbs)，包含加密、编码与逐坐标量化误差。CBS 和每次选择/旋转外积继续引入误差，Fourier 还包含原生 trace 减半及 FFT 舍入；公开提升分解必须能解析 LUT 尺度。形状校验和功能测试不能认证安全性、生产参数或失败概率。

[参数指南](../../guides/development/tfhe-parameters.md)记录示例选择与验证范围，[测试指南](../../guides/development/testing.md)说明独立契约的覆盖，[实现说明](IMPLEMENTATION.md)记录算法和内部缓冲布局。

## Features

默认 features 为空，Fourier 泛型接口不选择具体 FFT 引擎。`rustfft` / `tfhe-fft` 分别转发到 `primus_fft` 的对应实现；可以同时启用。使用具体引擎的测试、示例和基准在 Cargo target 上声明 `required-features`；双引擎对照 target 需要两者。`simd` 不会自动启用 FFT 引擎。

## 基准

```sh
# 创建并释放一个公开的高精度 LUT。
cargo bench -p primus_tfhe_ntru_lut --bench pipeline --features rustfft,tfhe-fft -- '/create_lut_and_drop$'
# 使用已准备的 LUT 和工作区，同态求值全部输出 chunk。
cargo bench -p primus_tfhe_ntru_lut --bench pipeline --features rustfft,tfhe-fft -- '/evaluate$'
```

创建计时包含分配、系数填充和释放；求值计时不包含密钥生成、公开 LUT 创建、输入加密和工作区分配。工作负载与资源统计见[基准说明](IMPLEMENTATION.md#benchmark-fixture)。

原有 ID 使用多项式示例；包含 `/dense_seed42/` 的 ID 使用相同参数下的固定稠密映射。用 `dense_seed42` 过滤可只运行该负载，用 `c8_d5_o8/evaluate$` 可只测多项式示例的同态求值。

`/shared_middle_chunk/` 诊断映射把每个输出 digit 都设为 `(m_0+m_6) mod 4`，用于隔离越过 chunk 5 的公开选择、省略 chunks 5 和 7 的高位 CBS，以及相同最终输出的复用。它是专门的共享负载，与完整位宽的算术函数不同。
