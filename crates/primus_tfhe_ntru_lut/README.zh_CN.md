# primus_tfhe_ntru_lut

[English](README.md) | 简体中文

对已加密的 NTRU-TFHE chunks 执行高精度查表，串联 one-hot CBS、公开及密文表选择、负向旋转和独立 LWE 返回。本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace，API 和数值契约可能变化。

## 工作流

使用 [NTT](../primus_tfhe_ntru_ntt/README.zh_CN.md) 或 [Fourier](../primus_tfhe_ntru_fourier/README.zh_CN.md) 的 classic binary/ternary context，通过 `context.try_generate_keys(Some(cbs_config), rng)` 生成配对密钥。拒绝 sparse 密钥和缺失 CBS 材料。客户端生成 chunks，再用 `encrypt_padded` 分别加密。

`HighPrecisionLookupTable::try_new(parameters, config, function)` 编译公开表。回调接收 `(完整输入索引, 输出 chunk 索引)`，返回一个 digit。用 `NttLookupTableEvaluator::try_new(context, server_key, table)` 或 `FourierLookupTableEvaluator::try_new(context, server_key, table)` 绑定资源，调用一次 `allocate_output()`，随后重复调用 `evaluate_to(input_chunks, output_chunks)`。输出逐个使用 context 的普通 decryptor 解码。Evaluator 借用 context、服务端密钥和表，求值不需要客户端秘密。

对于 u32、`t=8`、`N=1024` 的 context，八个两位 chunks 表示一个 16 位输入。以下片段计算 `(x*x+3*x+7) mod 65536`，返回八个 chunks：

```rust,ignore
use primus_tfhe_ntru_lut::{
    HighPrecisionLookupTable, LookupTableConfig, NttLookupTableEvaluator,
};

let table = HighPrecisionLookupTable::try_new(
    context.parameters(),
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
cargo run --release -p primus_tfhe_ntru_lut --example fourier_lookup
```

[evaluation.rs](tests/evaluation.rs) 另行穷举小域，检查工作区复用和拒绝边界。

## 编码与表分区

要求明文模数 `t=2*M`，其中 `M=2^tau>=2`。输入与输出 chunks 共用 tau，数量独立指定且均为正。两个密文切片都按低位在前排列：`x=sum_i m_i*M^i`。输入已经分别加密，API 不对单个高精度 LWE 做同态拆分。

令 `c=input_chunk_count`、`d=coefficient_chunk_count`、`o=output_chunk_count`，要求 `0<=d<=c`、`M^d<=N`。低 d 个 chunks 选择系数，其余高位 chunks 选择多项式。各布局量的含义为：

| 布局量 | 含义 |
| --- | --- |
| `chunk_bits()` = tau | 每个输入/输出 chunk 的统一位宽 |
| `input_value_count()` = M^c | 完整输入可能的取值总数 |
| `entries_per_polynomial()` = K = M^d | 每个多项式中用于存放 LUT 表项的系数个数 |
| `polynomials_per_output()` = P = M^(c-d) | 每个输出 chunk 对应的多项式数量 |
| N | 每个多项式实际分配的系数个数，包括补零区域 |

将输入拆成 `x=p*K+z`。对于输出 chunk j，第 p 个多项式的第 z 个系数存放 `E_Q(F(x,j))`，系数 `K..N` 补零。其中 `E_Q(v)=round(Q*v/(2*M))`，乘法在舍入之前。`F(x,j)` 返回目标函数结果的第 j 个 chunk，必须位于 `0..M`。编译按输出优先、再按 x 升序枚举，每对 `(x,j)` 恰好调用一次。在值域及存储限制内可以编译任意有限映射；整数、有符号数或定点数的解释由调用方的 chunk 编码和回调决定。

例如 `M=4, c=3, d=1, N=64` 时，有 64 种输入，每个输出对应 16 个多项式，每个多项式放 4 个表项。多项式 0 存放输入 0..3，多项式 1 存放输入 4..7，以此类推。输入 6 选择多项式 1 的系数 2。每个多项式其余 60 个系数均为零。

`as_slice()` 暴露 `[output][prefix][coefficient]` 顺序的只读系数。输入取值总数本身必须能用 `usize` 表示，即 `tau*c < usize::BITS`；这是完整枚举的索引限制，并非论文约束。表存储量为 `o*P*N` 个标量。长度检查拒绝索引和字节数溢出，但不保证指数级表一定有足够物理内存可分配。

### 选择系数 chunk 数

固定 N、M、c 时，可优先考虑 `d=min(c, floor(log2(N)/tau))`，即选择不超过 N 的最大 M^d。d 每增加 1，P 和表存储量都缩小到原来的 1/M，CMux 工作量减少，每个输出增加一次旋转外积。`d<c` 时，每个输出执行 `P+P/M-1` 次表选择外积和 d 次旋转外积；`d=c` 时，执行一次公开提升和 d 次旋转外积。每次求值仍对全部 c 个输入各执行一次 one-hot CBS。分区保持显式指定，因为这些运算次数不能直接确定最佳噪声余量或实测耗时，而增大 N 会让环运算更昂贵。

## 求值与工作区

首个表选择层计算完整求和 `sum_k T_k odot NLEV[delta_k]`，包含 k=0。后续层计算 `c_0 + sum_{k>0}(c_k-c_0) otimes NGSW[delta_k]`，每层结束原地压缩候选。d=c 时没有表选择层，仍用服务端 `NLEV[1]` 及其 BR basis 提升唯一公开多项式。

每个系数 chunk i 聚合 `C_i=G+sum_{k>0}(X^(-k*M^i)-1)*NGSW[delta_k]`。G 是 gadget 向量，表示平凡 NGSW[1]；目标明文为 `1+sum_{k>0}(X^(-k*M^i)-1)*delta_k(m_i)=X^(-m_i*M^i)`，包含 m_i=0。负向旋转与表的正系数索引配套。单项式因子在构造时预计算；NTT 因子使用环剩余，Fourier 因子使用整数尺度，G 和密文使用 torus 尺度。

数据 LUT 对每个输入和输出 chunk 只存一份函数值。用于容忍输入相位误差的重复保护块放在前面的 one-hot CBS 测试多项式中，用来生成离散 selectors。之后的选择和旋转产生加性密文误差，而非带噪声的 LUT 索引；这些误差仍需计入解码预算。

每次调用对每个输入 chunk 仅执行一次 CBS。只有公开首层生成全部 M 个 NLEV selectors；旋转控制和后续密文层通过 `one_hot_nonzero_ngsw_to` 仅请求 r=1..M-1，跳过 r=0 的投影和 scheme switch，紧凑输出的第 r-1 块对应分支 r。首层 NLEV selectors、后续表层 NGSW selectors 和聚合旋转控制跨输出复用，仅保存一个输出的候选树。所有缓冲在构造时分配，`evaluate_to` 覆盖输出且不分配。输入/输出 chunk 数及所有 LWE 维数在任何输出或 scratch 写入前检查；绑定时拒绝不兼容的 N/t/q/Q 和服务端资源。秘密身份仍由调用方保证，变换密钥必须使用绑定 context 的表示，Fourier 还要求同一 FFT 表实例。

一个 NLEV/NGSW selector 在 NTT 表示中占 L*N 个环元素，在 Fourier 表示中占 L*N/2 个复数；公开首层的完整 one-hot 批次包含 M 个这样的 selectors，后续每个密文层及复用的旋转 scratch 则各含 M-1 个。聚合后的旋转控制与单个 selector 等长，而对应的 M-1 个公开因子各占一个变换多项式，不含 gadget 层。多项式和密文使用对应的语义迭代器；包含多个对象的批次继续用切片 chunks。两个 evaluator 都将常量预计算、旋转控制聚合、公开表选择和后续每一层密文选择分开实现。完整资源公式与原地压缩契约见[阶段与缓冲布局](IMPLEMENTATION.md#stage-and-buffer-layout)。

选表并旋转后，使用现有 NTRU→LWE key 逐系数 Q→q、提取相位系数，再切换到外部秘密。输出近似 q 域 chunk 编码；二次舍入差和返回误差需要计入解码预算。

表选择和旋转复用 one-hot evaluator 的外积工作区，Fourier 还复用其 FFT engine；这些串行阶段无需另存变换或分解缓冲。复用前覆盖 scratch 内容，每个 evaluator 仍独立拥有可变工作区。

## 数值限制与验证

输入继承 [one-hot 保护区](../primus_tfhe_ntru/README.zh_CN.md#one-hot-cbs)，包括加密、编码和逐坐标量化误差。CBS 和每次选择/旋转外积会增加误差，Fourier 还包含 native trace 减半与 FFT 舍入。公开提升必须能分辨 LUT 尺度。形状检查和功能测试通过不构成安全性、生产参数或失败概率认证。

[编译测试](tests/lookup_table.rs) 用整数 oracle 检查分区、Rounded 编码、padding 和拒绝边界。[求值测试](tests/evaluation.rs) 穷举极小值域，在较大值域选择 chunk/表边界。覆盖 u32/u64、Q≠q、radix 2/4、classic binary/ternary、NTT 和两个 FFT、全部默认分支、后续密文表层、无表层、满系数容量、不等输入输出 chunk 数、写入前拒绝和在线零分配。大尺寸功能参数使用独立的[验证入口](../../guides/development/tfhe-parameters.md#validation-and-observations)。

```sh
cargo test -p primus_tfhe_ntru_lut
just tfhe
just tfhe-simd
```

## 基准

[流水线基准](benches/pipeline.rs) 测量真实 evaluator 的各阶段及完整查表，setup、分配和解密不计入延迟；报告密钥/工作区保留堆内存、输出存储、在线分配次数及相对已知结果的相位误差。阶段测量使用预先生成的 selectors 或控制；完整查表包含它们的生成。默认与 SIMD 使用相同工作负载。

```sh
cargo bench -p primus_tfhe_ntru_lut --bench pipeline
```

参数、阶段边界、复现命令与验证范围见[实现与基准指南](IMPLEMENTATION.md#benchmark-fixture)。延迟和少量相位样本不构成安全性或失败概率结论。
