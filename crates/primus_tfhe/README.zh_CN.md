# primus_tfhe

[English](README.md) | 简体中文

公共 LUT 编译、编码元数据及 PBS trait 层，供 GLWE 和 NTRU 两族复用。
本 crate 不持有客户端密钥、变换 table 或 evaluator 工作区。完整使用流程从下面的后端示例开始。

## Crate 分工与能力

| Family | NTT 后端 | Fourier 后端 |
| --- | --- | --- |
| [GLWE 参数与客户端](../primus_tfhe_glwe/README.zh_CN.md) | [GLWE NTT](../primus_tfhe_glwe_ntt/README.zh_CN.md) | [GLWE Fourier](../primus_tfhe_glwe_fourier/README.zh_CN.md) |
| [NTRU 参数与客户端](../primus_tfhe_ntru/README.zh_CN.md) | [NTRU NTT](../primus_tfhe_ntru_ntt/README.zh_CN.md) | [NTRU Fourier](../primus_tfhe_ntru_fourier/README.zh_CN.md) |

| 后端 | 密文模数 | PBS / ManyLUT | Boolean 门 | CBS |
| --- | --- | --- | --- | --- |
| GLWE NTT | 显式域模数 | 支持 | 支持 | 支持 |
| GLWE Fourier | 原生 torus | 支持 | 支持 | 未实现 |
| NTRU NTT | 显式域模数 | 支持 | 未实现 | 支持 |
| NTRU Fourier | 原生 torus | 支持 | 未实现 | 支持 |

四后端均支持私钥和 LWE 公钥客户端。Fourier 后端支持 RustFFT 与 TfheFFT。
参数和 API 仍处于实验阶段；示例及 benchmark fixture 不是生产安全参数或失败概率建议。

## LUT 与资源生命周期

1. Family 参数描述外部 LWE 和 accumulator 环。
2. 后端 context 绑定参数与 NTT/FFT table，并生成配套的 client/server key。
3. 通过 family 参数或 context 编译 `LookupTable` / `InterleavedLookupTable`。
   evaluator 创建一次，在线 `_to` 调用复用其 scratch。
4. 调用方输出分配一次，后续加密与求值重复使用同一存储。

单函数或切片为 `0..ceil(t_in/2)` 输入域编程，输出属于输出 codec 指定的 `0..t_out`。
另一半遵循负循环扩展，不能独立编程。交错 LUT（ManyLUT）的有效输出数 `k` 为正，
步长为 `s = next_power_of_two(k)`，满足 `ceil(t/2) <= N/s`。callback 按输入优先
顺序接收 `(input, output_index)`，每个有效组合调用一次；切片包含相同顺序的 `D*k` 个值。
例如 `k=3` 时三个输出占用四个槽：编译器将第四槽置零，不调用 callback；求值端只返回三个密文。
所有输出共享一次盲旋转（BR）和密钥切换，再分别提取。
输出越多，旋转分辨率与输入噪声余量越低。这是一个输入求多个函数，不是独立密文批处理。

### 旋转布局

令 `D = input_domain_len()` 为已编程前缀长度，`s = stride()`（普通 LUT 为 1），`M = N/s`。
消息先编码为 `E(m) = round(m*q_in/t) mod q_in`，再映射到虚拟中心
`R(E(m), q_in, 2M)`，其中 `R(x,q,L) = floor((x*L + floor(q/2))/q) mod L`，
两次舍入遇到中点均向上。Native 的 `q_in` 为 `2^T::BITS`。合并两次舍入可能改变表内容。

编译器选择最近中心的值，中点相等时选择较大的中心；最后在 `min(R(E(D), q_in, 2M), M)`
追加值为 `-f(0)` 的中心以终止编程前缀，其后的系数不是额外的输入域。
raw 输出必须已经是 `q_acc` 下的规范值，越界值会被拒绝。
累加器模数与输出尺度均独立于 `q_in`。

单输出与 ManyLUT 共用一次中心和区间扫描。每个区间直接写入结果多项式，
首行兼作输出值缓冲区；使用内置模数类型且 callback 不分配时，编译过程仅分配结果多项式。
callback 报错或输出越界时立即停止，不返回部分编译的表。

四后端逐个将 LWE 系数量化为 `s*R(x, q_in, 2N/s)`，旋转指数为
`-R_s(b) + sum(R_s(a[i])*secret[i])`，不能替换为对解密相位的一次量化。
旋转量是 `s` 的倍数，保留 `s*r+j` 上的各输出列；提取系数 `j` 时按负循环符号读取该列。

## 编码与密钥契约

| 接口 | 输入 / 输出含义 |
| --- | --- |
| 普通 `encrypt` | `0..t` 范围的 unsigned 消息 |
| `encrypt_padded` | 相同 unsigned 尺度，输入限制为 `0..ceil(t/2)`，供普通 LUT 使用 |
| `encrypt_centered` | 接收 `0..t` 的模代表元；上半区表示负数，例如 `t=4` 时 `3` 表示 `-1` |
| GLWE Boolean | 外部 `false/true` 对应模 4 下的 `0/1`；内部 LUT 使用 rounded 模 8 尺度的正负值，随后平移恢复外部编码 |
| CBS | 普通 unsigned LWE 输入转为指定 gadget 尺度的 GGSW/NGSW，秘密为 accumulator secret；`0/1` 输入可生成 CMUX 控制 |

客户端 `decrypt` 使用参数 codec，返回 `0..t` 中的规范代表元。Centered 加密不能替代普通 LUT 的 unsigned
输入契约。PBS 保留 LUT 的输出尺度，不会自动把 Boolean 或 gadget 输出改为普通消息编码。

原始 `LweCiphertext` 不记录秘密、编码或噪声。调用方必须使用配套密钥、显式模数下的
规范系数，并保证噪声余量。LUT 与维数错误在写入输出前拒绝，但这些检查不能验证实际
秘密一致性。Fourier 密钥和 evaluator 必须使用同一 FFT table 实例。

最小 trait 为 `ProgrammableBootstrap` 和 `ProgrammableBootstrapInterleaved`。
普通应用使用 context/family 编译入口，由其检查并编码明文输出。
`LookupTable::try_new` 与 `InterleavedLookupTable::try_new` 接收已编码输出和显式的
编程前缀长度，Boolean 与 CBS 通过它们使用各自的输出尺度。
兼容性检查绑定多项式长度与编码模数；输入位于已编程前缀内仍由调用方保证。
`backend_support` 服务于后端实现。

### 选择输出编码

两族参数/context 的四个 `compile_*_lookup_table_fn/slice` 方法均以
`&RoundedCodec<T, M>` 为第一个参数。输入参数仍决定 `0..ceil(t_in/2)` 与旋转中心；
输出 codec 决定 `t_out`，检查输出位于 `0..t_out`，并按 unsigned embedding 编码。
交错 LUT 的各列共用这个 codec。其密文模数必须与 accumulator 一致，否则返回
`OutputModulusMismatch`。现有完整 PBS 链仍要求 `q_in = q_acc = q_out`；
选择不同的明文模数不会改变密文模数。

例如，在 `t_in=16` 的 NTRU context 中，用 `t_out=4` 编码 `x % 4`：

```rust
use primus_encoding::RoundedCodec;

let output_codec = RoundedCodec::new(4u32, context.parameters().external_lwe().cipher_modulus());
let lut = context.compile_lookup_table_fn(&output_codec, |x| (x % 4) as u32).unwrap();
let input = encryptor.encrypt_padded(7u32, &mut rng).unwrap();
let output = evaluator.apply_lookup_table(&input, &lut);
let message = output_codec.decode_value(decryptor.decrypt_phase(&output).unwrap());
assert_eq!(message, 3);
```

GLWE 用 `context.parameters().glwe().cipher_modulus()` 构造输出 codec。
沿用参数编码时，传入 `small_lwe().plaintext_codec()`（GLWE）或
`external_lwe().plaintext_codec()`（NTRU），随后仍可用普通 `decrypt`。
各后端 basic 示例展示了无需额外密钥的独立输出编码。

`decrypt_phase` 返回外部 LWE 秘密下的规范带噪剩余类，调用方保留输出 codec 用于解码。
LUT 兼容性元数据仍描述输入与 accumulator，不要求 `t_out = t_in`。
继续串联 PBS 时，下一次输入编码和 LUT 几何必须与上一次输出编码一致；context 不会从
raw 密文推断编码变化。自定义编码、逐列尺度及 Boolean/CBS gadget 输出使用 raw 构造器，
遵循各自的解码契约。

## 有界双输入 PBS

`BivariateLookupTable::try_new(B, R, N, input_codec, output_codec, function)`
通过 `z = x + B*y` 编译 `0 <= x < B`、`0 <= y < R` 上的 `f(x,y)`。
`B`、`R` 必须为正，`D = B*R <= ceil(t_in/2)`，并满足普通 LUT 的容量和旋转中心检查。
只编译 `0..D` 前缀，回调按 `x` 优先变化的顺序求值；`B` 不必是二次幂。
输出 codec 独立选择 `t_out`，但必须使用相同密文模数。
这个共享类型适用于四个后端，不持有密钥或 scratch。

例如，对 `t_in=16` 的 NTRU context 复用已有客户端和 evaluator：

```rust
use primus_tfhe::BivariateLookupTable;

let compare = BivariateLookupTable::try_new(
    3, 2, context.parameters().poly_length(),
    context.parameters().external_lwe().plaintext_codec(),
    &output_codec, |x, y| u32::from(x > y),
).unwrap();
let lhs = encryptor.encrypt_padded(2u32, &mut rng).unwrap();
let rhs = encryptor.encrypt_padded(1u32, &mut rng).unwrap();
compare.pack_to(&lhs, &rhs, &mut packed);
evaluator.apply_lookup_table_to(&packed, compare.lookup_table(), &mut output);
assert_eq!(output_codec.decode_value(decryptor.decrypt_phase(&output).unwrap()), 1);
```

按外部 LWE 维数一次性分配 `packed` 和 `output`。
`pack_to` 用一遍模乘加写入 `lhs + B*rhs`，不分配内存；长度不同或缺少 body 时在写入前拒绝。
两输入必须具有相同的实际秘密、密文模数及传入的 unsigned 输入 codec，系数规范、明文不超出各自边界。
raw 密文无法验证这些语义条件。GLWE 使用其 order 对应的外部维数与
`small_lwe().plaintext_codec()`，无需增加密钥材料。

即使不考虑加密噪声，也不能忽略编码舍入。令 `E(m)=round(m*q/t_in)`，打包相位为
`E(x+B*y) + e_x + B*e_y + rho` 模 `q`，其中
`rho = E(x)+B*E(y)-E(x+B*y)`。`t_in` 整除 `q` 时 `rho=0`，否则可用保守界
`|rho| <= (B+2)/2`（密文单位）。PBS 输入噪声预算需计入这个偏差、放大的输入误差、
BR 前可能发生的密钥切换误差及逐系数模切舍入。容量条件防止明文索引回绕，不能证明噪声余量。
这是有界单输出工作流，不是任意精度整数运算或 LWE 到环密文的 packing。
完整运行示例见 [NTRU NTT](../primus_tfhe_ntru_ntt/examples/ntru_ntt_basic.rs)。

## 验证

在 workspace 根目录运行：

```sh
just tfhe
just tfhe-simd
```

这两个 [recipe](../../justfile) 覆盖七包默认 / nightly SIMD 的 check、Clippy 和测试；
`tfhe` 还检查 `xtask` 调用方并构建文档。`just ci` 执行 workspace 检查及底层、TFHE 两组 SIMD 检查。
各后端 README 提供可运行示例与 Criterion 命令。
共享 raw 输出 LUT 的构造基准包含分配与释放：

```sh
cargo bench -p primus_tfhe --bench lookup_table
```

## 保留模数类型的旋转量化

raw LUT 编译接收独立的输入模数类型和 accumulator 模数类型。
`backend_support::RotationQuantizer::new(input_modulus, two_n, window)` 准备固定
模数对的转换，`exponent(value)` 无分配复用。旋转域 `two_n = 2N` 必须能由输入
系数类型表示；即使输入使用 Native 模数，目标 `two_n/window` 也为显式二次幂。
GLWE 密钥和 NTRU 参数在构造时
缓存普通 PBS 量化；ManyLUT 在系数循环前按步长准备，先在 `two_n/window`
个位置内舍入，再乘 `window`。仅描述模数域的元数据仍使用 `Option<T>`。
