# primus_glwe

[English](README.md) | [简体中文](README.zh_CN.md)

单模数 GLWE 密钥和运算，分别提供 NTT 与原生环面 Fourier 表示。下文 `k` 为 GLWE 维数，`N` 为多项式长度。

## 密钥与表示

| 类型 | 存储与职责 |
| --- | --- |
| `GlweSecretKey<T>` | 有符号系数多项式；采样，以及密钥转换、生成的输入 |
| `NttGlweSecretKey<T>` | 模 `q` 的规范 NTT 剩余类；NTT 加解密 |
| `FourierGlweSecretKey` | 按整数尺度变换的 Fourier 私钥多项式；原生环面 Fourier 加解密 |
| `NttGlwePublicKey<S>` | 一个 NTT 零加密密文；公钥加密 |

根据所用的 NTT 或 Fourier 后端，通过 `generate_pair` 生成私钥。它只采样一次，返回有符号系数私钥及其对应的变换形式：

```rust,ignore
let (coeff_sk, ntt_sk) = NttGlweSecretKey::generate_pair(&ntt_params, &ntt_table, &mut rng);
let (coeff_sk, fourier_sk) =
    FourierGlweSecretKey::generate_pair(&fourier_params, &mut fft, &mut rng);
```

只需要有符号系数私钥时使用 `GlweSecretKey::generate`。转换已有系数私钥时使用 `from_coeff_secret_key`。固定重量分布作用于全部 `k*N` 个系数，而非逐多项式分别采样。私钥缓冲区在析构时擦除，也覆盖生成中发生 panic 的展开路径。

密钥不保存变换表：后续操作必须保持生成时的模数和变换表示。公钥原始字节采用本机字节序，不包含参数元数据。

## 加密与解密

NTT 私钥、Fourier 私钥和 NTT 公钥共享以下普通加密接口：

| 方法 | 输入 | 输出存储 |
| --- | --- | --- |
| `encrypt` / `encrypt_to` | `[0, t)` 中的明文，使用无符号嵌入 | 分配 / 覆盖 |
| `encrypt_centered_to` | `[0, t)` 中的明文，使用居中嵌入 | 覆盖 |
| `encrypt_encoded_to` | 已编码的密文环系数 | 覆盖；不做明文缩放 |
| `encrypt_zeros` / `encrypt_zeros_to` | 零多项式 | 分配 / 覆盖 |

私钥提供 `decrypt`、`decrypt_to` 和 `phase_to`。Phase 提取返回带噪声的系数域值，不做解码；两种明文嵌入使用同一解码器。解密多项式使用密文系数类型 `T`，输出类型转换由应用处理。

```text
ntt_sk.encrypt_to(input, output, params, ntt_table, rng)
ntt_pk.encrypt_to(input, output, params, ntt_table, rng, context)
fourier_sk.encrypt_to(input, output, params, fft, rng, context)
ntt_sk.phase_to(input, output, modulus, ntt_table)
fourier_sk.phase_to(input, output, fft, context)
```

NTT 域私钥运算无需 context。Fourier 运算使用 `FourierGlweEncryptContext<T>` / `FourierGlweDecryptContext`；NTT 公钥加密使用 `NttGlwePublicEncryptContext<T>`。这些 context 按 `N` 构造，并在相同长度下复用。Context 保存工作区而非参数，析构时擦除私密中间值。

对于系数域密文，`NttGlweSecretKey` 提供 `encrypt_coeff_to`、`phase_coeff_to`
和 `decrypt_coeff_to`，最后一个参数是长度为 N 的 scratch 切片。
它们复用所有缓冲，省去 body 的正 NTT。加密接收无符号明文；相同 RNG 状态下，
结果与 `encrypt_to` 后逆 NTT 精确一致。Scratch 无需初始化，加密后保留依赖私钥的乘积，
应由 `zeroize::Zeroizing<Vec<T>>` 等负责擦除的类型持有。

`_to` 路径复用输出和工作区。布局和变换长度检查失败会在写输出前报错；长度相同并不代表变换表示兼容。无效明文值可能在部分写入或消耗随机数后触发 panic。已编码的 NTT 输入必须是 `[0, q)` 中的规范剩余类，该范围由调用方保证。

## Gadget 与截断密文

`encrypt_glev_to` 和 `encrypt_ggsw_to` 对系数域环多项式应用 gadget 基，不做明文缩放。因此 GGSW 控制位使用常数多项式 `0` 或 `1`。两者使用由 `GadgetSize` 构造的 gadget context：GLev 要求多项式长度匹配；GGSW 还要求 level 数量匹配。

已有分解基时，使用 `GlevParameters::try_with_basis(&glwe_params, basis)` 直接转移其所有权，复用预计算，并检查模数和 gadget 布局。`try_with_glwe_params` 则根据基的对数和 level 数构造分解基；两个入口均返回 `GlevParameterError`。

`encrypt_ggsw_constant_batch_to` 将环常数切片加密为连续的 GGSW，仅做一次批量检查，不分配临时缓冲区。NTT 接收规范剩余类，输出长度为 `input.len() * params.ggsw_len()`；Fourier 接收原生环值，输出包含 `input.len() * params.fourier_ggsw_len()` 个复数。Fourier 保留逐 level 原生环缩放后再 FFT 的数值路径。空批次仍检查共享资源，但不消耗随机数。

NTT 的 `encrypt_truncated_zeros`、`phase_truncated` 和 `decrypt_truncated` 操作系数域密文，其 mask 完整，body 最多包含 `N` 个系数。Phase 提取和解密只返回保留的系数，内部工作区仍保存完整多项式。

## 求值原语

求值密钥保存自己的布局和分解基。NTT 求值参数为 `input, output, modulus, ntt, context`；Fourier 求值省略 `modulus`。Context 是可复用的工作区。必须保持密钥的变换表示，仅长度和模数匹配不能证明表示兼容。

两种自同构密钥都提供系数域 `apply_to`。`NttGlweAutomorphismKey::apply_ntt_to` 和 `FourierGlweAutomorphismKey::apply_fourier_to` 复用同一密钥处理变换域输入、输出。Fourier 求值要求使用生成密钥时的同一个 FFT table 实例；直接处理 Fourier 输入、输出的舍入结果可能与系数域往返不同。

`NttGlweTraceKey<T>` 和 `FourierGlweTraceKey<T>` 在以下系数域操作间共享自同构密钥。`M` 表示输入明文；所有输出 phase 系数都可能存在求值误差。

| Trace key 方法 | 目标明文 |
| --- | --- |
| `apply_to` / `apply_reverse_to` | 常数 `N*M[0]` / `M[0]` |
| `apply_partial_to(input, r, ...)` | `d * sum_j M[j*d] X^(j*d)`，其中 `d=N/r` |
| `apply_reverse_partial_to(input, r, ...)` | `sum_j M[j*d] X^(j*d)` |
| `project_coefficient_to` / `project_coefficients_to` | 常数 `M[index]` / 按选择顺序排列的常数 |
| `project_prefix_coefficients_to(input, count, ...)` | 常数 `M[0]` 到 `M[count-1]`，无需明文零尾 |
| `expand_coefficients_to` | 按系数顺序排列的 `N` 个常数 GLWE |
| `expand_partial_coefficients_to(input, count, ...)` | 明文高位全零时，展开前 `count` 项为常数 |
| `pack_lwe_to` / `pack_lwes_to` | LWE 消息对应的常数 / `p` 个 LWE 的 `sum_i m[i] X^(i*N/p)` |

Partial trace 的 `retained_coefficient_count`（`r`）是 `1..=N` 内的 2 的幂。它在一个 GLWE 中保留等间隔位置：`N=8, r=2` 保留索引 0 和 4。`r=N` 复制输入，`r=1` 为 full trace。反向 trace 每级先缩放，再自同构和相加：NTT 乘 `2^-1 mod q`，Fourier 对无符号系数取 `floor(x/2)`。NTT 域运算不直接继承 torus RevHomTrace 的噪声界。

投影支持任意索引、重复索引和空选择，每个索引执行一次反向 trace，写入 `indices.len() * size.glwe_len()` 个值。前缀投影接受 `0..=N` 内任意 `count`，复用相同计算且无需索引数组；即使 `count=1` 也执行完整反向 trace。部分展开在 `count` 个输出 GLWE 块中构建共享树，先按 `count` 归一化一次，再执行 `count-1` 次自同构。`count` 必须是 `1..=N` 内的 2 的幂；`count=1` 复制输入，`count=N` 为完整展开。NTT 归一化使用域上的逆元，Fourier 使用无符号向下除法。两条路径具有不同的误差行为。

部分展开产生常数的前提是明文 `count..N` 项全零。这个未检查前提针对明文，不针对密文 mask 或 body。否则第 `i` 个输出的目标为 `sum_j M[i+j*count] X^(j*count)`。所有输出保持环次数 `N`，使用普通 trace context。

Trace key 的 packing 使用 [RevHomTrace 算法](https://github.com/Stirling75/RevHomTrace/blob/main/src/glwe_conv_rev.rs)。每个 LWE 的维数必须为 `k*N`，私钥等于 GLWE 私钥的系数展平，模数和编码相同。批量输入为 `p` 个完整 LWE 组成的平坦切片，`p` 是 `1..=N` 内的 2 的幂；仅 `p=N` 时槽位相邻。为固定数量构造 `NttGlwePackingContext::new(size, p)` 或 `FourierGlwePackingContext::new(size, p)`。单条 LWE packing 使用 trace context。求值复用输出和工作区，在写入前检查形状、索引及后端兼容性。

`NttLwePackingKeySwitchingKey<T>` 和 `FourierLwePackingKeySwitchingKey<T>` 支持从独立的 LWE 私钥转换到目标 GLWE 私钥。`generate` 接受 `primus_lwe::LweSecretKeyRef`、目标私钥和 GLev 参数。输入维数可以不同于 `k*N`；输入和输出必须使用相同密文模数与消息编码。

| Packing key 方法 | 目标明文 |
| --- | --- |
| `key_switch_to` | 单条 LWE 的消息作为常数 GLWE |
| `pack_lwes_to` | 任意 `1 <= p <= N` 条 LWE 的 `sum_i m[i] X^i` |

批量输入为完整 LWE 组成的平坦切片。输出消息系数连续，数量无需为 2 的幂，也不依赖 trace key。使用已有的 `NttGlweKeySwitchingContext::new(output_size.glwe_size())` 或 Fourier 对应类型；同一工作区支持变化的批量数量。批量求值将分解数字组成多项式，顺序读取变换域密钥；单条 LWE 使用标量数字，无需数字变换。两条路径最后都仅对每个输出分量做一次逆变换。目标明文的零尾部仍可能包含噪声。解码余量需要覆盖输入噪声、由输入私钥加权的分解误差和累计密钥噪声；Fourier 还包含浮点误差。NTT 密钥存储 `input_dimension * output_size.glev_len()` 个剩余类，Fourier 存储 `input_dimension * output_size.fourier_glev_len()` 个复数。

`NttGlweSchemeSwitchKey<T>` 和 `FourierGlweSchemeSwitchKey<T>` 通过 `apply_to` 将系数域 GLev 转换为密钥对应变换域的 GGSW。传入 `generate` 的两种私钥表示必须对应同一个私钥。使用 `key.key_size()` 构造 `primus_lattice::context::{NttGlweExternalProductContext, FourierGlweExternalProductContext}`。工作区可与其他外积共享：GLWE 布局不变时，`rebind` 无分配切换分解层数；scheme switch 前恢复为 `key.key_size()`。输出继承输入 GLev 的 gadget 缩放；`key.key_basis()` 只控制 external product 分解，可以不同于输出基。每个 mask row 使用私钥多项式取负后的加密，body row 直接变换输入。Fourier 乘积直接累加到输出，无需逆 FFT 再正向 FFT。

## 源码与测试

[私钥](src/secret_key)、[公钥](src/public_key)、[key switching](src/key_switch)、[自同构](src/automorphism)、[trace/packing](src/trace)、[packing key switching](src/packing_key_switch) 和 [scheme switching](src/scheme_switch) 中维护公开契约与实现细节。

测试按操作分组：普通密钥工作流、gadget phase 与 external product、常数批次等价性、CMUX、key switching、自同构、scheme switching，以及 trace/展开/packing。`tests/common` 保存求值测试共用的小规模朴素 phase oracle。边界拒绝和容量擦除使用独立测试文件。Fourier 常数批次、自同构、trace、packing key switching 和 scheme switching 测试覆盖 RustFFT 和 tfhe-fft。

```sh
cargo test -p primus_glwe
cargo clippy -p primus_glwe --all-targets -- -D warnings
cargo +nightly test -p primus_glwe --features simd
```

## 基准

```sh
cargo bench -p primus_glwe --bench encryption
cargo bench -p primus_glwe --bench primitives
cargo bench -p primus_glwe --bench key_conversion
# 执行全部 case，不收集计时样本：
cargo bench -p primus_glwe -- --test
```

所有基准均使用 `(k, N) = (1, 1024)` 和 `(2, 4096)`。每次迭代执行一次操作，复用输出和工作区；密钥、变换表构造与分配在计时外。参数和固定 seed 记录在基准源码中。这些工作负载用于跟踪回归，不用于比较相同安全级别，也不作为安全参数建议。

| 基准 | 测量内容 |
| --- | --- |
| [encryption](benches/encryption.rs) | 私钥/公钥加密、私钥解密（含 NTT 系数域路径）、GLev/GGSW 生成及 8 个常数 GGSW 的批量加密；包含采样、编解码及必要变换 |
| [primitives](benches/primitives.rs) | 普通/反向 trace；8 和 `N/8` 项的投影与部分展开；完整展开；1、8、`N` 条 LWE packing；两种 FFT 后端的直接 Fourier 自同构 |
| [key_conversion](benches/key_conversion.rs) | 独立私钥下 1、8、`N` 条 LWE packing（输入维数 512；单条用例覆盖基数 `2^3` 和 `2^10`）；NTT/Fourier GLev-to-GGSW scheme switching |

普通和反向 trace 分别按各自 API 的明文尺度测量。投影与部分展开使用同一份明文高位为零的密文，throughput 按输出消息数量计算。编解码变体在 `primus_encoding` 中单独测量。
