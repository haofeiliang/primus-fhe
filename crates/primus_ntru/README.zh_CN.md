# primus_ntru

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。 尚不提供推荐安全参数。

在 `Z_q[X]/(X^N + 1)` 上提供单多项式私钥 NTRU 加密与求值。NTT 使用显式域模数， Fourier 使用原生 wrapping 模数 `2^T::BITS`，两种表示保留独立数值契约。

## 快速开始

下面使用 u64 和 NTT 展示普通消息与 encoded/phase 两条路径。调用方直接依赖 `primus_ntru`（启用 `ntt`）、`primus_ntt`、`primus_poly`、`primus_modulus`、`primus_encoding` 和 `rand`。N=32 仅用于简短的功能示例，不是安全参数。

```rust
use primus_encoding::PlaintextEmbedding;
use primus_modulus::BarrettModulus;
use primus_ntru::{NtruParameters, NttNtruSecretKey, SecretKeyDistr};
use primus_ntt::{NttTable, U64NttTable};
use primus_poly::{PolyLength, Polynomial};

let poly_length = PolyLength::new(32);
let modulus = BarrettModulus::new(132_120_577u64);
let table = U64NttTable::new(poly_length, modulus).unwrap();
let params = NtruParameters::new(poly_length, 16, modulus, SecretKeyDistr::SparseTernary, 0.7);
let mut rng = rand::rng();
let (_coeff_secret, secret) =
    NttNtruSecretKey::generate_pair(params.encryption_parameters(), &table, &mut rng).unwrap();
let message = Polynomial::new(vec![3u64; poly_length.get()]);
let embedding = PlaintextEmbedding::Unsigned;

// 普通消息：适配层使用参数中的 codec。
let mut ciphertext = secret.encrypt_message(&message, &params, embedding, &table, &mut rng);
assert_eq!(
    secret.decrypt_message(&ciphertext, &params, &table),
    message
);

// 已编码输入和提取出的 phase 都是系数多项式。
let codec = params.plaintext_codec();
let mut encoded = Polynomial::new(vec![0; poly_length.get()]);
codec.encode_slice_to(message.as_ref(), encoded.as_mut(), embedding);
secret.encrypt_encoded_to(
    &encoded,
    &mut ciphertext,
    params.encryption_parameters(),
    &table,
    &mut rng,
);
let mut phase = Polynomial::new(vec![0; poly_length.get()]);
secret.decrypt_phase_to(&ciphertext, &mut phase, modulus, &table);
let mut decoded = vec![0; poly_length.get()];
codec.decode_slice_to(phase.as_ref(), &mut decoded);
assert_eq!(decoded, message.as_ref());
```

普通调用用 `encrypt_message_to` 复用密文，不必先分配 encoded 多项式。需要直接操作编码时使用 `encrypt_encoded_to`；其输入和 `decrypt_phase_to` 的输出都是系数域，密文是 NTT 域。重复请求保留参数、表、密钥和输出；Fourier 路径还需复用对应 FFT engine 与工作区，见下文。

## 密文语义

设 `f` 是可逆私钥，`mu` 是编码消息，`g_l` 是 gadget scalar。下表省略应用层的明文 codec：

| 类型 | 系数行 `c_l` 的相位 |
| --- | --- |
| NTRU | `f*c = mu + e` |
| 消息 `m` 的 NLev | `f*c_l = g_l*m + e_l` |
| 消息 `m` 的 NGSW | `f*c_l = g_l*f*m + e_l` |

NLev 与 NGSW 存储的行数相同，但数学角色不同。`NLev[1]` 可通过外积把系数多项式 变成加密的 NTRU；`NGSW[1]` 保留已经加密的 NTRU 消息。直接把消息复制到 `c` 一般不能构成 NTRU 的平凡加密。

## 私钥与推荐流程

普通 `NtruParameters::new` / `try_new` 构造直接传入已验证的 [primus_poly::PolyLength](../primus_poly/README.zh_CN.md#环多项式长度)；`params.poly_length()` 返回经过检查的值，直接传给工作区和 NTT/FFT 表构造器，raw 存储或数值内核处才调用 `.get()`。`PolyLength` 集中检查 FHE 共用的 `32..=2^17` 二次幂范围，NTRU 参数不重复检查上界。

`NtruParameters::try_new` 对固定尺度编码、秘密支持集/重量和噪声采样错误返回 `NtruParameterError`，固定重量不得超过 N；`new` 在相同错误下 panic。这些检查不证明采样秘密可逆、变换可用或噪声/安全预算成立。 `NtruParameterError::SecretKey` 以 `SecretKeySamplerError` 保留采样配置、重量或模数适配的具体原因；`Noise` 保留 `GaussianError`。

`NtruEncryptionParameters::try_new(poly_length, modulus, secret_distribution, noise)` 不依赖明文域，直接准备环和采样器。仅使用 gadget 时，将它放入 `Arc`，调用 `NlevParameters::try_from_parts(shared_encryption, basis)`；需要普通加密时才调用 `NtruParameters::try_from_parts(shared_encryption, codec)`。这些 parts 入口检查独立传入的 basis 或 codec 模数。直接构造及 `NlevParameters::with_ntru_params` 复用组件创建时建立的相同模数保证，仍检查新 gadget 布局；`try_with_basis` 同样共享普通参数的加密状态，检查传入的 basis，不保留 codec。`gadget.try_with_new_basis(basis)` 在同一环中派生另一组 gadget 参数，共享采样状态，不复制旧 basis 或转换密文。

两种参数均通过 `encryption_parameters()` 为密钥生成、raw/零加密提供采样状态。消息加密与解密接收 `NtruParameters`；`encrypt_message` / `encrypt_message_to` 显式选择 `PlaintextEmbedding`。克隆普通或 gadget 参数共享不可变采样表，gadget basis 仍独立拥有。不同噪声分布应使用独立的加密参数；相同的采样参数可跨密钥角色共享。共享内容是分布预计算，不包含秘密系数或可变 RNG 状态。

将 `params.encryption_parameters()` 传给 `NttNtruSecretKey::generate_pair` 或 `FourierNtruSecretKey::generate_pair`，同时保留有符号系数私钥和变换表示。系数私钥用于生成求值密钥；变换私钥及其缓存 逆元用于加密和相位提取。

`NttNtruSecretKey` 记录 `NTT(f)` 及其逆元共同使用的显式 q，通过 `cipher_modulus()` 读取。转换和生成在同一模数/table 下建立两者。普通加密、phase 和 gadget 入口在采样或输出写入前核对拥有型密钥、算术参数和 table 的 q。Key-switch、自同构、trace、scheme-switch 和 TFHE 密钥生成继承 gadget 检查。相同 q/N 不能证明 NTT roots、求值顺序或秘密身份，后续操作仍须保留构造时的表示。通过 `try_from_coeff_secret_key` 导入时，有符号系数幅度须小于 q；不可逆秘密被拒绝，转换失败的缓冲区会擦除。不提供 raw NTT 密钥/逆元对导入。

NTT 生成拒绝含零点值的私钥。Fourier 生成检查原生环可逆性（系数和为奇数）和 复数逆元的稳定性。这两组条件不同。有界拒绝采样可能失败，重试次数及逆元例程 不承诺常数时间。

`generate_padded_pair(params.encryption_parameters(), active_length, ...)` 只采样有效前缀，尾部保持为零； 固定重量作用于该前缀。它与完整长度生成共用采样器，包括 ternary。最多尝试 1024 个 候选；Native 的固定 binary/ternary 分布若非零总数为偶数，在采样前返回 `NonInvertibleSecretKey`，其他未找到可用候选的情况返回 `KeyGenerationExhausted`。 返回私钥服从候选分布**在后端接受条件下的条件分布**；`distr()` 记录候选分布。

一般 NTRU 支持非 binary 环秘密。NTRU TFHE 使用独立外部 LWE 秘密作为 binary/ternary 盲旋转控制，不要求环秘密为补零 binary。

私钥和私有加密、生成、解密工作区会在析构时擦除自身缓冲区。显式工作区清零保留 可复用存储；显式私钥清零会销毁私钥。NTT 私钥的公开分布和 q 元数据仍保留，但擦除后应丢弃私钥。内置 FFT 后端也在析构时擦除 scratch；长寿命 engine 可在处理阶段结束后调用 `FftEngine::zeroize_workspace()`。调用方持有的明文及 相位输出有各自的生命周期。

[automorphism 示例](examples/automorphism.rs) 使用 u64 系数和显式 NTT 素数，展示配对私钥生成、求值密钥构造，以及复用工作区、在原私钥下完成 NTT 自同构：

```sh
cargo run -p primus_ntru --example automorphism --features ntt
```

## 操作与表示

| 操作 | 输入与输出 |
| --- | --- |
| `encrypt_message`、`encrypt_message_to` | 消息系数经 codec 缩放后写出变换域 NTRU，显式选择 embedding |
| `encrypt_encoded_to`、`encrypt_zeros_to` | 编码环系数或零写出变换域 NTRU |
| `decrypt_phase_to`、`decrypt_message`、`decrypt_message_to` | 变换域 NTRU 写出系数相位或解码消息 |
| `encrypt_nlev_to`、`encrypt_ngsw_to` | 编码多项式写出变换域 gadget 行，不进行明文 codec 缩放 |
| `encrypt_nlev_constant_to` | 常数环元素写出变换域 NLev |
| `encrypt_ngsw_signed_constant_batch_to` | 有符号常数写出连续的变换域 NGSW |
| NTT/Fourier NGSW 的 `cmux_ternary_monomial_to` | 正负比特控制通过一次外积旋转系数域 NTRU |
| `NttNtruKeySwitchingKey`、`FourierNtruKeySwitchingKey` | 输入私钥下的系数 NTRU 切换到输出私钥下的系数 NTRU |
| `NttNtruAutomorphismKey::apply_to`、`FourierNtruAutomorphismKey::apply_to` | 系数 NTRU 自同构后写出同一私钥下的系数 NTRU |
| `apply_ntt_to`、`apply_fourier_to` | 变换域 NTRU 自同构后保留对应变换表示和原私钥 |

`NttNlev::lift_monomial_to` / `FourierNlev::lift_monomial_to` 将公开多项式提升与首次 binary/ternary 旋转融合。传入 NLEV[1]、正向 NLEV 比特及可选的负向 NLEV 比特；只分解公开多项式，指数为零仍执行提升。`NttNtruCmuxWorkspace` / `FourierNtruCmuxWorkspace` 与后续三元 CMUX 共用一块组合控制缓冲。

Ternary 旋转取得 `poly_length = params.poly_length()` 和 `levels = params.decompose_length()`（`DecompositionLevelCount`）后，一次构造 `NttNtruCmuxWorkspace::new(poly_length, levels)` 或 `FourierNtruCmuxWorkspace::new(poly_length, levels)`，随后复用工作区，传入互斥的正负 NGSW 比特控制。Fourier 使用 Native basis，两份控制必须使用 engine 对应的同一个 FFT 表实例 和 torus 缩放。指数已量化到 `0..2N`，负指数由内部派生。 NTRU TFHE 后端使用此原语执行经典 ternary blind rotation。

`encrypt_message(input, params, embedding, table, rng)` 分配 NTT 输出；`encrypt_message_to(input, output, params, embedding, table, rng)` 复用输出。Fourier 使用 `(input, [output,] params, embedding, fft, rng, workspace)`。两种 embedding 都接收 `[0,t)` 内的规范消息 residue；centered 的 `t-1` 表示 `-1`。`decrypt_message` / `decrypt_message_to` 共用解码器，返回规范 residue，不需要 embedding 参数。

消息适配位于各私钥后端的 `message.rs`。加密先在输出或已有 Fourier 系数 scratch 中采样噪声，原地累加编码，再变换一次并乘逆密钥。Raw encoded 与零加密不需要 codec，也不分配中间消息缓冲。NLev 在乘逆密钥**之前**加入 gadget 缩放消息；NGSW 在零加密**之后**注入。

`decrypt_phase_to` 计算系数域 `f*c`，不做解码：NTT 参数为 `(input, output, modulus, table)`；Fourier 为 `(input, output, fft, workspace)`。诊断时用实际 codec 与 embedding 编码**预期消息**，再通过 [`phase_error_magnitude_slice_to`](../primus_encoding/README.zh_CN.md#相位误差诊断) 与该相位比较。解码后重新编码不是独立参考；Fourier 的相位误差还包含变换舍入。

解密返回系数域多项式，使用密文系数类型 `T`；输出类型转换由应用按需处理。

求值密钥持有自己的分解基；可复用求值 workspace 只保存工作缓冲区。拥有契约的公开 操作在输出写入前检查传入尺寸、模数及变换和工作区长度；对应的低层 lattice 内核 依赖这些契约。实际私钥一致性、输入 residue 的规范性及足够的噪声预算仍由调用方保证。

自同构指数 `d` 是 `[1, 2N)` 内的奇数。求值密钥保存 `NLev_f[f(X^d)]`，把代换后 的秘密切换回 `f`，不生成 `f(X^d)` 的逆元。有符号秘密先编码，再在模数域置换。 变换输入仍需恢复系数以进行分解；变换输出省去最后的逆变换。NLev 可逐行使用 这一单多项式操作，但逐行作用于 NGSW **不能**保留 NGSW 的消息与私钥关系。

Fourier 值、求值密钥及置换映射绑定到生成时的确切 FFT table 实例，包括其后端 存储顺序；后续操作必须复用该 table。Fourier 输出路径省去一次输出 torus 舍入， 因此不必与系数往返路径逐位相同。调用方需核算浮点、分解及加密误差。 示例与基准参数用于功能工作负载，不是安全估计。

Sample extraction、NLev/NGSW 外积与 CMUX 位于 [`primus_lattice`](../primus_lattice/README.zh_CN.md)。PBS、ManyLUT 和可选 CBS 位于 [`primus_tfhe_ntru_ntt`](../primus_tfhe_ntru_ntt) 和 [`primus_tfhe_ntru_fourier`](../primus_tfhe_ntru_fourier)，其 message/carry 示例展示多个输出共用一次盲旋转。

## 独立 LWE 返回

`NtruLweKeySwitchingKey::generate(f, Q, s, lwe_parameters.encryption_parameters(), basis, rng)` 从有符号 NTRU 秘密 f 生成返回原语，目标 s 是独立生成的 `primus_lwe::LweSecretKey`。密钥接收不含 codec 的 `LweEncryptionParameters` 和目标模数 q 下的 basis；s 的维数可以不同，也无需补零成为可逆 NTRU 秘密。f 的每个有符号系数的幅值必须小于显式 q，生成时在采样前检查。返回密钥和 batch 工作区的维数使用 `LweDimension`；`LweDimension::from(params.poly_length())` 返回提取维数 N。组合密钥和批量存储长度仍在构造边界检查。

输入必须是系数域 NTRU 密文，NTT/Fourier 输出需要先恢复为系数。工作区一次创建后复用。所有返回路径均覆盖输出，在线不分配，并在写入前检查调用方提供的形状和目标模数。

构造这些工作区时，使用输入 NTRU 参数返回的已验证长度 `poly_length = params.poly_length()`。

| 返回内容 | 密钥方法 | 工作区 |
| --- | --- | --- |
| 一个系数 | `key_switch_at_to`；索引零可用 `key_switch_to` | `NtruLweKeySwitchingWorkspace::new(poly_length)` |
| 同一 NTRU 的多个系数 | `key_switch_many_at_to` | `NtruLweKeySwitchingBatchWorkspace::new(poly_length, output_dimension)` |
| 陆续生成的不同 NTRU 的系数 | `modulus_switch_extract_at_to`，随后 `key_switch_extracted_batch_to` | 同一种批量工作区 |

单项路径将转换和提取融合到一份 N+1 元素的中间 LWE。返回同一输入的多个系数时，向 `key_switch_many_at_to` 传入 `0..outputs.len()` 或 `indices.iter().copied()`。接口保留索引顺序及重复项，并在写入前验证精确长度、可克隆的迭代器。多个输出共享一次 Q→q 转换和固定小块 LWE key switch；空批次不操作，单元素使用标量路径。结果与逐项调用一致，包括舍入 ties。[返回阶段基准](benches/lwe_return.rs) 单独比较这两条路径，不包含盲旋转。

不同源多项式陆续生成时：

1. 选取包含 k 个输出的小块，其中 `k <= workspace.batch_capacity()`。
2. 用 `modulus_switch_extract_at_to(input.as_view(), index, workspace.extracted_slot_mut(slot), q)` 填充 `0..k` 的每个槽位。slot 是当前块内的输出位置，index 是源多项式的系数索引。每份输入独立转换，提取后即可覆盖源多项式。
3. 将恰好 k 个输出传给 `key_switch_extracted_batch_to`。它只读取已填充的前缀，槽位 i 对应输出 i，提取样本保持不变。末块不足容量时无需清空后续槽位。
4. 为下一块重新填充将被消费的槽位。若要改用同一工作区返回共享输入的多个系数，应先完成待返回的小块；共享输入路径可能覆盖这些槽位。

工作区不跟踪已填充槽位数或样本的密钥/模数身份。存储初始化为零，不代表槽位已经为当前请求准备好。

运算先逐系数执行 `c' = round(q*c/Q) mod q`（最近舍入，半格向上），再提取 `b=0`、`i<=index` 时 `a[i]=-c'[index-i]`、否则 `a[i]=c'[N+index-i]`，最后在 q 下进行 LWE key switch。提取秘密为 f 的有符号系数向量，LWE 相位 `b-<a,f>=(f*c')[index]`。舍入必须先于提取取负，否则恰好半格时可能得到不同结果。单输出路径把模数转换和提取融合为一次 scratch 写入，复用 `primus_reduce::ModulusSwitch` 与 `primus_lwe::LweKeySwitchingKey`。

两端模数均可为 native 或显式模数，也可以相等。实现与测试覆盖 u32→u32、u64→u64，包括完整位宽 native 源、接近整数位宽上限的显式源和舍入进位回零。不进行跨位宽窄化：u64 输入即使转换到较小 q，输出系数仍为 u64。输入须为 Q 下的规范剩余。误差预算须包含 f 加权的系数舍入、秘密加权的分解误差、LWE 密钥噪声和已有 NTRU/FFT 误差；Q 下的编码缩放到 q 一般不等于直接在 q 下编码。NTRU TFHE 后端已使用此原语返回外部 LWE。

## Trace、投影与展开

Trace 密钥生成只检查一次共享资源、编码一次秘密，并在各 degree 间复用两块
局部系数缓冲。两块缓冲在返回或 unwind 时擦除。每个 degree 独立持有计算密钥
和置换；在线工作区不保留这些生成缓冲。

`NttNtruTraceKey` 和 `FourierNtruTraceKey` 绑定 `log2(N)` 个 automorphism key。 所有入口的输入、输出均为原秘密下的系数密文，环长度保持 N。普通 partial trace 保留 r 个系数，目标为 `(N/r) * sum_j M[j*N/r] X^(j*N/r)`；reverse trace 保留原消息尺度。NTT 使用模 q 下的 2 的幂逆元归一化；Fourier 在每个逆序步骤前 对无符号系数代表元做向下取整的整数除法，其 phase 舍入误差再乘 f。 两条数值路径的误差分布不同，不能相互替换。

逆序步骤访问 `2r+1, 4r+1, ..., N+1` 次自同构。后续步骤将新引入的自同构误差投影到等间距系数位置；较晚引入的误差可能保留在目标位置以外。Native 减半另外贡献投影后的 `f * parity` 项，其半模数提升项则会消去。这里的 floor 是除二最近舍入的向下取平规则，不承诺舍入无偏。

`project_coefficient(s)_to` 将指定系数移到常数位后做 reverse trace，支持重复及 乱序索引。`project_prefix_coefficients_to(input, count, ...)` 接受 `0..=N` 内 任意 count，为 `0..count` 执行相同的反向 trace，无需索引数组或明文零尾； count 为 1 时仍执行完整反向 trace。 `expand_coefficients_to` 使用展开树，按自然顺序展开整个消息。 `expand_partial_coefficients_to(input, count, ...)` 要求 count 为不大于 N 的 2 的幂，且目标消息仅在前 count 个位置非零；使用 count-1 次 automorphism， 直接复用输出存储展开树。一般输入会得到残余类多项式，不能承诺常数消息。 密文或噪声不要求零尾，输出非目标位置仍可能含噪声。

## 同一秘密下的 scheme switching

`NttNtruSchemeSwitchKey` / `FourierNtruSchemeSwitchKey` 将系数形式的 `NLev_f[m]` 转换为变换形式的 `NGSW_f[m]`。`key_basis` 用于分解每个输入 密文多项式；独立的 `output_basis` 决定输入和输出的 gadget scalar 与层数。 工作区直接复用现有 external-product workspace。输入必须已使用该 output basis， 仅靠长度相同无法验证这一点。

求值密钥保存 `NGSW_f[f]`，通过加密 f 生成，无需显式计算有符号多项式平方。 输入误差乘 f，分解误差乘 f²，还须计入求值密钥与 FFT 误差。公开这种秘密相关 消息的密钥需要独立论证 key-dependent-message/circular-security 假设及参数； 代数推导和功能测试不构成安全性证明或 CBS 参数建议。消息 m 为 bit 时，输出可供 CMUX 使用。

## Features

默认 features 为空，参数、系数密文和有符号秘密，以及 NTRU→LWE 返回路径无需变换后端。`ntt` / `fourier` 分别启用对应的密钥、转换、加解密、求值与工作区，并向 lattice 传递能力。`fourier` 不选择具体 FFT 引擎；`rustfft` / `tfhe-fft` 同时启用 `fourier` 和对应实现，所有后端 feature 可以叠加。`simd` 仅向已启用的算术依赖传播，不激活变换或 FFT 引擎。

使用具体表示或引擎的测试、示例和基准声明 `required-features`；混合 NTT/Fourier target 需同时启用 `ntt` 和其指定的引擎。完整普通验证使用 `--features ntt,rustfft,tfhe-fft`；不满足要求时 Cargo 跳过整个 target。

## 进一步阅读

公开契约见 [rustdoc 对应源码](src)；[测试与基准指南](benches/README.zh_CN.md)保存覆盖范围、工作负载和复现命令。Workspace 验证入口见[测试指南](../../guides/development/testing.md)。

## 许可证

可选择使用 [Apache-2.0](../../LICENSE-APACHE-2.0) 或 [MIT](../../LICENSE-MIT)。
