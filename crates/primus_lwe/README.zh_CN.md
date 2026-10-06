# primus_lwe

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

Primus FHE 的单模数 LWE 密钥生成、私钥加密、公钥加密和密钥切换实现。 密文存储与算术来自 [`primus_lattice`](../primus_lattice/README.zh_CN.md)， 消息编码使用 [`RoundedCodec`](../primus_encoding/README.zh_CN.md)。

`LweEncryptionParameters` 保存已验证的密文域和预计算采样器，不含消息 codec；`LweParameters` 再绑定 `RoundedCodec` 供普通加解密使用。生成密钥传入 `params.encryption_parameters()`，`params.into_encryption_parameters()` 可直接移出采样状态而不克隆。TFHE 可直接构造 `LweEncryptionParameters`，稍后再选择消息编码。

## API

公开类型均从 crate 根导出，实现模块为私有模块。

| 类型 | 职责 |
| --- | --- |
| `LweEncryptionParameters<T, M>` | 密文域与预计算采样器，不含消息 codec |
| `LweParameters<T, M>` | 维度、模数、明文 codec、私钥分布及预计算采样器 |
| `LweSecretKey<T>` | 持有 Encoded 系数；提供 message、encoded 和 phase 操作 |
| `LweSecretKeyRef<'a, T>` | 借用 `Encoded` 或 `Signed` 系数；提供单条密文的 raw 操作 |
| `LwePublicKey<T>` | 方阵 Lindner–Peikert 风格的公钥加密 |
| `LweKeySwitchingKey<T>` | 在相同密文模数下切换私钥，允许改变维度 |
| `LweCiphertext<T>` | `primus_lattice::lwe::Lwe<Vec<T>>` 的别名 |
| `MultiMsgLweCiphertext<T>` | `primus_lattice::lwe::MultiMsgLwe<Vec<T>>` 的别名 |

`encrypt_message` / `encrypt_message_batch` 显式接收 `PlaintextEmbedding` 并分配输出；对应的 `_to` 接口覆盖调用方提供的存储， 不进行分配。私钥解密接受拥有或借用存储的密文。公钥密文使用相同的解密和密钥切换接口。

## 快速开始

下面使用小维度演示存储复用、独立公钥 batch 和密钥切换，参数未经安全性评估。 调用方 crate 需要直接依赖 `primus_lwe`、`primus_lattice`、`primus_modulus`、 `primus_decompose`、`primus_encoding` 和 `rand`，以使用示例中的导入。

```rust
use primus_encoding::PlaintextEmbedding;
use primus_decompose::{DecompositionBaseLog, primitive::ApproxSignedBasis};
use primus_lattice::lwe::{Lwe, LweIter};
use primus_lwe::{LweDimension, LweKeySwitchingKey, LweParameters, LwePublicKey, LweSecretKey, SecretKeyDistr};
use primus_modulus::NativeModulus;

fn main() {
    let params = LweParameters::new(
        LweDimension::new(64),
        4u64,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let mut rng = rand::rng();
    let secret = LweSecretKey::generate(params.encryption_parameters(), &mut rng);

    let ciphertext = secret.encrypt_message(3u64, &params, PlaintextEmbedding::Unsigned, &mut rng);
    assert_eq!(secret.decrypt_message(&ciphertext, &params), 3);

    let mut storage = vec![0u64; ciphertext.lwe_len()];
    secret.encrypt_message_to(2u64, &mut Lwe::new(&mut storage[..]), &params, PlaintextEmbedding::Unsigned, &mut rng);
    assert_eq!(
        secret.decrypt_message(&Lwe::new(&storage[..]), &params),
        2
    );

    let public = LwePublicKey::generate(secret.as_view(), params.encryption_parameters(), &mut rng);
    let messages = [0u64, 1, 2, 3];
    let batch = public.encrypt_message_batch(&messages, &params, PlaintextEmbedding::Unsigned, &mut rng);
    assert_eq!(secret.decrypt_message_batch(&batch, &params), messages);
    for (sample, &message) in LweIter::new(&batch, ciphertext.lwe_len()).zip(&messages) {
        assert_eq!(secret.decrypt_message(&sample, &params), message);
    }

    let output_params = LweParameters::new(
        LweDimension::new(32),
        4u64,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let output_secret = LweSecretKey::generate(output_params.encryption_parameters(), &mut rng);
    let basis = ApproxSignedBasis::new(params.cipher_modulus_value(), DecompositionBaseLog::new(4), None);
    let switching = LweKeySwitchingKey::generate(
        secret.as_view(),
        &output_secret,
        output_params.encryption_parameters(),
        basis,
        &mut rng,
    );
    let switched = switching.key_switch_batch(&batch, params.cipher_modulus());
    assert_eq!(
        output_secret.decrypt_message_batch(&switched, &output_params),
        messages
    );
}
```

[examples/basic.rs](examples/basic.rs) 提供可运行的私钥、公钥和 batch 工作流： `cargo run -p primus_lwe --example basic`。

## 参数与编码

外部配置输入先用 `LweDimension::try_new` 检查非零 `n` 和可表示的 `n+1`，失败返回 `LweDimensionError`。`LweParameters::try_new` 接收该维数，对编码、秘密支持集/重量和噪声采样错误返回 `LweParameterError`。固定重量不得超过 n。`new` 是主动 panic 的便捷形式；明文模数从保存的 codec 派生。 `LweParameterError::SecretKey` 以 `SecretKeySamplerError` 保留采样配置、重量或模数适配的具体原因；`Noise` 保留 `GaussianError`。

`LweParameters::new(LweDimension::new(n), t, modulus, secret_distribution, noise_standard_deviation)` 要求满足 codec 和采样器的有效性条件，包括 `t >= 2`、`q > t`。`params.dimension()` 返回 `LweDimension`，用 `.ciphertext_len()` 分配存储，在原始切片边界用 `.get()` 提取整数。原始秘密视图仍返回整数维数，允许零维。`NativeModulus<T>` 表示 `q = 2^T::BITS`； `cipher_modulus_value()` 对 Native 模数返回 `None`，对显式模数返回 `Some(q)`。 噪声标准差以密文系数为单位。

消息接口接受类型 `T`、位于 `[0,t)` 内的规范剩余类，批量及 packed 加密接受 `&[T]`。 `encrypt_message` 通过 `primus_encoding` 中的 `PlaintextEmbedding::Unsigned` 或 `PlaintextEmbedding::Centered` 选择编码。Centered embedding 仍接受无符号剩余类， 其中 `t - 1` 表示 `-1`。两种编码都使用 `decrypt_message` 解密，结果使用密文系数类型 `T`， 位于 `[0,t)`。批量和 packed 解密同样返回 `Vec<T>` 或写入 `[T]`；应用在加密前、 解密后按需转换整数类型或有明确语义的消息类型。

对密文 `[a, b]`，私钥加密计算 `b = <a,s> + e + Encode(message) mod q`。 只有相位噪声处于 codec 的解码余量内时，才能恢复原消息。私钥、密文和参数的维度及模数 必须一致，Encoded 系数必须是规范剩余类。拥有型私钥操作在采样或写入前检查记录的模数；raw view 依赖调用方事先建立模数兼容性。

`LweSecretKey::generate` 在采样前接管秘密缓冲区，采样 panic 导致栈展开时擦除已写入的秘密，并记录参数模数；`LweSecretKey::new(coefficients, distribution, modulus)` 导入时记录显式传入的模数，不扫描系数。导入数据须已是符合声明分布的规范剩余类。`cipher_modulus_minus_one()` 返回 `q - 1`（Native 为 `T::MAX`），用于区分剩余类域，不证明秘密身份或导入来源。`as_view()` 不携带这些元数据：调用 raw 接口前，应先检查拥有型密钥。显式 `zeroize()` 清空系数，保留公开的模数/分布元数据；擦除后应丢弃密钥。

拥有型 `secret.encrypt_encoded` / `encrypt_encoded_to` 接收已编码剩余类和 `LweEncryptionParameters`；`secret.decrypt_phase` 接收密文和模数。这些入口保留 owner 的模数检查。

借用型单条私钥 raw 操作通过 `secret.as_view()` 直接使用预计算资源：`encrypt_encoded` / `encrypt_encoded_to` 接受已编码的剩余类、模数、均匀采样器、噪声采样器和 RNG； `decrypt_phase` 返回 `b - <a,s>`，不进行解码。向 raw 加密传入零会得到随机化的零密文。 `LweSecretKeyRef::Signed` 直接借用有符号系数，不分配 Encoded 副本。点积调用模数后端的 `ReduceDotProductSigned` 实现，将表示转换与乘法融合。 显式模数下要求 `-q < s_i < q`；Native 模数下允许所有有符号值。 Raw 采样器必须使用相同模数。这些范围及采样器约定是调用方前提。

诊断噪声时，先通过 `phase = secret.decrypt_phase(input, modulus)` 提取相位，用实际 codec 和 embedding 编码**预期消息**，再调用 `primus_encoding::phase_error_magnitude(phase, expected_phase, modulus)`。结果是环形距离，不估计噪声分布，也不证明解密正确。将解码结果重新编码作为参考，可能掩盖错误解密。

## 公钥加密

消息加密使用 `encrypt_message[_to]`，传入 `LweParameters` 与显式 embedding。Raw `encrypt_encoded[_to]` 直接接收已编码剩余类、模数、噪声采样器和 RNG，让 TFHE 调用方复用已有资源，无需重新构造参数对象。

`LwePublicKey::generate` 是 raw 入口，不能检查拥有型私钥的模数元数据，须先检查再借用。它接收 `LweSecretKeyRef`：owned LWE 私钥传入 `secret.as_view()`，GLWE/NTRU 系数可直接使用 `LweSecretKeyRef::Signed`， 生成过程中无需复制秘密。借用视图仍须满足对应模数下的系数范围契约。

公钥存储 `n` 行 `[A_i, b_i]`，其中 `A` 为方阵，`b = A s + e`， 总计 `n * (n + 1)` 个系数。加密采样稀疏三元向量 `r`，分布为 `Pr[0] = 1/2`、`Pr[-1] = Pr[1] = 1/4`，再采样独立的新高斯噪声 `e1, e2`：

```text
a = A^T r + e1
c = b^T r + e2 + Encode(message)
phase = Encode(message) + e^T r + e2 - e1^T s  (mod q)
```

加密时的噪声采样器描述 `e1` 和 `e2`，并非最终密文的总噪声。 参数选择需要同时考虑长期私钥、临时私钥、额外噪声项及目标解密失败概率， 私钥加密参数不能直接视为适合公钥加密。实现检查维度和模数身份，不验证安全性或噪声界。 这是 CPA 加密原语，不包含 KEM 或 CCA 变换。行选择根据临时系数分支，当前实现并非恒定时间。

## 独立 batch 与 packed 消息

独立 batch 使用扁平 `Vec<T>` 或切片，连续存放 `count` 个 `[a, b]`， 每条长度为 `n + 1`，条数不受 `n` 限制，没有单独的 batch 容器。`Lwe::lwe_len()` 的长度包含 body。 `LweIter` / `LweIterMut` 可借用其中的单条密文；迭代器本身会忽略不完整尾部， LWE batch 接口则会拒绝这种输入。

- `encrypt_message_batch_to` 的输出必须恰好包含 `messages.len() * (n + 1)` 个元素。 `decrypt_message_batch_to` 的输出长度必须等于密文条数。
- `encrypt_message_batch` 及其 `_to` 版本显式接收 embedding。 Raw batch 使用 `encrypt_encoded_batch` / `encrypt_encoded_batch_to` 和 `decrypt_phase_batch` / `decrypt_phase_batch_to`。
- 所有私钥 batch 方法均要求持有 Encoded 系数的 `LweSecretKey<T>`。 Signed 视图只支持单条密文的 raw 操作。Raw 私钥 batch 直接接收模数和预计算采样器，保留零维密钥支持。
- 私钥 batch 复用单条加密；公钥 batch 分块处理以复用矩阵行，RNG 顺序不保证与逐条加密一致。 空的独立 batch 不消耗随机数。
- 公钥加密从每个随机字提取 16 个临时三元系数，在单条密文或 batch 分块结束时丢弃未用的 bit。 固定 seed 不保证跨库版本生成相同的密文字节。
- Batch 入口在处理前检查完整缓冲区长度；非法消息或 RNG 失败可能留下部分输出并消耗随机数。

Packed 加密使用不同布局：`encrypt_message_packed` 存储一个长度为 `n` 的共享 mask 及 `count <= n` 个 body，共 `n + count` 个系数。第 `i` 个 body 使用 mask 右移 `i` 位、并将前 `i` 个系数取负后的掩码。这些样本共享掩码结构。 使用 `decrypt_message_packed` 或 `MultiMsgLwe::extract_lwe_at` 处理该表示， 不能在其存储上直接用 `LweIter` 遍历单条样本。`encrypt_encoded_packed` 和 `decrypt_phase_packed` 在同一布局下处理已编码剩余类和相位。`encrypt_zeros_packed` 构造 packed 零消息； 即使消息列表为空，packed 加密仍保留并采样共享 mask。

## 密钥切换

`LweKeySwitchingKey::generate` 接受 `Encoded` 或 `Signed` 输入私钥视图、 Encoded 输出私钥 `&LweSecretKey<T>`、不含 codec 的 `&LweEncryptionParameters<T, M>` 输出参数以及转移所有权的 `ApproxSignedBasis<T>`。 生成的切换密钥保留维度与分解基，不保存完整 `LweParameters`。 存储顺序为输入私钥系数、分解层、输出密文的 `[a, b]` 系数， 总计 `input_dimension * levels * (output_dimension + 1)` 个元素。

`key_switch` / `key_switch_to` 处理单条密文；`key_switch_batch` / `key_switch_batch_to` 使用独立 batch 切片。输入、输出分别使用各自维度，密文模数必须相同。 密钥切换不重新编码消息，也不切换模数。解密参数需要保持编码一致，噪声预算需覆盖 分解误差和密钥条目噪声。Batch 输出与逐条切换逐系数相同，`_to` 路径复用密钥条目， 不需要堆上临时工作区。

## 源码布局

- [src/parameter.rs](src/parameter.rs)：参数校验、codec 和采样器。
- [src/secret_key/](src/secret_key/)：存储与生成（`owned.rs`）、raw 视图（`borrowed.rs`）、 encoded 标量原语（`single.rs`）、raw 独立 batch（`batch.rs`）、raw 共享掩码操作（`packed.rs`）及消息适配（`message.rs`）。
- [src/public_key/](src/public_key/)：`mod.rs` 实现生成及 raw 单条加密，`batch.rs` 实现 raw 分块加密，`message.rs` 提供消息适配。
- [src/key_switch/](src/key_switch/)：`mod.rs` 实现生成及单条切换，`batch.rs` 实现分块切换。
- [src/batch.rs](src/batch.rs)：私有 batch 长度及布局辅助函数。

## Feature 与验证

默认 feature 集为空；`simd` 启用底层 crate 的 nightly SIMD 算术。 在 workspace 根目录运行：

```sh
cargo test -p primus_lwe
cargo clippy -p primus_lwe --all-targets -- -D warnings
cargo +nightly test -p primus_lwe --features simd
cargo run -p primus_lwe --example basic
cargo bench -p primus_lwe --bench secret_key
cargo bench -p primus_lwe --bench public_key
cargo bench -p primus_lwe --bench key_switch
```

测试聚焦独立算术校验、私钥表示、packed 提取与边界契约。 三个 benchmark 分别覆盖私钥分配与复用及 packed 加密、公钥生成与矩阵行复用、 密钥切换生成与单条及 batch 处理。
