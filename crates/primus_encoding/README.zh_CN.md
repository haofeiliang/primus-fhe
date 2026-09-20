# primus_encoding

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

Primus FHE 的明文系数编码与解码。

## API

| 编码器 | 编码规则 | 当前用途 |
| --- | --- | --- |
| `RoundedCodec<T,M>` | `round(lift(m)*q/t) mod q` | LWE 和 TFHE 查找表 |
| `ScaledCodec<T,M>` | `lift(m)*round(q/t) mod q` | 单模数 GLWE/NTRU |
| `BfvRnsCodec<T,M>` | `lift(m)*floor(Q/t) mod Q` | RNS 系数缩放（`rns` feature） |

公开类型直接从 crate 根部导出，实现模块保持私有。单模数构造器为 `new(plaintext_modulus, ciphertext_modulus)`，密文模数使用具体模数类型， 例如 `RoundedCodec::new(256u64, NativeModulus::new())` 表示 `q=2^64`， `RoundedCodec::new(7u64, BarrettModulus::new(131))` 使用显式模数。 所需能力为 `PrepareModulusSwitch` 和 `ReduceAdd`，无需完整 `RingContext`。 `RingContext` 已包含准备能力；codec 也支持 `UintModulus`、`CompactModulus`， 无需它们实现完整环运算。 `RoundedCodec` 在构造时准备固定的 `t → q`、`q → t` 转换；`ScaledCodec` 保留固定尺度乘法并复用预备解码转换。绝对值舍入和解码复用模切内核；批量路径将 符号、输出写回和累加与各自算术融合，无需中间缓冲区；标量包装保留各自的直接特化路径。 `t` 整除 `q` 时，两者都使用精确整数尺度 `q/t`；否则 `RoundedCodec` 对每个缩放消息舍入，`ScaledCodec` 使用统一的舍入整数尺度。

整数尺度为二次幂时使用移位，否则使用普通单字乘法。固定尺度构造器的恢复条件 保证 `(t-1)*delta < q`，因此绝对值编码无需模乘。中心取负和累加仍需要 密文模数运算。

对于非整数比例，逐消息编码分解 `q = a*t + r`；当带舍入偏置的余数乘积 能够放入单字时，对消息绝对值计算 `m*a + floor((m*r + floor(t/2))/t)`， 否则保留宽位算术。

仅当 `t` 整除 `q` 时，解码才使用 `round(c/delta) mod t`；舍入后的尺度 是二次幂并不足以保证该等式。其他参数使用原生乘法高半部分或显式窄／宽乘积 比例舍入内核。批处理算术策略均在系数循环外选择。

TFHE 输入编码来自参数；普通 LUT 编译显式接收输出 `RoundedCodec`。 `plaintext_modulus()` 与 `ciphertext_modulus()` 分别公开输出明文模数和密文模数。 明文模数可以与输入不同，密文模数须与 accumulator 一致。客户端可返回 raw phase， 供同一个输出 codec 解码。

这些类型负责系数编码。目前未实现 BFV/BGV 整数槽打包、BGV 的无缩放明文 提升，以及 CKKS 的典范嵌入。

## 编码契约

消息必须是 `[0,t)` 内的规范剩余。无符号嵌入提升到 `[0,t)`，中心嵌入提升到 `[-floor(t/2),ceil(t/2))`，包括 `t=2` 时的 `1 -> -1`。逐消息编码先对绝对值 舍入（中点向上），再应用符号；解码对规范相位乘以 `t/q` 后舍入（中点向上）， 结果模 `t`。累加器与解码输入必须是对应密文模数或有序 RNS 基上的规范剩余。 这些密文输入范围由调用方保证，编码器不会验证。

`RoundedCodec` 要求 `t >= 2` 且 `q > t`。`ScaledCodec` 还检查 `abs(t*round(q/t)-q)*(t-1) < q/2`，这是两种嵌入无噪声恢复的充分条件。 对于选定的整数提升 `m` 和噪声 `e`，恢复条件为 `abs((t*delta-q)*m + t*e) < q/2`。生产方与消费方必须使用一致的编码参数和约定。

`BfvRnsCodec` 使用有序密文模数的乘积 `Q`。除 rustdoc 中记录的模数范围与 互素条件外，构造器检查保守的恢复充分条件：`Q > 4*(Q % t)*(t-1)` 和 `gamma > 4*k`，其中 `k` 为模数数量。对于相位 `delta*m+e`，解码的充分条件为 `abs(t*e-(Q % t)*m)/Q + k/gamma < 1/2`。 当密文基包含多个模数时，目标模数 `t` 和 `gamma` 的实现还必须满足 `BaseConverter::fast_convert` 文档中的额外点积输入要求；`FieldContext` 本身 不保证这一点。

RNS 编码输出系数域 `CrtPolynomial`，调用方单独执行 NTT 转换。 `decode_coeffs_to` 会覆盖系数域输入，并要求工作区恰好包含 `decode_scratch_len(output.len())` 个元素。单模数基不需要工作区，其他基需要 一个 RNS 多项式大小的工作区。该编码器是 BFV 的组成部分， 并非完整 BFV 方案。

单模数切片方法使用 `_to` 表示独立输出，`_assign` 表示原地更新。RNS 使用 `encode_coeffs_to`、`add_encode_coeffs_assign` 和 `decode_coeffs_to`，从明文 切片推导多项式长度。批量编码在写入前检查消息范围和精确长度。 编码输入与解码输出统一使用系数类型 `T`，值为 `[0,t)` 内的规范剩余类。标量输入为 `T`，切片为 `[T]`；整数类型或语义消息类型的转换由应用在边界处理。

## 源码结构

- `rounded.rs` 和 `scaled.rs`：两个单模数编码器及其 API。
- `integer_scale.rs`、`decode.rs` 和 `helpers.rs`：共享的私有内核与边界辅助函数。
- `bfv_rns/`：BFV RNS 编码器；`mod.rs` 管理参数和构造，`encode.rs` 实现编码与累加， `decode.rs` 实现解码及其工作区契约。

测试分别覆盖 API 一致性、独立算术 oracle 和 BFV RNS 契约。 `benches/plaintext_codec.rs` 测量单模数算术和标量调度， `benches/bfv_rns.rs` 测量 RNS 累加编码与解码。输入覆盖中心嵌入的两个半区 以及各自的密文模数范围。编码器和可复用缓冲区在计时外准备；破坏性解码以固定 批量恢复输入。吞吐量按明文系数计数，RNS case 名称注明模数数量。

## Feature

- 默认：仅单模数编码器。
- `rns`：启用 `primus_data`、`primus_poly` 和 `primus_rns` 依赖。
- `simd`：启用 nightly SIMD 算术，不会单独启用 `rns`。

## 验证

```sh
cargo test -p primus_encoding
cargo test -p primus_encoding --features rns
cargo +nightly test -p primus_encoding --features rns,simd
cargo bench -p primus_encoding --bench plaintext_codec
cargo bench -p primus_encoding --bench bfv_rns --features rns
```
