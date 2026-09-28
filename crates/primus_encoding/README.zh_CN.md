# primus_encoding

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

Primus FHE 的明文系数编码与解码。

## API

`RoundedCodec::try_new` 和 `ScaledCodec::try_new` 对非法数值域或不满足固定尺度恢复界返回 `CodecError`；`new` 形式在相同错误下 panic。构造检查不建立噪声预算。

| 编码器 | 编码规则 | 当前用途 |
| --- | --- | --- |
| `RoundedCodec<T,M>` | `round(lift(m)*q/t) mod q` | LWE 和 TFHE 查找表 |
| `ScaledCodec<T,M>` | `lift(m)*round(q/t) mod q` | 单模数 GLWE/NTRU |
| `BfvRnsCodec<T,M>` | `lift(m)*floor(Q/t) mod Q` | RNS 系数缩放（`rns` feature） |

单模数构造器为 `new(plaintext_modulus, ciphertext_modulus)`，例如 `RoundedCodec::new(256u64, NativeModulus::new())` 或 `RoundedCodec::new(7u64, BarrettModulus::new(131))`。构造需要 `PrepareModulusSwitch` 和 `ReduceAdd`；`RingContext` 已包含这些能力，`UintModulus` / `CompactModulus` 也可使用。构造一次后复用 codec。t 整除 q 时两种编码都使用精确尺度 q/t；否则 Rounded 对每个消息舍入，Scaled 使用统一的整数尺度。

TFHE 普通 LUT 的输出 `RoundedCodec` 使用 accumulator 模数，明文模数可与输入不同。解码使用返回密文模数下、相同输出明文模数的 codec；NTRU 的 Q→q 路径尤其需要区分二者。见[输出编码指南](../primus_tfhe/README.zh_CN.md#选择输出编码)。

这些类型负责系数编码。目前未实现 BFV/BGV 整数槽打包、BGV 的无缩放明文 提升，以及 CKKS 的典范嵌入。

## 编码契约

消息必须是 `[0,t)` 内的规范剩余。无符号嵌入提升到 `[0,t)`，中心嵌入提升到 `[-floor(t/2),ceil(t/2))`，包括 `t=2` 时的 `1 -> -1`。逐消息编码先对绝对值 舍入（中点向上），再应用符号；解码对规范相位乘以 `t/q` 后舍入（中点向上）， 结果模 `t`。累加器与解码输入必须是对应密文模数或有序 RNS 基上的规范剩余。 这些密文输入范围由调用方保证，编码器不会验证。

`RoundedCodec` 要求 `t >= 2` 且 `q > t`。`ScaledCodec` 还检查 `abs(t*round(q/t)-q)*(t-1) < q/2`，这是两种嵌入无噪声恢复的充分条件。 对于选定的整数提升 `m` 和噪声 `e`，恢复条件为 `abs((t*delta-q)*m + t*e) < q/2`。生产方与消费方必须使用一致的编码参数和约定。

`BfvRnsCodec` 使用有序密文模数的乘积 `Q`。除 rustdoc 中记录的模数范围与 互素条件外，构造器检查保守的恢复充分条件：`Q > 4*(Q % t)*(t-1)` 和 `gamma > 4*k`，其中 `k` 为模数数量。对于相位 `delta*m+e`，解码的充分条件为 `abs(t*e-(Q % t)*m)/Q + k/gamma < 1/2`。 当密文基包含多个模数时，目标模数 `t` 和 `gamma` 的实现还必须满足 `BaseConverter::fast_convert` 文档中的额外点积输入要求；`FieldContext` 本身 不保证这一点。

RNS 编码输出系数域 `CrtPolynomial`，调用方单独执行 NTT 转换。 `decode_coeffs_to` 会覆盖系数域输入，并要求工作区恰好包含 `decode_scratch_len(output.len())` 个元素。单模数基不需要工作区，其他基需要 一个 RNS 多项式大小的工作区。该编码器是 BFV 的组成部分， 并非完整 BFV 方案。

单模数切片方法使用 `_to` 表示独立输出，`_assign` 表示原地更新。RNS 使用 `encode_coeffs_to`、`add_encode_coeffs_assign` 和 `decode_coeffs_to`，从明文 切片推导多项式长度。批量编码在写入前检查消息范围和精确长度。 编码输入与解码输出统一使用系数类型 `T`，值为 `[0,t)` 内的规范剩余类。标量输入为 `T`，切片为 `[T]`；整数类型或语义消息类型的转换由应用在边界处理。

## 进一步阅读

[实现说明](IMPLEMENTATION.md)记录算术内核与基准边界；[公开 API 源码](src/lib.rs)和[测试指南](../../guides/development/testing.md)分别说明方法契约与验证范围。

## Feature

- 默认：仅单模数编码器。
- `rns`：启用 `primus_data`、`primus_poly` 和 `primus_rns` 依赖。
- `simd`：启用 nightly SIMD 算术，不会单独启用 `rns`。
