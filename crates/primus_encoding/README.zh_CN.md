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

`MessageDecoder::from(&codec)` 从任一种单模数 codec 复制已准备好的 q→t 状态，不分配内存或重新准备 switch。它提供 `decode_value`、`decode_slice_to` 和 `decode_slice_assign`，沿用规范输入契约。共用解码规则不表示 Rounded/Scaled 编码可以互换，也不建立噪声预算。

`BfvRnsCodec` 使用有序密文模数的乘积 `Q`。除 rustdoc 中记录的模数范围与 互素条件外，构造器检查保守的恢复充分条件：`Q > 4*(Q % t)*(t-1)` 和 `gamma > 4*k`，其中 `k` 为模数数量。对于相位 `delta*m+e`，解码的充分条件为 `abs(t*e-(Q % t)*m)/Q + k/gamma < 1/2`。 基转换继承 `BaseConverter::fast_convert` 的跨模数点积契约。这里使用的运行时或派生 Barrett 已建立所需的操作数范围；源 residue 允许超过 `t` 或 `gamma`，不需要额外约简。自定义 context 仍须提供相同的数值保证。

`BfvRnsCodec::try_new` 在模数或恢复条件无效时返回 `BfvRnsCodecError<T>`；`new` 委托它构造，失败时 panic。传入的 `RNSBase` 已验证密文基非空且两两互素。这些检查在构造时完成，不建立加密的噪声或安全预算。

Codec 和内部解码转换器共享传入基的不可变 CRT 表及模数值缓存。Codec 的克隆也共享这些基表，BFV 缩放因子和转换矩阵仍独立拥有。Gadget 参数可以共享同一个 `RNSBase`，无需持有 BFV 编码数据。

给定完整相位噪声幅度上界 `E`，在准备参数时调用一次 `validate_noise_bound(E, embedding)`。它用精确多 limb 整数运算检查 `(t*E + (Q % t)*A)/Q + k/gamma < 1/2`，其中 unsigned 的 `A=t-1`，centered 的 `A=floor(t/2)`。失败返回 `InsufficientNoiseRecovery`；这是充分条件，可能拒绝实际仍能解码的情形。调用方须在 `E` 中计入加密与求值的全部噪声贡献。

RNS 编码输出系数域 `CrtPolynomial`，调用方单独执行 NTT 转换。 `decode_coeffs_to` 会覆盖系数域输入，并要求工作区恰好包含 `decode_scratch_len(output.len())` 个元素。单模数基不需要工作区，其他基需要 一个 RNS 多项式大小的工作区。该编码器是 BFV 的组成部分， 并非完整 BFV 方案。

单模数切片方法使用 `_to` 表示独立输出，`_assign` 表示原地更新。RNS 使用 `encode_coeffs_to`、`add_encode_coeffs_assign` 和 `decode_coeffs_to`，从明文 切片推导多项式长度。批量编码在写入前检查消息范围和精确长度。 编码输入与解码输出统一使用系数类型 `T`，值为 `[0,t)` 内的规范剩余类。标量输入为 `T`，切片为 `[T]`；整数类型或语义消息类型的转换由应用在边界处理。

## 相位误差诊断

`phase_error_magnitude(phase, expected_phase, modulus)` 用系数类型返回精确的非负圆周距离，范围为 `[0, floor(q/2)]`。它只需要模减能力，不必显式表示 Native 的 `2^BITS`，不分配，也不转换为浮点数。`phase_error_magnitude_slice_to` 将逐项距离写入调用方切片；三个切片长度必须一致，空切片也遵循此规则。长度不匹配在写入前 panic；规范 residue 由调用方保证。

先通过加密库提取系数域 phase，再用与该 phase 一致的 codec、embedding 和模数编码**预期消息**。例如：

```rust
use primus_encoding::{PlaintextEmbedding, RoundedCodec, phase_error_magnitude};
use primus_modulus::PowOf2Modulus;

let modulus = PowOf2Modulus::new(256u64);
let codec = RoundedCodec::new(4, modulus);
let expected_phase = codec.encode_value(0, PlaintextEmbedding::Unsigned);
let phase = 64; // 预期消息是 0，但这个 phase 会解码为 1。
assert_eq!(phase_error_magnitude(phase, expected_phase, modulus), 64);
```

如果重编码解码所得的值，这个例子的 residual 为零，会掩盖错误消息。解码是否正确仍须单独判断。圆周距离没有符号，不能恢复已绕模的整数误差，也包含 phase 中已有的变换或求值误差。逐 limb 的 RNS 距离不代表乘积模数下的整体误差。

## 进一步阅读

[实现说明](IMPLEMENTATION.md)记录算术内核与基准边界；[公开 API 源码](src/lib.rs)和[测试指南](../../guides/development/testing.md)分别说明方法契约与验证范围。

## Feature

- 默认：单模数编码器与相位误差诊断。
- `rns`：启用 `primus_data`、`primus_poly` 和 `primus_rns` 依赖。
- `simd`：启用 nightly SIMD 算术，不会单独启用 `rns`。
