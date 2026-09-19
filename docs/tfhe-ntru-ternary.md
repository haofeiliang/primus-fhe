# NTRU ternary：秘密采样与后端条件

[B7 分步计划](tfhe-backend-plan.md#b7ntru-经典-ternary)的恢复入口。
**B7.1 已完成底层采样前置；TFHE 参数、导入密钥和 binary CMUX 限制仍保留。**
NGSW 融合单步及完整链分别留给 B7.2–B7.4；不包含桶聚合 ternary。

## 1. 目标分布与秘密身份

首批候选使用现有 `SecretKeyDistr` 的全部五种 ternary 分布：

| 分布 | 有效前缀的候选采样规则 |
| --- | --- |
| `UniformTernary` | 每个系数等概率取 `-1/0/1` |
| `SparseTernary` | `P(-1)=P(1)=1/4`，`P(0)=1/2` |
| `Ternary` | 调用方配置正负概率；实际概率沿用底层采样器的有限精度规则 |
| `FixedHammingWeightTernary` | 均匀选定 `h` 个非零位置，符号独立均匀 |
| `FixedCompositionTernary` | 均匀安排 `h_-` 个负一和 `h_+` 个正一，其他位置为零 |

对外部 LWE 维数 `n` 和 NTRU 环长度 `N`，候选为
`f_client = s_0 + s_1 X + ... + s_(n-1) X^(n-1)`，`1 <= n <= N`。
仅前 `n` 个系数参与采样和固定重量约束，`n..N` 始终为零；重试重新采样完整前缀，
不通过翻转一个系数来修正奇偶性。成功后的这一个前缀才是外部 LWE 秘密，不能另采样
一份 LWE 秘密再假设两者相同。负一以 signed 系数保留，转换到 NTT 时编码为 `q-1`，
转换到 Fourier 时采用 Native signed bit pattern。

底层两个后端统一提供 `generate_padded_pair`，替换原 `generate_padded_binary_pair`；
`generate_pair` 以 `n=N` 复用相同路径。底层入口沿用全部 NTRU 采样器（含 Gaussian），
**这不扩大 TFHE 控制代数**；后续经典 ternary BR 仅处理 binary/ternary 家族。
分布标记只记录候选规则，不记录补零长度或接受条件；TFHE 参数仍负责绑定外部维数。

## 2. 两种接受条件

### NTT：精确环内可逆

使用与参数匹配的 NTT 表和显式域模数 `q`。每个候选转换后逐点求逆，任一求逆失败就
拒绝该候选。对分裂的 `X^N+1`，这等价于 `f` 在每个 NTT 根处非零。
非零重量为偶数并不构成拒绝理由；例如 `1-X` 在奇特征的该环中可逆。

### Native / Fourier：环内可逆和数值筛选

对 `N=2^k`，模 2 下 `X^N+1=(X+1)^N`，因此 `f` 可逆当且仅当 `f(1)` 为奇数。
该条件也足以提升到模 `2^BITS`：若 `fg=1+2h`，有限几何级数给出 `1+2h` 的逆。

binary/ternary 的每个非零系数模 2 都是 1，故：

- 固定 binary/ternary 重量 `h` 为偶数，或固定 composition 的 `h_-+h_+` 为偶数：
  **采样前返回 `NtruError::NonInvertibleSecretKey`**，包括总重量零。
- 固定奇数重量满足环内可逆条件，但仍需通过 Fourier 数值筛选。
- 非固定重量逐候选检查奇偶性；退化概率分布可能永远失败，由重试上限终止。

Fourier 使用整数 FFT 的复数逐点逆，并非用浮点数表示模 `2^BITS` 的多项式逆。
当前数值筛选要求每个计算出的 `|FFT(f)_j|²` 有限且大于 `f64::EPSILON`；
否则拒绝候选。此阈值沿用现有实现，只排除明显退化值，**不保证后续 PBS 误差预算**。
RustFFT 与 TfheFFT 分别检查自身变换结果，临界候选可能因实现差异而有不同接受结果。

两个条件不可混同：测试中的整数多项式 `f=(1-X+X²)^8` 满足 `f(1)=1`，但在
`N=32` 的根 `exp(11πi/32)` 附近求值约 `1e-10`，两种 FFT 都拒绝其逆元。
这是数值筛选的反例，不是 ternary 采样分布中的候选。

## 3. 有界拒绝与实际分布

每次调用至多采样 `K=1024` 个候选，返回第一个通过者，否则返回
`KeyGenerationExhausted`；不会返回最后一个失败候选或自动换用别的分布。
参数长度/重量不合法仍按现有 API panic。候选、变换和逆元缓冲区在重试间复用，
成功、失败及 unwind 时均保留既有擦除责任。

令 `D_n` 为前缀候选分布，`A` 为所选后端的接受集合，`p = Pr[D_n ∈ A]`。
在独立候选模型下，成功返回时：

```text
Pr[s | success] = D_n(s) * 1_A(s) / p
Pr[exhausted]   = (1-p)^1024
```

有界次数不会在“成功返回”这一条件下再改变上述分布；它增加失败事件。
`distr()` 和参数中的分布仍是 `D_n`，并非声称输出系数仍独立或在原支持集上均匀。
NTT 的可逆性条件与 Fourier 的奇偶性、数值条件也不能视为相同筛选。

以下结论仍未建立，不由采样通过率或功能测试替代：

- 零 padding、固定重量/符号及上述筛选后的具体安全估计；后续公钥与评估密钥必须使用
  同一个条件秘密模型，不能直接沿用未筛选 iid ternary 的估计。
- Fourier 阈值与完整 BR/CBS/MVB 的噪声尾界；B7.3/B7.4 须独立验证误差预算。
- 密钥生成重试次数和逆元计算的恒时性。

## 4. 实现与验证入口

- [NTT 生成](../crates/primus_ntru/src/secret_key/ntt/mod.rs)、
  [Fourier 生成](../crates/primus_ntru/src/secret_key/fourier/mod.rs)。
- [聚焦测试](../crates/primus_ntru/tests/padded_secret_key.rs)：五种 ternary 前缀、固定
  composition/重量和补零；u64 NTT 通过独立系数卷积核对精确 `f*c=mu+e`；两种 FFT
  核对奇偶性及返回系数/变换私钥身份；固定偶数重量在采样前报错；数值逆元反例。
- [既有秘密擦除测试](../crates/primus_ntru/tests/zeroize.rs)继续覆盖拒绝后成功的缓冲复用、
  失败候选和耗尽时擦除；[普通加解密测试](../crates/primus_ntru/tests/secret_key.rs)覆盖 u32/u64。
  [TFHE 参数测试](../crates/primus_tfhe_ntru/tests/parameters.rs)继续拒绝非 binary 客户端秘密。

CI 只保留 `N=32,n=23` 的四个新增聚焦测试，不新增采样统计或 benchmark。
该步没有在线内核变化，也不宣称性能改善。B7.2 下一步验证 NTT NGSW ternary 融合单步，
尚未开放完整 NTRU ternary PBS。

本步已通过 `primus_ntru` 默认/SIMD 的 all-targets check、测试和 Clippy，
以及 `just tfhe`、`just tfhe-simd` 和 NTRU 四包的严格 rustdoc 检查。
