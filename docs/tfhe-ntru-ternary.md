# NTRU ternary：秘密采样与融合单步

[B7 分步计划](tfhe-backend-plan.md#b7ntru-经典-ternary)的恢复入口。
**B7.1 采样前置及 B7.2/B7.3 NTT/Fourier NGSW 融合单步已完成；TFHE 参数及导入密钥仍限制 binary。**
完整链留给 B7.4；不包含桶聚合 ternary。

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

B7.1 只增加 `N=32,n=23` 的四个聚焦测试，不增加采样统计或 benchmark；
该步没有在线内核变化，不宣称性能改善。尚未开放完整 NTRU ternary PBS。

本步已通过 `primus_ntru` 默认/SIMD 的 all-targets check、测试和 Clippy，
以及 `just tfhe`、`just tfhe-simd` 和 NTRU 四包的严格 rustdoc 检查。

## 5. B7.2：NTT NGSW ternary 融合单步

### 代数与调用契约

`NttNgsw::cmux_ternary_monomial_to` 使用互斥比特 `s⁺,s⁻` 的独立 NGSW 加密，
计算一次外积：

```text
D = (X^a - 1) C
G = NGSW(s⁺) - X^(-a) NGSW(s⁻)
C_out = C + G ⊠ D
```

忽略噪声和分解误差，乘子 `1+(s⁺-X^-a s⁻)(X^a-1)` 在
`s=s⁺-s⁻` 为 `1/-1/0` 时分别等于 `X^a/X^-a/1`。
两份控制均在 accumulator NTRU 秘密 `f` 下，使用同一个模数、NTT 布局和 gadget basis。
`a` 已量化到 `0..2N`；内部从它派生 `2N-a`，不再量化负 LWE 系数。
零指数直接复制输入，输入输出均为系数表示，输出保持规范剩余类。

[实现](../crates/primus_lattice/src/ngsw/ternary.rs)复用已有 `sub_mul_monomial_to` 和
NTRU gadget-product 内核。先在 NTT 中组合控制，再分解 `D` 并完成一次外积；
不修改原 binary CMUX。构造
`NttNtruTernaryCmuxContext::new(N, levels)` 后，在线复用工作区，不要求清零或分配。
组合控制使用外积的 digit 缓冲临时保存单项式因子，随后的分解完全覆盖它；输出在分解期间
保存 `D`，所以乘积在 context 的独立 accumulator 中累加。

### 误差与验收

若每行控制的相位误差为 `e_l⁺,e_l⁻`，组合后为 `e_l⁺-X^-a e_l⁻`。
令 `r` 为 `D` 的重构误差、`d_l` 为分解 digit，则输出相对于理想旋转的相位误差是：

```text
f * (s⁺-X^-a s⁻) * r + sum_l d_l * (e_l⁺-X^-a e_l⁻)
```

这解释了为什么两份加密零控制也会带来噪声，以及融合和两次 binary CMUX 不必产生
相同密文或相同噪声。对互斥控制和 `||r||∞ <= E`，可用的保守单步界为
`||f||₁ E + N (B/2) sum_l (||e_l⁺||∞ + ||e_l⁻||∞)`；这里不是完整 PBS 尾界。

新增两个测试，分别承担独立契约：

- [lattice 无噪声 oracle](../crates/primus_lattice/tests/ternary_cmux.rs)：u32、
  `N=16`、两种截断深度，覆盖 `-1/0/1`、全部 `0..2N` 指数、负循环符号、
  规范输出和脏工作区复用；误差受 basis 的重构界约束。
- [真实控制测试](../crates/primus_ntru/tests/ternary_cmux.rs)：u64、`N=32`、
  固定 seed。由 signed 秘密做独立 schoolbook 卷积，核对融合与两次 binary CMUX
  相对于理想相位的误差；界使用本次实际控制误差，避免 Gaussian 概率断言。
  全部符号/指数的融合调用从首次起零分配，零指数精确复制。

### 单步成本与保留决定

[基准](../crates/primus_ntru/benches/ternary_cmux.rs)每次迭代执行一个完整 ternary
旋转：包含控制组合、系数旋转差分、分解、NTT/INTT 和输出相加。
参照路径顺次用同一对控制做正、负两次 binary CMUX；两者都读取真实独立加密的 `(0,1)`
控制，输出和工作区预分配，公共指数 `a=N/3`。只比较同一行参数下的两种算法。

测量：AMD Ryzen 9 9955HX3D，固定 CPU 2，
`rustc 1.100.0-nightly (bff8e12ff 2026-08-26)`；仓库 `target-cpu=native`，
Criterion 30 samples、warm-up 1 s、measurement 2 s。以下为 Criterion 时间点估计：

| 类型 / feature | `q` / `N` / `logB,L` | 两次 binary（µs） | 融合（µs） | 时间减少 |
| --- | --- | ---: | ---: | ---: |
| u32 / default | 132120577 / 1024 / 8,3 | 18.126 | 10.475 | 42.2% |
| u32 / SIMD | 同上 | 17.964 | 10.650 | 40.7% |
| u64 / default | 1125899906826241 / 1024 / 8,6 | 61.509 | 40.003 | 35.0% |
| u64 / SIMD | 同上 | 53.108 | 31.849 | 40.0% |

按构造时实际分配的缓冲区字节计，排除共同 input/output、NTT 表和栈上容器：

| 类型 | 正负控制合计 | 两次 CMUX scratch（含中间密文） | 融合 scratch | 增量 |
| --- | ---: | ---: | ---: | ---: |
| u32，L=3 | 24 KiB | 17 KiB | 25 KiB | 8 KiB |
| u64，L=6 | 96 KiB | 33 KiB | 73 KiB | 40 KiB |

原外积工作区为 `3N` 个系数加 `N` 个 bool 字节；两次 CMUX 增加 `N` 个系数的中间密文，
融合增加 `LN` 个系数的组合控制。因此两种完整步骤相差 `(L-1)N*sizeof(T)`，没有另存
单项式多项式。固定布局带来的空间代价换取本组 35%–42% 的时间减少，保留此实现。
没有额外实现逐行组合或改变既有 binary 内核；此处也不宣称达到最优。

两路基准重复使用同一对控制，不能外推整把 BSK 的缓存/带宽成本，也不比较等安全参数。
完整 NTRU ternary PBS、误差累积及资源成本留给 B7.4；Fourier 单步见下一节。

复现命令见基准文件顶部；本次使用 `taskset -c 2`，默认/SIMD 都使用上述 nightly，
Criterion 参数为 `--save-baseline b72-default --noplot` / `--save-baseline b72-simd --noplot`。

B7.2 已通过 lattice/NTRU 默认与 SIMD 的 all-targets check、Clippy 和测试，
以及 `just tfhe`、`just tfhe-simd`、lattice/NTRU 严格 rustdoc。

## 6. B7.3：Fourier NGSW ternary 融合单步

### 实现与数值契约

`FourierNgsw::cmux_ternary_monomial_to` 沿用 §5 的代数，一次组合、一次外积。
`FourierNtruTernaryCmuxContext::new(N, levels)` 保存组合 NGSW 和普通外积工作区，
单项式准备复用其系数及 Fourier digit 缓冲；随后分解覆盖这两个缓冲，无额外分配。
输出先保存 `(X^a-1)C`，外积在工作区内累加，逆变换后加回输入。零指数精确复制。

`FourierNgsw::sub_mul_monomial_to` 与现有 GGSW 方法使用
[同一实现](../crates/primus_lattice/src/macros/fourier_monomial.rs)：先在系数缓冲写
一个 `±1` 的 signed bit pattern，再以**整数尺度**变换并执行逐点减乘。
控制始终是 Native torus 尺度，必须由 engine 对应的同一个表实例产生；不能在
RustFFT/TfheFFT 的频率排列之间混用。原 binary 内核不变。

Fourier 误差在 §5 的分解/控制误差之外，还包含单项式变换、控制组合、digit FFT、
复数乘加和输出舍入。不能将融合输出与两次 CMUX 输出直接作相等断言。

### 聚焦验证

- 扩展既有 [Fourier 算术测试](../crates/primus_lattice/tests/fourier.rs)：GGSW/NGSW
  共用一个系数 oracle，覆盖两个 FFT 的全部小环指数、各层及脏 scratch；
  独立调用 helper 的零指数是 `self-rhs`，与 CMUX 的零指数复制不同。
- 在 [真实控制测试](../crates/primus_ntru/tests/ternary_cmux.rs)中增加一个表驱动测试：
  u32/u64 × 两种 FFT，`N=32, logB=8, L=3/7, sigma=0.7`，固定 seed `0xB703`。
  覆盖 `s=-1/0/1` 和全部 `0..2N` 指数；signed 秘密的精确 wrapping schoolbook
  卷积给出独立输入/输出相位。融合和两次 CMUX 分别对照理想旋转，从首次调用起检查
  融合零分配，工作区跨调用复用，最后检查零指数精确复制。
- 相位预算使用实际控制系数的误差与分解界，另计恢复每个控制行时的系数舍入；
  FFT 部分采用该小环的数值回归 allowance：每个输出系数 `max(1, 2^(BITS-40))`，
  再乘 `||f||₁`。两次 CMUX 计两次分解与浮点 allowance。这是明确的数值回归预算，
  **不是任意环长/密钥的解析 FFT 上界或失败率认证**。

### 单步成本、误差与保留决定

扩展既有 [ternary_cmux 基准](../crates/primus_ntru/benches/ternary_cmux.rs)，
不新增基准 target。两种 FFT 均测 `N=1024, t=16, logB=8, sigma=3.2`，
Native u32 用 `L=3`，u64 用 `L=6`；秘密为 SparseTernary，seed `0xB703`。
每次迭代完整执行一组真实 `(0,1)` 控制、`a=N/3` 的旋转，包含单项式变换和输出恢复；
对照使用同一输入、同一控制做两次 binary CMUX。密钥、表和缓冲区在计时外构造。

测量机器、CPU 绑定、nightly 和 Criterion 设置同 §5。以下为时间点估计：

| FFT / 类型 / feature | 两次 binary（µs） | 融合（µs） | 时间减少 |
| --- | ---: | ---: | ---: |
| RustFFT / u32 / default | 6.5913 | 4.2110 | 36.1% |
| RustFFT / u32 / SIMD | 6.6069 | 4.1876 | 36.6% |
| RustFFT / u64 / default | 15.242 | 9.0551 | 40.6% |
| RustFFT / u64 / SIMD | 16.017 | 8.8725 | 44.6% |
| TfheFFT / u32 / default | 5.2179 | 3.4800 | 33.3% |
| TfheFFT / u32 / SIMD | 5.3883 | 3.4723 | 35.6% |
| TfheFFT / u64 / default | 12.810 | 7.6567 | 40.2% |
| TfheFFT / u64 / SIMD | 13.770 | 7.4518 | 45.9% |

基准在计时外用独立系数卷积求相位，相对于理想 `X^-a` 旋转输入相位的最大误差如下。
这是一次固定输入/控制的观测；默认/SIMD 在表中精度内相同，不能当作统计尾界。

| FFT / 类型 | 融合 `max |error|/q` | 两次 CMUX `max |error|/q` |
| --- | ---: | ---: |
| RustFFT / u32 | 1.217e-5 | 1.124e-5 |
| TfheFFT / u32 | 1.217e-5 | 1.124e-5 |
| RustFFT / u64 | 8.816e-14 | 9.533e-14 |
| TfheFFT / u64 | 7.607e-14 | 6.760e-14 |

本组误差小于 `t=16` 的半编码间距 `1/32`；该比较仅说明单步增量的量级，
未计入输入加密误差，也不保证多步累积后的解码正确率。

按实际构造分配的字节计，排除共同 input/output、表和 FFT engine scratch：

| 类型 | 正负控制合计 | 两次 CMUX scratch（含中间密文） | 融合 scratch | 增量 |
| --- | ---: | ---: | ---: | ---: |
| u32，L=3 | 48 KiB | 25 KiB | 45 KiB | 20 KiB |
| u64，L=6 | 96 KiB | 33 KiB | 73 KiB | 40 KiB |

原外积工作区含 `N` 个系数、`N` 个 bool、共 `N` 个 Complex64；融合增加 `LN/2`
个 Complex64，双 CMUX 则增加 `N` 个系数。空间差为 `8LN-N*sizeof(T)` 字节。
本组默认/SIMD 均减少约 33%–46% 的完整单步时间，保留实现。
SIMD 本身并非对所有路径提速；此处不改动底层 SIMD 内核。

基准重复读取同一对控制，不能外推整把 BSK 的缓存/带宽成本。完整 BR、已有上层组合、
客户端分布和误差累积留给 B7.4；本步不放宽 TFHE 的 binary 限制。
复现使用基准文件顶部命令，附 `taskset -c 2`，默认/SIMD 都用上述 nightly，过滤 `fourier`，
Criterion 参数为 `--save-baseline b73-default --noplot` / `--save-baseline b73-simd --noplot`。


B7.3 已通过 lattice/NTRU/GLWE 默认与 SIMD 的 all-targets check、Clippy 和测试，
以及 `just tfhe`、`just tfhe-simd`、相关底层及 TFHE 包的严格 rustdoc。
Cargo 仍报告两个后端同名 `circuit_bootstrap` 示例的既有输出文件名冲突警告，检查成功。
