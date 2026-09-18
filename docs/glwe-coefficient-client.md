# GLWE 系数域客户端：减少变换的验证

## 结论与范围

**NTT 已接入，Fourier 按用户决定暂不接入。** 在 `primus_glwe` 的已准备 NTT/Fourier 私钥上直接处理系数密文，
可以减少变换、缩小 `AccumulatorClient` 工作区，并保持在线零分配。
NTT 与原路径精确等价；Fourier 原型的性能收益更大，但 u64 的真实环相位噪声发生变化，
不能作为位级等价替换，也不能仅凭 roundtrip 关闭噪声问题。

前期验证使用独立临时原型，源码对照为 `e025ba6` 加 B1.7 收尾；B1.7 未改变这里的数值内核。
随后仅将 NTT 路径接入库和客户端，接口及验证见文末。
只追踪 GLWE 私钥加解密、表示转换及两个 TFHE `AccumulatorClient`，不扩展到公钥、GLev/GGSW 生成或 NTRU。

## 算法与变换次数

令环为 `Z_q[X]/(X^N+1)`，GLWE dimension 为 `k`，密文满足 `b=Σaᵢsᵢ+E(m)+e`。
`F` / `I` 分别表示一个长度 N 多项式的正/逆变换，不计私钥预处理。

| 系数域操作 | 原完整路径 | 减少变换后 |
| --- | --- | --- |
| NTT 加密 | `F + (k+1)I` | `(k+1)I` |
| NTT 解密 | `(k+1)F + I` | `kF + I` |
| Fourier 加密 | `(k+1)F + (k+1)I` | `kF + I` |
| Fourier 解密 | `(k+1)F + I` | `kF + I` |

变换域入口见 [NTT 加密](../crates/primus_glwe/src/secret_key/ntt/encrypt.rs)、
[Fourier 加密](../crates/primus_glwe/src/secret_key/fourier/encrypt.rs)。
[NTT client](../crates/primus_tfhe_glwe_ntt/src/accumulator.rs) 已使用直接系数域运算；
[Fourier client](../crates/primus_tfhe_glwe_fourier/src/accumulator.rs) 保留整密文转换。

### NTT

现有 mask **直接在 NTT 域均匀采样**，并没有逐个 forward；不能按系数采样误算收益。
原型保持“先噪声、再逐 mask”的随机数顺序：

1. 在系数输出 body 中采样 `e` 并加入 `E(m)`。
2. 每个输出 mask 先接收 NTT 域均匀样本，累加其与秘密的点乘，再原地 inverse 成为系数 mask。
3. 对乘积和 inverse，一次加入 body。

NTT 的可逆线性关系保证与原路径系数密文相同。解密逐 mask forward 并累加乘积，inverse 后在系数域作
`b−Σaᵢsᵢ`，再解码；无需 forward body。一个 N 系数 scratch 可在加解密间复用，解密结果缓冲暂存乘积。
已有 truncated 原语也使用系数 mask 的类似计算，但它分配内部缓冲，不能直接当作零分配入口。

### Fourier

原型把噪声及编码消息留在系数 scratch；采样的系数 mask 直接留在最终输出，逐个 forward 到一个复用缓冲，
累加 `FFT(aᵢ)*FFT(sᵢ)`。乘积和 backward 到 body，再用模整数加法加入 `E(m)+e`。
解密同样只 forward masks、backward 乘积，最后在系数域计算 `b−Σaᵢsᵢ`。

这保留原始均匀 mask，改变了旧路径 mask 的 FFT roundtrip 和 body 舍入位置。
特别是新加密与新解密可能复算同一个浮点乘积，使误差在 roundtrip 中相消；
因此解密出精确采样噪声并不能证明真实环相位同样精确。

## 原型耗时与工作区

2026-09-18，AMD Ryzen 9 9955HX3D，逻辑 CPU 2；`rustc 1.100.0-nightly (bff8e12ff 2026-08-26)`，
Criterion 0.8.2，仓库 `target-cpu=native`。默认及 SIMD 各 30 samples、1 s 预热、2 s 测量、10,000 resamples。
前后在同一个可执行文件中测等价的完整系数加密/解密，每轮一次操作；复用密钥、table、输出与 scratch。
采样、编码/解码及全部必要变换均计时，构造与分配在计时之外。构建和其他验证不与计时并行。

沿用 [GLWE 加密基准](../crates/primus_glwe/benches/encryption.rs) 的两组规模：u64，
`(k,N)=(1,1024)/(2,4096)`，binary 私钥、t=16、sigma=3.2；NTT 使用 `U64NttTable`，q=`1_125_899_906_826_241`，
Fourier q=`2^64`，分别使用 RustFFT/TfheFFT。私钥 seed=42，加密 RNG seed=17。
这些是前后回归负载，不是后端间同安全参数比较。

均值单位 µs，每格为 **原路径 → 原型**；95% 置信区间见[计时 CSV](benchmarks/glwe-coefficient-client.csv)。

| 后端 | k / N | 默认加密 | 默认解密 | SIMD 加密 | SIMD 解密 |
| --- | --- | ---: | ---: | ---: | ---: |
| NTT | 1 / 1024 | 14.77 → 13.85 | 3.96 → 3.37 | 14.03 → 13.06 | 3.16 → 2.64 |
| NTT | 2 / 4096 | 84.28 → 81.07 | 27.88 → 24.38 | 78.00 → 73.69 | 21.58 → 18.20 |
| RustFFT | 1 / 1024 | 17.68 → 14.40 | 4.40 → 3.82 | 17.75 → 14.32 | 4.42 → 3.85 |
| RustFFT | 2 / 4096 | 103.09 → 74.50 | 24.00 → 20.97 | 102.97 → 74.44 | 23.92 → 20.85 |
| TfheFFT | 1 / 1024 | 17.51 → 14.47 | 4.04 → 3.61 | 17.44 → 14.25 | 3.99 → 3.62 |
| TfheFFT | 2 / 4096 | 100.42 → 74.03 | 19.38 → 17.46 | 100.12 → 72.02 | 19.24 → 17.39 |

本组 NTT 加密耗时降低 **3.8%–7.0%**、解密 **12.6%–16.4%**；
Fourier 加密降低 **17.3%–28.1%**、解密 **9.2%–13.1%**。不外推到其他规模/机器或宣称 PBS 本体提速。

下面是同时支持加解密的 scratch 载荷，排除私钥、FFT engine、最终密文/明文输出和 Vec 元数据：

| 表示 | 原路径 | 原型 | k=1,N=1024,u64 | k=2,N=4096,u64 |
| --- | --- | --- | ---: | ---: |
| NTT | `(k+1)N*sizeof(T)` | `N*sizeof(T)` | 16 → 8 KiB | 96 → 32 KiB |
| Fourier | `(k+2)*(N/2)*sizeof(Complex64)+N*sizeof(T)` | `2*(N/2)*sizeof(Complex64)+N*sizeof(T)` | 32 → 24 KiB | 160 → 96 KiB |

Fourier 的两个变换缓冲分别保存当前 mask 和乘积，另一个系数缓冲保存噪声/消息；都与 k 无关。
首调用及复用的原型加解密均测得零分配。

## 精确性与误差验证

- NTT：u32/u64、ternary、k=2/N=256、8 个固定 seed，每个先非零后零消息复用；
  新旧系数密文和未解码相位逐位相等。计时的两组 u64/binary fixture 也做同样差分预检。
- Fourier：u32/u64、两种 FFT、两组规模、每组 4 个 ternary 私钥，t=16、sigma=3.2；
  key seed=`0xE110+i`，encryption seed=`0xCAFE+i`。用 signed 系数私钥的朴素负循环卷积独立计算
  `b−Σaᵢsᵢ`，同时用该整数卷积构造第三组密文测试两种解密路径；独立检查新 masks 与原始均匀样本相等。
- 核对新旧/整数卷积三类密文的真实相位、旧/新解密的数值误差与正确解码；另检查 Fourier 原型在输出/RNG 变化前拒绝错误消息长度。
  结果见[误差 CSV](benchmarks/glwe-coefficient-client-noise.csv)。默认与 SIMD 的误差统计相同。
- 接上现有 CBS→CMUX，使用原型加密候选并用原型及现有 client 交叉解密：
  N256、k=1、small n=4、t=4、sigma=0.7、ternary accumulator、两种 order，以及两种 FFT，
  `1→0→1` 复用均通过且在线零分配；默认/SIMD 均验证。未将临时诊断加入 CI。

u32 的所测真实相位误差等于采样噪声，最大值 14；两种解密的数值误差为 0。
u64 的真实相位噪声包含浮点误差，观察到原型 RMS 增长约 **5.9%–13.1%**：

| FFT | k / N | 真实相位 RMS：原 → 新 | 最大模距离：原 → 新 |
| --- | --- | ---: | ---: |
| RustFFT | 1 / 1024 | 57,386.84 → 60,793.07 | 199,232 → 292,262 |
| RustFFT | 2 / 4096 | 188,687.91 → 209,104.47 | 728,240 → 897,555 |
| TfheFFT | 1 / 1024 | 50,797.94 → 57,441.14 | 225,376 → 242,040 |
| TfheFFT | 2 / 4096 | 159,150.44 → 175,447.35 | 670,064 → 739,159 |

距离均以 torus 原始整数单位计。固定样本全部正确解码，但不建立生产尾概率或其他参数的安全噪声预算。
不能以“FFT 次数更少”断言噪声一定更小；也不能只保留加解密自洽的测试。

## NTT 接入

[`NttGlweSecretKey`](../crates/primus_glwe/src/secret_key/ntt/coefficient.rs) 增加
`encrypt_coeff_to`、`phase_coeff_to`、`decrypt_coeff_to`，在原类型上直接提供系数域运算。
最后一个参数为长度恰好 N 的 scratch 切片，不要求初始清零；变换域方法继续供原有消费者使用。
没有新增公共 context、trait 或密文包装，也没有更改 FFT/NTT trait 和 PBS 内核。

NTT `AccumulatorClient` 保持原接口，将 `(k+1)N` 的转换缓冲替换为 N 系数 scratch，
使用 `Zeroizing<Vec<T>>` 在析构时擦除未加噪声的乘积。底层调用方自行管理 scratch 的擦除。
布局、模数和 table 长度由底层公开边界在采样/写入前检查；客户端不重复这些检查。

既有 u32/u64 私钥测试补充相同 RNG 下的密文、相位精确差分及非零→零消息复用；
边界测试补充错误长度/table 的写入前拒绝。现有 CBS→CMUX/外积测试验证客户端消费和首调用零分配，
不另建完整测试矩阵。常规 `encryption` 基准仅新增两种规模的系数域加密/解密。

Fourier 未接入上述接口，保留当前实现和本次误差记录。

### 接入验证与复测

`primus_glwe`、`primus_tfhe_glwe_ntt` 的默认/SIMD all-targets check、Clippy（`-D warnings`）、
测试和严格 rustdoc 均通过；已运行 `cargo fmt --all`。

正式实现沿用上述机器、工具链、参数和 Criterion 采样配置，复用 `encryption` 基准的 seed=42 RNG。
每次迭代包含完整系数域加密或解密；以变换域方法加整密文转换作同可执行文件中的临时对照。
分别使用通用 `UintNttTable<u64>` 和 TFHE 常用的 `U64NttTable`，默认与 SIMD 均测量。
后者与前期原型使用同一种 table；不把不同 table 或不同轮次的绝对耗时作直接比较。

下表为均值 µs，**原路径 → 接入后**；95% 置信区间见[接入计时 CSV](benchmarks/glwe-ntt-coefficient.csv)。

| Table | k / N | Feature | 加密 | 解密 |
| --- | --- | --- | ---: | ---: |
| UintNttTable | 1 / 1024 | default | 20.921 → 18.022 | 10.750 → 7.971 |
| UintNttTable | 1 / 1024 | simd | 20.874 → 17.735 | 10.615 → 7.719 |
| UintNttTable | 2 / 4096 | default | 118.012 → 104.689 | 66.417 → 53.892 |
| UintNttTable | 2 / 4096 | simd | 115.048 → 101.157 | 63.624 → 50.698 |
| U64NttTable | 1 / 1024 | default | 14.024 → 13.068 | 3.750 → 3.327 |
| U64NttTable | 1 / 1024 | simd | 13.464 → 12.532 | 3.143 → 2.651 |
| U64NttTable | 2 / 4096 | default | 78.738 → 73.269 | 27.010 → 24.473 |
| U64NttTable | 2 / 4096 | simd | 73.079 → 69.369 | 20.521 → 18.373 |

常规复测运行 `cargo bench -p primus_glwe --bench encryption -- coeff`。
临时对照和 U64 table 的测量变体已移除，保留每种规模的两个正式入口基准。
重建对照时在相同 fixture 中计时 `encrypt_to` + `write_coeff_form`，或 `write_ntt_form` + `decrypt_to`；
U64 变体将该 fixture 的 table 替换为 `U64NttTable`，密钥仍从配套 table 生成。
本轮原始样本为 `target/criterion/glwe_ntt*/.../coeff_integrated_{default,simd}/`。

原型代码已清理；持久保留算法步骤、参数、计时/误差摘要。Fourier 复现时按上述步骤构造等价 `_to` 原型，
以现有 secret-key `encrypt_to` 后整密文逆变换、整密文正变换后 `decrypt_to` 为基线。
原始 Criterion 样本保存在 `target/criterion/glwe_coeff*/.../coeff_probe_{default,simd}/`，清理 target 后需重新采样。
