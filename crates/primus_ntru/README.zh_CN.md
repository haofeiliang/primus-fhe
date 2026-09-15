# primus_ntru

[English](README.md) | 简体中文

在 `Z_q[X]/(X^N + 1)` 上提供单多项式私钥 NTRU 加密与求值。NTT 使用显式域模数，
Fourier 使用原生 wrapping 模数 `2^T::BITS`，两种表示保留独立数值契约。
本 crate 属于实验性 workspace，尚不提供稳定 API 或推荐安全参数。

## 密文语义

设 `f` 是可逆私钥，`mu` 是编码消息，`g_l` 是 gadget scalar。下表省略应用层的明文 codec：

| 类型 | 系数行 `c_l` 的相位 |
| --- | --- |
| NTRU | `f*c = mu + e` |
| 消息 `m` 的 NLev | `f*c_l = g_l*m + e_l` |
| 消息 `m` 的 NGSW | `f*c_l = g_l*f*m + e_l` |

NLev 与 NGSW 存储的行数相同，但数学角色不同。`NLev[1]` 可通过外积把系数多项式
变成加密的 NTRU；`NGSW[1]` 保留已经加密的 NTRU 消息。直接把消息复制到 `c`
一般不能构成 NTRU 的平凡加密。

## 私钥与推荐流程

使用 `NttNtruSecretKey::generate_pair` 或 `FourierNtruSecretKey::generate_pair`
同时保留有符号系数私钥和变换表示。系数私钥用于生成求值密钥；变换私钥及其缓存
逆元用于加密和相位提取。

NTT 生成拒绝含零点值的私钥。Fourier 生成检查原生环可逆性（系数和为奇数）和
复数逆元的稳定性。这两组条件不同。有界拒绝采样可能失败，重试次数及逆元例程
不承诺常数时间。一般 NTRU 支持非二元私钥；NTRU TFHE 层另行验证盲旋转所需的
二元、零填充控制私钥前提。

私钥和私有加密、生成、解密工作区会在析构时擦除自身缓冲区。显式工作区清零保留
可复用存储；显式私钥清零会销毁私钥。内置 FFT 后端也在析构时擦除 scratch；长寿命
engine 可在处理阶段结束后调用 `FftEngine::zeroize_scratch()`。调用方持有的明文及
相位输出有各自的生命周期。

[automorphism 示例](examples/automorphism.rs) 展示配对私钥生成、求值密钥构造，
以及复用工作区、在原私钥下完成 NTT 自同构：

```sh
cargo run -p primus_ntru --example automorphism
```

## 操作与表示

| 操作 | 输入与输出 |
| --- | --- |
| `encrypt_to`、`encrypt_centered_to` | 明文系数经 codec 缩放后写出变换域 NTRU |
| `encrypt_encoded_to`、`encrypt_zeros_to` | 编码环系数或零写出变换域 NTRU |
| `phase_to`、`decrypt_to` | 变换域 NTRU 写出系数相位或解码明文 |
| `encrypt_nlev_to`、`encrypt_ngsw_to` | 编码多项式写出变换域 gadget 行，不进行明文 codec 缩放 |
| `encrypt_nlev_constant_to` | 常数环元素写出变换域 NLev |
| `encrypt_ngsw_signed_constant_batch_to` | 有符号常数写出连续的变换域 NGSW |
| `NttNtruKeySwitchingKey`、`FourierNtruKeySwitchingKey` | 输入私钥下的系数 NTRU 切换到输出私钥下的系数 NTRU |
| `NttNtruAutomorphismKey::apply_to`、`FourierNtruAutomorphismKey::apply_to` | 系数 NTRU 自同构后写出同一私钥下的系数 NTRU |
| `apply_ntt_to`、`apply_fourier_to` | 变换域 NTRU 自同构后保留对应变换表示和原私钥 |

解密返回系数域多项式，使用密文系数类型 `T`；输出类型转换由应用按需处理。

求值密钥持有自己的分解基；可复用求值 context 只保存工作缓冲区。拥有契约的公开
操作在输出写入前检查传入尺寸、模数及变换和工作区长度；对应的低层 lattice 内核
依赖这些契约。实际私钥一致性、输入 residue 的规范性及足够的噪声预算仍由调用方保证。

自同构指数 `d` 是 `[1, 2N)` 内的奇数。求值密钥保存 `NLev_f[f(X^d)]`，把代换后
的秘密切换回 `f`，不生成 `f(X^d)` 的逆元。有符号秘密先编码，再在模数域置换。
变换输入仍需恢复系数以进行分解；变换输出省去最后的逆变换。NLev 可逐行使用
这一单多项式操作，但逐行作用于 NGSW **不能**保留 NGSW 的消息与私钥关系。

Fourier 值、求值密钥及置换映射绑定到生成时的确切 FFT table 实例，包括其后端
存储顺序；后续操作必须复用该 table。Fourier 输出路径省去一次输出 torus 舍入，
因此不必与系数往返路径逐位相同。调用方需核算浮点、分解及加密误差。
示例与基准参数用于功能工作负载，不是安全估计。

Sample extraction、NLev/NGSW 外积与 CMUX 位于
[`primus_lattice`](../primus_lattice/README.zh_CN.md)。PBS、ManyLUT 和可选 CBS 位于
[`primus_tfhe_ntru_ntt`](../primus_tfhe_ntru_ntt) 和
[`primus_tfhe_ntru_fourier`](../primus_tfhe_ntru_fourier)，其 message/carry
示例展示多个输出共用一次盲旋转。

## Trace、投影与展开

`NttNtruTraceKey` 和 `FourierNtruTraceKey` 绑定 `log2(N)` 个 automorphism key。
所有入口的输入、输出均为原秘密下的系数密文，环长度保持 N。普通 partial trace
保留 r 个系数，目标为 `(N/r) * sum_j M[j*N/r] X^(j*N/r)`；reverse trace
保留原消息尺度。NTT 使用模 q 下的 2 的幂逆元归一化；Fourier 在每个逆序步骤前
对无符号系数代表元做向下取整的整数除法，其 phase 舍入误差再乘 f。
两条数值路径的误差分布不同，不能相互替换。

`project_coefficient(s)_to` 将指定系数移到常数位后做 reverse trace，支持重复及
乱序索引。`expand_coefficients_to` 使用展开树，按自然顺序展开整个消息。
`expand_partial_coefficients_to(input, count, ...)` 要求 count 为不大于 N 的
2 的幂，且目标消息仅在前 count 个位置非零；使用 count-1 次 automorphism，
直接复用输出存储展开树。一般输入会得到残余类多项式，不能承诺常数消息。
密文或噪声不要求零尾，输出非目标位置仍可能含噪声。

## 同一秘密下的 scheme switching

`NttNtruSchemeSwitchKey` / `FourierNtruSchemeSwitchKey` 将系数形式的
`NLev_f[m]` 转换为变换形式的 `NGSW_f[m]`。`key_basis` 用于分解每个输入
密文多项式；独立的 `output_basis` 决定输入和输出的 gadget scalar 与层数。
工作区直接复用现有 external-product context。输入必须已使用该 output basis，
仅靠长度相同无法验证这一点。

求值密钥保存 `NGSW_f[f]`，通过加密 f 生成，无需显式计算有符号多项式平方。
输入误差乘 f，分解误差乘 f²，还须计入求值密钥与 FFT 误差。公开这种秘密相关
消息的密钥需要独立论证 key-dependent-message/circular-security 假设及参数；
代数推导和功能测试不构成安全性证明或 CBS 参数建议。消息 m 为 bit 时，输出可供 CMUX 使用。

## 测试与基准

```sh
cargo test -p primus_ntru
cargo clippy -p primus_ntru --all-targets -- -D warnings
cargo +nightly test -p primus_ntru --features simd
cargo bench -p primus_ntru --bench encryption
cargo bench -p primus_ntru --bench primitives -- 'ntt/n4096/logb3'
cargo bench -p primus_ntru --bench constant_gadget
```

`encryption` 测量普通加密和未解码相位提取。`primitives` 测量 key switching、
自同构、trace/reverse trace、三个系数投影、八系数前缀展开及 scheme switching
（输出 B=2^8、L=3），覆盖 `N = 1024/4096/8192`、`B = 2^3/2^10` 和分解基支持的最大层数。两者使用
`u64`、稀疏三元私钥及 sigma 3.2；NTT 使用 `q = 1_125_899_906_826_241`，Fourier
覆盖两个 FFT 后端。`constant_gadget` 保留常数 NLev 和八控制位 NGSW 生成基准。
设置、table、密钥生成及分配位于计时 closure 外。附加 `-- --test` 可执行 fixture
冒烟检查；该检查不测量性能，也不能证明可解密性。

NTT 标量产品复用已有 CPU dispatch 与依赖的可选 SIMD 支持，NTRU 公开 API 不新增
ISA 选择参数。仅比较匹配工作负载的耗时；这些后端参数并不具有相同的安全强度。

## 许可证

可选择使用 [Apache-2.0](../../LICENSE-APACHE-2.0) 或 [MIT](../../LICENSE-MIT)。
