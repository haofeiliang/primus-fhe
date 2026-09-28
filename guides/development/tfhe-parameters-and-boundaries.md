# TFHE 参数职责与模块边界

本文说明参数来源、数据域和构造检查的归属。已有接口的基础用法见[库使用导航](README.zh_CN.md)，具体数值前提以对应 rustdoc 为准。这里没有提供生产参数、失败概率或性能结论。

## 参数与密钥域

以 q 表示外部 LWE 模数、Q 表示累加环模数，n 表示盲旋转控制秘密的 LWE 维数，N 表示环长度，k 表示 GLWE 秘密多项式数。

| 对象 | 独立选择 | 派生或绑定内容 |
| --- | --- | --- |
| `LweParameters` | n、t、q、秘密分布、系数噪声标准差 | n+1 密文长度可表示；Rounded codec、秘密/噪声 sampler；t 从 codec 读取 |
| `GlweParameters` | k、N、t、Q、环秘密分布、系数噪声 | `GlweSize`、Scaled codec、`GlweParametersInner`；固定重量作用于整个 kN 秘密 |
| `NtruParameters` | N、t、Q、环秘密分布、系数噪声 | Scaled codec、sampler；固定重量作用于整个 N 系数秘密；不预先证明秘密可逆 |
| `DecompositionConfig` | `log_basis`、`level_count` | 绑定 q 或 Q 后生成 `ApproxSignedBasis`；`None` 表示保留全部可用层，不等于零分解残差 |
| `GlevParameters` / `GgswParameters`、`NlevParameters` | 环参数和该运算的 basis | 对应密文形状、层序及预计算；GGSW/GLev 共用参数不等于密文语义相同 |
| `TfheConfig` → `TfheParameters` | 家族特定的 LWE/环配置、BR/KS 分解、PBS order（GLWE） | 同域检查、派生返回布局和编码；NTT/Fourier 表由后端 context 绑定 |
| `CircuitBootstrapConfig` → `CircuitBootstrapParameters` | output、trace、scheme-switch 三个 basis；后两者各自的噪声 | 环大小/模数继承累加环，输出布局由 output basis 派生；检查 interleaved 容量 |
| `LookupTableConfig` | 输入 chunk 数 c、输出 chunk 数 o、低位系数 chunk 数 d | `M=t/2`、每个多项式的有效系数数 `M^d`、每输出多项式数 `M^(c-d)`，以及完整存储长度 |

入口：[LWE](../../crates/primus_lwe/src/parameter.rs)、[GLWE](../../crates/primus_glwe/src/parameter/glwe/single.rs)、[NTRU](../../crates/primus_ntru/src/parameter.rs)、[分解](../../crates/primus_decompose/src/config.rs)、[GLWE TFHE](../../crates/primus_tfhe_glwe/src/parameters.rs)、[NTRU TFHE](../../crates/primus_tfhe_ntru/src/parameters.rs)。

所有这些配置的噪声标准差均以对应模数下的**系数单位**表示；Fourier 内部将环系数转为归一化 torus，不改变配置输入的单位。BR、返回 KS、trace、scheme switch 的误差来源不同。GLWE 普通 BR/KS 当前继承 accumulator 噪声；NTRU 的返回 KS 单独选择 q 下的噪声。CBS 的 trace 和 scheme-switch 噪声独立于普通 PBS。

## Ordinary PBS 的三个返回链路

| 家族 / order | 外部域及完整路径 | 参数和检查入口 |
| --- | --- | --- |
| GLWE `BootstrapKeyswitch` | `LWE(s_small,n,q)` → BR 得到 `GLWE(s_ring,k,N,Q=q)` → GLWE KS 到 padded small secret → compact extraction 返回 n 维 LWE | `small_lwe` 确定输入；要求 n≤kN；返回 `k'=ceil(n/N)` 由参数构造器派生 |
| GLWE `KeyswitchBootstrap` | 外部 `LWE(flatten(s_ring),kN,q)` → inverse extraction → GLWE KS 和 compact extraction 得到 n 维 LWE → BR → extraction 返回 kN 维 LWE | `small_lwe` 仍是 BR 控制秘密；外部维数和新鲜加密噪声来自 accumulator |
| NTRU | 独立 `LWE(s,n,q)` → 首次融合提升和 BR 得到 `NTRU(f,N,Q)` → 系数模切 Q→q、phase extraction → LWE KS 回到独立 s | q/Q、n/N 独立，仅共享 t 和系数类型；返回 basis/noise 属于 q，BR basis 属于 Q |

数学域检查在家族参数中完成；表长度和 NTT 模数由 context 检查；server key 的布局/basis 由 evaluator 绑定时检查。相同长度、模数或分布标签不证明秘密身份相同。Fourier 还要求使用生成对应表示的同一表实例。

追踪入口：[GLWE NTT evaluator](../../crates/primus_tfhe_glwe_ntt/src/evaluator.rs)、[GLWE Fourier evaluator](../../crates/primus_tfhe_glwe_fourier/src/evaluator.rs)、[NTRU NTT evaluator](../../crates/primus_tfhe_ntru_ntt/src/evaluator.rs)、[NTRU Fourier evaluator](../../crates/primus_tfhe_ntru_fourier/src/evaluator.rs)、[NTRU→LWE 返回原语](../../crates/primus_ntru/src/key_switch/lwe.rs)。

客户端输入使用 Rounded 编码。Ordinary LUT 编译器按输入编码设置窗口，输出 codec 可独立指定；NTRU LUT 在 Q 编码，返回到 q 后须按对应 q 域输出 codec 解码并预算两次舍入误差。底层 GLWE/NTRU 参数保存的 Scaled codec 用于其普通加密，不决定 PBS 的 LUT 输出编码。

## CBS、CMux、MVB 与高精度查表

| 工作流 | 从输入到消费者 | 独立约束及检查归属 |
| --- | --- | --- |
| 普通 CBS → CMux | Rounded LWE → gadget-scaled identity ManyLUT 的 BR → reverse-trace 系数投影 → GLev/NLev → scheme switch → GGSW/NGSW → CMux | CBS 参数检查 output basis 模数、trace/SS 环布局及 ManyLUT 容量；CMux 控制必须表示 0/1，输出为 gadget 尺度 |
| Factorized MVB | 公共 common polynomial 和 factors → 一次 BR → 每输出乘 factor → 按所属 PBS 返回链路输出 LWE | 共享编译器约束固定 Scaled 输出；后端准备变换 factors 并绑定 context 身份；factor 会放大共用 BR 噪声，NTRU 返回还会缩放 Q→q |
| NTRU one-hot CBS | t=2M 的 chunk → packed LUT BR → 各 selector 的偏移/投影 → NLEV，可选 scheme switch 成 NGSW | 使用已有 CBS key/output basis；`W=next_power_of_two(L)`，要求 `2MW≤N`；guard 在 one-hot LUT 上，classic binary/ternary 由后端支持检查限定 |
| NTRU 高精度 LUT | 每个输入 chunk 一次 one-hot → 高 c-d 个 chunk 选择多项式 → 低 d 个 chunk 聚合 `NGSW[X^(-m_i*M^i)]` 并旋转 → 独立 LWE 返回 | 编译器检查 chunk、`M^d≤N`、枚举/存储溢出及输出 digit；evaluator 绑定 N/t/q/Q、CBS 能力及资源；在线入口在写入前检查全部 chunk 数和 LWE 维数 |

CBS 输出保留累加环秘密，不走 ordinary PBS 的返回链路；GLWE `KeyswitchBootstrap` 仍在 BR 前处理输入 KS。普通 CBS 投影的是可能有非零尾部的 ManyLUT 累加器，不能直接替换为只适用于特定稀疏消息的 prefix expansion。

NTT 与 native Fourier 的 reverse trace 归一化契约不同：前者使用模逆除二，后者包含系数减半的舍入误差。NTRU scheme-switch key 绑定完整 output basis，GLWE 的 key 绑定 output layout，可在相同输出层数等兼容条件下复用不同 output basis；这解释了两家族 CBS 绑定接口的差别。

追踪入口：两家族的 [GLWE CBS 参数](../../crates/primus_tfhe_glwe/src/circuit_bootstrap.rs) / [NTRU CBS 参数](../../crates/primus_tfhe_ntru/src/circuit_bootstrap.rs)，以及下列消费链。

- CBS：[GLWE NTT](../../crates/primus_tfhe_glwe_ntt/src/circuit_bootstrap/evaluator.rs) / [Fourier](../../crates/primus_tfhe_glwe_fourier/src/circuit_bootstrap/evaluator.rs)，[NTRU NTT](../../crates/primus_tfhe_ntru_ntt/src/circuit_bootstrap/evaluator.rs) / [Fourier](../../crates/primus_tfhe_ntru_fourier/src/circuit_bootstrap/evaluator.rs)。
- MVB：[共享编译](../../crates/primus_tfhe/src/lookup_table/factorized.rs)，[GLWE NTT](../../crates/primus_tfhe_glwe_ntt/src/factorized.rs) / [Fourier](../../crates/primus_tfhe_glwe_fourier/src/factorized.rs)，[NTRU NTT](../../crates/primus_tfhe_ntru_ntt/src/factorized.rs) / [Fourier](../../crates/primus_tfhe_ntru_fourier/src/factorized.rs)。
- One-hot：[公共几何](../../crates/primus_tfhe_ntru/src/one_hot.rs)，[NTT](../../crates/primus_tfhe_ntru_ntt/src/circuit_bootstrap/one_hot.rs) / [Fourier](../../crates/primus_tfhe_ntru_fourier/src/circuit_bootstrap/one_hot.rs)。
- 高精度 LUT：[编译和布局](../../crates/primus_tfhe_ntru_lut/src/lookup_table.rs)，[NTT evaluator](../../crates/primus_tfhe_ntru_lut/src/ntt.rs) / [Fourier evaluator](../../crates/primus_tfhe_ntru_lut/src/fourier.rs)。公共第一层使用完整 NLEV selectors，后续密文层及旋转控制只请求非零 NGSW selectors；d=c 时仍须提升公开多项式。

## 构造与错误归属

配置输入沿以下已有类型逐层构造；上层保留错误来源，不复制底层的数学检查。

| 边界 | 负责检查 | 返回类型 |
| --- | --- | --- |
| `RoundedCodec::try_new` / `ScaledCodec::try_new` | t≥2、q>t；Scaled 额外检查固定尺度恢复界 | `CodecError` |
| `SecretKeySampler::try_new` | 概率和对应 signed 字宽下的 Gaussian 预计算 | `SecretKeySamplerError`，嵌套 `GaussianError` |
| `SecretKeySampler::validate_length` | 固定重量及加和溢出，按完整逻辑密钥长度 | `SecretKeySamplerError::InvalidWeight` |
| `SecretKeySampler::validate_modulus` | 秘密支持范围是否适配输出模数；`T::MAX` 作为 modulus-minus-one 表示 native | `SecretKeySamplerError::ModulusTooSmall`，携带支持上界和 modulus-minus-one |
| `LweParameters::try_new` / `GlweParameters::try_new` / `NtruParameters::try_new` | 布局、codec、秘密支持集/重量、噪声 sampler；复用上述检查 | 家族各自的 `*ParameterError`；`SecretKey` 保留 `SecretKeySamplerError`，`Noise` 保留 `GaussianError` |
| `TfheParameters::try_from_config` / `try_new` | BR/KS 域及分解、控制秘密类别、维数容量、2N 可表示性 | `TfheParameterError`；累加环错误为 `AccumulatorParameters`，NTRU 返回加密错误为 `KeySwitchingEncryption` |
| `CircuitBootstrapParameters::try_from_config` / `try_new` | output/trace/SS basis、环布局、投影容量；trace/SS 噪声 | `CircuitBootstrapParameterError`，`EncryptionParameters` 标明 key role 和原错误 |
| Context / key generation / evaluator | 表、秘密实际可用性、选定能力及密钥布局绑定 | 各层已有的 context/key/evaluation errors |

底层 `new` 是在相同校验错误下主动 panic 的便捷形式，适合已知有效的常量配置；其实现复用 `try_new`，没有第二套校验。`GlweParametersInner` 不持有布局，固定重量检查由外层 `GlweParameters` 或实际采样入口完成。公开 sampler 接受不同输出长度时仍需检查实际长度。

RNS GLWE 参数仍使用原有的 panicking 构造器；秘密模数适配复用 `validate_modulus`，逐个检查有序 RNS 基的各 limb，并在失败时报告索引。噪声的 signed Gaussian 支持界由 RNS 参数另行逐 limb 检查。单模数的 `maximum_magnitude <= modulus_minus_one` 与显式 RNS 的 `maximum_magnitude < q_i` 等价；校验发生在构造阶段，在线采样不重复执行。

参数角色与底层失败原因分开表达。例如 CBS 的 trace 噪声错误沿 `CircuitBootstrapParameterError::EncryptionParameters { role, source }` → `NtruParameterError::Noise` → `GaussianError` 传播；`KeyGenerationError` 透明转发 CBS 错误。带上下文的 `Display` 只描述当前层，通过标准 `Error::source()` 逐层取得原因；透明包装同时委托显示及 source，不增加重复的报告层。只打印最外层 `Display` 会省略底层细节，报告器应遍历原因链；LWE/GLWE/NTRU 加密参数的 panicking 构造器通过 `expect` 保留嵌套采样错误的 Debug 信息。

返回包含浮点输入的 sampler 错误后，两家族的 `TfheParameterError`、`CircuitBootstrapParameterError` 和 `KeyGenerationError` 保留 `PartialEq`，不实现 `Eq`。配置/形状检查成功不意味着支持的参数具有足够噪声余量；table 构造也不替代模数素性和秘密身份等调用方前提。

## 保留的分层与接口

依赖方向为算术/编码/采样 → 格式与加密原语 → TFHE 共享客户端/LUT → 家族参数与秘密域 → NTT/Fourier 后端 → NTRU 高精度 LUT。共享代码集中真实相同的编码和公共 LUT 几何，后端保留变换顺序、尺度、密钥表示和工作区的差异。

- `try_from_config` 接受独立配置；`try_new` 接受已有 LWE/环/gadget 参数及 basis，支持已有预计算的组合。两条路径均有实际调用方，并承担不同的构造职责。
- Backend 的参数别名固定其模数类型；GGSW/GLev 参数别名表达同一份加密/basis 配置的不同用途。它们不构成旧 API 兼容层。
- GLWE 的 accumulator 保留普通加密 codec，gadget 参数保留专属 basis/layout；派生值只在参数构造处建立。LWE 的明文模数直接读取 codec，避免另存一份需要同步的字段。
- 高精度 LUT 单独拥有表分区、编译及候选树资源，one-hot 仍为 NTRU CBS 扩展。当前职责足以支持独立 crate；无需引入覆盖所有家族的统一 backend trait。
- 工作区改名、容器选择及 scratch 复用是独立改动，遵循[工作区和存储原则](README.zh_CN.md#区分运行环境与工作区)，不改变这里的数学域和错误归属。

## 验证入口

参数拒绝由 [codec](../../crates/primus_encoding/tests/plaintext_codec.rs)、[sampler](../../crates/primus_distr/tests/secret_key_sampler.rs)、[LWE](../../crates/primus_lwe/tests/parameters.rs)、[GLWE](../../crates/primus_glwe/tests/boundaries.rs)、[NTRU](../../crates/primus_ntru/tests/secret_key.rs) 和两家族 [GLWE 参数](../../crates/primus_tfhe_glwe/tests/parameters.rs) / [NTRU 参数](../../crates/primus_tfhe_ntru/tests/parameters.rs) 在拥有契约的层保护。配置回归使用小参数，不生成大密钥。

后端 PBS、CBS/CMux、MVB、one-hot 和高精度 LUT 的现有独立数值/资源回归继续验证合法输入链路；默认和 nightly 全 features 分开运行，命令及覆盖归属见[测试指南](testing.md)。参数构造整理不提供 kernel 提速结论，也不扩大数值支持范围。
