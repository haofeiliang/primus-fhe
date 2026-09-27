# primus_tfhe_ntru

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

与后端无关的 NTRU-TFHE 参数和 LWE 客户端层。变换域 server key 与 evaluator 由 [NTT](../primus_tfhe_ntru_ntt/README.zh_CN.md) 或 [Fourier](../primus_tfhe_ntru_fourier/README.zh_CN.md) 后端提供。 完整能力与编码约定见[公共指南](../primus_tfhe/README.zh_CN.md)。

## 参数与密钥域

`TfheParameters<T, M, LM = M>` 分离 accumulator 环模数 `Q` 和外部 LWE 模数 `q`，二者共用整数类型 `T`。`TfheConfig` 的 `accumulator_modulus` 指定 `Q`；`external_lwe` 指定 `q`、维数、binary/ternary 分布、明文模数与加密噪声。`blind_rotation` 分解在 `Q` 下，`key_switching` 分解和独立的 key-switch 噪声在 `q` 下。`level_count: None` 保留完整分解。

直接构造入口是 `TfheParameters::try_new(external_lwe, blind_rotation, key_switching, key_switching_noise_standard_deviation)`。两个域须共用明文模数 `t`，`2N` 必须能由 `T` 表示；外部维数不再受 `n <= N` 限制。

`ClientKey` 保存独立 `LweSecretKey<T>` 秘密 `s` 和 `NtruSecretKey<T>` 秘密 `f`。外部秘密不再补零或执行 NTRU 可逆性筛选；只有 `f` 检查可逆性，Fourier 另检查逆的稳定性。`ClientKey::new(s, f)` 导入二者，`external_lwe_secret_key()` 返回在 `q` 下编码的 LWE 秘密；原来的 client NTRU/prefix API 已删除。配套生成使用 `context.try_generate_keys(circuit_bootstrap, rng)`。

普通 PBS 固定顺序：`f,Q` 下盲旋转 → 逐系数 `Q→q` 最近舍入 → 提取相位系数 → 在 `q` 下 LWE key switch 到 `s`。返回路径复用 `primus_ntru::NtruLweKeySwitchingKey`，在线无额外分配。ManyLUT 共享一次盲旋转，每个输出分别执行 LWE key switch；`context.allocate_lwe_ciphertext()` 按外部维数分配。

Classic PBS/ManyLUT、Boolean、CBS、MVB 支持 binary/ternary 外部秘密。首次融合使用 NLEV，后续坐标使用 NGSW；ternary 保存正负控制对。`SparseTernary` 仅描述分布，不自动选择桶聚合。外部秘密不受环秘密的条件采样限制。

[NTT](../primus_tfhe_ntru_ntt/README.zh_CN.md#实验性稀疏-pbs) 和 [Fourier](../primus_tfhe_ntru_fourier/README.zh_CN.md#实验性稀疏-pbs) 的桶聚合须显式选择固定重量 binary 外部秘密，支持奇数和偶数重量。它支持普通/ManyLUT PBS，拒绝 sparse CBS/MVB。公开映射在固定外部秘密后采样，匹配失败不会重采样该秘密。

## 客户端与 LUT

`Encryptor`、`Decryptor`、`BooleanEncryptor` 和 `BooleanDecryptor` 从 [`primus_tfhe`](../primus_tfhe/README.zh_CN.md#客户端与服务端边界) 重导出。家族构造入口验证客户端密钥，选择外部 LWE 秘密和噪声；公共客户端负责编码、范围检查及输出复用，借用 LWE 密钥视图，不再持有家族参数或客户端密钥类型。

Client 加密接受 `T`，解密返回 `Result<T, ClientError>`，消息是 `[0,t)` 内的 规范剩余类，消息类型转换由应用按需处理。

参数和 context 都提供 `encryptor(&client)`、`public_encryptor(&public)`、`decryptor(&client)`。家族私钥客户端构造返回 `TfheClientError`，公钥构造和普通操作返回公共 `ClientError`。通过 `client_key.try_generate_public_key(parameters, rng)` 生成 `LwePublicKey`。 这是独立外部秘密下的外部 LWE 公钥，不是 NTRU 环公钥。解密需要 client key。 公钥生成和新鲜加密误差均使用 `external_lwe` 噪声采样器，但总误差为 `e^T r + e2 - e1^T s`。公钥存储 外部维数对应的 `n * (n + 1)` 个系数。 维数/模数检查不能证明密钥身份；使用配套密钥，并为 PBS/ManyLUT 预算组合噪声。 噪声和秘密来源要求见 [LWE 公钥契约](../primus_lwe/README.zh_CN.md#公钥加密)。

`encrypt`、`encrypt_padded` 和 `encrypt_centered` 均提供 `*_to(message, output, rng)`。两类密钥都可复用输出存储，消息或维数错误先于采样和写入。 参数编译的前半区 LUT 使用 padded unsigned 输入；centered 模消息有独立的编码契约。

ManyLUT 编译同一个输入的多个函数。后端 sparse 示例计算 `x % 4`、`x / 4` 和 `x % 2`， 不代表已经实现完整的加密整数类型或算术系统。

通过 `context.parameters().compile_*` 编译普通/交错 LUT。默认输出在 `Q` 下按参数的明文模数编码，返回 `q` 后用普通 `decrypt` 解码。`*_with_codec_fn` / `_slice` 接受 `Q` 下的输出 `RoundedCodec`；若输出明文模数不同，返回后用相同明文模数、外部密文模数 `q` 的 codec 解码 `decrypt_phase`。原始 LUT 值按 `q/Q` 缩放，不会重新编码；舍入和返回 key switch 的误差须纳入预算。

奇数全域使用 `compile_odd_full_domain_lookup_table_fn` / `_slice`，输入改用普通 `encrypt`；输出 codec 与既有 PBS 求值入口相同。容量、折叠中心和噪声条件见 [奇数全域 PBS](../primus_tfhe/README.zh_CN.md#奇数全域-pbs)。

有界双输入函数使用共享 `BivariateLookupTable` 打包 `x+B*y`，再把其中的普通 LUT 交给现有 evaluator。范围、共同编码与误差放大条件见[有界双输入 PBS](../primus_tfhe/README.zh_CN.md#有界双输入-pbs)。

分解式 MVB 通过 `context.compile_factorized_lookup_table_fn` 与 unsigned `ScaledCodec` 编译，再绑定 `context.factorized_evaluator(&server_key)`。后端契约见 [奇数 q NTT](../primus_tfhe_ntru_ntt/README.zh_CN.md#固定尺度分解式-mvb) 和 [Native 偶尺度 Fourier](../primus_tfhe_ntru_fourier/README.zh_CN.md#固定尺度分解式-mvb)。

## Boolean 客户端与门

明文模数采用 4 时，context 提供 `boolean_encryptor(&client)`、`boolean_public_encryptor(&public)`、`boolean_decryptor(&client)` 和 `boolean_evaluator(&server)`。直接构造使用已有普通客户端：`BooleanEncryptor::try_new(encryptor)` 和 `BooleanDecryptor::try_new(decryptor)`。加密接受 `bool`，解密拒绝 `0/1` 以外的值。操作返回公共 `BooleanError`，其 `Client` 分支包装 `ClientError`；家族私钥工厂用 `TfheClientError` 报告构造失败。求值器构造返回 `TfheEvaluationError`。门预处理、正负 LUT 和输出修正在 `primus_tfhe::BooleanEvaluator` 中共享。用法和编码约定见[公共 Boolean 契约](../primus_tfhe/README.zh_CN.md#boolean-门)。

## CBS 与示例

两后端均提供可选的 CBS 参数、密钥和 evaluator。CBS 从 BR 后分支，在 `f_acc` 下执行 系数投影、trace/scheme switching，跳过普通 PBS 的返回密钥切换与提取。 包括 bit 在内，输入使用 unsigned rounded LWE 编码。输出 NGSW 使用 gadget 尺度；输入为 `0/1` 时可控制 CMUX，其候选密文也必须使用 `f_acc`。 本 TFHE 层不提供 LWE 到环密文的 packing。

`CircuitBootstrapParameters<T, M>` 统一维护 CBS 布局与容量校验，NTT/Fourier 后端提供对应模数域的类型别名。显式模数保留模 trace 检查，Fourier 输出长度方法仅用于 native 域。CBS 参数独立选择 output、trace 和 scheme-switch basis。内部 ManyLUT 仅在输出组中 补零，投影 NLev 和输出 NGSW 保留请求的层数；scheme-switch key 绑定完整 output basis。

普通与 CBS 密钥必须共享 accumulator secret 和变换 table。Scheme switching 将输入 误差乘 f、分解误差乘 f²；`NGSW_f[f]` 材料需要独立论证 key-dependent-message/ circular-security 假设，见 [NTRU 契约](../primus_ntru/README.zh_CN.md)。 NTT 使用模逆元归一化；Fourier 还引入原生整数除二和 FFT 误差。

后端 README 链接到可运行的 PBS 和 CBS → CMUX 示例。Fixture 不构成生产噪声余量或 安全性论证。

## One-hot CBS

`OneHotLookupTable::try_new(tfhe, cbs)` 编译两后端共用的 packed one-hot 多项式；`OneHotBootstrapError` 区分编码、容量、存储溢出和求值资源错误。首版要求 plaintext modulus `t=2*M`、`M=2^tau`、`tau>=1`。输入 chunk 使用 `encrypt_padded` 的无符号 Rounded 编码 `round(q*m/(2*M))`，`0<=m<M`；q 与环 Q 可以不同。

令 gadget 层数为 L，`W=next_power_of_two(L)`、`S=N/M`、`A=N/(2*M*W)`。要求 `2*M*W<=N`，padding 层为零，BR 的量化步长仅为 W，不是 M*W。测试多项式是 `sum_{j=1-A}^{A} sum_l g_l X^(l-j*W)`。若实际逐坐标量化后的相位满足 `u_bar=S*m+W*e mod 2N`、`-A<=e<A`，负向 BR 后用 `X^(r*S-l)` 移位再做完整 reverse trace，即得到第 r 个 selector、第 l 层的 `g_l*delta_r(m)`。窗口左闭右开，相邻消息的中点归较大的消息。e 包含输入噪声、编码舍入和量化误差；参数形状检查不证明这个保护区成立。

两后端的 `OneHotCircuitBootstrapEvaluator` 完整输出接口生成全部 M 个 selectors，包括实体化的 r=0；NLEV 为系数表示，NGSW 为各后端变换表示。支持分别生成或共享一次 BR 同时生成两者。`one_hot_nonzero_ngsw_to` 则仅输出 r=1..M-1，按 `[r-1][level][行元素]` 紧凑排列，跳过 r=0 的投影和 scheme switch；m=0 时所有目标 bit 为零。完整投影不要求 BR 消息零尾，不依赖额外的部分 trace 工作区接口。后续 scheme switch 保留普通 CBS 的 f/f² 误差预算，Fourier 还须计入 native 减半及 FFT 误差。本功能不改变普通 CBS，也不包含多多项式高精度查表。

多 chunk 求值由独立的 [primus_tfhe_ntru_lut](../primus_tfhe_ntru_lut/README.zh_CN.md) crate 提供，消费这些 selectors 和共用返回密钥。

## 进一步阅读

[实现说明](../primus_tfhe/IMPLEMENTATION.md) · [基准入口与性能取舍](../primus_tfhe/IMPLEMENTATION.md#performance-decisions-and-reproducibility)
