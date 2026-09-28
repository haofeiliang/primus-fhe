# primus_tfhe_ntru

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

NTRU-TFHE 的参数与 LWE 客户端层；[NTT](../primus_tfhe_ntru_ntt/README.zh_CN.md) 和 [Fourier](../primus_tfhe_ntru_fourier/README.zh_CN.md) 后端提供 context、求值密钥和 evaluator。

## 参数与密钥域

`TfheParameters<T, M, LM=M>` 分离环模数 Q 与外部 LWE 模数 q，共用整数类型 T。通过 `TfheParameters::try_from_config(TfheConfig { .. })` 构造：`external_lwe` 指定外部维数、q、明文模数、binary/ternary 分布和加密噪声；`accumulator_modulus` 指定 Q；`blind_rotation` 分解在 Q 下，`key_switching` 分解和返回密钥噪声在 q 下。`level_count: None` 选择支持的最大层数，仍须检查[分解精度](../primus_decompose/README.zh_CN.md)。

直接组合入口为 `TfheParameters::try_new(external_lwe, blind_rotation, key_switching, key_switching_noise_standard_deviation)`。两个域共用明文模数 t，2N 必须能由 T 表示；外部维数 n 不要求小于等于 N。构造器返回带具体原因的参数错误，不验证安全性或完整噪声预算。

`ClientKey` 保存独立 LWE 秘密 s 与 NTRU 环秘密 f。使用 `context.try_generate_keys(cbs_config, rng)` 生成配套密钥，或用 `ClientKey::new(s, f)` 导入。只有 f 需要可逆性检查，Fourier 还检查逆稳定性；外部秘密不要求补零、可逆或奇数重量。`external_lwe_secret_key()` 返回 q 下的 LWE 秘密。

普通 PBS 的返回顺序为：f,Q 下盲旋转 → 逐系数 Q→q 最近舍入 → 提取相位系数 → q 下 LWE key switch 到 s。ManyLUT 共享盲旋转，每个输出分别返回；`context.allocate_lwe_ciphertext()` 使用外部维数。

Classic PBS、ManyLUT、CBS、Boolean 和 MVB 支持 binary/ternary 外部秘密。Sparse 须显式选择 fixed-weight binary 生成入口，允许偶数重量，只支持普通/ManyLUT PBS；`SparseTernary` 分布本身不会选择桶聚合。首次提升与稀疏桶的推导见[实现说明](../primus_tfhe/IMPLEMENTATION.md#ternary-and-sparse-rotation)。

## 客户端与 LUT

使用 context 的 `encryptor(&client)`、`public_encryptor(&public)` 和 `decryptor(&client)`；`client.try_generate_public_key(parameters, rng)` 生成独立外部 s 下的 LWE 公钥。它不是 NTRU 环公钥，总噪声要求见 [LWE 公钥契约](../primus_lwe/README.zh_CN.md#公钥加密)。普通消息使用 T，`decrypt` 返回 `Result<T, ClientError>`。

前半区 LUT 使用 `encrypt_padded`，奇数全域使用普通 `encrypt`。默认 LUT 在 Q 下按参数的明文模数编译，返回 q 后使用普通 `decrypt`。显式 `*_with_codec_fn` / `_slice` 接受 Q 下的输出 `RoundedCodec`；返回后用相同明文模数、q 下的 codec 解码 `decrypt_phase`。返回路径缩放已有编码，不重新编码，须计入舍入和 key-switch 误差。

[公共指南](../primus_tfhe/README.zh_CN.md) 说明 ManyLUT、奇数全域和 MVB。MVB 使用 Q 下的 unsigned `ScaledCodec` 编译，q 下的 Scaled codec 解码，并预算两端固定尺度的差异。有界双输入 `BivariateLookupTable` 目前仅支持 q=Q。

## Boolean 客户端与门

t=4 时使用 `boolean_encryptor`、`boolean_public_encryptor`、`boolean_decryptor` 和 `boolean_evaluator`。它们处理外部 LWE 的 bool 编码，使用普通 PBS 密钥；调用与串联契约见 [Boolean 门](../primus_tfhe/README.zh_CN.md#boolean-门)。

## CBS 与示例

`context.try_generate_keys(Some(cbs_config), rng)` 添加 trace/scheme-switch 材料；绑定 `context.circuit_bootstrap_evaluator(&server)`。CBS 跳过普通 PBS 返回路径，生成 f 下的 NGSW。输入 0/1 时它可控制 CMux，候选环密文须使用同一 f、Q 和编码；完整消费过程见后端示例。

`CircuitBootstrapParameters` 独立选择 output、trace、scheme-switch basis。输出保留请求的层数，scheme-switch key 绑定完整 output basis；相同长度不能证明 basis 或实际秘密相同。BR 分解必须能解析 LUT 和最小输出 gadget 尺度。

NTT reverse trace 使用模逆元，Fourier 使用原生整数减半并引入 FFT 误差。Scheme switching 的输入误差乘 f、分解误差乘 f²；发布 `NGSW_f[f]` 材料需要独立论证 key-dependent-message/circular-security 假设，见 [NTRU 契约](../primus_ntru/README.zh_CN.md#同一秘密下的-scheme-switching)。

## One-hot CBS

`OneHotCircuitBootstrapEvaluator::try_new(&context, &server)` 复用 classic binary/ternary CBS 材料。要求 t=2M、M=2^tau、tau>=1；输入用 `encrypt_padded` 加密 0..M。输出基有 L 层时，令 W=next_power_of_two(L)，要求 2MW<=N。

完整接口通过 `allocate_nlev_output` / `allocate_ngsw_output` 分配，再用 `one_hot_nlev_to`、`one_hot_ngsw_to` 或 `one_hot_to` 写入 δ_r(m)，r=0..M-1。NLEV 是 Q 下的系数表示，NGSW 是后端变换表示。布局为 `[selector][level][row element]`，层顺序与 `output_basis().scalar_iter()` 一致；每行 N 个整数，Fourier NGSW 每行 N/2 个复数。NLEV 先变换后可用于公开多项式提升，NGSW 用于加密候选的 CMux。

只需要非零分支时，使用 `allocate_nonzero_ngsw_output` 和 `one_hot_nonzero_ngsw_to`；紧凑位置 r-1 对应 r=1..M-1，跳过 r=0 的投影与 scheme switch。输入 m=0 时所有目标 bit 为零。每次调用共享一次 BR，复用输出与工作区；同时请求两种表示用 `one_hot_to`。

令 S=N/M、A=N/(2MW)。正确选择要求量化后的相位满足 `u_bar=S*m+W*e mod 2N` 且 `-A<=e<A`。窗口左闭右开，中点归较大的消息；e 包含输入噪声、编码舍入及逐坐标量化误差。形状校验不能证明该条件或输出可解码；推导见 [one-hot 归一化与保护区](../primus_tfhe/IMPLEMENTATION.md#one-hot-cbs)。

多 chunk 与多多项式流程由独立的 [primus_tfhe_ntru_lut](../primus_tfhe_ntru_lut/README.zh_CN.md) 提供。

## 进一步阅读

[操作与资源复用](../primus_tfhe/README.zh_CN.md) · [实现说明](../primus_tfhe/IMPLEMENTATION.md) · [基准指南](../primus_tfhe/BENCHMARKS.md)
