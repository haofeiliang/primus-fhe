# primus_tfhe_ntru

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

NTRU-TFHE 的参数与 LWE 客户端层；[NTT](../primus_tfhe_ntru_ntt/README.zh_CN.md) 和 [Fourier](../primus_tfhe_ntru_fourier/README.zh_CN.md) 后端提供 context、求值密钥和 evaluator。

该 family 的默认依赖只使用系数类型、参数和客户端运算，不引入 NTT/FFT。需要同态求值时选择下述具体后端；其普通依赖会启用对应表示。

## 参数与密钥域

`TfheParameters<T, M, LM=M>` 分离环模数 Q 与外部 LWE 模数 q，共用整数类型 T。通过 `TfheParameters::try_from_config(TfheConfig { .. })` 构造：`external_lwe` 指定外部维数、q、binary/ternary 分布和加密噪声；`accumulator_modulus` 指定 Q；`blind_rotation` 分解在 Q 下，`key_switching` 分解和返回密钥噪声在 q 下。`level_count: None` 选择支持的最大层数，仍须检查[分解精度](../primus_decompose/README.zh_CN.md)。

维数选择使用 `LweDimension`；分解选择使用 `DecompositionBaseLog` 和 `Option<DecompositionLevelCount>`。这些单位只构造一次，参数访问器返回的值直接传给工作区。在原始存储或内核边界用 `.get()` 提取整数；组合长度和 basis/模数兼容性仍由构造器检查。

直接组合入口为 `TfheParameters::try_new(external_lwe, blind_rotation, key_switching, key_switching_noise_standard_deviation)`。`external_lwe` 为不含 codec 的 `LweParametersInner`，`blind_rotation` 为 `NlevParameters`。2N 必须能由 T 表示；外部维数 n 不要求小于等于 N。构造器返回带具体原因的参数错误，不验证安全性或完整噪声预算。

`accumulator_ntru()` 借用盲旋转 gadget 在 Q 下的环与采样状态。密钥参数不保存消息 codec。Trace 和 scheme-switch 配置构造不含 codec 的 NLev 参数，各自选择噪声。

`ClientKey` 保存独立 LWE 秘密 s 与 NTRU 环秘密 f。使用 `context.try_generate_keys(cbs_config, rng)` 生成配套密钥，或用 `ClientKey::new(s, f)` 导入。只有 f 需要可逆性检查，Fourier 还检查逆稳定性；外部秘密不要求补零、可逆或奇数重量。`external_lwe_secret_key()` 返回 q 下的 LWE 秘密。绑定在借用 raw view 前检查该密钥记录的模数；即使 binary 系数相同，异模数也返回 `TfheKeyError::LweSecretKeyModulusMismatch`。

普通 PBS 的返回顺序为：f,Q 下盲旋转 → 逐系数 Q→q 最近舍入 → 提取相位系数 → q 下 LWE key switch 到 s。ManyLUT 共享盲旋转，每个输出分别返回；`context.allocate_lwe_ciphertext()` 使用外部维数。

Classic PBS、ManyLUT、CBS、Boolean 和 MVB 支持 binary/ternary 外部秘密。Sparse 须显式选择 fixed-weight binary 生成入口，允许偶数重量，支持普通/ManyLUT PBS 和分解式 MVB；CBS、one-hot 仍要求 classic 密钥。`SparseTernary` 分布本身不会选择桶聚合。首次提升与稀疏桶的推导见[实现说明](../primus_tfhe/IMPLEMENTATION.md#ternary-and-sparse-rotation)。

## 客户端与 LUT

`ClientKey` 是完整 setup 组合；普通客户端只需 `let external_secret = client.external_lwe_secret_key();`，类型为 `&LweSecretKey`。也可直接按 `parameters.external_lwe()` 生成该密钥，或通过 `client.into_parts()` 移出，不必持有累加秘密。绑定只检查外部域；累加秘密的形状、可逆性和返回密钥幅度界由各自消费者负责。环客户端只接收 `client.accumulator_ntru_secret_key()`。

选择外部 q 下的 `RoundedCodec`，再使用 context 的 `encryptor(external_secret, &input_codec)`、`public_encryptor(&public, &input_codec)` 和 `decryptor(external_secret, &input_codec)`；`parameters.try_generate_public_key(external_secret, rng)` 生成独立外部 s 下的 LWE 公钥。它不是 NTRU 环公钥，总噪声要求见 [LWE 公钥契约](../primus_lwe/README.zh_CN.md#公钥加密)。普通消息使用 T，`decrypt` 返回 `Result<T, ClientError>`。

客户端读写接收 LWE 借用视图：向 `encrypt_to` 传入 `output.as_mut_view()`，向 `decrypt` 或 `decrypt_phase` 传入 `ciphertext.as_view()`。分配型加密方法仍返回 `LweCiphertext<T>`；Boolean 客户端遵循同样的约定。

前半区 LUT 使用 `encrypt_padded`，奇数全域 LUT 使用普通 `encrypt`。`parameters.lookup_table_compiler(&input_codec)?` 创建可复用编译器，支持 `compile_fn` / `compile_slice` 及交错、奇数全域方法。编译器检查输入 q 和 Q 下的默认输出 codec 是否有效。默认按输入 codec 的明文模数在 Q 下编码，返回 q 后用普通 `decrypt` 解码。`compiler.try_with_output_codec(&codec)?` 可选择其他输出 codec，传入的 `RoundedCodec` 必须使用 Q；解码 `decrypt_phase` 时使用相同输出明文模数、密文模数为 q 的 codec。返回路径缩放既有编码，不重新编码；须预算舍入和 key-switch 误差。

[公共指南](../primus_tfhe/README.zh_CN.md) 说明 ManyLUT、奇数全域和 MVB。MVB 使用 Q 下的 unsigned `ScaledCodec` 编译，q 下的 Scaled codec 解码，并预算两端固定尺度的差异。有界双输入 `BivariateLookupTable` 目前仅支持 q=Q。

## Boolean 客户端与门

显式传入 t=4 的 `RoundedCodec`，使用 `boolean_encryptor`、`boolean_public_encryptor`、`boolean_decryptor` 和 `boolean_evaluator`。它们处理外部 LWE 的 bool 编码，使用普通 PBS 密钥；调用与串联契约见 [Boolean 门](../primus_tfhe/README.zh_CN.md#boolean-门)。

## CBS 与示例

两后端提供独立的 `BlindRotationKey`、返回密钥与 `CircuitBootstrapKey` owner，通过 `ServerKey::new` / `into_parts` 移入或移出完整组合。`parameters.try_generate_lwe_return_key(&client, rng)` 无需变换工作区即可生成返回密钥；`parameters.check_lwe_return_key(&key)` 在组合时核对 N/Q/q、维数与 basis。CBS-only 生成和绑定无需返回密钥，也无需 f 满足外部 q 的幅度界；累加秘密仍须满足各后端的转换要求。

`context.try_generate_keys(Some(cbs_config), rng)` 添加 trace/scheme-switch 材料；两个后端均通过公共 `BootstrapResources` 与 `CircuitBootstrapEvaluator::try_new` 组合；资源复用方式见各后端 README。CBS 跳过普通 PBS 返回路径，生成 f 下的 NGSW。输入 0/1 时它可控制 CMux，候选环密文须使用同一 f、Q 和编码；完整消费过程见后端示例。

`CircuitBootstrapParameters` 独立选择 output、trace、scheme-switch basis。输出保留请求的层数，scheme-switch key 绑定完整 output basis；相同长度不能证明 basis 或实际秘密相同。BR 分解必须能解析 LUT 和最小输出 gadget 尺度。CBS 的输入编码和 ManyLUT 容量在 evaluator 绑定时检查；同一密钥材料可服务多个 t。`accumulator_client(client.accumulator_ntru_secret_key(), scaled_codec)` 独立绑定 Q 下的普通环消息，复用 gadget 的采样状态；其明文模数可与输入 LWE 不同。

NTT reverse trace 使用模逆元，Fourier 使用原生整数减半并引入 FFT 误差。Scheme switching 的输入误差乘 f、分解误差乘 f²；发布 `NGSW_f[f]` 材料需要独立论证 key-dependent-message/circular-security 假设，见 [NTRU 契约](../primus_ntru/README.zh_CN.md#同一秘密下的-scheme-switching)。

## One-hot CBS

`OneHotCircuitBootstrapEvaluator::try_new(&resources, circuit_key, &input_codec)` 复用 classic binary/ternary CBS 材料，并在每次调用时借用公共资源。要求 t=2M、M=2^tau、tau>=1；输入用 `encrypt_padded` 加密 0..M。输出基有 L 层时，令 W=next_power_of_two(L)，要求 2MW<=N。

完整接口通过 `allocate_nlev_output` / `allocate_ngsw_output` 分配，再用 `one_hot_nlev_to`、`one_hot_ngsw_to` 或 `one_hot_to` 写入 δ_r(m)，r=0..M-1。NLEV 是 Q 下的系数表示，NGSW 是后端变换表示。布局为 `[selector][level][row element]`，层顺序与 `output_basis().scalar_iter()` 一致；每行 N 个整数，Fourier NGSW 每行 N/2 个复数。NLEV 先变换后可用于公开多项式提升，NGSW 用于加密候选的 CMux。

只需要非零分支时，使用 `allocate_nonzero_ngsw_output` 和 `one_hot_nonzero_ngsw_to`；紧凑位置 r-1 对应 r=1..M-1，跳过 r=0 的投影与 scheme switch。输入 m=0 时所有目标 bit 为零。每次调用共享一次 BR，复用输出与工作区。两种完整表示用 `one_hot_to`；完整 NLEV 加非零 NGSW 用 `one_hot_nlev_and_nonzero_ngsw_to`，仅为 NLEV 投影零分支，省去其 scheme switch，其余分支共享投影。

令 S=N/M、A=N/(2MW)。正确选择要求量化后的相位满足 `u_bar=S*m+W*e mod 2N` 且 `-A<=e<A`。窗口左闭右开，中点归较大的消息；e 包含输入噪声、编码舍入及逐坐标量化误差。形状校验不能证明该条件或输出可解码；推导见 [one-hot 归一化与保护区](../primus_tfhe/IMPLEMENTATION.md#one-hot-cbs)。

多 chunk 与多多项式流程由独立的 [primus_tfhe_ntru_lut](../primus_tfhe_ntru_lut/README.zh_CN.md) 提供。

## NTRU→LWE 返回

`LweReturnEvaluator::new(server.key_switching_key(), q_modulus)` 借用 Q→q、f→s
返回密钥并绑定外部 q，本身不分配。两个后端均重新导出它。按需调用
`new_scalar_workspace()` 和／或 `new_batch_workspace()`；后者返回
`LweReturnBatchWorkspace`，保存固定容量 tile 与流式有效前缀。
输入须为配对环秘密下、Q 域的规范系数形式 NTRU，并满足返回噪声预算。

- `return_at_to(input.as_view(), index, output.as_mut_view(), &mut scalar)` 返回一个相位系数。
- `return_prefix_to(input.as_view(), outputs, &mut batch)` 返回连续系数，多个输出共用一次 Q→q 转换。
- 不同来源依次调用 `batch.begin_batch()`、有序 `append_at(input.as_view(), index, &mut batch)`、`return_batch_to(outputs, &mut batch)`。

每次追加只保留提取后的 LWE，随后即可复用来源及 one-hot/FFT 缓冲。提交数量须等于
已追加数量，不超过 `batch.batch_capacity()`（目前为八）；空批次和单项有效。
成功提交结束批次，`batch.discard_batch()` 取消，重新开始丢弃旧前缀；校验失败保留
前缀供重试。活跃批次拒绝共享前缀返回，独立的 scalar 缓冲仍可使用。
同一批次的追加与提交须使用相同实际秘密及 Q/q，工作区尺寸不能证明密钥身份。
换用其他绑定前先结束或取消批次。在线操作均不分配。

## 进一步阅读

[操作与资源复用](../primus_tfhe/README.zh_CN.md) · [实现说明](../primus_tfhe/IMPLEMENTATION.md) · [基准指南](../primus_tfhe/BENCHMARKS.md)
