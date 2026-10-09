# primus_tfhe_ntru

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

NTRU-TFHE 的参数与 LWE 客户端层；[NTT](../primus_tfhe_ntru_ntt/README.zh_CN.md) 和 [Fourier](../primus_tfhe_ntru_fourier/README.zh_CN.md) 后端提供 context、求值密钥和 evaluator。

该 family 的默认依赖只使用系数类型、sparse 密钥存储、参数和客户端运算，不引入 NTT/FFT。需要同态求值时选择下述具体后端；其普通依赖会启用对应表示。

`PbsConfig::bsk_poly_length` 接收 `primus_poly::PolyLength`。用 `PolyLength::try_new(n)?`（已知常量可用 `new`）构造一次，供参数、尺寸与变换表复用。无效整数由 `PolyLengthError` 报告；参数构造仍负责组合布局、模数及采样器检查。

## 实验配套参数

`PbsConfig` 直接描述 PBS/ManyLUT/MVB 的 LWE/环域、`bsk_gadget`、`algorithm`、必需的 `key_switching` 与 `messages`。`CbsConfig { pbs, gadget }` 在同一域上补充 CBS 分解；selector 输入消息模数来自 `pbs.messages.input_modulus`。配置是可复制的数值描述，不含准备后的 sampler 或 codec。

`bsk_poly_length` 与 `acc_modulus` 描述 accumulator/BSK 共用的环；`bsk_secret_distr` 描述加密 BSK 的环秘密，`bsk_gadget` 描述其分解与行噪声。BR 输出使用该环秘密；公开 LUT 本身不采样加密噪声。输入 LWE 秘密在 `external_lwe` 中单独描述。`algorithm: BlindRotationMethod` 选择 classic 或 sparse 及其桶几何。

`PbsParameters::try_from_config(pbs_config)` 返回含必需 KS、算法和默认消息选择的 `PbsParameters`。`CbsParameters::try_from_config(cbs_config.pbs, cbs_config.gadget)` 将它与 `CbsGadgetParameters`、输入 codec 组合。后端 Context 用一个 Box 保存完整操作状态；`try_from_pbs_config` / `try_from_cbs_config` 移入准备后的参数。`parameters()` 始终借用完整 PBS 域；`cbs_parameters()` 查询额外的 CBS 能力。`try_with_circuit_bootstrap(gadget)` 添加 CBS 时复用同一份公共参数和变换表。

PBS 和 CBS 的 `key_switching` 都是必需的 `GadgetEncryptionConfig`，分解和噪声可独立于 BR 选择。CBS 当前阶段输出环/gadget 密文；后续消费结果返回 LWE 时复用同一份 KS。输入 LWE 与环秘密仍独立采样。 NTRU 返回在外部 q 下执行 KS。

参数入口为 `PbsParameters::try_from_config(pbs_config)`、`CbsParameters::try_from_config(pbs_config, gadget_config)` 和 `CbsParameters::try_with_config(pbs_parameters, gadget_config)`；最后一种移动已有公共状态，不重建 sampler。已有参数按值移入 Context，BR、trace、scheme-switch 继续共享既有环 sampler Arc；显式 `clone()` 可能复制 LWE sampler 数据。

具体后端的 `experimental::*_U64` 提供 PBS、ManyLUT、MVB 和 CBS 等教学配置。`PbsMessageConfig::new(t)` 默认输入/输出消息模数相同，`.with_output_modulus(t_out)` 可单独修改输出。后端 PBS/ManyLUT 的客户端和编译器根据消息选择派生 Rounded 编码，MVB 通过专用工厂选择 Scaled 输出；CBS 保存输入 codec，候选环消息模数由消费方选择。这些配置没有安全性或失败概率评估，来源与操作条件见[参数指南](../../guides/development/tfhe-parameters.md#scope-of-paired-parameter-entries)。

## 参数与密钥域

`PbsParameters<T, M, LM=M>` 分离环模数 Q 与外部 LWE 模数 q，共用整数类型 T。普通 PBS 使用 `PbsParameters::try_from_config(pbs_config)`：`external_lwe` 指定外部维数、q、binary/ternary 分布与新鲜加密噪声；`acc_modulus` 指定 Q。`bsk_gadget` 选择 Q 下的 BR 分解和密钥行噪声，`key_switching` 选择 q 下的返回密钥分解和密钥行噪声。环加密客户端复用 BR 密钥行噪声，外部 LWE 加密保留独立噪声。`level_count: None` 选择支持的最大层数，仍须检查[分解精度](../primus_decompose/README.zh_CN.md)。`CbsParameters::try_from_config(cbs_config.pbs, cbs_config.gadget)` 为环输出 CBS/one-hot 准备参数；返回 KS 与 PBS 共用，始终准备并保留。

维数选择使用 `LweDimension`；分解选择使用 `DecompositionBaseLog` 和 `Option<DecompositionLevelCount>`。这些单位只构造一次，参数访问器返回的值直接传给工作区。在原始存储或内核边界用 `.get()` 提取整数；组合长度和 basis/模数兼容性仍由构造器检查。

`PbsParameters::try_from_config` 一次准备外部 LWE、BR 环域和必需返回 KS。返回分解在外部 q 下构造，密钥行噪声以 q 下的系数单位独立选择。`2N` 必须能由 T 表示；外部维数 n 与环长度 N 独立。CBS/one-hot 复用同一份返回状态，不另建返回参数。构造器报告具体参数错误，不验证安全性或完整噪声预算。

`accumulator_ntru()` 借用盲旋转 gadget 在 Q 下的环与采样状态。密钥参数不保存消息 codec。CBS 的 `output`、`trace` 和 `scheme_switch` 各使用 Q 下的 `DecompositionConfig`。`CbsGadgetParameters::try_from_config` 从 BR 派生不含 codec 的 trace/scheme-switch NLev 参数，通过 `Arc` 共享环与采样状态。所有密钥行使用累加环加密噪声，分解 basis 和随机采样仍然独立。

`ClientKey` 保存独立采样的 LWE 秘密 s 与 NTRU 环秘密 f。普通 PBS 用 `context.try_generate_keys(rng)`，环输出 CBS 用 `try_generate_circuit_bootstrap_keys(rng)`；已有材料用 `ClientKey::new(s, f)` 导入。只有 f 需要可逆性检查，Fourier 还检查逆稳定性；外部秘密不要求补零、可逆或奇数重量。`external_lwe_secret_key()` 返回 q 下的 LWE 秘密。绑定在借用 raw view 前检查该密钥记录的模数；即使 binary 系数相同，异模数也返回 `TfheKeyError::LweSecretKeyModulusMismatch`。

普通 PBS 的返回顺序为：f,Q 下盲旋转 → 逐系数 Q→q 最近舍入 → 提取相位系数 → q 下 LWE key switch 到 s。ManyLUT 共享盲旋转，每个输出分别返回；`context.allocate_lwe_ciphertext()` 使用外部维数。

Classic PBS、ManyLUT、CBS、Boolean 和 MVB 支持 binary/ternary 外部秘密。Sparse 须显式选择 fixed-weight binary 生成入口，允许偶数重量，支持普通/ManyLUT PBS、分解式 MVB、CBS 和 one-hot。`SparseTernary` 分布本身不会选择桶聚合。首次提升与稀疏桶的推导见[实现说明](../primus_tfhe/IMPLEMENTATION.md#ternary-and-sparse-rotation)。

## Sparse 系数密钥

`SparseNtruBootstrappingKey<T>` 统一持有系数控制密文与公开 bucket map，两个后端均重导出此类型。首桶通过 `first_bucket()` 提供 NLEV，后续桶通过 `ngsw_bucket(i)` 提供 NGSW，每桶末尾都有 dummy。Basis 与模数仍由后端 BR owner 持有；共享存储类型不表示 NTT residue 与 native torus 系数可以互换。

通常通过后端 `KeyGenerator` 加密生成。若已有独立生成的控制密文，可用 `try_new(data, map, hamming_weight, &nlev_parameters)` 移入缓冲区并检查组合布局；它不验证加密选择、实际秘密或噪声预算。持有和读取这些系数不需要变换引擎。

## 客户端与 LUT

通过 `PbsMessageConfig::new(t_in)` 和可选的 `with_output_modulus(t_out)` 设置 `config.messages`。后端 `context.encryptor(external_secret)`、`public_encryptor(&public)` 自动准备 Rounded 输入；`pbs_decryptor` 选择普通 PBS/ManyLUT 的 Rounded 输出，`mvb_decryptor` 选择 MVB 的 Scaled 输出。客户端不接收 codec 或 LUT，`pbs_lookup_table_compiler()` 和 `compile_mvb_fn` 使用同一默认选择。家族 `PbsParameters` 提供同样的默认客户端工厂且无需变换表，Context 委托这些方法。高级同钥消息域通过家族 `*_with_codec` 工厂绑定已准备的 codec；见[选择输出编码](../primus_tfhe/README.zh_CN.md#选择输出编码)。

`ClientKey` 是完整 setup 组合；普通客户端只需 `let external_secret = client.external_lwe_secret_key();`，类型为 `&LweSecretKey`。也可直接按 `br.external_lwe()` 生成该密钥，或通过 `client.into_parts()` 移出，不必持有累加秘密。绑定只检查外部域；累加秘密的形状、可逆性和返回密钥幅度界由各自消费者负责。环客户端只接收 `client.accumulator_ntru_secret_key()`。

高级显式编码入口可选择外部 q 下的 `RoundedCodec`，再使用 `br.encryptor_with_codec(external_secret, &input_codec)`、`br.public_encryptor_with_codec(&public, &input_codec)` 和 `br.decryptor_with_codec(external_secret, &input_codec)`；`br.try_generate_public_key(external_secret, rng)` 生成独立外部 s 下的 LWE 公钥。它不是 NTRU 环公钥，总噪声要求见 [LWE 公钥契约](../primus_lwe/README.zh_CN.md#公钥加密)。普通消息使用 T，`decrypt` 返回 `Result<T, ClientError>`。

客户端读写接收 LWE 借用视图：向 `encrypt_to` 传入 `output.as_mut_view()`，向 `decrypt` 或 `decrypt_phase` 传入 `ciphertext.as_view()`。分配型加密方法仍返回 `LweCiphertext<T>`；Boolean 客户端遵循同样的约定。

显式 codec 入口解密 LUT 结果时，将返回输出 codec 传给 `br.decryptor_with_codec(external_secret, &output_codec)`，再调用 `decrypt()`。Rounded 和 Scaled 均可绑定，包括消息模数与输入不同的 MVB 输出。已准备的解码状态按值复制，秘密保持借用；`decrypt_phase` 继续供诊断使用。

前半区 LUT 使用 `encrypt_padded`，奇数全域 LUT 使用普通 `encrypt`。显式编译时，用 `br.pbs_codecs(PbsMessageConfig::new(t_in))?` 准备编码，默认输出消息模数与输入相同；需要不同时，在准备前调用 `.with_output_modulus(t_out)`。`br.lookup_table_compiler(&codecs)?` 直接绑定选定的输入/输出编码，支持 `compile_fn` / `compile_slice` 及交错、奇数全域方法。输出 decryptor 绑定 `codecs.output_codec()`。编译器检查输入 q 与 LUT 输出 Q，不会先准备未使用的默认输出。返回路径缩放既有编码，不重新编码；须预算 Q→q 舍入和 key-switch 误差。

[公共指南](../primus_tfhe/README.zh_CN.md) 说明 ManyLUT、奇数全域和 MVB。MVB 使用 Q 下的 unsigned `ScaledCodec` 编译，q 下的 Scaled codec 解码，并预算两端固定尺度的差异。有界双输入 `BivariateLookupTable` 目前仅支持 q=Q。

## Boolean 客户端与门

构造后端 Context 前设置 `config.messages = PbsMessageConfig::new(4)`，即可用 `boolean_encryptor`、`boolean_public_encryptor`、`boolean_decryptor` 和 `boolean_evaluator`，无需传 codec。输入、输出均需 t=4 才能串联门操作；密钥沿用普通 PBS 材料。高级数值组合保留共享 Boolean 构造器，调用与串联契约见[公共 Boolean 契约](../primus_tfhe/README.zh_CN.md#boolean-门)。

## CBS 与示例

`CbsParameters` 保存输入 Rounded 编码与 gadget，通过 `compile_lookup_table` / `_fn` / `_slice` 编译恒等或自定义整数函数。后端 Context 的 `compile_cbs_identity` / `compile_cbs_fn` / `compile_cbs_slice` 使用相同状态；输入加密共用 `context.encryptor`。候选环客户端接收独立 t_ring，并按累加 Q 准备 Scaled 编码。独立 codec 配对使用底层显式编译与客户端接口。

通过 `context.circuit_bootstrap_evaluator_with_lookup_table(&server, program)?` 创建拥有公共资源的默认 `CbsEvaluator`；`context.circuit_bootstrap_evaluator(&server)?` 编译并绑定恒等函数。输出为 `g_j * F(m) mod Q`，无需输出消息 codec 或额外 BR；CMux 要求完整输入域上的 F 为 bit，其他整数遵循外积噪声契约。NTT/Fourier 均支持 classic binary/ternary 与 sparse binary。显式输入编码和逐调用资源借用保留在底层 `CircuitBootstrapEvaluator`。

两个后端均提供 `context.try_generate_circuit_bootstrap_keys(rng)`，返回 `(ClientKey, CircuitBootstrapServerKey)`。该组合含一个 BR/KS `ServerKey` 和一个必需的 `CircuitBootstrapKey`，同样服务 one-hot 和高精度 LUT。通过 `server.server_key()` 绑定普通 PBS，CBS/one-hot 借用相同 BR，无重复密钥。完整组合也检查返回 q 的秘密幅度界；在线 CBS 仍不分配返回 scratch。见[材料选择](../primus_tfhe/README.zh_CN.md#选择盲旋转算法)。

两后端保留独立 BR、返回 KS 和 CBS 组件接口。`ServerKey::new(br, ks)` / `into_parts()` 移动 BR/KS；`CircuitBootstrapServerKey::new(server_key, circuit_key)` / `into_parts()` 移动完整 CBS 组合，不复制密文缓冲。`parameters.try_generate_lwe_return_key(&client, rng)` 直接返回 `Result<NtruLweKeySwitchingKey<_>, _>`，无需变换工作区；`check_lwe_return_key(&key)` 核对 N/Q/q、维数与 basis。单独生成 BR/CBS 组件只承担实际运算的数值条件；完整 PBS/CBS 组合还须满足返回 q 的幅度界。

`context.try_with_circuit_bootstrap(gadget)?` 为 PBS Context 添加 CBS，随后 `context.try_generate_keys(rng)` 复用主秘密变换、生成混合材料。CBS 跳过普通返回路径，在 f 下生成 NGSW；CMux 消费的函数须为 bit，候选环密文共享 f、Q 和编码。

`CbsGadgetParameters` 独立选择 output、trace、scheme-switch basis。输出保留请求的层数，scheme-switch key 绑定完整 output basis；相同长度不能证明 basis 或实际秘密相同。BR 分解必须能解析 LUT 和最小输出 gadget 尺度。CBS 的输入编码和 ManyLUT 容量在程序编译时检查，evaluator 绑定检查域和 basis；同一密钥材料可服务多个 t。`accumulator_client(client.accumulator_ntru_secret_key(), t_ring)` 独立绑定 Q 下的普通环消息，复用 gadget 的采样状态；其明文模数可与输入 LWE 不同。

NTT reverse trace 使用模逆元，Fourier 使用原生整数减半并引入 FFT 误差。Scheme switching 的输入误差乘 f、分解误差乘 f²；发布 `NGSW_f[f]` 材料需要独立论证 key-dependent-message/circular-security 假设，见 [NTRU 契约](../primus_ntru/README.zh_CN.md#同一秘密下的-scheme-switching)。

## One-hot CBS

后端 `context.one_hot_evaluator(&server)?` 使用相同 CBS 能力，组合 selector 状态和公共资源。底层 `OneHotCircuitBootstrapEvaluator::try_new(&resources, circuit_key, &input_codec)` 服务显式数值组合与逐调用资源借用。两者支持 classic binary/ternary 或 sparse fixed-weight binary BR。要求 t=2M、M=2^tau、tau>=1；用 `encrypt_padded` 加密 0..M。输出有 L 层时，令 W=next_power_of_two(L)，要求 2MW<=N。

完整接口通过 `allocate_nlev_output` / `allocate_ngsw_output` 分配，再用 `one_hot_nlev_to`、`one_hot_ngsw_to` 或 `one_hot_to` 写入 δ_r(m)，r=0..M-1。NLEV 是 Q 下的系数表示，NGSW 是后端变换表示。布局为 `[selector][level][row element]`，层顺序与 `output_basis().scalar_iter()` 一致；每行 N 个整数，Fourier NGSW 每行 N/2 个复数。NLEV 先变换后可用于公开多项式提升，NGSW 用于加密候选的 CMux。

只需要非零分支时，使用 `allocate_nonzero_ngsw_output` 和 `one_hot_nonzero_ngsw_to`；紧凑位置 r-1 对应 r=1..M-1，跳过 r=0 的投影与 scheme switch。输入 m=0 时所有目标 bit 为零。每次调用共享一次 BR，复用输出与工作区。两种完整表示用 `one_hot_to`；完整 NLEV 加非零 NGSW 用 `one_hot_nlev_and_nonzero_ngsw_to`，仅为 NLEV 投影零分支，省去其 scheme switch，其余分支共享投影。

令 S=N/M、A=N/(2MW)。正确选择要求量化后的相位满足 `u_bar=S*m+W*e mod 2N` 且 `-A<=e<A`。窗口左闭右开，中点归较大的消息；e 包含输入噪声、编码舍入及逐坐标量化误差。形状校验不能证明该条件或输出可解码；推导见 [one-hot 归一化与保护区](../primus_tfhe/IMPLEMENTATION.md#one-hot-cbs)。

访问分支时，通过 evaluator 的 `nlev_selectors`、`ngsw_selectors` 或
`nonzero_ngsw_selectors` 借用原输出缓冲的已检查视图。
`selector(r)` 使用数学分支编号，`iter()` 返回 `(r, ciphertext)`。
非零批次从 r=1 开始，不包含 selector 零。系数域 NLEV 使用共享的
`NlevSelectors`，两个后端分别提供 `NttNgswSelectors` 与
`FourierNgswSelectors`。视图不分配，拒绝不完整或长度不匹配的批次；
basis、秘密和变换身份仍由调用方保证。

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

[操作与资源复用](../primus_tfhe/README.zh_CN.md) · [实现说明](../primus_tfhe/IMPLEMENTATION.md) · [基准指南](../../benchmarks/tfhe/BENCHMARKS.md)
