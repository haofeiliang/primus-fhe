# primus_tfhe

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

公共外部 LWE 客户端、LUT 编译、编码元数据、PBS trait 及 Boolean 门求值层，供 GLWE 和 NTRU 两族复用。 Boolean evaluator 持有门 LUT 与 LWE 工作区；客户端密钥、变换 table 和环求值工作区仍由各自层管理。 完整使用流程从下面的后端示例开始。

## 选择同态操作

先选择要计算的函数及其编码，再选择 GLWE/NTRU 家族、NTT/Fourier 表示和秘密分布。 下表中的“普通密钥”指 ServerKey 的 PBS/KS 材料；所有 `_to` 操作都可复用输出和工作区。

| 任务 | 输入域与编码 | 输出 | 求值材料 | 执行与复用 |
| --- | --- | --- | --- | --- |
| 单变量函数 | unsigned Rounded 前半区 `0..ceil(t/2)` | 一个指定 codec 的 Rounded LWE | 普通密钥 | `LookupTable` + `Evaluator` |
| 奇数全域 | unsigned Rounded，奇数 `t>=3` 的 `0..t` | 一个 Rounded LWE | 普通密钥 | 同一 `LookupTable`/`Evaluator`，输入裕量较小 |
| 交错多输出（ManyLUT） | 同一前半区输入；`ceil(t/2)<=N/next_power_of_two(k)` | k 个同输出 codec 的 Rounded LWE | 普通密钥 | `InterleavedLookupTable`，共用普通 evaluator |
| 分解式 MVB | Rounded 前半区前缀 | k 个 unsigned Scaled LWE | 普通密钥 | 预处理程序 + `FactorizedEvaluator`，共享一次 BR、逐输出乘法 |
| 有界双输入 | 同秘密/编码，`x<B,y<R` 且 `B*R<=ceil(t/2)` | 一个 Rounded LWE | 普通密钥 | `BivariateLookupTable`，另复用一个打包 LWE |
| Boolean 门 | `t=4` 下的 Rounded 0/1 | 可直接串联的同编码 Boolean LWE | 普通密钥 | `BooleanEvaluator` 持有门 LUT 和临时密文 |
| CBS → CMUX | Rounded 前半区；CMUX 要求 F(m) 为 bit | accumulator 秘密下的 GGSW/NGSW gadget 控制，再选择环密文 | BR + trace/SS；GLWE KS→BR 另需输入 KS | `CbsEvaluator`；环客户端独立使用 `AccumulatorClient` |
| One-hot CBS | 一个 padded chunk，t=2M | δ_r(m) 的 NLEV/NGSW selectors | NTRU CBS 材料 | [One-hot 接口](../primus_tfhe_ntru/README.zh_CN.md#one-hot-cbs) |
| 高精度查表 | 多个独立加密、统一位宽的 chunks | 可独立指定数量的输出 chunks | NTRU CBS 和返回密钥；按需提供公开提升 | [高精度查表](../primus_tfhe_ntru_lut/README.zh_CN.md) |

ManyLUT 和 MVB 都计算**同一个输入的多个函数**，不批处理独立输入。 MVB 保留步长 1，但因子会放大噪声；交错 LUT 则用旋转分辨率换多输出。 Scaled 数值标志、Boolean LWE 和 CBS gadget 控制不能互换。 完整工作流从后端 basic 示例开始；各方法的域与噪声前提见下文及 rustdoc。

## Crate 分工与能力

| 家族 | NTT 后端 | Fourier 后端 |
| --- | --- | --- |
| [GLWE 参数与客户端](../primus_tfhe_glwe/README.zh_CN.md) | [GLWE NTT](../primus_tfhe_glwe_ntt/README.zh_CN.md) | [GLWE Fourier](../primus_tfhe_glwe_fourier/README.zh_CN.md) |
| [NTRU 参数与客户端](../primus_tfhe_ntru/README.zh_CN.md) | [NTRU NTT](../primus_tfhe_ntru_ntt/README.zh_CN.md) | [NTRU Fourier](../primus_tfhe_ntru_fourier/README.zh_CN.md) |

四个后端都有私钥和 LWE 公钥客户端；Fourier 支持 RustFFT 与 TFHE-FFT，环模数仅支持 Native。示例参数不构成生产安全性或失败概率推荐。

| 密钥模式 | 普通 / ManyLUT PBS | CBS | Factorized MVB | One-hot / 高精度查表 |
| --- | --- | --- | --- | --- |
| GLWE classic binary/ternary | 两种 PBS 顺序 | 支持 | 支持 | 未提供 |
| GLWE sparse fixed-weight binary | 两种 PBS 顺序 | 支持 | 支持 | 未提供 |
| NTRU classic binary/ternary | 支持 | 支持 | 支持 | 支持 |
| NTRU sparse fixed-weight binary | 支持 | 支持 | 支持 | 支持 |

Sparse 模式需显式选择生成入口，暂不支持 sparse ternary。NTRU 的外部 LWE 秘密独立于环秘密；只有环秘密需要可逆性筛选及 Fourier 逆稳定性检查，外部固定重量可以是偶数。

## 选择盲旋转算法

四个后端均导出 `BlindRotationMethod`。算法由操作配置保存，独立于秘密分布；从 PBS 配置创建 Context 后，默认生成与求值不再补传参数：

```rust,ignore
// GLWE 使用 config.method；NTRU 使用 config.algorithm。
config.method = BlindRotationMethod::Sparse { copy_count: 3, bucket_count: 64 };
let context = TfheContext::try_from_pbs_config(config)?;
let (client, server) = context.try_generate_keys(rng)?;
let mut pbs = context.evaluator(&server)?;
```

`Classic` 支持 binary/ternary，包括固定重量分布。`Sparse` 要求 fixed-weight binary 且 `0<h<n`，只重试公开桶映射，匹配失败返回错误；不会修改客户端秘密或回退到 classic。`KeyGenerator::try_generate(rng)` 复用生成工作区；已有客户端使用 `context.try_generate_server_key(&client, rng)`。只有算法比较或独立组件配线才使用具名的 `try_generate_with_parameters` / `try_generate_server_key_with_parameters`，显式传 KS、算法；CBS 专用工厂另接收必需 gadget。

Context 绑定独立 CBS 参数时检查域、算法及共用输入 KS 配对；sparse 配置检查在秘密采样前执行。新生成密钥依赖采样器保证，已有客户端在生成边界验证。NTRU 若无法通过采样器上界保证返回 q 条件，则检查实际接受的环秘密；完整 CBS 组合同样承担该返回界；独立 BR/CBS 组件只检查实际运算所需的数值条件。

`context.try_generate_keys(rng)` 始终返回含 BR 和必需 KS 的 `ServerKey`。Context 添加 CBS 后，用 `try_generate_circuit_bootstrap_keys(rng)` 返回 `CircuitBootstrapServerKey { server_key, circuit_bootstrap }` 的组合；它只有一份 BR/KS，`server_key()` 和 `circuit_bootstrap_key()` 分别借用两部分。独立 BR、CBS、返回与 NTRU 公开提升接口仍保留。

仅需环输出 CBS 或 NTRU one-hot 时，从 `CbsConfig` 创建 Context：

```rust,ignore
let context = TfheContext::try_from_cbs_config(config)?;
let (client, server) = context.try_generate_circuit_bootstrap_keys(rng)?;
let mut cbs = context.circuit_bootstrap_evaluator(&server)?;
```

`CircuitBootstrapServerKey` 始终包含 BR、KS 和 CBS 材料；CBS 当前阶段仅借用 BR/CBS，并按 GLWE order 使用输入 KS。完整 CBS Context 也可执行普通 PBS：`context.evaluator(server.server_key())?`。NTRU one-hot 使用同一 Context 的 `one_hot_evaluator(&server)`。默认工厂组合保存的输入 codec/gadget 与拥有的公共资源；`compile_cbs_fn` / `compile_cbs_slice` 按同一输入选择编译自定义程序。两类组合的 `into_parts()` 移出拥有型组件，不复制密文数组。

## 客户端与服务端边界

`Encryptor`、`Decryptor` 及其 Boolean 包装共享编码、范围检查和无分配的 `*_to` 操作。`LweClientParameters::new(&lwe_parameters)` 复制维数和小型 Rounded 状态，借用已准备噪声采样器，并从 codec 模数派生 mask 采样器。字段私有，通过访问器读取。家族构造入口先验证密钥，再一次性选定有效 LWE 秘密和噪声；两家族通过 `LweClientParameters::try_from_parts(dimension, &codec, &noise)` 绑定所选消息编码：GLWE BR→KS 使用 small LWE 的噪声和维数，KS→BR 使用提取维数和 accumulator 噪声；NTRU 使用独立外部 LWE 参数。绑定时检查 codec 与密钥、噪声的模数配对。这些检查不建立噪声或安全预算。

公共层接收 `LweSecretKeyRef` 或 `&LwePublicKey`；唯一的客户端 trait `EncryptionKey<T, M>` 只分派加密实现，不关联家族参数或错误类型。普通操作返回 `ClientError`，Boolean 操作返回 `BooleanError`。

家族入口在借用 raw view 前检查拥有型 LWE 私钥记录的模数，不匹配返回 `TfheKeyError::LweSecretKeyModulusMismatch`。直接调用公共层接收 `LweSecretKeyRef` 的构造器时，调用方须事先建立秘密的模数兼容性；raw view 无法执行该检查。绑定后的客户端保留视图，不在每条消息上重复检查拥有型密钥。

分配型加密方法返回 `LweCiphertext<T>`。客户端写入接口按值接收 `Lwe<&mut [T]>`，读取接口按值接收 `Lwe<&[T]>`：使用 `encryptor.encrypt_padded_to(message, output.as_mut_view(), rng)` 和 `decryptor.decrypt(output.as_view())`。视图只借用系数，不复制或分配；已有切片可通过 `primus_tfhe::Lwe::new` 包装，因此同一接口也支持 boxed、对齐及栈存储。Boolean 客户端遵循同样的借用方式。

求值端的单项 LWE 参数使用相同视图：`evaluator.apply_lookup_table_to(input.as_view(), &lut, output.as_mut_view())`。Boolean 门和双输入打包借用各自的操作数；CBS、one-hot 和 MVB 借用其 LWE 输入。分配型方法仍返回拥有型密文。ManyLUT/MVB 输出批次以及高精度输入/输出批次借用预先分配的 `LweCiphertext<T>` 切片。每个有效输出对应一个完整 LWE，LUT padding 不需要额外密文。每个 LWE 保留自己的系数缓冲，直接传入已有切片即可，无需打包系数或收集视图。写入输出前会检查数量和每个密文的维数。

客户端生成配套密钥，保留 setup 组合 `ClientKey`（也可通过 `into_parts()` 分开持有秘密）和加解密器，将 `ServerKey` 提供给服务端。 服务端只需公开 context、求值密钥、LUT/程序和输入密文；计算后将密文结果返回客户端。 示例在同一进程展示这些阶段，参数构造单独放置。输入和输出编码是双方约定的公开信息。 各阶段直接写在 `main` 中，用注释标明双方职责：服务端准备只使用公开 context、codec 与计算密钥，加密/解密使用客户端秘密。CBS 的候选环密文由客户端加密；sparse 高精度计划可能还需客户端生成 NLEV[1] 提升密文。公开 LUT 可由服务端编译，双方各自分配并复用缓冲；示例不引入传输层。

普通缓冲分配不依赖私钥：四个后端的 `context.allocate_lwe_ciphertext()` 按外部 LWE 维度分配 mask/body；`context.allocate_accumulator_ciphertext()` 按累加器布局分配系数域 GLWE/NTRU。两者只分配零存储，不执行加密。CBS 控制的布局还依赖输出分解和变换表示， 因此使用 `cbs.allocate_output()`。工作区和结果缓冲在各自一端创建一次并复用。

## 错误边界

配置和绑定入口优先使用 `try_*`，处理该入口实际返回的错误类型。`LookupTableError` 负责 LUT 编译，`TfheEvaluationError` 负责求值资源绑定；家族/后端提供参数、密钥生成、客户端和变换表错误。普通客户端操作返回 `ClientError`，Boolean 操作返回 `BooleanError`。底层原因通过 `std::error::Error::source()` 保留，详见各公开 API 的 rustdoc。

## Boolean 门

Boolean 客户端使用配置中的消息域：构造 Context 前设置 `config.messages = PbsMessageConfig::new(4)`。输入加密和输出解密各自要求 t=4，门 evaluator 要求输入、输出均为 t=4；四个工厂不再接收 codec。客户端使用 unsigned Rounded `0/1` 编码的 `LweCiphertext<T>`，解密拒绝非 Boolean 值。直接数值组合仍可将已有客户端传给 `BooleanEncryptor::try_new(encryptor)` / `BooleanDecryptor::try_new(decryptor)`，或使用共享 `BooleanEvaluator::try_new`。门求值使用普通 PBS 密钥，无需 CBS 材料。

```rust,ignore
let external_secret = client.external_lwe_secret_key();
let encryptor = context.boolean_encryptor(external_secret)?;
let decryptor = context.boolean_decryptor(external_secret)?;
let mut gates = context.boolean_evaluator(&server)?;
let lhs = encryptor.encrypt(true, &mut rng)?;
let rhs = encryptor.encrypt(false, &mut rng)?;
let mut output = context.allocate_lwe_ciphertext();
let mut next = context.allocate_lwe_ciphertext();
gates.evaluate_binary_to(
    BooleanGate::Nand, lhs.as_view(), rhs.as_view(), output.as_mut_view(),
);
assert!(decryptor.decrypt(output.as_view())?);
gates.mux_to(output.as_view(), rhs.as_view(), lhs.as_view(), next.as_mut_view());
core::mem::swap(&mut output, &mut next);
assert!(!decryptor.decrypt(output.as_view())?);
```

`BooleanEvaluator` 在两族间共享仿射预处理、内部模 8 正负 LUT 和恢复输出编码的平移。 二元门使用一次 PBS，NOT 无需 PBS，MUX 使用两次。通过 `evaluate_binary_to`、`not_to`、 `mux_to` 和已有输出复用存储。 输出保持外部 Boolean 编码，可直接送入后续门。 客户端维数错误返回 `BooleanError::Client`，门求值维数错误则 panic。 原始密文不携带密钥身份或编码元数据，这些仍由调用方保证。

## CBS 输出与消费

四后端都在默认 `CbsEvaluator` 中组合 CBS 程序、投影缓冲与所需公共资源。下例为 GLWE，Context 的输入消息模数配置为 t_in=8；NTRU 使用 `client_key.accumulator_ntru_secret_key()` 取代 GLWE 访问器。共用的 `context.encryptor` 读取配置的 Rounded 输入编码；候选环客户端仅接收独立的 t_ring，由 Context 提供累加模数 Q。

```rust,ignore
// 客户端：候选在累加 Q 下使用独立的 t_ring=8。
let mut ring_client = context.accumulator_client(client_key.glwe_secret_key(), 8)?;
let lhs = ring_client.encrypt(&lhs_message, &mut rng);
let rhs = ring_client.encrypt(&rhs_message, &mut rng);
let mut decoded = vec![0; lhs_message.len()];
let input = context.encryptor(client_key.external_lwe_secret_key())?
    .encrypt_padded(3, &mut rng)?;

// 服务端：计算 F(m) = [m >= 2]，再选择环密文。
let program = context.compile_cbs_fn(|m| u64::from(m >= 2))?;
let mut cbs = context.circuit_bootstrap_evaluator_with_lookup_table(&server_key, program)?;
let mut control = cbs.allocate_output();
let mut selected = context.allocate_accumulator_ciphertext();
cbs.circuit_bootstrap_to(input.as_view(), control.as_mut_view());
cbs.cmux_to(control.as_view(), lhs.as_view(), rhs.as_view(), selected.as_mut_view());

// 客户端：解密返回结果。
ring_client.decrypt_to(&selected, &mut decoded);
```

`compile_cbs_fn` 在完整 `0..ceil(t_in/2)` 上求值，将每层编译为 `g_j * F(m) mod Q`。`compile_cbs_slice` 接收恰好该数量的结果（此例为 `[0, 0, 1, 1]`）；`compile_cbs_identity` 编译恒等函数。默认绑定核对程序的输入消息区间、N、q/Q 与完整 gadget basis，再移动程序；输入数量相同不足以证明编码相同。`circuit_bootstrap_evaluator(&server)` 是恒等快捷入口。改变兼容函数不需要新密钥或额外 BR。

CMux 要求完整输入域上的 F 为 0 或 1；输入本身可以不是 bit。其他 canonical 环整数（显式 Q 时小于 Q）可作为外积控制，需要独立乘法与噪声预算。输入 t、函数整数值、候选 t_ring 与 gadget basis 分别承担不同数学角色。One-hot 使用专用 selector 表，通过 `context.one_hot_evaluator(&server)` 创建同样拥有公共资源的 `OneHotEvaluator`。

`allocate_output` 返回后端的原始 GGSW/NGSW；候选与返回环密文为系数域 GLWE/NTRU。`cmux_to` 在 0 时选择 lhs、1 时选择 rhs；`external_product_to` 也可消费非 bit gadget。控制须匹配 evaluator 的 basis、实际累加秘密及变换表示；候选须采用同一秘密/模数及共同编码。这些身份和噪声余量由调用方保证；公开入口在写输出前检查精确长度。

`AccumulatorClient` 拥有准备好的累加秘密和转换缓冲，并借用 Context。它加解密 N 个 Scaled 环消息系数；该消息域独立于外部 LWE。准备 t_ring 编码、密钥检查或 NTRU 秘密转换失败会返回 `TfheClientError`。形状错误在写入/消耗 RNG 前 panic；非法明文可能已消耗随机数。创建一次后复用 `_to` 和输出缓冲。

显式输入编码、逐调用资源借用和 GLWE 替代 output basis 使用底层 `CircuitBootstrapEvaluator` / `OneHotCircuitBootstrapEvaluator`；候选原始 Scaled 配对可用 `AccumulatorClient::try_new`。它们服务独立数值组合和已有 PBS 资源复用。

## 复用 evaluator

默认 `CbsEvaluator` / `OneHotEvaluator` 只组合原有操作缓冲与 `BootstrapResources`，不复制 Context、密钥或变换表，也不分配普通返回 scratch。`into_parts()` 移动取出操作状态和公共资源；随后可将资源转给 PBS，并继续通过底层 evaluator 短借用它。串行复用不要求同时保留多个同形 scratch；并发 worker 需要独立可变资源。

Context 保存不可变参数和变换表，ServerKey 保存求值材料；Evaluator 持有可变工作区。 编译后的 LUT/程序可以长期保留，多次调用 `_to` 写入预分配输出。

NTRU 两后端使用短借用组合：普通 PBS 拥有公共 BR/EP（Fourier 含 FFT）和返回缓冲，CBS/one-hot 只准备 LUT/投影状态。构造用 `try_new(pbs.bootstrap_resources(), circuit_key, &input_codec)`，执行时最后一个参数传 `pbs.bootstrap_resources_mut()`。Factorized MVB 用 `context.mvb_evaluator(&server_key)` 构造并拥有 PBS 状态，每次请求只传输入、程序和输出。高级组合将已准备的 PBS evaluator 移入 `FactorizedEvaluator::new(pbs)`。仅需 CBS 时可用 `context.bootstrap_resources(br)` 独立准备公共资源。完整用法见 [NTT 资源复用](../primus_tfhe_ntru_ntt/README.zh_CN.md#复用-evaluator)与 [Fourier 资源复用](../primus_tfhe_ntru_fourier/README.zh_CN.md#复用-evaluator)。

GLWE 两后端同样使用短借用。独立 CBS 可用 `context.bootstrap_resources_from_server_key(&server)` 准备资源，由工厂选择所需输入 KS；替代输出 basis 使用 `CircuitBootstrapEvaluator::try_with_parameters`。MVB 用 `context.mvb_evaluator(&server_key)` 构造并拥有 PBS 状态，支持 classic、sparse 和两种 PBS 顺序。公共资源在 KS→BR 时保留输入 KS；独立 BR→KS 不分配输出 KS。Fourier 整个流程复用同一 FFT engine。见 [GLWE NTT 资源复用](../primus_tfhe_glwe_ntt/README.zh_CN.md#复用-evaluator)与 [GLWE Fourier 资源复用](../primus_tfhe_glwe_fourier/README.zh_CN.md#复用-evaluator)。

所有后端均在构造时准备存储，在线 `_to` 操作不隐式分配。Boolean 的 `try_new` 接受 PBS 所有权，`into_bootstrapper` 可回收。

## LUT 与资源生命周期

后端接受纯数值 `PbsConfig` / `CbsConfig` 并派生公共环参数，`TfheContext::try_from_parameters` 自动创建选定类型的变换表。本 crate 从 [`primus_decompose`](../primus_decompose/README.zh_CN.md) 重新导出 `DecompositionConfig`（分解基与保留层数）。`GadgetEncryptionConfig { decomposition, noise_standard_deviation }` 集中 blind rotation 或 PBS key switching 的独立选择。`CbsGadgetConfig` 包含三组 `DecompositionConfig`：`output`、`trace` 和 `scheme_switch`。Trace 与 scheme-switch 密钥行继承累加环加密噪声并共享其不可变采样状态，basis 和随机采样仍然独立。各后端绑定自己的模数、布局与表示。`TfheContext` 保留完整 PBS/CBS 能力，独立组件使用显式高级工厂；server key 持有对应参数和材料，各 evaluator 只持有自身工作区。

`LweConfig` 通过 `primus_lwe::LweEncryptionParameters::try_from(config)?` 转换为采样参数；具体模数同样使用 `BarrettModulus::try_from(config)`、`PowOf2Modulus::try_from(config)` 或 `NativeModulus::try_from(config)`。这些 setup 转换保留模数与采样错误，不准备消息 codec。

`GadgetEncryptionConfig<D = DecompositionConfig>` 默认接收分解配置；GLWE 的直接构造入口用已准备的 `ApproxSignedBasis<T>` 作为 D，移动其所有权而不重新构造。噪声标准差使用密钥模数下的系数单位：GLWE BR/KS 使用共同 q，NTRU BR 与 CBS trace/scheme switching 使用累加 Q，NTRU 返回 KS 使用外部 q。Config 本身不校验，由原有参数构造边界验证。`PbsConfig::bsk_gadget` 中的噪声也用于累加环加密，以及 GLWE KS→BR 的新鲜外部 LWE 加密。KS 噪声仍独立配置；CBS trace/scheme-switch 密钥行继承累加环噪声。

1. Family 参数描述外部 LWE 和 accumulator 环。
2. 后端 context 绑定参数与 NTT/FFT table，并生成配套的 client/server key。
3. 通过 family 参数编译 `LookupTable` / `InterleavedLookupTable`。 evaluator 创建一次，在线 `_to` 调用复用其 scratch。
4. 调用方输出分配一次，后续加密与求值重复使用同一存储。

前半区单函数或切片编译器为 `0..ceil(t_in/2)` 输入域编程，输出属于输出 codec 指定的 `0..t_out`。 其余输入不独立编程；奇数全域使用下文的独立入口。交错 LUT（ManyLUT）的有效输出数 `k` 为正， 补齐后的输出数为 `s = next_power_of_two(k)`，满足 `ceil(t/2) <= N/s`。callback 按输入优先 顺序接收 `(input, output_index)`，每个有效组合调用一次；切片包含相同顺序的 `D*k` 个值。 例如 `k=3` 时三个输出占用四个槽：编译器将第四槽置零，不调用 callback；求值端只返回三个密文。 所有输出共享一次盲旋转（BR）。GLWE 共享环 key switch 后分别提取；NTRU 每个输出分别返回并执行 LWE key switch。 输出越多，旋转分辨率与输入噪声余量越低。这是一个输入求多个函数，不是独立密文批处理。

通过各后端的 `context.pbs_lookup_table_compiler()?` 创建可复用的 `LookupTableCompiler`。Context 提供默认输入/输出消息选择；`pbs_lookup_table_compiler_with_messages(messages)` 为单个编译器覆盖消息域，不改变默认值或客户端。家族的 `br.lookup_table_compiler(&codecs)` 仍是显式 codec 入口。直接使用共享层时，`LookupTableCompiler::try_new(poly_length, &input_codec, accumulator_modulus, &output_codec)` 绑定相同的编码环境。它只复制所需编码状态，不分配内存，也不借用 parameters/context。方法如下：

| 程序 | 函数输入 | 切片输入 |
| --- | --- | --- |
| 前半区，单输出 | `compile_fn(function)` | `compile_slice(values)` |
| 前半区，多输出 | `compile_interleaved_fn(k, function)` | `compile_interleaved_slice(k, values)` |
| 奇数全域，单输出 | `compile_odd_full_domain_fn(function)` | `compile_odd_full_domain_slice(values)` |

构造编译器时检查输出 codec 的模数；GLWE 工厂还检查输入 codec 与密钥模数的配对。编译时在填表前检查各程序的容量与切片长度，保持回调顺序，并在首个非法输出或旋转中心碰撞处停止。

共享 LUT 构造器和 `BooleanEvaluator::try_new` 都接收从 `primus_poly` 重新导出的 `PolyLength`。直接传入环参数返回的已验证长度，或用 `PolyLength::try_new(N)` 构造一次。该类型集中检查 `32..=2^17` 内的二次幂；编译仍检查旋转域能否由系数字宽表示、编码、输出容量与数值范围。

Raw 构造器 `LookupTable::try_new` / `InterleavedLookupTable::try_new` 显式接收 编程前缀长度 `D` 和已编码输出。`input_ciphertext_modulus` 描述输入量化模数， `coefficient_modulus` 描述 LUT/累加器模数，raw 输出必须是后者下的规范值。 `k` 和明文模数都不必是二次幂；补齐数量 `s` 必须与容量、实际中心分离和噪声余量相容。 构造失败不会返回部分表。输出槽、重复区间与舍入规则见[旋转几何](IMPLEMENTATION.md#rotation-geometry)。

## 编码与密钥契约

| 接口 | 输入 / 输出含义 |
| --- | --- |
| 普通 `encrypt` | `0..t` 范围的 unsigned 消息 |
| `encrypt_padded` | 相同 unsigned 尺度，输入限制为 `0..ceil(t/2)`，供前半区 LUT 使用 |
| `encrypt_centered` | 接收 `0..t` 的模代表元；上半区表示负数，例如 `t=4` 时 `3` 表示 `-1` |
| 两族 Boolean | 外部 `false/true` 对应模 4 下的 `0/1`；内部 LUT 使用 rounded 模 8 尺度的正负值，随后平移恢复外部编码 |
| CBS | unsigned 前半区输入经 F 映射为指定 gadget 尺度的 GGSW/NGSW，秘密为 accumulator secret；F 为 bit 时可生成 CMUX 控制 |

客户端 `decrypt` 使用绑定的 codec，返回 `0..t` 中的规范代表元。Centered 加密不能替代普通 LUT 的 unsigned 输入契约。PBS 保留 LUT 的输出尺度，不会自动把 Boolean 或 gadget 输出改为普通消息编码。

原始 `LweCiphertext` 不记录秘密、编码或噪声。调用方必须使用配套密钥、显式模数下的 规范系数，并保证噪声余量。LUT 与维数错误在写入输出前拒绝，但这些检查不能验证实际 秘密一致性。Fourier 密钥和 evaluator 必须使用同一 FFT table 实例。

最小 trait 为 `ProgrammableBootstrap` 和 `ProgrammableBootstrapInterleaved`。 普通应用使用参数返回的编译器，由其检查并编码明文输出。 `LookupTable::try_new` 与 `InterleavedLookupTable::try_new` 接收已编码输出和显式的 编程前缀长度，Boolean 与 CBS 通过它们使用各自的输出尺度。 兼容性检查绑定多项式长度与编码模数；输入位于已编程前缀内仍由调用方保证。 `rotation::RotationModulusSwitch` 准备 LUT 编译与盲旋转共用的逐系数模数切换，包括 ManyLUT 和 CBS 所需的旋转步长对齐。

### 选择输出编码

用 `PbsMessageConfig::new(t_in)` 集中指定消息域，默认 `t_out=t_in`；通过 `.with_output_modulus(t_out)` 显式修改输出域，不改变输入编码或密钥。ManyLUT 的各 lane、MVB 的各输出共用该输出模数。操作允许时，继续支持奇数明文模数。

按二进制输入位宽选择时，`PbsMessageConfig::from_input_bits(4)` 对应 16 个合法 padded 输入、codec 模数 32，其中一位用于 padding。默认完整输出模数仍为 32，不自动代表输出带 padding 或可以继续 PBS。`try_from_input_bits(u32)` 拒绝无法表示的模数；密文兼容性和 LUT 容量仍在 setup 检查。一般/奇数模数继续使用 `new(t)`。

GLWE、NTRU 家族的 `PbsParameters` 从 `config.messages` 按用途准备编码，四个后端 Context 委托它们创建客户端。客户端仅需外部秘密或公钥，可以先于 LUT 创建；家族工厂无需变换表。PBS、ManyLUT 和 factorized MVB 的输入共用 `context.encryptor(external_secret)`；公钥输入用 `public_encryptor(&public)`。

| 程序工厂 | q 下输入 | Q 下 LUT 输出 | q 下返回输出工厂 |
| --- | --- | --- | --- |
| `context.pbs_lookup_table_compiler()` | Rounded | Rounded | `pbs_decryptor`：Rounded |
| `context.compile_mvb_fn(domain_len, output_count, function)` | Rounded | Scaled | `mvb_decryptor`：Scaled |

例如先设置 `config.messages = PbsMessageConfig::new(16).with_output_modulus(4)` 并构造 Context：

```rust,ignore
let encryptor = context.encryptor(external_secret)?;
let decryptor = context.pbs_decryptor(external_secret)?;
let lut = context.pbs_lookup_table_compiler()?.compile_fn(|x| (x % 4) as u64)?;
let input = encryptor.encrypt_padded(7, &mut rng)?;
let output = evaluator.apply_lookup_table(input.as_view(), &lut);
assert_eq!(decryptor.decrypt(output.as_view())?, 3);
```

同一密钥、Context 和 evaluator 可保持配置中的输入域，并为另一程序选择不同输出消息模数：

```rust,ignore
let parameters = context.parameters();
let messages = parameters.messages().with_output_modulus(8);
let codecs = parameters.pbs_codecs(messages)?;
let decryptor = parameters.decryptor_with_codec(external_secret, codecs.output_codec())?;
let compiler = parameters.lookup_table_compiler(&codecs)?;
let lut = compiler.compile_fn(|x| (x % 8) as u64)?;
```

MVB 选择其他输出域时，用 `context.compile_mvb_fn_with_messages(messages, domain_len, output_count, function)` 编译，通过 `parameters.factorized_pbs_codecs(messages)` 与 `parameters.decryptor_with_codec` 准备相应 Scaled 输出解密器。保持 `messages.input_modulus` 与配置一致时，可复用 `context.encryptor(external_secret)`。需要普通 PBS 与 MVB 使用完全相同编码进行数值对比时，使用家族的 `parameters.compile_factorized_lookup_table_fn(&codecs, ...)`，再将原始程序交给相应后端的 `NttFactorizedLookupTable::new` / `FourierFactorizedLookupTable::new`。Context 不再重复提供手工 codec 的客户端或编译转发。编译不会改变默认值或已绑定客户端；默认工厂只准备所需 codec，几何、分解条件与噪声预算仍由具体操作负责。

GLWE 的输入、LUT 和返回使用同一密文模数。NTRU 从同一 `t_out` 派生 Q 下的 LUT 输出和 q 下的返回 LWE 编码；返回过程缩放已有 phase，不重新生成精确的 q 编码中心，须预算 Q→q 舍入和 key-switch 噪声。q 下的 Scaled codec 也有自身恢复条件。即使 `t_out=t_in`，MVB 输出仍使用 Scaled。

Encryptor 复制小型 Rounded 状态，借用所选新鲜噪声采样器和密钥；Decryptor 复制已准备解码器，仅借用秘密。两者均不持有 LUT、服务端密钥或可变工作区，codec 变量无需与客户端同寿命。Rounded/Scaled 共用 q→t 解码，但编码中心与恢复界不同；`decrypt_phase` 仍用于未解码 phase 的诊断。

输入加密使用 `config.messages.input_modulus`，输入、输出模数仍可独立配置。高级输入域组合可准备一次 codec，再通过 `context.parameters().encryptor_with_codec(secret, codecs.input_codec())` 绑定已有输入编码；编译器和解密器可复用同一准备结果。此类组合仍可显式构造 `RoundedCodec`/`ScaledCodec` 并使用底层 LUT 构造接口。`LookupTableCompiler::try_new` 直接接收配好的输入与 LUT 输出 codec，无需先准备默认输出。`try_with_output_codec` 只更改编译器的输出 codec、检查其密文模数，保持输入几何不变；显式接口的调用方自行保留对应输出 decoder。奇数全域方法及原始 Boolean/CBS 输出尺度继续遵守各自契约。

返回值属于 `0..t_out`，前半区输入仅接受 `0..ceil(t_in/2)`。相同消息模数不保证结果可直接输入下一次 PBS；还需匹配下一程序的编码、输入域和噪声余量。

## 奇数全域 PBS

使用 `compiler.compile_odd_full_domain_fn(function)` 或其 `_slice` 形式；需要不同输出消息模数时，在准备 codec 前通过 `PbsMessageConfig::with_output_modulus` 配置。这些方法编程整个 **`0..t_in`**。要求奇数 `t_in >= 3`、`t_in <= N`；切片按输入顺序包含 恰好 `t_in` 个输出。输入用普通 `encrypt`，随后复用 `apply_lookup_table_to`。 默认或显式指定输出编码，都将对应输出 codec 绑定到 decryptor 后调用 `decrypt`。 例如，构造 Context 前设置 `config.messages = PbsMessageConfig::new(15).with_output_modulus(8)`，输入与 accumulator 共用密文模数：

```rust,ignore
let encryptor = context.encryptor(external_secret)?;
let decryptor = context.pbs_decryptor(external_secret)?;
let compiler = context.pbs_lookup_table_compiler()?;
let lut = compiler.compile_odd_full_domain_fn(|x| ((x * x + 3) % 8) as u32).unwrap();
let input = encryptor.encrypt(14u32, &mut rng).unwrap();
evaluator.apply_lookup_table_to(input.as_view(), &lut, output.as_mut_view());
let message = decryptor.decrypt(output.as_view())?;
assert_eq!(message, 7);
```

已编码输出使用 `LookupTable::try_new_odd_full_domain`。编译器折叠负循环旋转中心并恢复输出符号， 折叠中心碰撞返回 `RotationCenterCollision`。Callback 顺序和区间细节由 rustdoc 说明。

典型中心间距为 `N/t_in`，噪声余量约为前半区编译的一半。容量与碰撞检查只保证 LUT 几何可表示，不提供 PBS 失败概率；仍需计入输入误差和逐系数模切误差。 此入口仅支持单输出奇数全域，交错与双输入编译器保持前半区契约；无需新增密钥或在线 evaluator。 [旋转几何](IMPLEMENTATION.md#rotation-geometry)说明符号折叠及其限制。

## 有界双输入 PBS

`BivariateLookupTable::try_new(B, R, poly_length, input_codec, output_codec, function)` 通过 `z = x + B*y` 编译 `0 <= x < B`、`0 <= y < R` 上的 `f(x,y)`。 `B`、`R` 必须为正，`D = B*R <= ceil(t_in/2)`，并满足普通 LUT 的容量和旋转中心检查。 只编译 `0..D` 前缀，回调按 `x` 优先变化的顺序求值；`B` 不必是二次幂。 输出 codec 独立选择 `t_out`，但必须使用相同密文模数。

按外部 LWE 维数一次性分配 `packed` 和 `output`。 `pack_to` 用一遍模乘加写入 `lhs + B*rhs`，不分配内存；长度不同或缺少 body 时在写入前拒绝。 两输入必须具有相同的实际秘密、密文模数及传入的 unsigned 输入 codec，系数规范、明文不超出各自边界。 raw 密文无法验证这些语义条件。GLWE 使用其 order 对应的外部维数与显式选择的输入 codec，无需增加密钥材料。

打包将第二个输入的噪声放大 B 倍；`t_in` 不整除 q 时还可能产生编码舍入偏差。 PBS 前须同时预算两者，容量检查本身不保证足够噪声余量。 具体误差界见 `BivariateLookupTable` rustdoc。 这是有界单输出工作流，不是通用整数运算或 LWE 到环密文的 packing。

当前构造器只有一个密文模数，输入与输出 codec 必须共用该模数。它适用于 GLWE，以及 q=Q 的 NTRU 配置；不支持 q≠Q 的 NTRU 双输入查表。普通 NTRU LUT 的 Q→q 支持并不解除此限制。

## 固定尺度分解式 MVB

`FactorizedLookupTable::try_new(D, poly_length, output_count, input_codec, output_codec, function)` 使用 Rounded 输入和 unsigned Scaled 输出编译非空前半区前缀。系数模数可以显式且为奇数， 或为 Native 且实际 Scaled 输出尺度为偶数；显式偶模数仍不支持。 Callback 每个组合调用一次，参数为 `(input, output_index)`，**外层遍历输出索引**。 有符号整数因子范数决定噪声放大；代数关系见 `FactorizedLookupTable` rustdoc 和 [MVB 设计](IMPLEMENTATION.md#factorized-mvb)。

全部输出共享一次步长为 1 的 BR，再分别乘公开多项式。正输出数不补齐、不降低输入容量； 代价是各输出的因子会放大 BR 噪声，输入几何检查不能代替噪声预算。解密相位须使用保留的 Scaled codec；接入下一次 Rounded 输入 PBS 时须计入编码中心差异。

[GLWE NTT](../primus_tfhe_glwe_ntt/README.zh_CN.md#固定尺度分解式-mvb) 与 [NTRU NTT](../primus_tfhe_ntru_ntt/README.zh_CN.md#固定尺度分解式-mvb) 均支持此程序。 GLWE NTT 支持经典/稀疏密钥和两种 order；NTRU NTT 支持 classic binary/ternary 和 sparse binary，共享公开提升和 BR，再逐输出返回。 [GLWE Fourier](../primus_tfhe_glwe_fourier/README.zh_CN.md#固定尺度分解式-mvb) 支持 u32/u64、Native 偶尺度、经典 binary/ternary、sparse binary 和两种 order；因子按有符号整数变换， 还须预算 FFT 误差。[NTRU Fourier](../primus_tfhe_ntru_fourier/README.zh_CN.md#固定尺度分解式-mvb) 支持相同字宽和 Native 尺度，以及 classic binary/ternary 和 sparse binary；因子同时放大加密初始化和 BR 噪声，之后逐输出 KS。 `t_out` 不必为二次幂，检查的是实际尺度。 预处理产物借用一个 context，独立 evaluator 复用工作区。 本实现不含奇数全域 MVB 和 CBS 输出；代数与噪声条件见 [MVB 设计](IMPLEMENTATION.md#factorized-mvb)。

[GLWE](../primus_tfhe_glwe_ntt/examples/mvb_thresholds.rs) 和 [NTRU](../primus_tfhe_ntru_ntt/examples/ntru_ntt_mvb_thresholds.rs) 阈值示例展示一个加密分数 生成交错容量之外的 17 个标志。交错容量和旋转余量足够时优先考虑 ManyLUT； 需要更多输出且差分因子范数较小时考虑 MVB，完整成本须按实际后端和参数测量。

## 进一步阅读

[实现说明](IMPLEMENTATION.md) · [性能取舍](IMPLEMENTATION.md#performance-decisions-and-reproducibility)
