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
| CBS → CMUX | Rounded 前半区；CMUX 控制输入为 0/1 | accumulator 秘密下的 GGSW/NGSW gadget 控制，再选择环密文 | BR + trace/SS；GLWE KS→BR 另需输入 KS | `CircuitBootstrapEvaluator`；环客户端独立使用 `AccumulatorClient` |
| One-hot CBS | 一个 padded chunk，t=2M | δ_r(m) 的 NLEV/NGSW selectors | Classic NTRU CBS 材料 | [One-hot 接口](../primus_tfhe_ntru/README.zh_CN.md#one-hot-cbs) |
| 高精度查表 | 多个独立加密、统一位宽的 chunks | 可独立指定数量的输出 chunks | Classic NTRU CBS 与返回密钥 | [高精度查表](../primus_tfhe_ntru_lut/README.zh_CN.md) |

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
| NTRU sparse fixed-weight binary | 支持 | 不支持 | 不支持 | 不支持 |

Sparse 模式需显式选择生成入口，暂不支持 sparse ternary。NTRU 的外部 LWE 秘密独立于环秘密；只有环秘密需要可逆性筛选及 Fourier 逆稳定性检查，外部固定重量可以是偶数。

## 客户端与服务端边界

`Encryptor`、`Decryptor` 及其 Boolean 包装共享编码、范围检查和无分配的 `*_to` 操作。`LweClientParameters::new(&lwe_parameters)` 借用已验证 LWE 域的维数、Rounded codec 和噪声，并从 codec 模数派生 mask 采样器。字段私有，通过访问器读取。家族构造入口先验证密钥，再一次性选定有效 LWE 秘密和噪声；两家族通过 `LweClientParameters::try_from_parts(dimension, &codec, &noise)` 绑定所选消息编码：GLWE BR→KS 使用 small LWE 的噪声和维数，KS→BR 使用提取维数和 accumulator 噪声；NTRU 使用独立外部 LWE 参数。绑定时检查 codec 与密钥、噪声的模数配对。这些检查不建立噪声或安全预算。

公共层接收 `LweSecretKeyRef` 或 `&LwePublicKey`；唯一的客户端 trait `EncryptionKey<T, M>` 只分派加密实现，不关联家族参数或错误类型。普通操作返回 `ClientError`，Boolean 操作返回 `BooleanError`。

家族入口在借用 raw view 前检查拥有型 LWE 私钥记录的模数，不匹配返回 `TfheKeyError::LweSecretKeyModulusMismatch`。直接调用公共层接收 `LweSecretKeyRef` 的构造器时，调用方须事先建立秘密的模数兼容性；raw view 无法执行该检查。绑定后的客户端保留视图，不在每条消息上重复检查拥有型密钥。

分配型加密方法返回 `LweCiphertext<T>`。客户端写入接口按值接收 `Lwe<&mut [T]>`，读取接口按值接收 `Lwe<&[T]>`：使用 `encryptor.encrypt_padded_to(message, output.as_mut_view(), rng)` 和 `decryptor.decrypt(output.as_view())`。视图只借用系数，不复制或分配；已有切片可通过 `primus_tfhe::Lwe::new` 包装，因此同一接口也支持 boxed、对齐及栈存储。Boolean 客户端遵循同样的借用方式。

求值端的单项 LWE 参数使用相同视图：`evaluator.apply_lookup_table_to(input.as_view(), &lut, output.as_mut_view())`。Boolean 门和双输入打包借用各自的操作数；CBS、one-hot 和 MVB 借用其 LWE 输入。分配型方法仍返回拥有型密文。ManyLUT/MVB 输出批次以及高精度输入/输出批次借用预先分配的 `LweCiphertext<T>` 切片。每个有效输出对应一个完整 LWE，LUT padding 不需要额外密文。每个 LWE 保留自己的系数缓冲，直接传入已有切片即可，无需打包系数或收集视图。写入输出前会检查数量和每个密文的维数。

客户端生成配套密钥，保留 setup 组合 `ClientKey`（也可通过 `into_parts()` 分开持有秘密）和加解密器，将 `ServerKey` 提供给服务端。 服务端只需公开 context、求值密钥、LUT/程序和输入密文；计算后将密文结果返回客户端。 示例在同一进程展示这些阶段，参数构造单独放置。输入和输出编码是双方约定的公开信息。

普通缓冲分配不依赖私钥：四个后端的 `context.allocate_lwe_ciphertext()` 按外部 LWE 维度分配 mask/body；`context.allocate_accumulator_ciphertext()` 按累加器布局分配系数域 GLWE/NTRU。两者只分配零存储，不执行加密。CBS 控制的布局还依赖输出分解和变换表示， 因此使用 `cbs.allocate_output()`。工作区和结果缓冲在各自一端创建一次并复用。

## 错误边界

配置和绑定入口优先使用 `try_*`，处理该入口实际返回的错误类型。`LookupTableError` 负责 LUT 编译，`TfheEvaluationError` 负责求值资源绑定；家族/后端提供参数、密钥生成、客户端和变换表错误。普通客户端操作返回 `ClientError`，Boolean 操作返回 `BooleanError`。底层原因通过 `std::error::Error::source()` 保留，详见各公开 API 的 rustdoc。

## Boolean 门

Boolean 客户端要求 `t=4`。四个 context 工厂均显式接收 Rounded codec，如下例；构造时使用相应家族的外部 LWE 模数。客户端使用 unsigned rounded `0/1` 编码的 `LweCiphertext<T>`，解密拒绝非 Boolean 值。直接构造时，将已有客户端传给 `BooleanEncryptor::try_new(encryptor)` 或 `BooleanDecryptor::try_new(decryptor)`。门求值使用普通 PBS 密钥，无需 CBS 材料。

```rust,ignore
let codec = primus_encoding::RoundedCodec::new(4, context.parameters().cipher_modulus());
let external_secret = client.external_lwe_secret_key();
let encryptor = context.boolean_encryptor(external_secret, &codec)?;
let decryptor = context.boolean_decryptor(external_secret, &codec)?;
let mut gates = context.boolean_evaluator(&server, &codec)?;
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

四后端都在同一个 CBS evaluator 中绑定输出布局与消费参数。下例为 GLWE，独立选择 Rounded 输入 codec 和 Scaled accumulator codec。NTRU 使用 `client_key.accumulator_ntru_secret_key()` 取代 GLWE 访问器，接收相同的 codec 参数，输入 codec 使用外部 q，环 codec 使用累加 Q：

```rust,ignore
// 客户端：加密两条候选消息。
let input_codec = primus_encoding::RoundedCodec::new(4, context.parameters().cipher_modulus());
let ring_codec = primus_encoding::ScaledCodec::new(8, context.parameters().cipher_modulus());
let mut ring_client = context.accumulator_client(client_key.glwe_secret_key(), ring_codec)?;
let lhs = ring_client.encrypt(&lhs_message, &mut rng);
let rhs = ring_client.encrypt(&rhs_message, &mut rng);
let mut decoded = vec![0; lhs_message.len()];

// 服务端：接收加密的输入位和候选消息，返回 selected。
let mut cbs = context.circuit_bootstrap_evaluator(&server_key, &input_codec)?;
let mut control = cbs.allocate_output();
let mut selected = context.allocate_accumulator_ciphertext();
cbs.circuit_bootstrap_to(input_bit.as_view(), &mut control);
cbs.cmux_to(&control, &lhs, &rhs, &mut selected);

// 客户端：解密返回结果。
ring_client.decrypt_to(&selected, &mut decoded);
```

`allocate_output` 返回后端原有的 GGSW/NGSW，环密文仍是系数域 GLWE/NTRU。 `cmux_to` 在控制位为 0/1 时选择 lhs/rhs；`external_product_to(control, input, output)` 也允许非 bit 的 gadget 控制。控制必须使用此 evaluator 的输出 basis、accumulator 私钥和变换表示， 候选使用该私钥/模数与相同编码。身份及噪声余量由调用方保证；所有密文长度在写输出前检查。

`AccumulatorClient` 持有已准备的 accumulator 私钥与复用转换缓冲区，并借用 context。 它使用 accumulator codec 加解密 N 个无符号系数；该环域与外部 LWE 客户端分开。 形状错误在写入或消耗随机数前 panic；明文越界可能消耗随机数。 准备失败返回 `TfheClientError`：两家族均检查密钥以及传入 Scaled codec 的模数；NTRU 还检查秘密变换。

准备一次，随后复用 `_to` 调用与输出缓冲，在线无需分配。

## 复用 evaluator

Context 保存不可变参数和变换表，ServerKey 保存求值材料；Evaluator 持有可变工作区。 编译后的 LUT/程序可以长期保留，多次调用 `_to` 写入预分配输出。

普通 PBS 与 MVB/CBS 交替时，消费已有 evaluator，避免为同一工作流同时保留两份 PBS 工作区：

- GLWE MVB：`FactorizedEvaluator::from_bootstrapper(pbs)`；NTRU MVB 使用可失败的 `try_from_bootstrapper`。
- GLWE/NTRU CBS 与 NTRU one-hot 均显式接收 CBS 材料：`CircuitBootstrapEvaluator::try_from_bootstrapper(pbs, circuit_key, &input_codec)`（one-hot 使用自己的 evaluator 类型）。
- `bootstrapper_mut()` 借用普通 PBS 操作。导入 `ProgrammableBootstrap` / `ProgrammableBootstrapInterleaved` 即可调用相应 `_to`，借用不能替换内部 evaluator。
- `into_bootstrapper()` 回收 MVB 工作区。GLWE CBS 使用 `try_into_bootstrapper(glwe_ks_key)`，复用已有输入或返回 KS 缓冲；独立 BR→KS CBS 在此分配缺失返回缓冲。NTRU CBS/one-hot 使用 `try_into_bootstrapper(return_key)`；从完整 PBS 转入时可用任意兼容返回密钥无分配恢复，并丢弃旧待提交样本；独立 CBS 在此分配缺失缓冲。

只需一种能力时使用 `context.factorized_evaluator` 或 `context.circuit_bootstrap_evaluator`。独立 GLWE BR→KS CBS 与 NTRU CBS/one-hot 省略普通返回缓冲，其 PBS 借用是 `None`，恢复时显式分配缺失缓冲。GLWE KS→BR CBS 保留必需的输入 KS，不需额外返回存储即可提供 `Some`。从完整 PBS 转入的 CBS/one-hot 始终返回 `Some`；MVB 提供直接借用。需要频繁交替则从普通 PBS 转入。构造允许分配，在线执行和借用不做隐藏分配。Boolean 的 `try_new` 接受 PBS 所有权，`into_bootstrapper` 可回收。

## LUT 与资源生命周期

后端接受具名 `TfheConfig` 并派生公共环参数，`TfheContext::try_from_parameters` 自动创建选定类型的变换表。本 crate 从 [`primus_decompose`](../primus_decompose/README.zh_CN.md) 重新导出 `DecompositionConfig`（分解基与保留层数）， 并定义 `CircuitBootstrapConfig`（独立的 output/trace/scheme-switch 配置）， 由各后端绑定自己的模数、布局与表示。`Option<CircuitBootstrapConfig>` 在配套密钥生成时选择是否启用 CBS； server key 持有对应参数和材料，各 evaluator 只持有自身工作区。

1. Family 参数描述外部 LWE 和 accumulator 环。
2. 后端 context 绑定参数与 NTT/FFT table，并生成配套的 client/server key。
3. 通过 family 参数编译 `LookupTable` / `InterleavedLookupTable`。 evaluator 创建一次，在线 `_to` 调用复用其 scratch。
4. 调用方输出分配一次，后续加密与求值重复使用同一存储。

前半区单函数或切片编译器为 `0..ceil(t_in/2)` 输入域编程，输出属于输出 codec 指定的 `0..t_out`。 其余输入不独立编程；奇数全域使用下文的独立入口。交错 LUT（ManyLUT）的有效输出数 `k` 为正， 补齐后的输出数为 `s = next_power_of_two(k)`，满足 `ceil(t/2) <= N/s`。callback 按输入优先 顺序接收 `(input, output_index)`，每个有效组合调用一次；切片包含相同顺序的 `D*k` 个值。 例如 `k=3` 时三个输出占用四个槽：编译器将第四槽置零，不调用 callback；求值端只返回三个密文。 所有输出共享一次盲旋转（BR）。GLWE 共享环 key switch 后分别提取；NTRU 每个输出分别返回并执行 LWE key switch。 输出越多，旋转分辨率与输入噪声余量越低。这是一个输入求多个函数，不是独立密文批处理。

通过两家族的 `parameters.lookup_table_compiler(&input_codec)?` 创建可复用的 `LookupTableCompiler`。TFHE 参数只保存密钥域和采样状态，不含明文模数；客户端和程序独立选择 codec。直接使用共享层时，`LookupTableCompiler::try_new(poly_length, &input_codec, accumulator_modulus, &output_codec)` 绑定相同的编码环境。它只复制所需编码状态，不分配内存，也不借用 parameters/context。方法如下：

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
| CBS | 普通 unsigned LWE 输入转为指定 gadget 尺度的 GGSW/NGSW，秘密为 accumulator secret；`0/1` 输入可生成 CMUX 控制 |

客户端 `decrypt` 使用绑定的 codec，返回 `0..t` 中的规范代表元。Centered 加密不能替代普通 LUT 的 unsigned 输入契约。PBS 保留 LUT 的输出尺度，不会自动把 Boolean 或 gadget 输出改为普通消息编码。

原始 `LweCiphertext` 不记录秘密、编码或噪声。调用方必须使用配套密钥、显式模数下的 规范系数，并保证噪声余量。LUT 与维数错误在写入输出前拒绝，但这些检查不能验证实际 秘密一致性。Fourier 密钥和 evaluator 必须使用同一 FFT table 实例。

最小 trait 为 `ProgrammableBootstrap` 和 `ProgrammableBootstrapInterleaved`。 普通应用使用参数返回的编译器，由其检查并编码明文输出。 `LookupTable::try_new` 与 `InterleavedLookupTable::try_new` 接收已编码输出和显式的 编程前缀长度，Boolean 与 CBS 通过它们使用各自的输出尺度。 兼容性检查绑定多项式长度与编码模数；输入位于已编程前缀内仍由调用方保证。 `rotation::RotationModulusSwitch` 准备 LUT 编译与盲旋转共用的逐系数模数切换，包括 ManyLUT 和 CBS 所需的旋转步长对齐。

### 选择输出编码

先选择编译器的输出编码，再使用它的函数或切片入口：

| 输出编码 | 编译器构造 | 解码 |
| --- | --- | --- |
| GLWE 默认：所选输入 codec | `parameters.lookup_table_compiler(&input_codec)?` | `decryptor.decrypt(output.as_view())` |
| NTRU 默认：输入 codec 明文模数，在 Q 下编码 | `parameters.lookup_table_compiler(&input_codec)?` | `decryptor.decrypt(output.as_view())` |
| 显式指定输出 codec | `compiler.try_with_output_codec(&codec)?` | 用返回模数下的 codec 解码 `decrypt_phase(output)` |

函数输出范围可以小于明文模数，例如 `x % 4` 仍可采用 `t=32` 编码。GLWE basic 示例使用这个默认流程：

```rust,ignore
let input_codec = primus_encoding::RoundedCodec::new(32, context.parameters().cipher_modulus());
let compiler = context.parameters().lookup_table_compiler(&input_codec)?;
let lut = compiler.compile_fn(|x| (x % 4) as u32)?;
```

`try_with_output_codec` 返回持有新 `RoundedCodec` 副本的编译器，保持输入域与累加器模数。输出 codec 决定 `t_out`，检查输出位于 `0..t_out`，并按 unsigned embedding 编码；交错 LUT 的各列共用这个 codec。密文模数不匹配时，在绑定 codec 阶段、编译之前返回 `OutputModulusMismatch`。GLWE 输入、accumulator 和返回使用同一模数；NTRU 在 Q 下编译、返回 q，解码 codec 使用 q 和同一个 `t_out`，须预算缩放舍入及返回误差。MVB 继续显式使用 unsigned `ScaledCodec`。

例如，在 NTRU 中选择 `t_in=16` 的输入 codec，用 `t_out=4` 编码 `x % 4`。片段沿用已创建的 context、客户端和 evaluator：

```rust,ignore
use primus_encoding::RoundedCodec;

let input_codec = RoundedCodec::new(16u32, context.parameters().external_lwe().cipher_modulus());
let table_codec = RoundedCodec::new(4u32, context.parameters().accumulator_ntru().cipher_modulus());
let output_codec = RoundedCodec::new(4u32, context.parameters().external_lwe().cipher_modulus());
let compiler = context.parameters().lookup_table_compiler(&input_codec)?
    .try_with_output_codec(&table_codec).unwrap();
let lut = compiler.compile_fn(|x| (x % 4) as u32).unwrap();
let input = encryptor.encrypt_padded(7u32, &mut rng).unwrap();
let output = evaluator.apply_lookup_table(input.as_view(), &lut);
let message = output_codec.decode_value(decryptor.decrypt_phase(output.as_view()).unwrap());
assert_eq!(message, 3);
```

GLWE 用 `context.parameters().cipher_modulus()` 构造输出 codec。 独立输出编码不需要额外求值密钥；保留该 codec，用于解码结果密文。

`decrypt_phase` 返回外部 LWE 秘密下的规范带噪剩余类，调用方保留输出 codec 用于解码。 LUT 兼容性元数据仍描述输入与 accumulator，不要求 `t_out = t_in`。 继续串联 PBS 时，下一次输入编码和 LUT 几何必须与上一次输出编码一致；context 不会从 raw 密文推断编码变化。自定义编码、逐列尺度及 Boolean/CBS gadget 输出使用 raw 构造器， 遵循各自的解码契约。

## 奇数全域 PBS

使用 `compiler.compile_odd_full_domain_fn(function)` 或其 `_slice` 形式；需要不同输出编码时通过 `try_with_output_codec` 配置。这些方法编程整个 **`0..t_in`**。要求奇数 `t_in >= 3`、`t_in <= N`；切片按输入顺序包含 恰好 `t_in` 个输出。输入用普通 `encrypt`，随后复用 `apply_lookup_table_to`。 默认编码用 `decrypt` 解码；显式指定输出编码时使用对应 codec。 例如，输入与 accumulator 共用密文模数、`t_in=15`，输出 codec 配置 `t_out=8`：

```rust,ignore
let input_codec = primus_encoding::RoundedCodec::new(15, context.parameters().cipher_modulus());
let compiler = context.parameters().lookup_table_compiler(&input_codec)?
    .try_with_output_codec(&output_codec).unwrap();
let lut = compiler.compile_odd_full_domain_fn(|x| ((x * x + 3) % 8) as u32).unwrap();
let input = encryptor.encrypt(14u32, &mut rng).unwrap();
evaluator.apply_lookup_table_to(input.as_view(), &lut, output.as_mut_view());
let message = output_codec.decode_value(decryptor.decrypt_phase(output.as_view()).unwrap());
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

[GLWE NTT](../primus_tfhe_glwe_ntt/README.zh_CN.md#固定尺度分解式-mvb) 与 [NTRU NTT](../primus_tfhe_ntru_ntt/README.zh_CN.md#固定尺度分解式-mvb) 均支持此程序。 GLWE NTT 支持经典/稀疏密钥和两种 order；NTRU NTT 共享加密初始化和 BR，再逐输出 KS。 [GLWE Fourier](../primus_tfhe_glwe_fourier/README.zh_CN.md#固定尺度分解式-mvb) 支持 u32/u64、Native 偶尺度、经典 binary/ternary、sparse binary 和两种 order；因子按有符号整数变换， 还须预算 FFT 误差。[NTRU Fourier](../primus_tfhe_ntru_fourier/README.zh_CN.md#固定尺度分解式-mvb) 支持相同字宽和 Native 尺度，秘密为 binary/ternary；因子同时放大加密初始化和 BR 噪声，之后逐输出 KS。 `t_out` 不必为二次幂，检查的是实际尺度。 预处理产物借用一个 context，独立 evaluator 复用工作区。 本实现不含奇数全域 MVB 和 CBS 输出；代数与噪声条件见 [MVB 设计](IMPLEMENTATION.md#factorized-mvb)。

[GLWE](../primus_tfhe_glwe_ntt/examples/mvb_thresholds.rs) 和 [NTRU](../primus_tfhe_ntru_ntt/examples/ntru_ntt_mvb_thresholds.rs) 阈值示例展示一个加密分数 生成交错容量之外的 17 个标志。交错容量和旋转余量足够时优先考虑 ManyLUT； 需要更多输出且差分因子范数较小时考虑 MVB，完整成本须按实际后端和参数测量。

## 进一步阅读

[实现说明](IMPLEMENTATION.md) · [常用 PBS 基准参数](BENCHMARKS.md) · [性能取舍](IMPLEMENTATION.md#performance-decisions-and-reproducibility)
