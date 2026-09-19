# primus_tfhe

[English](README.md) | 简体中文

公共 LUT 编译、编码元数据、PBS trait 及 Boolean 门求值层，供 GLWE 和 NTRU 两族复用。
Boolean evaluator 持有门 LUT 与 LWE 工作区；客户端密钥、变换 table 和环求值工作区仍由各自层管理。
完整使用流程从下面的后端示例开始。

## Crate 分工与能力

| Family | NTT 后端 | Fourier 后端 |
| --- | --- | --- |
| [GLWE 参数与客户端](../primus_tfhe_glwe/README.zh_CN.md) | [GLWE NTT](../primus_tfhe_glwe_ntt/README.zh_CN.md) | [GLWE Fourier](../primus_tfhe_glwe_fourier/README.zh_CN.md) |
| [NTRU 参数与客户端](../primus_tfhe_ntru/README.zh_CN.md) | [NTRU NTT](../primus_tfhe_ntru_ntt/README.zh_CN.md) | [NTRU Fourier](../primus_tfhe_ntru_fourier/README.zh_CN.md) |

| 后端 | 密文模数 | PBS / ManyLUT | 分解式 MVB | Boolean 门 | CBS |
| --- | --- | --- | --- | --- | --- |
| GLWE NTT | 显式域模数 | 支持 | 支持 | 支持 | 支持 |
| GLWE Fourier | 原生 torus | 支持 | 偶尺度，u32/u64 | 支持 | 支持 |
| NTRU NTT | 显式域模数 | 支持 | 支持 | 支持 | 支持 |
| NTRU Fourier | 原生 torus | 支持 | 偶尺度，u32/u64 | 支持 | 支持 |

四后端均支持私钥和 LWE 公钥客户端。Fourier 后端支持 RustFFT 与 TfheFFT。
参数和 API 仍处于实验阶段；示例及 benchmark fixture 不是生产安全参数或失败概率建议。

GLWE 和 NTRU 两后端的经典 PBS、CBS、MVB 均支持 binary/ternary 输入秘密；
NTRU 客户端秘密还需通过后端的可逆性筛选。

GLWE 两后端均支持固定重量二元 small 秘密的实验性稀疏 PBS：两种 order、普通/交错/分解式 LUT。
[NTT](../primus_tfhe_glwe_ntt/README.zh_CN.md#实验性稀疏-pbs) 使用精确变换，
[Fourier](../primus_tfhe_glwe_fourier/README.zh_CN.md#实验性稀疏-pbs) 使用 Native 系数域聚合。
两后端均支持 sparse CBS；sparse ternary 尚不支持。

NTRU [NTT](../primus_tfhe_ntru_ntt/README.zh_CN.md#实验性稀疏-pbs) 和
[Fourier](../primus_tfhe_ntru_fourier/README.zh_CN.md#实验性稀疏-pbs) 稀疏 PBS
支持固定重量二元客户端的普通/交错 LUT；Fourier 要求奇数重量及稳定逆元。两者均拒绝 sparse CBS/MVB。

## 错误边界

错误按操作职责命名，从 crate 根导出；按调用的操作处理相应错误类型。

| 操作 | 错误 |
| --- | --- |
| LUT 编译 / 普通、Boolean 或 CBS evaluator 绑定 | 公共 `LookupTableError` / `TfheEvaluationError` |
| TFHE / CBS 参数准备 | Family `TfheParameterError` / `CircuitBootstrapParameterError` |
| Client key 兼容性 / 客户端操作 | Family `TfheKeyError` / `TfheClientError` |
| Boolean 客户端构造、加密和解密 | Family `BooleanError`；`Client` 分支保留底层客户端错误 |
| 常规/稀疏 server、稀疏 BSK 或独立 CBS 密钥生成 | Family `KeyGenerationError`；NTRU 采样/变换直接进入 `Ntru` 分支；稀疏失败进入 `SparseBootstrapping` |
| NTRU accumulator 客户端构造 | Family `TfheClientError`；`Ntru` 分支保留秘密转换失败 |
| 自动建表或显式绑定表 | 后端 `TfheContextError`；`TransformTable` 保留底层 FFT/NTT 错误 |

`KeyGenerationError::ClientKey` 直接报告客户端不兼容；稀疏失败的 `BucketMap` 分支保留映射原因。

## Boolean 门

参数采用 `t=4` 时，四后端 context 均提供 `boolean_encryptor(key)`、
`boolean_decryptor(client)` 和 `boolean_evaluator(server)`。加密器接受私钥或 LWE 公钥，
解密器需要 client secret；直接使用 unsigned rounded `0/1` 编码的 `LweCiphertext<T>`，
解密拒绝非 Boolean 值。门求值使用普通 PBS 密钥，无需 CBS 材料。

```rust,ignore
let encryptor = context.boolean_encryptor(&client)?;
let decryptor = context.boolean_decryptor(&client)?;
let mut gates = context.boolean_evaluator(&server)?;
let lhs = encryptor.encrypt(true, &mut rng)?;
let rhs = encryptor.encrypt(false, &mut rng)?;
let mut output = LweCiphertext::zero(context.parameters().external_lwe_dimension());
let mut next = LweCiphertext::zero(output.dimension());
gates.evaluate_binary_to(BooleanGate::Nand, &lhs, &rhs, &mut output);
assert!(decryptor.decrypt(&output)?);
gates.mux_to(&output, &rhs, &lhs, &mut next);
core::mem::swap(&mut output, &mut next);
assert!(!decryptor.decrypt(&output)?);
```

`BooleanEvaluator` 在两族间共享仿射预处理、内部模 8 正负 LUT 和恢复输出编码的平移。
二元门使用一次 PBS，NOT 无需 PBS，MUX 使用两次。通过 `evaluate_binary_to`、`not_to`、
`mux_to` 和已有输出复用存储。
输出保持外部 Boolean 编码，可直接送入后续门。
客户端维数错误返回 `BooleanError::Client`，门求值维数错误则 panic。
原始密文不携带密钥身份或编码元数据，这些仍由调用方保证。

`BooleanEvaluator::try_new(dimension, poly_length, input_codec, coefficient_modulus, bootstrapper)`
是自定义后端入口；调用方须保证参数绑定正确、后端保留 LUT 输出尺度。
构造返回 `TfheEvaluationError`：输入明文模数不是 4，或显式密文模数不大于 8 时返回
`InvalidBooleanEncoding`。

## CBS 输出与消费

四后端都在同一个 CBS evaluator 中绑定输出布局与消费参数：

```rust,ignore
let mut cbs = context.circuit_bootstrap_evaluator(&server)?;
let mut accumulator = context.accumulator_client(&client)?;
let choices = [accumulator.encrypt(&lhs, &mut rng), accumulator.encrypt(&rhs, &mut rng)];
let mut control = cbs.allocate_output();
let mut selected = accumulator.allocate_ciphertext();
let mut decoded = vec![0; lhs.len()];

cbs.circuit_bootstrap_to(&input_bit, &mut control);
cbs.cmux_to(&control, &choices[0], &choices[1], &mut selected);
accumulator.decrypt_to(&selected, &mut decoded);
```

`allocate_output` 返回后端原有的 GGSW/NGSW，环密文仍是系数域 GLWE/NTRU。
`cmux_to` 在控制位为 0/1 时选择 lhs/rhs；`external_product_to(control, input, output)`
也允许非 bit 的 gadget 控制。控制必须使用此 evaluator 的输出 basis、accumulator 私钥和变换表示，
候选使用该私钥/模数与相同编码。身份及噪声余量由调用方保证；所有密文长度在写输出前检查。

`AccumulatorClient` 持有已准备的 accumulator 私钥与复用转换缓冲区，并借用 context。
它使用 accumulator codec 加解密 N 个无符号系数；该环域与外部 LWE 客户端分开。
形状错误在写入或消耗随机数前 panic；明文越界可能消耗随机数。
NTRU 准备的密钥校验/变换失败返回 `KeyGenerationError`，GLWE 准备返回 `TfheKeyError`。

准备一次，随后复用 `_to` 调用与输出缓冲，在线无需分配。

## LUT 与资源生命周期

后端接受具名 `TfheConfig` 并派生公共环参数，`TfheContext::try_from_parameters`
自动创建选定类型的变换表。本 crate 提供 `DecompositionConfig`（分解基与保留层数）
及 `CircuitBootstrapConfig`（独立的 output/trace/scheme-switch 配置），
由各后端绑定自己的模数、布局与表示。`Option<CircuitBootstrapConfig>` 在配套密钥生成时选择是否启用 CBS；
server key 持有对应参数和材料，各 evaluator 只持有自身工作区。

1. Family 参数描述外部 LWE 和 accumulator 环。
2. 后端 context 绑定参数与 NTT/FFT table，并生成配套的 client/server key。
3. 通过 family 参数 编译 `LookupTable` / `InterleavedLookupTable`。
   evaluator 创建一次，在线 `_to` 调用复用其 scratch。
4. 调用方输出分配一次，后续加密与求值重复使用同一存储。

前半区单函数或切片编译器为 `0..ceil(t_in/2)` 输入域编程，输出属于输出 codec 指定的 `0..t_out`。
其余输入不独立编程；奇数全域使用下文的独立入口。交错 LUT（ManyLUT）的有效输出数 `k` 为正，
补齐后的输出数为 `s = next_power_of_two(k)`，满足 `ceil(t/2) <= N/s`。callback 按输入优先
顺序接收 `(input, output_index)`，每个有效组合调用一次；切片包含相同顺序的 `D*k` 个值。
例如 `k=3` 时三个输出占用四个槽：编译器将第四槽置零，不调用 callback；求值端只返回三个密文。
所有输出共享一次盲旋转（BR）和密钥切换，再分别提取。
输出越多，旋转分辨率与输入噪声余量越低。这是一个输入求多个函数，不是独立密文批处理。

直接使用共享层时，`LookupTable` / `InterleavedLookupTable` 的 `try_from_fn`、`try_from_slice`
接收输入 codec、累加器模数和输出 codec，负责 unsigned Rounded 编码与检查。
奇数全域使用 `LookupTable::try_from_odd_full_domain_fn` / `_slice`；family 编译入口复用这些方法。

Raw 构造器 `LookupTable::try_new` / `InterleavedLookupTable::try_new` 显式接收
编程前缀长度 `D` 和已编码输出。`input_ciphertext_modulus` 描述输入量化模数，
`coefficient_modulus` 描述 LUT/累加器模数，raw 输出必须是后者下的规范值。
`k` 和明文模数都不必是二次幂；补齐数量 `s` 必须与容量、实际中心分离和噪声余量相容。
构造失败不会返回部分表。输出槽、重复区间与舍入规则见[旋转布局设计](../../docs/tfhe.md#前半区旋转布局)。

## 编码与密钥契约

| 接口 | 输入 / 输出含义 |
| --- | --- |
| 普通 `encrypt` | `0..t` 范围的 unsigned 消息 |
| `encrypt_padded` | 相同 unsigned 尺度，输入限制为 `0..ceil(t/2)`，供前半区 LUT 使用 |
| `encrypt_centered` | 接收 `0..t` 的模代表元；上半区表示负数，例如 `t=4` 时 `3` 表示 `-1` |
| 两族 Boolean | 外部 `false/true` 对应模 4 下的 `0/1`；内部 LUT 使用 rounded 模 8 尺度的正负值，随后平移恢复外部编码 |
| CBS | 普通 unsigned LWE 输入转为指定 gadget 尺度的 GGSW/NGSW，秘密为 accumulator secret；`0/1` 输入可生成 CMUX 控制 |

客户端 `decrypt` 使用参数 codec，返回 `0..t` 中的规范代表元。Centered 加密不能替代普通 LUT 的 unsigned
输入契约。PBS 保留 LUT 的输出尺度，不会自动把 Boolean 或 gadget 输出改为普通消息编码。

原始 `LweCiphertext` 不记录秘密、编码或噪声。调用方必须使用配套密钥、显式模数下的
规范系数，并保证噪声余量。LUT 与维数错误在写入输出前拒绝，但这些检查不能验证实际
秘密一致性。Fourier 密钥和 evaluator 必须使用同一 FFT table 实例。

最小 trait 为 `ProgrammableBootstrap` 和 `ProgrammableBootstrapInterleaved`。
普通应用使用 参数 编译入口，由其检查并编码明文输出。
`LookupTable::try_new` 与 `InterleavedLookupTable::try_new` 接收已编码输出和显式的
编程前缀长度，Boolean 与 CBS 通过它们使用各自的输出尺度。
兼容性检查绑定多项式长度与编码模数；输入位于已编程前缀内仍由调用方保证。
`rotation` 集中 LUT 编译与 BR 执行共用的旋转量化契约。

### 选择输出编码

两族参数 的普通和交错 LUT 编译方法以 `&RoundedCodec<T, M>` 为第一个参数。
输入参数决定旋转中心，并与所选编译模式共同决定输入域；
输出 codec 决定 `t_out`，检查输出位于 `0..t_out`，并按 unsigned embedding 编码。
交错 LUT 的各列共用这个 codec。其密文模数必须与 accumulator 一致，否则返回
`OutputModulusMismatch`。现有完整 PBS 链仍要求 `q_in = q_acc = q_out`；
选择不同的明文模数不会改变密文模数。

例如，在 `t_in=16` 的 NTRU context 中，用 `t_out=4` 编码 `x % 4`：

```rust
use primus_encoding::RoundedCodec;

let output_codec = RoundedCodec::new(4u32, context.parameters().external_lwe().cipher_modulus());
let lut = context.parameters().compile_lookup_table_fn(&output_codec, |x| (x % 4) as u32).unwrap();
let input = encryptor.encrypt_padded(7u32, &mut rng).unwrap();
let output = evaluator.apply_lookup_table(&input, &lut);
let message = output_codec.decode_value(decryptor.decrypt_phase(&output).unwrap());
assert_eq!(message, 3);
```

GLWE 用 `context.parameters().accumulator_glwe().cipher_modulus()` 构造输出 codec。
沿用参数编码时，传入 `input_plaintext_codec()`，随后仍可用普通 `decrypt`。
各后端 basic 示例展示了无需额外密钥的独立输出编码。

`decrypt_phase` 返回外部 LWE 秘密下的规范带噪剩余类，调用方保留输出 codec 用于解码。
LUT 兼容性元数据仍描述输入与 accumulator，不要求 `t_out = t_in`。
继续串联 PBS 时，下一次输入编码和 LUT 几何必须与上一次输出编码一致；context 不会从
raw 密文推断编码变化。自定义编码、逐列尺度及 Boolean/CBS gadget 输出使用 raw 构造器，
遵循各自的解码契约。

## 奇数全域 PBS

使用 `compile_odd_full_domain_lookup_table_fn(&output_codec, function)` 或其 `_slice`
形式，编程整个 **`0..t_in`**。要求奇数 `t_in >= 3`、`t_in <= N`；切片按输入顺序包含
恰好 `t_in` 个输出。输入用普通 `encrypt`，随后复用 `apply_lookup_table_to` 和输出 codec 解码。
例如，context 配置 `t_in=15`，输出 codec 配置 `t_out=8`：

```rust,ignore
let lut = context.parameters().compile_odd_full_domain_lookup_table_fn(
    &output_codec, |x| ((x * x + 3) % 8) as u32,
).unwrap();
let input = encryptor.encrypt(14u32, &mut rng).unwrap();
evaluator.apply_lookup_table_to(&input, &lut, &mut output);
let message = output_codec.decode_value(decryptor.decrypt_phase(&output).unwrap());
assert_eq!(message, 7);
```

raw 入口为 `LookupTable::try_new_odd_full_domain`。它计算真实中心
`c[m] = R(E(m), q_in, 2N)`，将 `N..2N` 中心减去 `N` 并写入取负后的输出，
提取时的负循环符号将其恢复。折叠中心按 `0, (t+1)/2, 1, (t+3)/2, ...` 输入顺序排列，
callback 按此顺序各调用一次。区间取最近中心、中点取较大中心；`N` 处补 `-f(0)`，
处理回绕。即使 `t_in <= N`，折叠中心碰撞仍返回 `RotationCenterCollision`。

典型中心间距为 `N/t_in`，噪声余量约为前半区编译的一半。容量与碰撞检查只保证 LUT
几何可表示，不提供 PBS 失败概率；仍需计入输入误差和逐系数模切误差。
此入口仅支持单输出奇数全域，交错与双输入编译器保持前半区契约；无需新增密钥或在线 evaluator。
[推导与参数示例](../../docs/tfhe.md#p23-奇数明文模数全域)说明符号折叠及其限制。

## 有界双输入 PBS

`BivariateLookupTable::try_new(B, R, N, input_codec, output_codec, function)`
通过 `z = x + B*y` 编译 `0 <= x < B`、`0 <= y < R` 上的 `f(x,y)`。
`B`、`R` 必须为正，`D = B*R <= ceil(t_in/2)`，并满足普通 LUT 的容量和旋转中心检查。
只编译 `0..D` 前缀，回调按 `x` 优先变化的顺序求值；`B` 不必是二次幂。
输出 codec 独立选择 `t_out`，但必须使用相同密文模数。
这个共享类型适用于四个后端，不持有密钥或 scratch。

例如，对 `t_in=16` 的 NTRU context 复用已有客户端和 evaluator：

```rust
use primus_tfhe::BivariateLookupTable;

let compare = BivariateLookupTable::try_new(
    3, 2, context.parameters().poly_length(),
    context.parameters().input_plaintext_codec(),
    &output_codec, |x, y| u32::from(x > y),
).unwrap();
let lhs = encryptor.encrypt_padded(2u32, &mut rng).unwrap();
let rhs = encryptor.encrypt_padded(1u32, &mut rng).unwrap();
compare.pack_to(&lhs, &rhs, &mut packed);
evaluator.apply_lookup_table_to(&packed, compare.lookup_table(), &mut output);
assert_eq!(output_codec.decode_value(decryptor.decrypt_phase(&output).unwrap()), 1);
```

按外部 LWE 维数一次性分配 `packed` 和 `output`。
`pack_to` 用一遍模乘加写入 `lhs + B*rhs`，不分配内存；长度不同或缺少 body 时在写入前拒绝。
两输入必须具有相同的实际秘密、密文模数及传入的 unsigned 输入 codec，系数规范、明文不超出各自边界。
raw 密文无法验证这些语义条件。GLWE 使用其 order 对应的外部维数与
`input_plaintext_codec()`，无需增加密钥材料。

即使不考虑加密噪声，也不能忽略编码舍入。令 `E(m)=round(m*q/t_in)`，打包相位为
`E(x+B*y) + e_x + B*e_y + rho` 模 `q`，其中
`rho = E(x)+B*E(y)-E(x+B*y)`。`t_in` 整除 `q` 时 `rho=0`，否则可用保守界
`|rho| <= (B+2)/2`（密文单位）。PBS 输入噪声预算需计入这个偏差、放大的输入误差、
BR 前可能发生的密钥切换误差及逐系数模切舍入。容量条件防止明文索引回绕，不能证明噪声余量。
这是有界单输出工作流，不是任意精度整数运算或 LWE 到环密文的 packing。
完整运行示例见 [NTRU NTT](../primus_tfhe_ntru_ntt/examples/ntru_ntt_basic.rs)。

## 固定尺度分解式 MVB

`FactorizedLookupTable::try_new(D, N, output_count, input_codec, output_codec, function)`
使用 Rounded 输入和 unsigned Scaled 输出编译非空前半区前缀。系数模数可以显式且为奇数，
或为 Native 且实际 Scaled 输出尺度为偶数；显式偶模数仍不支持。
对每个未缩放整数 LUT `p_i`，保存 `W_i=(1-X)*p_i` 和共同多项式 `V=A*sum(X^j)`；
奇数 q 使用 `A=delta*inv2 mod q`，Native 使用整数 `A=delta/2`，满足 `V*W_i=delta*p_i`。
callback 每个组合调用一次，参数为 `(input, output_index)`，**外层遍历输出索引**。
因子以模 q 的规范 residue 保存，不在明文模数下约简；有符号整数 lift 决定噪声放大。

全部输出共享一次步长为 1 的 BR，再分别乘公开多项式。正输出数不补齐、不降低输入容量；
代价是各输出的因子会放大 BR 噪声，输入几何检查不能代替噪声预算。解密相位须使用保留的
Scaled codec；接入下一次 Rounded 输入 PBS 时须计入编码中心差异。

[GLWE NTT](../primus_tfhe_glwe_ntt/README.zh_CN.md#固定尺度分解式-mvb) 与
[NTRU NTT](../primus_tfhe_ntru_ntt/README.zh_CN.md#固定尺度分解式-mvb) 均支持此程序。
GLWE NTT 支持经典/稀疏密钥和两种 order；NTRU NTT 共享加密初始化和 BR，再逐输出 KS。
[GLWE Fourier](../primus_tfhe_glwe_fourier/README.zh_CN.md#固定尺度分解式-mvb)
支持 u32/u64、Native 偶尺度、经典 binary/ternary、sparse binary 和两种 order；因子按有符号整数变换，
还须预算 FFT 误差。[NTRU Fourier](../primus_tfhe_ntru_fourier/README.zh_CN.md#固定尺度分解式-mvb)
支持相同字宽和 Native 尺度，秘密为 binary/ternary；因子同时放大加密初始化和 BR 噪声，之后逐输出 KS。
`t_out` 不必为二次幂，检查的是实际尺度。
预处理产物借用一个 context，独立 evaluator 复用工作区。
本实现不含奇数全域 MVB 和 CBS 输出；代数与噪声条件见 [MVB 设计](../../docs/tfhe-mvb.md)。

[GLWE](../primus_tfhe_glwe_ntt/examples/mvb_thresholds.rs) 和
[NTRU](../primus_tfhe_ntru_ntt/examples/ntru_ntt_mvb_thresholds.rs) 阈值示例展示一个加密分数
生成交错容量之外的 17 个标志。算法选择参考 [GLWE 成本](../../docs/tfhe-mvb.md#8-p43-测量与应用选择)
和 [NTRU 成本](../../docs/tfhe-mvb-ntru.md)（NTT），以及 [Fourier 成本](../../docs/tfhe-mvb-fourier-costs.md)。

## 保留模数类型的旋转量化

raw LUT 编译接收独立的输入模数类型和系数模数类型。
`rotation::RotationQuantizer::new(input_modulus, two_n, rotation_step)` 准备固定
模数对的转换，`exponent(value)` 无分配复用。旋转域 `two_n = 2N` 必须能由输入
系数类型表示；即使输入使用 Native 模数，目标 `two_n/rotation_step` 也为显式二次幂。
交错旋转先在 `two_n/rotation_step` 个位置内舍入，再乘与 LUT 补齐输出数相等的
`rotation_step`。完整几何及准备阶段的实现见[设计文档](../../docs/tfhe.md#p11-精确几何与元数据)。

## 进一步阅读

[实现设计与开发验证](../../docs/tfhe.md) · [基准与测量](../../docs/benchmarks/tfhe.md)
