# TFHE 参数职责与模块边界

本文说明参数来源、数据域和构造检查的归属。已有接口的基础用法见[库使用导航](README.zh_CN.md)，具体数值前提以对应 rustdoc 为准。这里没有提供生产参数、失败概率或性能结论。

## 参数与密钥域

以 q 表示外部 LWE 模数、Q 表示累加环模数，n 表示盲旋转控制秘密的 LWE 维数，N 表示环长度，k 表示 GLWE 秘密多项式数。

已验证的参数、size 和工作区沿调用链传递 `LweDimension`、`GlweDimension`、`primus_poly::PolyLength`；分解参数使用 `DecompositionBaseLog` 和 `DecompositionLevelCount`。组合长度由拥有布局的构造边界检查。Raw 存储和数值内核使用整数，不从存储长度推断模数、秘密或表示身份。

| 对象 | 独立选择 | 派生或绑定内容 |
| --- | --- | --- |
| `LweParametersInner` | n、q、秘密分布、系数噪声标准差 | n+1 密文长度可表示；秘密/噪声 sampler，无 codec |
| `LweParameters` | n、t、q、秘密分布、系数噪声标准差 | n+1 密文长度可表示；Rounded codec、秘密/噪声 sampler；t 从 codec 读取 |
| `GlweParameters` | k、N、t、Q、环秘密分布、系数噪声 | `GlweSize`、Scaled codec、`GlweParametersInner`；固定重量作用于整个 kN 秘密 |
| `NtruParameters` | N、t、Q、环秘密分布、系数噪声 | Scaled codec、共享 `NtruParametersInner`；固定重量作用于整个 N 系数秘密；不预先证明秘密可逆 |
| `DecompositionConfig` | `log_basis`、`level_count` | 绑定 q 或 Q 后生成 `ApproxSignedBasis`；`None` 表示保留全部可用层，不等于零分解残差 |
| `GlevParameters` / `GgswParameters` | `GlweSize`、共享模数/采样状态、该运算的 basis | 固定秘密重量、basis 模数和 gadget 布局；无需普通消息 codec |
| `NlevParameters` | 共享 NTRU 环/采样状态和该运算的 basis | basis 模数、N*L 布局和层序；无需普通消息 codec |
| `TfheConfig` → `TfheParameters` | 家族特定的 LWE/环配置、BR/KS 分解、PBS order（GLWE） | 同域检查与派生返回布局；消息编码由程序/client 绑定；NTT/Fourier 表由后端 context 绑定 |
| `CircuitBootstrapConfig` → `CircuitBootstrapParameters` | output、trace、scheme-switch 三个 basis；后两者各自的噪声 | 环大小/模数继承累加环，输出布局由 output basis 派生；interleaved 容量由程序绑定检查 |
| `LookupTableConfig` | 输入 chunk 数 c、输出 chunk 数 o、低位系数 chunk 数 d | `M=t/2`、每个多项式的有效系数数 `M^d`、每输出多项式数 `M^(c-d)`，以及完整存储长度 |

入口：[LWE](../../crates/primus_lwe/src/parameter.rs)、[GLWE](../../crates/primus_glwe/src/parameter/ordinary.rs)、[NTRU](../../crates/primus_ntru/src/parameter/ordinary.rs)、[分解](../../crates/primus_decompose/src/parameters.rs)、[GLWE TFHE](../../crates/primus_tfhe_glwe/src/parameters.rs)、[NTRU TFHE](../../crates/primus_tfhe_ntru/src/parameters.rs)。

所有这些配置的噪声标准差均以对应模数下的**系数单位**表示；Fourier 内部将环系数转为归一化 torus，不改变配置输入的单位。BR、返回 KS、trace、scheme switch 的误差来源不同。GLWE 普通 BR/KS 当前继承 accumulator 噪声；NTRU 的返回 KS 单独选择 q 下的噪声。CBS 的 trace 和 scheme-switch 噪声独立于普通 PBS。

## GLWE 普通与 gadget 参数组合

| 资料 | 拥有者与检查边界 |
| --- | --- |
| k、N 和组合长度 | `GlweSize`；`GadgetSize` 再绑定分解层数并检查 GLev/GGSW 长度 |
| 密文模数、mask sampler、noise sampler | `GlweParametersInner`；构造时验证噪声及秘密支持界。Mask/noise 同时服务普通加密和求值密钥行加密 |
| secret sampler | 同一 `GlweParametersInner` 保存预计算，供秘密生成；与布局组合时检查完整 kN 上的固定重量 |
| gadget basis | `GlevParameters` 拥有，构造时核对其模数；与普通消息 t 无关 |
| 普通消息 codec | `GlweParameters` 独立拥有 `ScaledCodec`，组合时检查密文模数匹配；恢复条件由 codec 构造器验证 |

`GlevParameters::try_from_parts(size, Arc<GlweParametersInner>, basis)` 可直接构造 GLev/GGSW 参数。`GlweParameters::try_from_parts(size, shared_inner, codec)` 只在需要普通消息编码时组合 codec。两种入口都消费已经准备好的部件，不复制采样表、不重建 basis；独立布局与采样状态之间的固定重量检查仍由组合入口负责。既有 `try_with_basis` / `try_with_glwe_params` 适用于从已有普通参数派生 gadget，继续共享同一 Arc。

TFHE 的 BSK 共享 accumulator 的布局和采样状态。KS 目标直接组合补零后的布局、small-secret 分布、accumulator 噪声与 KS basis；不创建临时普通 GLWE codec。CBS trace 和 scheme-switch 同样直接组合 gadget 参数，分别准备各自噪声的状态。普通 GLWE 加密、client Rounded 编码与 LUT 几何各自的检查仍保留在原有边界。

## NTRU 普通与 gadget 参数组合

`NtruParametersInner` 绑定 N、Q、秘密 sampler 和系数单位噪声，不保存 codec，也没有 GLWE 的 mask sampler。NTRU 的完整秘密长度就是 N，固定重量和支持界在 inner 构造时检查；补零密钥生成另检查活跃前缀。可逆性、最多 1024 次候选重试、Fourier 逆元稳定性仍归密钥生成。

`NlevParameters::try_from_parts(Arc<NtruParametersInner>, basis)` 检查 basis/Q 和 N*L；`NtruParameters::try_from_parts(shared_inner, codec)` 检查 codec/Q，固定尺度恢复条件由 codec 自身保证。两者 `inner()` 均借用同一状态。密钥生成、encoded/zero 加密只需 inner；普通加解密仍使用含 codec 的参数。`try_with_basis` / `try_with_ntru_params` 是从普通参数派生 gadget 的便捷入口，只复制 Arc，不复制采样表。NLev 克隆仍复制其独立 basis；没有把秘密系数或 RNG 放入共享状态。

TFHE 显式拥有普通 accumulator 参数以及共享其 inner 的 BR 参数。直接组合入口接收 `external_lwe, accumulator_ntru, blind_rotation_basis, key_switching, key_switching_noise_standard_deviation`，继续检查共同 t 和 2N 可表示性。CBS trace/scheme-switch 直接构造无 codec 的 NLev，每个噪声角色独立准备 inner。构造分配、保留内存与在线加密的对比见[采样状态共享测量](workspaces-and-storage.md#ntru-parameter-sharing)。

## RNS 普通与 gadget 参数组合

`CrtGlweParametersInner` 绑定 `RnsGlweSize`、有序 Q 对应的 mask sampler、秘密 sampler 和系数噪声；固定重量按完整 kN 检查，秘密及噪声支持必须适用于每个 q_i。它只借用 `RNSBase` 准备采样缓存，不拥有另一份 base 或 converter。

`CrtGlevParameters::try_from_parts(Arc<CrtGlweParametersInner>, base_q, basis)` 检查缓存与 base 的模数数量及顺序、basis 的精确乘积和 limb 宽度、逐模数的 centered-lift radix 条件，以及 `RnsGadgetSize` 组合长度。它拥有传入的 base、basis 和各层 CRT 权重，不需要 t/gamma。普通 `CrtGlweParameters::try_from_parts(shared_inner, codec)` 则检查 codec 的有序 Q，并用共享噪声采样器的最大幅度验证新鲜私钥密文的 BFV 恢复条件；这不包含公钥或求值的附加噪声。

两种参数都通过 `inner()` 借用共享状态。公钥生成接收 inner、base 和 table；普通 DCRT key switch 接收 input inner 和 output gadget domain，输出噪声来自 domain；hybrid key switch 沿用 input inner 的密钥噪声，并额外检查辅助 P 模数的支持界。这些生成流程均不依赖 BFV codec，秘密缓冲擦除及采样顺序保持不变。`try_with_glwe_params` 从普通参数派生 gadget，共享 sampler 和 RNSBase 的不可变表；codec 内的转换器也共享该基。基内部集中有序模数值缓存，外层继续各自拥有基句柄、BFV/gadget 权重及转换矩阵；在线借用不 clone Arc。具体取舍见[存储说明](workspaces-and-storage.md#rns-base-sharing)。

三个方案共同遵循“采样状态 + gadget basis”与“采样状态 + 普通 codec”的组合规则，但布局检查保留各方案差异：GLWE inner 不绑定 k/N，固定重量由组合入口检查；NTRU inner 绑定 N；RNS inner 绑定 k/N/模数数量和缓存顺序。不能仅凭乘积 Q 相等认为 RNS 缓冲兼容，也不能把 GLWE 的 mask sampler 套用到 NTRU。组合检查都在构造边界，在线 kernel 沿用已经建立的不变量。

## 配置、绑定与工作区的职责

| 角色 | 保存或执行的内容 |
| --- | --- |
| `Config` | 调用方的独立选择；不保证组合已经有效 |
| `Parameters` | 已验证的数学域、派生布局、codec、basis 和 sampler |
| `Context` | 绑定家族参数与不可变 NTT/FFT 表；保留便捷工厂及公开布局的输出分配入口 |
| `Workspace` | 特定算法可复用的临时存储；不拥有客户端秘密或自行选择参数 |
| `KeyGenerator` / `AccumulatorClient` | 绑定 context，准备密钥生成或环客户端所需的表示和 scratch |
| `Evaluator` | 绑定 context、服务端密钥和对应算法工作区，执行在线同态运算 |

`ClientKey` 是生成服务端材料的拥有型 setup 组合，`check_compatible` 校验整套秘密。普通加解密、Boolean 客户端和 LWE 公钥生成改为接收外部秘密；`AccumulatorClient` 只接收系数域累加秘密。工厂绑定之后仍借用 raw view 执行，不复制秘密、不逐消息检查，也不扫描无关秘密。

| 客户端角色 | 最小秘密输入 | 绑定与生成的检查 |
| --- | --- | --- |
| GLWE BR→KS 外部消息 | `ExternalLweSecretKey::SmallLwe(&LweSecretKey)` | order、n、q、分布与 binary/ternary 系数 |
| GLWE KS→BR 外部消息 | `ExternalLweSecretKey::ExtractedGlwe(&GlweSecretKey)` | order、k/N 与分布；借用 signed kN 系数，幅度界继承 raw LWE 契约 |
| NTRU 外部消息 | `&LweSecretKey` | n、外部 q、分布与 binary/ternary 系数；不依赖 f 或 Q |
| GLWE/NTRU 环消息 | `&GlweSecretKey` / `&NtruSecretKey` | 累加布局、分布、Scaled codec 的 Q；按后端转换秘密并准备私有 scratch |
| 服务端密钥生成 | 完整 `&ClientKey` | 保留整套 setup 检查；NTRU 还检查 f 在返回 q 下的幅度界及变换可逆性 |

`ClientKey::external_lwe_secret_key()` 提供便捷借用；GLWE 的借用枚举保留 owner 元数据到绑定，不是新的身份系统。独立持有的秘密可直接传入工厂；`into_parts()` 只移动 buffer。LWE 公钥生成位于 `parameters.try_generate_public_key(external_secret, rng)`。Accumulator client 不要求外部 LWE 的返回界；NTT 输入系数的幅度、NTT roots/order 和实际秘密身份继续由调用方承担。

四个后端的 `TfheContext` 工厂仍可从同一入口调用，其 inherent impl 按职责放在 client、accumulator、key、sparse/key、CBS、factorized 或 boolean 模块。`context.rs` 保留参数/表绑定、访问器及公共布局分配，避免混入各功能的实现依赖。NTT/Fourier 和 GLWE/NTRU 的数值契约仍各自独立。

[共享客户端参数](../../crates/primus_tfhe/src/client/parameters.rs)从已验证的 `LweParameters` 构造，字段私有，mask 采样器从 codec 的密文模数派生。GLWE KS→BR 显式选取 `kN` 维数及 accumulator fresh-noise，并在客户端构造时核对噪声模数。没有在逐次加密或逐系数操作中重复核对采样器；预算与秘密身份仍由调用方负责。

共享客户端及 Boolean 客户端的单项读取使用 `Lwe<&[T]>`，写入使用 `Lwe<&mut [T]>`，视图按值传递。普通拥有型密文通过 `as_view()` / `as_mut_view()` 借用；其他存储可用已有 `Lwe::new` 包装切片，无需复制或构造临时 view 集合。`Lwe` 在共享层、两家族及四后端直接重新导出。分配型加密仍返回 `LweCiphertext<T>`，保留底层原有初始化路径；消息与维数错误仍发生在 RNG 消费和输出写入前。

PBS trait、四后端、Boolean 门、双输入打包、CBS、one-hot 与 MVB 的单项 LWE 输入也接收 `Lwe<&[T]>`；普通 PBS、Boolean 和 NTRU `return_at_to` 的单项 LWE 输出接收 `Lwe<&mut [T]>`。分配型求值仍返回拥有型密文。GLWE 返回内核迭代借用输出，单项使用 `once(output)`，批量从已有密文切片逐项借用，保持一次环密钥切换后提取多个系数。ManyLUT/MVB、高精 LUT 和 NTRU 批量返回仍使用现有密文切片；组合消费者在单项调用处借用，不复制系数或收集视图。维数、LUT 兼容性及 NTRU 活跃返回批次检查保留在原有边界；Boolean MUX 仍可能在检查 else 输入前更新内部第一分支，但不写调用方输出。

## 批量布局与借用边界

批量入口按实际访问方式保留容器。顶层 LWE 批次借用 `LweCiphertext<T>` 切片，既不取得所有权，也不调整各密文的系数缓冲；外层可来自 Vec、数组或其他已有切片。当前调用方均复用这些拥有型 LWE，不需要临时 `Vec<View>`。连续 gadget 和内部 key-switch tile 则沿用已有语义迭代器。

| 消费者 | 保留的表示与访问方式 | 完整批次边界 |
| --- | --- | --- |
| 四后端 ManyLUT | 单项 LWE 输入视图、输出密文切片；GLWE 逐项借用提取，NTRU 共享输入转换后分 tile 返回 | 有效输出数及全部维数先检查；LUT padding 不产生输出槽 |
| 四后端 factorized MVB | 输出密文切片与 factor 语义迭代器按序配对；NTRU 按返回容量分块 | 检查程序/context 身份、输出数量和全部维数后再做 BR；最后一个 tile 可以较短 |
| NTRU `return_prefix_to` / `return_batch_to` | 密文切片提供长度、单项分派和完整 tile；下层 `primus_ntru` 已支持 `[Lwe<B>]` 的 `DataMut` 存储 | prefix 检查提取范围；stream 要求输出数等于本批有效前缀；失败保留前缀供重试，成功失效 |
| 高精度 LUT | 输入/输出密文切片；分割低/高 chunks、按索引写出、读取先前完成的等价输出；Fourier 按连续求值区间返回 | 求值前检查整个请求，包括被剪枝的输入和复用结果的输出；不由选择图遍历次数推断请求合法 |
| One-hot CBS、gadget 和内部 LWE tile | 已有平坦系数/变换数组与 NLEV、NGSW、LWE 语义迭代器 | owning 入口核对精确元素数；内部迭代器省略尾块的行为不构成布局验证 |

保留切片使预检查、分块和历史输出访问无需引入可重放 iterator 或随机访问 batch trait。仅接受 `&mut [Lwe<&mut [T]>]` 会要求现有拥有型调用方另行拼装描述符；传播存储泛型会扩大长算法的特化范围。当前没有需要这两种代价的消费者，因此不增加第二套批量入口。若今后出现独立的 packed LWE 调用方，再按实际布局补边界，并保留完整请求的检查契约。

区分两种“尾部”：`outputs.chunks_mut(capacity)` 的短 tile 仍由完整密文组成，应当执行；平坦数组不足一个多项式/密文的残余元素属于非法布局，应在公开或构造边界拒绝。批量返回不会把短 tile 补成旧 scratch 槽位。

## GLWE TFHE 的密钥域与消息程序

`TfheParameters` 不保存明文模数或 codec。`TfheConfig.small_lwe` 使用 `LweParametersInner`；直接构造入口接受 small LWE core、`GgswParameters` 和返回 KS basis。`blind_rotation_ggsw()` 同时提供累加环布局与 BR gadget 配置。普通 LWE 仍用 `LweParameters` 绑定 codec，密钥生成传入其 `inner()`。

| 数据或检查 | 唯一归属与使用时机 |
| --- | --- |
| small LWE 的 n、q、秘密分布、fresh noise；累加环 k、N、q 和采样状态 | codec-free 参数构造；检查 n≤kN、binary/ternary 控制秘密和模数配对 |
| BR/返回 KS basis 与密钥噪声 | TFHE 密钥参数；BR 和返回 KS 沿用 accumulator noise |
| CBS output/trace/SS basis、布局、trace/SS noise | `CircuitBootstrapParameters`；不依赖输入明文模数 |
| Rounded 消息编码及 external fresh noise | client 工厂接收 `&RoundedCodec`，检查 codec 的 q；BR→KS 使用 small noise，KS→BR 使用 accumulator noise |
| 普通环消息 Scaled 编码 | `accumulator_client(client, codec)` 一次绑定；复用 gadget 共享采样状态，不复制 Gaussian 预计算 |
| 输入 t、编程域、单表/ManyLUT 的中心、输出编码和容量 | 普通 LUT compiler / factorized compiler；CBS 由 `compile_lookup_table(&input_codec)` 在 evaluator 构造时检查 |
| online ciphertext 与所选程序的消息编码一致、实际噪声余量 | 调用方契约；raw 密文没有编码/噪声元数据，不能据布局判定 |

因此更换输入 t 不需要重新生成 GLWE 密钥；重新绑定 client codec 并编译适配该编码的 LUT/CBS 程序即可。输入 q 不同由 client/compiler 绑定拒绝，N/q/basis 等资源不兼容仍由原边界拒绝。两个后端共用 CBS gadget identity 编译，在线 BR、返回和 trace 算法不变，不逐系数增加检查。Boolean 工厂显式接收 t=4 的 codec，factorized 工厂同时接收 Rounded 输入与 Scaled 输出 codec。

## NTRU TFHE 的密钥域与消息程序

`TfheConfig.external_lwe` 使用 `LweParametersInner`；直接组合入口接受 external LWE core、BR `NlevParameters` 和 q 下的返回 KS 配置。`accumulator_ntru()` 只借用 BR gadget 内的 `NtruParametersInner`，没有第二份普通参数或 codec。`NtruParameters::try_from_nlev` 在 accumulator client 绑定 Scaled codec 时共享 Arc 采样状态。

| 数据或检查 | 唯一归属与使用时机 |
| --- | --- |
| 外部 n、q、s 分布及 fresh noise；累加 N、Q、f 分布及 BR noise | 密钥参数构造；保持 binary/ternary 控制域、2N 可表示性，n 与 N、q 与 Q 相互独立 |
| f→s 返回 key 的 basis 与 noise | 密钥参数与返回 key 构造，均在 q 下；目标 LWE 参数不再构造无用 codec |
| CBS output/trace/SS basis、布局和各自 noise | `CircuitBootstrapParameters`；scheme-switch key 继续绑定完整 output basis |
| Rounded 输入 t/q、默认或独立输出 t/Q | client/compiler 绑定；输入 q 不符拒绝；默认输出 codec 在 Q 无法构造时返回 `OutputEncoding` |
| CBS 输入域和 ManyLUT 容量 | CBS LUT 编译/绑定；独立 CBS 参数只拥有 Q，输入 q 由后端绑定检查 |
| one-hot 的 t=2M、W、stride、非空 guard 与存储长度 | `OneHotLookupTable::try_new(tfhe, cbs, &input_codec)`；后端仍限制 classic binary/ternary |
| 高精度 chunk 位宽、数量、`M^d≤N`、表枚举和存储长度 | `HighPrecisionLookupTable::try_new(parameters, &input_codec, config, function)`；表保存 t/q/Q，evaluator 按表中 t 绑定 one-hot 并验证容量 |
| 在线输入的实际编码和噪声、返回输出的 q 域 decoder | 调用方契约；表在 Q 编码，Q→q 仍为最近舍入，不重新编码 |

跨家族统一的是 codec 归属和绑定时机，数值契约继续显式区分：GLWE 同域 q、有两种 PBS order；NTRU 保留独立 q/Q 与 f/s，以及系数模切→提取→LWE KS。GLWE 的 CBS output basis 可按其 layout/basis 契约组合；NTRU 仍要求 key 的完整 output basis。NTT reverse trace 使用模逆，native Fourier 使用整数减半及 FFT 舍入。更换 t 不改变这些条件，也不自动保证噪声余量。

## Ordinary PBS 的三个返回链路

| 家族 / order | 外部域及完整路径 | 参数和检查入口 |
| --- | --- | --- |
| GLWE `BootstrapKeyswitch` | `LWE(s_small,n,q)` → BR 得到 `GLWE(s_ring,k,N,Q=q)` → GLWE KS 到 padded small secret → compact extraction 返回 n 维 LWE | `small_lwe` 确定输入；要求 n≤kN；返回 `k'=ceil(n/N)` 由参数构造器派生 |
| GLWE `KeyswitchBootstrap` | 外部 `LWE(flatten(s_ring),kN,q)` → inverse extraction → GLWE KS 和 compact extraction 得到 n 维 LWE → BR → extraction 返回 kN 维 LWE | `small_lwe` 仍是 BR 控制秘密；外部维数和新鲜加密噪声来自 accumulator |
| NTRU | 独立 `LWE(s,n,q)` → 首次融合提升和 BR 得到 `NTRU(f,N,Q)` → 系数模切 Q→q、phase extraction → LWE KS 回到独立 s | q/Q、n/N 独立，仅共享系数类型，消息 t 由程序选择；返回 basis/noise 属于 q，BR basis 属于 Q |

数学域检查在家族参数中完成；表长度和 NTT 模数由 context 检查；server key 的布局/basis 由 evaluator 绑定时检查。相同长度、模数或分布标签不证明秘密身份相同。Fourier 还要求使用生成对应表示的同一表实例。

追踪入口：[GLWE NTT evaluator](../../crates/primus_tfhe_glwe_ntt/src/evaluator.rs)、[GLWE Fourier evaluator](../../crates/primus_tfhe_glwe_fourier/src/evaluator.rs)、[NTRU NTT evaluator](../../crates/primus_tfhe_ntru_ntt/src/evaluator.rs)、[NTRU Fourier evaluator](../../crates/primus_tfhe_ntru_fourier/src/evaluator.rs)、[NTRU→LWE 返回原语](../../crates/primus_ntru/src/key_switch/lwe.rs)。

客户端输入使用 Rounded 编码。Ordinary LUT 编译器按输入编码设置窗口，输出 codec 可独立指定；NTRU LUT 在 Q 编码，返回到 q 后须按对应 q 域输出 codec 解码并预算两次舍入误差。底层普通 GLWE/NTRU 参数保存的 Scaled codec 用于普通环消息加密，不决定 PBS 的 LUT 输出编码；两家族 TFHE 在 accumulator client 构造时才绑定它。

## Classic 与 CBS 能力绑定

NTRU `BlindRotationKey` 持有 classic/sparse 材料、BR basis 与输入分布；`ServerKey` 再组合该 owner、返回密钥与可选 CBS 密钥。`BlindRotationKey::classic_controls()` 返回借用的 `ClassicControls`，sparse 返回 `None`。视图集中 NLEV initializer、首坐标 NLEV 的正/可选负 bit，以及后续 NGSW bit 的语义迭代器。BR 构造时选择 binary/ternary/sparse 及其 scratch，在线提升不再重新分派服务端密钥或调用可能在 sparse 下 panic 的 initializer。

NTRU 三类材料可分别生成和持有：`KeyGenerator::try_generate_blind_rotation_key` / `try_generate_sparse_blind_rotation_key` 需要两个秘密角色，`TfheParameters::try_generate_lwe_return_key` 需要完整返回配对，`try_generate_circuit_bootstrap_key` 只接收累加秘密。`ServerKey::new` / `into_parts` 移动各组件而不复制密文数组；独立生成可能重复转换累加秘密，完整成对生成仍复用已转换表示。

| NTRU 求值入口 | 借用材料 | 绑定检查 |
| --- | --- | --- |
| `Evaluator::try_from_parts` | BR + return | BR layout/distribution/basis、返回 N/Q/q/n/basis |
| CBS / one-hot `try_from_parts` | BR + CBS | classic 能力、累加 N/Q、CBS 完整 basis 及输入 codec/容量；无返回约束 |
| 高精 LUT `try_from_parts` | BR + return + CBS | 上述材料及编译表的 N/Q/q/编码 |
| Factorized MVB `try_from_bootstrapper` | 已绑定 PBS | classic 能力与既有 MVB 程序约束 |

BR 不依赖返回 basis；位控制也不绑定外部 q。外部模数由输入程序和返回材料绑定。独立 BR/CBS 生成不检查 f 在返回 q 下的幅度界，完整 PBS 及返回密钥生成保留该要求。各入口检查一次，在线不再解包可选材料或扫描秘密。相同布局/模数不能证明独立材料的实际秘密身份。

CBS 的可选材料仍使用 `Option` 表示。私有绑定集中可用材料与所选 output parameters；NTRU CBS/one-hot 要求 classic，并始终使用 circuit key 的完整 output basis。GLWE CBS 支持 classic 与 sparse，独立 `try_from_parts` 验证调用方提供的参数、trace basis 和 scheme-switch layout，可复用兼容的独立 output basis。构造后保存借用的绑定，在线操作不再取得可选材料。布局及 basis 一致仍不证明秘密或变换表示身份。

入口：NTRU [NTT 控制视图](../../crates/primus_tfhe_ntru_ntt/src/key/classic.rs) / [Fourier 控制视图](../../crates/primus_tfhe_ntru_fourier/src/key/classic.rs)，各后端 `circuit_bootstrap/key.rs` 的私有绑定与 `circuit_bootstrap/evaluator.rs` 的公开构造器。高精度 LUT 从已绑定 one-hot 取得 initializer；返回缓冲和批次协议由家族 `LweReturnEvaluator` 拥有，NTT/Fourier evaluator 各自选择返回调度。

## NTRU 返回资源与批次

家族层的系数域 `LweReturnEvaluator` 绑定返回 key、q 和 scalar/batch scratch，不带变换表泛型。NTT/Fourier 复用同一个具体实现。单项直接转换并提取；共享输入的 interleaved 返回只转换 Q→q 一次；MVB 与 Fourier LUT 对每个来源独立转换，保留提取后的 LWE。转换始终先于提取符号。

其公开流式协议为 `begin_batch` → 顺序 `append_at` → `return_batch_to`；提交数须完全匹配有效前缀，成功后前缀失效。`discard_batch` 或重新开始丢弃旧前缀。追加不保留源借用，one-hot/外积/FFT 和独立 PBS 可穿插执行；活跃批次拒绝使用同一返回对象的 scalar/prefix 方法。两种 LUT 显式持有 standalone one-hot 与返回对象，NTT 继续逐项返回，Fourier 继续流式返回；不再依赖 one-hot 内嵌完整 PBS。

## 输入、盲旋转与返回组合

具体后端的私有 `BlindRotationEngine` 绑定 input 准备、所选 BR key/scratch、系数 accumulator 与 Fourier FFT engine。GLWE KS→BR 保留输入 KS，BR→KS 直接使用外部 input。普通 `Evaluator` 组合完整返回阶段：GLWE BR→KS 的输出 KS、KS→BR 的直接提取，或 NTRU 返回对象；必需资源不再是可能缺失的 `Option`。

CBS 私有小枚举只区分独立 BR/input 与完整 PBS 两种实际所有权。独立 GLWE BR→KS 和 NTRU CBS/one-hot 的 PBS 借用返回 `None`，恢复时显式分配缺失返回缓冲；独立 GLWE KS→BR 已有输入 KS，直接提取不需额外返回工作区，因此可提供 `Some` 且恢复无分配。NTRU 转入 CBS/one-hot 时显式提供 circuit key，`try_into_bootstrapper(return_key)` 显式绑定返回材料：传回原 key 对象时复用完整 PBS，独立状态或另一把兼容 key 则准备返回缓冲。公开借用仅暴露 PBS 操作，不能替换已绑定 evaluator。详见[资源组合表](workspaces-and-storage.md#input-blind-rotation-and-return-ownership)。

## CBS、CMux、MVB 与高精度查表

| 工作流 | 从输入到消费者 | 独立约束及检查归属 |
| --- | --- | --- |
| 普通 CBS → CMux | Rounded LWE → gadget-scaled identity ManyLUT 的 BR → reverse-trace 系数投影 → GLev/NLev → scheme switch → GGSW/NGSW → CMux | CBS 参数检查 output basis 模数、trace/SS 环布局及 ManyLUT 容量；CMux 控制必须表示 0/1，输出为 gadget 尺度 |
| Factorized MVB | 公共 common polynomial 和 factors → 一次 BR → 每输出乘 factor → 按所属 PBS 返回链路输出 LWE | 共享编译器约束固定 Scaled 输出；后端准备变换 factors 并绑定 context 身份；factor 会放大共用 BR 噪声，NTRU 返回还会缩放 Q→q |
| NTRU one-hot CBS | t=2M 的 chunk → packed LUT BR → 各 selector 的偏移/投影 → NLEV，可选 scheme switch 成 NGSW | 使用已有 CBS key/output basis；`W=next_power_of_two(L)`，要求 `2MW≤N`；guard 在 one-hot LUT 上，classic binary/ternary 由后端支持检查限定 |
| NTRU 高精度 LUT | 每个输入 chunk 一次 one-hot → 高 c-d 个 chunk 选择多项式 → 低 d 个 chunk 聚合 `NGSW[X^(-m_i*M^i)]` 并旋转 → 独立 LWE 返回 | 编译器检查 chunk、`M^d≤N`、枚举/存储溢出及输出 digit；evaluator 绑定 N/q/Q、表中 t 的 one-hot 几何、CBS 能力及资源；在线入口在写入前检查全部 chunk 数和 LWE 维数 |

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
| `LweParametersInner::try_new` | LWE 维数、秘密支持集/重量和噪声；不构造 codec | `LweParameterError` 的 `SecretKey` / `Noise` |
| `LweParameters::try_new` / `GlweParameters::try_new` / `NtruParameters::try_new` | 布局、codec、秘密支持集/重量、噪声 sampler；复用上述检查 | 家族各自的 `*ParameterError`；`SecretKey` 保留 `SecretKeySamplerError`，`Noise` 保留 `GaussianError` |
| `TfheParameters::try_from_config` / `try_new` | BR/KS 域及分解、控制秘密类别、维数容量、2N 可表示性 | `TfheParameterError`；累加环错误为 `AccumulatorParameters`，NTRU 返回加密错误为 `KeySwitchingEncryption` |
| 两家族 client / `lookup_table_compiler(&input_codec)` / CBS evaluator | 输入 codec 与密钥 q 一致；独立 NTRU CBS 编译器只拥有 Q，绑定时核对 q | `ClientError::CodecModulusMismatch` / `LookupTableError::InputModulusMismatch` |
| `LookupTableCompiler::try_new` / `try_with_output_codec` | 输出 codec 的密文模数等于累加模数；保存独立编码状态 | `LookupTableError::OutputModulusMismatch` |
| `LookupTableCompiler::compile_*` | 程序容量、切片长度、旋转中心与输出范围；复用原始 LUT 编译内核 | `LookupTableError` |
| `CircuitBootstrapParameters::try_from_config` / `try_new` | output/trace/SS basis、环布局和组合长度；trace/SS 噪声。两家族消息容量均由 CBS LUT 编译检查 | `CircuitBootstrapParameterError`，`EncryptionParameters` 标明 key role 和原错误 |
| Context / key generation / evaluator | 表、秘密实际可用性、选定能力及密钥布局绑定 | 各层已有的 context/key/evaluation errors |

底层 `new` 是在相同校验错误下主动 panic 的便捷形式，适合已知有效的常量配置；其实现复用 `try_new`，没有第二套校验。`GlweParametersInner` 不持有布局，固定重量检查由普通/gadget 参数与布局的组合入口或实际采样入口完成。公开 sampler 接受不同输出长度时仍需检查实际长度。

RNS GLWE 提供 `CrtGlweParameters::try_new`，其 `new` 是调用同一校验的 panicking 便捷形式。`CrtGlweParametersError` 保留布局、RNS 基、BFV 编码与秘密/噪声错误。构造时检查有序 RNS 基的每个 limb 能表示秘密和噪声的完整支持集，并用 `BfvRnsCodec::validate_noise_bound` 验证新鲜私钥明文加密的恢复条件；这不保证公钥加密或同态运算后的噪声余量。

`CrtGlevParameters::try_with_glwe_params` 复用已验证的布局/采样状态，另行检查多 limb 分解、centered lift 和 gadget 组合长度，通过 `CrtGlevParametersError` 保留原因。在线采样不重复这些参数检查。

参数角色与底层失败原因分开表达。例如 CBS 的 trace 噪声错误沿 `CircuitBootstrapParameterError::EncryptionParameters { role, source }` → `NtruParameterError::Noise` → `GaussianError` 传播；`KeyGenerationError` 透明转发 CBS 错误。带上下文的 `Display` 只描述当前层，通过标准 `Error::source()` 逐层取得原因；透明包装同时委托显示及 source，不增加重复的报告层。只打印最外层 `Display` 会省略底层细节，报告器应遍历原因链；LWE/GLWE/NTRU 加密参数的 panicking 构造器通过 `expect` 保留嵌套采样错误的 Debug 信息。

返回包含浮点输入的 sampler 错误后，两家族的 `TfheParameterError`、`CircuitBootstrapParameterError` 和 `KeyGenerationError` 保留 `PartialEq`，不实现 `Eq`。配置/形状检查成功不意味着支持的参数具有足够噪声余量；table 构造也不替代模数素性和秘密身份等调用方前提。

## 保留的分层与接口

依赖方向为算术/编码/采样 → 格式与加密原语 → TFHE 共享客户端/LUT → 家族参数与秘密域 → NTT/Fourier 后端 → NTRU 高精度 LUT。共享代码集中真实相同的编码和公共 LUT 几何，后端保留变换顺序、尺度、密钥表示和工作区的差异。

- `try_from_config` 接受独立配置；`try_new` 接受已有 LWE/环/gadget 参数及 basis，支持已有预计算的组合。两条路径均有实际调用方，并承担不同的构造职责。
- Backend 的参数别名固定其模数类型；GGSW/GLev 参数别名表达同一份加密/basis 配置的不同用途。它们不构成旧 API 兼容层。
- TFHE 密钥参数使用 codec-free LWE core 与 GGSW（GLWE）/NLev（NTRU）参数；client、普通 LUT、CBS 和 factorized 程序各自绑定所需编码。派生维数仍只在参数构造处建立，在线运算消费既有不变量。
- 高精度 LUT 单独拥有表分区、编译及候选树资源，one-hot 仍为 NTRU CBS 扩展。当前职责足以支持独立 crate；无需引入覆盖所有家族的统一 backend trait。
- 工作区改名、容器选择及 scratch 复用是独立改动，遵循[工作区和存储原则](README.zh_CN.md#区分运行环境与工作区)，不改变这里的数学域和错误归属。

## 验证入口

参数拒绝由 [codec](../../crates/primus_encoding/tests/plaintext_codec.rs)、[sampler](../../crates/primus_distr/tests/secret_key_sampler.rs)、[LWE](../../crates/primus_lwe/tests/parameters.rs)、[GLWE](../../crates/primus_glwe/tests/boundaries.rs)、[NTRU](../../crates/primus_ntru/tests/secret_key.rs) 和两家族 [GLWE 参数](../../crates/primus_tfhe_glwe/tests/parameters.rs) / [NTRU 参数](../../crates/primus_tfhe_ntru/tests/parameters.rs) 在拥有契约的层保护。配置回归使用小参数，不生成大密钥。

后端 PBS、CBS/CMux、MVB、one-hot 和高精度 LUT 的现有独立数值/资源回归继续验证合法输入链路；默认和 nightly 全 features 分开运行，命令及覆盖归属见[测试指南](testing.md)。参数构造整理不提供 kernel 提速结论，也不扩大数值支持范围。
