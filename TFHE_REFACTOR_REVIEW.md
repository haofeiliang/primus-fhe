# primus_tfhe* 重构分析与修改建议

审查日期：2026-09-14。源码基线：`e493df6`。开始时工作区和暂存区均无修改。
用户所写的 `primus_thfe*` 按仓库实际名称 `primus_tfhe*` 理解，范围为七个 crate。
本文是分析与实施建议；原审查仅新增本文。后续用户已明确纳入两族 TFHE LWE 公钥客户端，§3.1 的删除空泛型建议与 §5 的公钥后置安排已由 [实施步骤 S2](TFHE_REFACTOR_STEPS.md) 的当前方案替代；以下保留原审查基线结论和行号。文件链接随 S7 搬迁更新到当前位置。

## 1. 已确认的问题

### P2：GLWE NTT CBS 没有在公开边界说明两组求值密钥必须来自同一秘密

位置：[CBS evaluator 构造](crates/primus_tfhe_glwe_ntt/src/circuit_bootstrap/evaluator.rs)（第 70 行）、[CBS key 兼容性检查](crates/primus_tfhe_glwe_ntt/src/circuit_bootstrap/key.rs)（第 34 行）。

`CircuitBootstrapEvaluator::try_new(context, server_key, parameters, circuit_key)` 只验证参数、布局和分解基。调用方可以从同参数的两个不同 `ClientKey` 分别生成 `server_key` 与 `circuit_key`，构造仍会成功。随后 BR 产生第一个 GLWE 秘密下的 accumulator，trace/scheme switching 却使用第二个秘密，输出不再保证是所声明的 GGSW。

这不是要求从求值密钥恢复并验证秘密，而是公开契约缺失：[底层 scheme switching](crates/primus_glwe/src/scheme_switch/ntt.rs)（第 133 行） 明确要求输入与密钥使用同一秘密，TFHE 的组合入口没有传达这一要求。布局相同不能建立秘密相同。两路 NTRU CBS 已在相同位置记录该前提，见 [NTT](crates/primus_tfhe_ntru_ntt/src/circuit_bootstrap/evaluator.rs)（第 57 行） 和 [Fourier](crates/primus_tfhe_ntru_fourier/src/circuit_bootstrap/evaluator.rs)（第 58 行）。

建议：在 GLWE CBS 的 key 生成、evaluator 构造及 context 转发入口补充同一实际秘密、同一 NTT 表示的契约引用；分配返回的 `circuit_bootstrap` 也应继承 `_to` 的输入域、噪声与输出尺度要求。不要新增逐次秘密检查或自行设计 key fingerprint 系统。这里确认的是契约缺口，未运行异秘密混用的错误输出实验。

### P3：Boolean 的公开注释仍混有旧编码描述

位置：[BooleanError::InvalidPlaintext](crates/primus_tfhe_glwe/src/boolean/mod.rs)（第 513 行）。注释称有效代表元是 `-1/+1`，而 [BooleanDecryptor::decrypt](crates/primus_tfhe_glwe/src/boolean/client.rs)（第 131 行） 实际只接受 `0/1`。调用者依据错误注释导入 raw ciphertext 时可能选择错误编码并得到错误或 `InvalidPlaintext`。

建议：统一说明外部是 `t=4` 下的 `0/1`，内部 Boolean LUT 使用另一尺度，PBS 后还有平移修正；不要把内部正负 accumulator 值称为外部 Boolean 编码。顺手修正 `BOOLEAN_PLAINTEXT_BITS` 将位数称为模数的注释即可，不改变算法。

本轮未确认 P0/P1 算术或内存安全缺陷。以下是有源码依据的重构建议和功能取舍，不把所有建议都标成 bug。

## 2. 总体判断

建议保留现有七个 crate 的职责分层，先做两轮边界整理，再独立补充功能。当前主要问题是同一职责在不同层重复表达、客户端与在线求值的使用体验不完整，以及新旧代码在契约表达和组织方式上没有完全收敛。没有证据支持先合并所有后端、引入统一 backend trait，或重写底层数值内核。

已有结构中值得保留的部分：

- `primus_tfhe` 已把 LUT 编译、输入编码元数据、ManyLUT 布局和最小 PBS trait 集中起来，四路共用。
- family crate 管数学参数、系数私钥与客户端；backend crate 管变换 table、求值密钥和 workspace。这条边界合理。
- `TfheContext` 持有参数与只读 table，`Evaluator` 持有可复用工作区，密钥通过借用使用，适合重复求值和每线程独立 workspace。
- 四路普通 PBS/ManyLUT 已在写输出前检查 LUT 元数据与输出维数；不要把检查重新下沉到逐系数循环。
- NTRU 已使用连续 controls、真实 `NLev[1]` 初始化和配对私钥生成；CBS 保持独立参数/key/evaluator。
- 目标源码没有复杂自定义宏或显式 `unsafe`；可维护性问题主要在接口和数据流，不在宏展开。

### 当前能力矩阵

| 能力 | GLWE NTT | GLWE Fourier | NTRU NTT | NTRU Fourier |
| --- | --- | --- | --- | --- |
| 普通 PBS / `_to` | 有 | 有 | 有 | 有 |
| ManyLUT / `_to` | 有 | 有 | 有 | 有 |
| 外部 LWE 维数 | 随 PBS order 为 n 或 kN | 同左 | client 系数前缀 n | 同左 |
| PBS order | BR→KS、KS→BR | 同左 | 固定 BR→NTRU KS→提取 | 同左 |
| Boolean client / gate evaluator | 有 | 有 | 无 | 无 |
| 独立 CBS | 有，输出 NTT GGSW | 无 | 有，输出 NTT NGSW | 有，输出 Fourier NGSW |
| 公开原始 BR API | 有 | 有 | 私有 kernel | 私有 kernel |
| TFHE client `encrypt_to` / batch | 无 | 无 | 无 | 无 |
| 可直接运行的示例 | PBS、ManyLUT、Boolean、两种 order | 同左 | ManyLUT message/carry | 同左 |
| crate README | 无 | 无 | 中英文 | 中英文 |

最后两行 NTRU 指 backend crate；`primus_tfhe`、`primus_tfhe_glwe`、`primus_tfhe_ntru` 三个公共层也没有 README。矩阵来自全部 crate roots、manifest、公开 API 和调用方，并非仅依据测试名称。

## 3. 第一轮：先减少调用方负担

### 3.1 删除没有实际用途的 Key 泛型

[GlweEncryptor](crates/primus_tfhe_glwe/src/client.rs)（第 15 行） 的 `Key` 泛型只有 `GlweClientKey<T>` 一种实现；[后端 alias](crates/primus_tfhe_glwe_ntt/src/lib.rs)（第 5 行） 还明确以“将来加入公钥”为理由暴露默认泛型。当前没有第二种实现、对应 trait 或调用方。

建议直接改为 `GlweEncryptor<'a, T, LM, GM>`，字段使用 `&GlweClientKey<T>`。同步 Boolean 内部字段和两个 backend alias。将来需要公钥加密时根据真实所有权和参数契约设计入口，不保留空泛型位置。

`Encryptor::with_client_key`、`Decryptor::new` 和 NTRU 两者的 `new` 都返回 `Result`，而 evaluator/context 使用 `try_new`。这一小组建议统一为 `try_new`；context 的 `encryptor`、`decryptor`、`evaluator` 工厂名称可保留，它们的返回类型已经表达可失败性。不要因此给所有历史 API 机械加 `try_`。

### 3.2 GLWE 参数构造只接受一份 accumulator 描述

当前 [GlweTfheParameters::try_new](crates/primus_tfhe_glwe/src/parameters.rs)（第 97 行） 同时接收 `glwe` 和由它构造的 `bootstrapping`，之后又在 [validate_common](crates/primus_tfhe_glwe/src/parameters.rs)（第 163 行） 比较两者尺寸和 `inner` 相等。示例、测试和基准都先创建 GLWE，再创建 GGSW，再一起传入。

推荐把该构造器中的 `bootstrapping: GgswParameters` 换为 `bootstrapping_basis: ApproxSignedBasis<T>`，内部通过现有 `GgswParameters::try_with_basis(&glwe, basis)` 派生。保留 `glwe`，因为普通消息编码、私钥采样和客户端大 LWE 分支仍需要它。

拟议签名，尚未实施：

```rust,ignore
GlweTfheParameters::try_new(
    small_lwe,
    accumulator_glwe,
    bootstrapping_basis,
    key_switching_basis,
    pbs_order,
)
```

收益是取消调用方创建一个必然相等的描述及其 mismatch 状态，不是减少一个参数就宣称性能提升。BSK 与 KSK basis 顺序应固定并在 rustdoc 的参数表中说明。

注意：[GlevParameters](crates/primus_glwe/src/parameter/glwe/single.rs)（第 319 行） 只有 gadget layout、inner 和 basis，并不保存普通 GLWE 的完整 plaintext codec。因此不能简单删掉 `glwe` 字段并声称所有信息可由 `bootstrapping` 恢复。第一轮只简化 TFHE 构造边界，不为消除底层值复制改成 `Arc`，也不重构已完成的 GLWE 参数体系。

目前 GLWE KSK 的噪声由 accumulator GLWE 参数派生。若后续参数研究确实需要独立 KSK 噪声，应作为参数能力扩展处理；本轮不要靠一个未使用的 builder 或通用配置对象提前承载。

### 3.3 CBS 的 output 参数只描述实际使用的输出 basis

两路 NTRU [CBS 参数](crates/primus_tfhe_ntru_ntt/src/circuit_bootstrap/parameters.rs)（第 50 行） 已说明 output 的加密噪声不被使用；GLWE CBS 同样用它的 basis/尺寸产生 gadget-scaled LUT，而不按 output noise 重新加密。

建议三路 CBS 构造都优先接受 `output_basis`，从绑定的 accumulator 推导输出尺寸；trace 和 scheme-switch 继续接受完整加密参数，因为它们确实影响 key 生成。先复用 `ApproxSignedBasis`、`GadgetSize` 等现有类型，不新增只有 N、levels、basis 的公共包装层。

```rust,ignore
CircuitBootstrapParameters::try_new(
    tfhe_parameters,
    output_basis,
    trace_parameters,
    scheme_switch_parameters,
)
```

这里统一的是参数的数学角色，不强行统一 GLWE/NTRU 的存储与输出类型。GLWE 的 scheme-switch key 当前只绑定 output layout，输出尺度继承输入 GLev；NTRU key 显式绑定 output basis。不能为了形式一致，机械给 GLWE 加 NTRU 式 output-basis 拒绝检查。

### 3.4 补齐客户端的可复用输出入口

两族客户端现在只有分配返回的 `encrypt`、`encrypt_padded`、`encrypt_centered`。后端在线 PBS 已支持 `_to`，但调用方要反复加密仍须分配，或绕过 TFHE 参数层自己组装 codec、模数和噪声分布。

优先补 `encrypt_to`、`encrypt_padded_to`、`encrypt_centered_to`。三者共用一个私有编码/加密实现，借助 [LweSecretKeyRef::encrypt_encoded_to](crates/primus_lwe/src/secret_key/borrowed.rs)（第 101 行），保持 Signed/Encoded 秘密表示。可分配版本继续提供便利入口，不为了“都走 `_to`”损失底层已有的直接初始化分配路径。

约定：消息转换、范围和输出维数在采样/写入前检查；正常参数错误返回 `ClientError`，RNG panic 可能留下部分输出需引用底层契约。不添加输入密文状态包装，不复制整把私钥。

当前 `LweCiphertext<T>` 是 owned 输出，底层 `Lwe<S>` 支持 borrowed storage。若同时推进平铺 batch，固有 `_to` 方法可接受 `Lwe<impl DataMut<Elem=T>>`；先不要为了它改变两个 PBS trait 的整套泛型设计。

### 3.5 Boolean 的高层工厂应把配套参数一起传递

当前示例要分别写 `BooleanEncryptor::new(context.parameters(), ...)`、`context.evaluator(...)`、`BooleanEvaluator::try_new(context.parameters(), pbs_evaluator)`，同一个参数来源手工出现多次，见 [Fourier 示例](crates/primus_tfhe_glwe_fourier/examples/fourier_basic.rs)（第 81 行）。

建议 GLWE 两个 context 补 `boolean_encryptor`、`boolean_decryptor`、`boolean_evaluator` 工厂，内部从同一 context 派生；已有泛型 BooleanEvaluator 仍可供定制 PBS 实现使用，但要明确传入参数必须与 bootstrapper 的编码、维数和算术模数一致。这个便利入口有实际组合责任，不是无用途转发。

不要把 Boolean 混进普通 PBS 的尺度处理。`evaluate_binary_to`、`mux_to`、`not_to` 已能复用输出，无需为六个门各新增一套重复 `_to` 实现。

## 4. 第二轮：整理实现，但保持数值差异可见

### 4.1 优先合并同一后端内部的 PBS 阶段

[GLWE NTT evaluator](crates/primus_tfhe_glwe_ntt/src/evaluator.rs)（第 190 行） 中 ManyLUT 重复了普通 PBS 的 BR/KS 路径；[普通 evaluator 的 prepare_small_lwe](crates/primus_tfhe_glwe_ntt/src/evaluator.rs)（第 319 行） 与 [CBS 的同名方法](crates/primus_tfhe_glwe_ntt/src/circuit_bootstrap/evaluator.rs)（第 204 行） 也重复 inverse extraction→KS→compact extraction。两路 NTRU 的单输出和多输出同样重复 BR 后的 KS。

建议按数学阶段收敛，而不是按参数个数抽象：

1. 保留公开 single/Many 两个入口各自的完整输入与输出检查。
2. 在后端私有实现中复用“准备 small LWE”“BR 到 accumulator”“PBS 后 KS”这些已重复的阶段。
3. single 最后提取系数 0，Many 最后提取 `0..count`；CBS 在 BR 后转入 trace/SS，不能误走普通 PBS 后处理。
4. 只有共享多个配套 buffer 确实使借用和尺寸不变量更清楚时，才引入一个后端私有 workspace 结构。不要新增公共 `Backend`、`Domain`、万能 evaluator 或动态 dispatch。

BR loop 的双缓冲和零指数跳过保持原样。可先尝试用局部源/目标借用减少两份 CMUX 调用，但不为少十行代码改变缓冲区生命周期或搬动输出；如改动生成代码，必须实测 BR/PBS。

### 4.2 不再用 clone 表达“创建待覆盖输出”

GLWE [单输出](crates/primus_tfhe_glwe_ntt/src/evaluator.rs)（第 100 行） 先 clone input 再完整覆盖，四路 ManyLUT 使用 `vec![input.clone(); count]`；NTRU 单输出已经使用配置维数创建零输出。

建议可分配求值 API 按配置维数创建输出，而不是复制输入内容。Boolean 二元门同理；`not` 自身需要读取/变换输入，另行判断。这个建议主要让代码表达“输出”，不能直接推出零初始化比复制更快。在线 `_to` 路径已经无此分配，不把便利 API 的分配说成 PBS kernel 的缺陷。

### 4.3 只对确实难读的大文件按职责拆分

建议候选：

| 当前文件 | 建议组织 | 保留的边界 |
| --- | --- | --- |
| GLWE `bootstrapping_key.rs`，约 500 行/后端 | `bootstrapping_key.rs` 管存储/生成；`blind_rotation.rs` 管 BR API/kernel/workspace | key 的 basis 和布局保持单一来源 |
| family `boolean.rs`，528 行 | `boolean/mod.rs`、`client.rs`、`evaluator.rs` | 编码和仿射 gate 公式集中，避免每种门一个文件 |
| 三路 CBS 的平铺文件 | 可组织为 `circuit_bootstrap/{mod,parameters,key,evaluator}.rs` | 可选功能明确分组，根 re-export 保持可发现 |
| backend 中 4–14 行的 `client.rs` / `parameters.rs` alias | 可以直接放 `lib.rs` 对应 re-export 区 | 不为机械 alias 保留导航跳转 |

NTRU 当前 `bootstrapping_key.rs` 实际只有 BR workspace/kernel，名字与内容不符，可以直接改成 `blind_rotation.rs`。其 ServerKey 没有公开 raw BR 消费者，暂不创建新的公共 NTRU BootstrappingKey 只为与 GLWE 对称。

### 4.4 共享逻辑要有明确收益

GLWE/NTRU family 的普通 LUT 编译包装约有百行相似代码；真正复杂的负循环布局和 rotation-center 检查已经在 `primus_tfhe`。可以下沉重复的明文范围检查/codec 调用到现有共享编译层，但保留 family/context 的用户入口。

目前 ManyLUT 编译为每列创建临时单列 polynomial，再交错写入，见 [共享编译器](crates/primus_tfhe/src/lookup_table.rs)（第 345 行）。它发生在 setup，不是在线热路径；只有动态频繁编译成为实际负担时，再改为复用临时列或直接填交错输出。不为此新增在线 scratch 参数。

`backend_support` 和 encoded LUT compiler 虽有 `doc(hidden)`，仍是跨 crate public API。应保持内部用途清晰和错误前提完整，不用一个新公共配置类型仅掩盖几个参数。面向用户的 LUT API 则可以补充 domain/可支持输出数的查询，减少调用方重复 `ceil(t/2)` 与 `N/count` 计算；这类查询只代表布局容量，不能声称验证了噪声预算。

## 5. 功能补充的选择顺序

| 项目 | 建议 | 实施前提与验收 |
| --- | --- | --- |
| Client 三种 `encrypt_*_to` | 第一轮完成 | 输入错误先于写入；复用输出；保持两族、两种 GLWE order 的编码行为 |
| PBS 原地 `_assign` | 有链式求值需求时补 | 先用输入完成 BR/KS，再覆盖原 LWE；不能用 clone 隐藏分配；无需同时补所有 Boolean assign |
| 独立输入的 batch PBS/client API | 在单条边界稳定后补 | 明确区别于 ManyLUT：batch 是多输入，ManyLUT 是一输入多函数；复用同一个 evaluator，先串行，不内置线程池 |
| Fourier GLWE CBS | 有完整 CBS 使用需求时作为首个算法补充 | 复用已存在 Fourier trace/SS；保持独立 key/参数；覆盖 native 归一化、FFT 误差和两种 order，不能照搬 NTT 噪声结论 |
| NTRU Boolean | 需要跨 family 门计算时补 | 将共同 Boolean 编码/仿射逻辑移动到合适公共层，family 提供客户端适配；避免再复制 528 行；验证两路后端的完整门真值表与链式使用 |
| ServerKey 存储量查询 | 有当前调用方价值 | `xtask` 已手写布局字节公式，见下文；优先复用现有 `Size` 契约或明确 `coefficient_bytes` 语义，不混同 allocator 占用 |
| 公钥客户端加密 | 暂后置 | 先明确公开的是 small-LWE 还是 kN/client-prefix LWE 公钥，以及生成参数；复用 `primus_lwe::LwePublicKey`，不要恢复空 Key 泛型 |
| small integer/message-carry 类型层 | 暂后置 | 已有 ManyLUT 示例足以说明功能；只有确定运算集、carry 状态和噪声策略后才设计语义类型 |
| NTRU packing、序列化格式、GPU、多位 BR | 本轮不纳入 | 无本轮必要性；packing 在 HANDOFF 中明确排除，不能作为 CBS 前置任务重新引入 |

新增 batch 不应恢复已删除的 `LweBatch` 包装。若需要平铺存储，用精确长度切片或已有 `Lwe` view，并在 batch 最外层检查全部布局。Signed NTRU/GLWE 大 LWE client 不能直接套用只支持 Encoded 私钥的底层 owned batch；可复用单条 Signed kernel，保持 dispatch 在批处理循环外。

`xtask` 的 [server_key_bytes](xtask/src/ntru_params.rs)（第 493 行） 根据配置重建 initializer/controls/KSK 的长度，随着存储重构容易漂移。让真实 ServerKey 提供具有明确范围的存储统计，能消除一个已存在的跨层重复；普通系数存储字节数与 CBS benchmark 的 live requested heap 统计应分别命名。

## 6. 推荐保留的接口族及签名矩阵

以下矩阵描述目标职责，不要求所有内部函数使用同一参数顺序，也不要求把不同表示合成一个 trait。

| 函数族 | 主要输入顺序 | 输出位置 | 可复用状态 | 返回/检查语义 |
| --- | --- | --- | --- | --- |
| raw encrypt | `message, rng` | 返回 owned LWE | 已绑定 key/parameters | 消息转换/范围用 `Result` |
| raw encrypt `_to`（拟补） | `message, output, rng` | 显式 output | 已绑定 key/parameters | 输出维数与消息先检查 |
| decrypt | `input` | 返回明文 | 已绑定 key/parameters | 维数/输出转换用 `Result` |
| LUT fn/slice | `function` 或 `outputs` | 返回 LUT | context/parameters | 只编译前半输入域，输出是普通编码 |
| ManyLUT fn/slice | `output_count, function/outputs` | 返回 ManyLUT | context/parameters | fn 参数 `(input, output_index)`，slice 为 input-major |
| PBS `_to` | `input, lookup_table, output` | 单 LWE | evaluator 自有 scratch | 维数/LUT 不兼容在写入前 panic |
| ManyLUT `_to` | `input, lookup_table, outputs` | LWE slice | 同上 | 所有输出先检查，共享一次 BR/KS |
| CBS `_to` | `input, output` | GGSW/NGSW，保留表示类型 | 固定 LUT、投影、trace/SS scratch | output 是 gadget scale，key domain 为 accumulator |
| GLWE raw BR | `input, accumulator/LUT, output, modulus/table, scratch` | 环 accumulator | 显式工作区 | 保持低层原始契约，NTT/Fourier 参数可不同 |

不要批量重命名 `apply_lookup_table_to` 为 `pbs`；四路及 trait 当前一致，已有可发现的职责。不要为同名强行把 NTRU 的固定 PBS 链加上 GLWE order。不要给原地操作加 `must_use`；对返回新值的构造、转换和纯计算按丢弃是否容易误用补齐即可。

## 7. 测试、基准和文档如何跟着重构

### 测试：保留独立契约，减少绑定实现步骤的断言

| 现有资产 | 独立价值与建议 |
| --- | --- |
| `primus_tfhe` 的 modulus-switch oracle | 保留 native 环回与 explicit 整数舍入诊断 |
| GLWE family `lookup_table.rs` 四个测试 | 保留错误先于 callback、原始独立尺度、奇偶 t 的 padded domain、rotation center 两侧；三个纯 compiler 测试可迁到拥有实现的 `primus_tfhe/tests`，客户端契约留 family |
| GLWE family `parameters.rs` | 保留两种 order 的 KSK 推导和错模 basis 拒绝；随新构造签名调整 |
| NTRU family `parameters.rs` / `key.rs` | 保留尺寸、域、binary prefix/零填充、奇偶 padded domain；不是可删的普通存储转发测试 |
| 两路 GLWE `blind_rotation.rs` / `context.rs` | 保留独立负循环 oracle、raw exponent、资源/输出边界拒绝、basis 绑定、两条 keygen 工作流 |
| 四路 `many_lut.rs` | 保留 count=1/2/4、count=1 与单 PBS 等值、每项元数据拒绝、全部输出维数先检查、拒绝后 evaluator 可复用；Fourier 已覆盖 RustFFT/TfheFFT |
| 两路 GLWE `boolean.rs` | 保留六门真值表、NOT、MUX 和重复输出；重构后可用一个表覆盖两种 order，避免同文件重复 setup |
| GLWE NTT `circuit_bootstrap.rs` | 当前主要覆盖两种 order 的 CMUX 消费和 trace-basis mismatch。改 CBS 边界时补代表性的输出长度拒绝/旧输出不变、奇数 output levels padding、首次调用无分配；不要照抄全部 NTRU cases |
| 两路 NTRU `pbs.rs` | basis/模数绑定保留；简单单 PBS toggle 与 ManyLUT count=1 有重叠，合并时保留独立参数/基约束诊断，勿整文件删除 |
| 两路 NTRU `circuit_bootstrap.rs` | 已覆盖 level=2/3、逐层 gadget phase、CMUX、第一次调用零分配、坏输入/输出先拒绝、三种 basis 与容量错误，值得保留 |
| NTRU allocation helper | 现有跨 backend/bench 共用，有真实诊断价值；无需创建通用测试框架，仅改善路径组织即可 |

两路 GLWE [fresh_and_split 测试](crates/primus_tfhe_glwe_ntt/tests/context.rs)（第 98 行） 除功能正确，还断言两个生成工作流消耗相同 RNG 流。若这不是明确的可重现性契约，可删除“必须消耗相同随机数”的限制，分别验证各自产生的 client/server 配对可用。不能只删除比较却继续拿 A 的 client 配 B 的 server；测试应使用各自配套客户端，才能允许合法的采样顺序调整。

API 草案落地时，最低新增测试围绕新契约：`encrypt_padded_to` 越界时输出不变、合法输入复用输出、batch 多输入与 ManyLUT 的不同语义。无需为每个 alias、getter、机械转发加测试。

### 基准：保留长期问题，不把跨参数数字当后端排名

- 四路 PBS 的 `complete_pbs_reused_output` 与 ManyLUT 对比多个独立 PBS，应保留；每次迭代的真实输出数应在名字或 throughput 中体现。
- GLWE allocating/reused 输出对比适合验证输出创建变更；BR、KS、extraction stage 用于定位整体回退，不能替代完整 PBS。
- GLWE 两个 order 的各阶段实现相同并不必然意味着基准重复：输入域和完整链不同。只有实际无法影响决策的 case 才删。
- [GLWE NTT key_switch benchmark](crates/primus_tfhe_glwe_ntt/benches/key_switch.rs)（第 75 行） 比较 `LWE kN→n` 与 `GLWE k→k'`，没有把两条路径的 extraction 一起计时。可作为内核问题保留，但若结论是“选哪个 TFHE key-switch 方案”，必须补齐等价输入到等价外部 LWE 输出的完整链；不能用这两项直接裁决方案。
- 两路 NTRU CBS 的 N=1024/4096、B=2^3/2^10、完整 trace/SS 与堆占用统计回答明确问题，可保留。其统计在计时外，不能因为有打印就当作测试调试输出删除。
- 当前 GLWE Fourier PBS 主要测 RustFFT；如果重构影响 FFT workspace 或 backend，补同一 workload 的 TfheFFT 对照。GLWE CBS 若调整实现，应有独立完整 CBS 基准。
- 本轮没有实测任何优化收益；性能变更以同基线、参数、CPU、工具链及 feature 的 Criterion 对照为准。

### 文档：让入门路径覆盖真实资源生命周期

为公共层及 GLWE 两 backend 补中英文 README，包含功能矩阵、参数→context→key→LUT→evaluator 的最短工作流，以及一次分配、重复 `_to` 的例子。现有 NTRU README 中 CBS 的 `rust,ignore` 片段不是可编译示例；补一份能实际运行的 CBS→CMUX 例子，再由两种表示按各自类型展示。

GLWE 两套 `_basic` / `_keyswitch_bootstrap` 示例相似，可每 backend 用一个示例分别运行两个 order，直接说明外部维数 n/kN；不要用宏隐藏步骤。保留 NTRU message/carry 示例，但写清它是一个输入产生 message/carry 两个输出，不代表已有完整整数类型系统。

文档必须区分：普通 unsigned/padded/centered 消息、Boolean 内部尺度、CBS gadget 尺度；FFT table 身份是已有调用方契约，不重新包装成已完成的自动验证功能。临时 `boolean_parameters()` 保持开发用途标识，可迁入明确的 development 命名区或示例 fixture，不能当成生产默认安全参数。

## 8. 建议分批实施与验收

| 批次 | 修改内容 | 完成条件 |
| --- | --- | --- |
| A：收敛参数和契约 | 修本文两项文档问题；移除空 Key 泛型；client 构造命名统一；GLWE BSK 与 CBS output 改为 basis 输入 | 所有 workspace 调用方同步；普通 PBS/Boolean/CBS 数学行为不变；更新两族参数测试 |
| B：补最小客户端工作流 | 三类 encrypt `_to`、GLWE Boolean context 工厂、推荐示例 | 新接口不分配临时 ciphertext，不复制秘密；错误发生在采样/写入前；默认/SIMD 测试通过 |
| C：整理内部实现 | 同后端重复阶段、文件命名/组织、输出 clone、必要 LUT 包装重复 | 私有工作区不变量局部可读；原先拒绝条件和输出不变性保留；如改热路径，现有 BR/PBS/CBS 基准无无法解释的回退 |
| D：单独补功能 | 先选择 Fourier GLWE CBS 或 NTRU Boolean；batch/assign 按具体消费需求推进 | 每项有独立端到端例子与最少回归；普通 PBS 无新增可选密钥/工作区负担 |
| E：文档与维护入口收尾 | README、示例、测试/基准精简、TFHE SIMD 检查入口 | 七 crate 入口能说明各自职责，命令实际覆盖 TFHE feature，删除本轮产生的废弃代码和临时实验 |

每一批单独检查完整 diff。A/B 不应夹带底层算术优化；C 的性能调查不顺带改变参数或选用后端。对 `primus_lattice/lwe/glwe/ntru` 仅做已明确需要的接口复用或调用方同步，不重开其已完成重构。

推荐先实施 A、B。它们直接解决当前易用性问题，风险较容易控制；C 在稳定的新接口下推进，D 的新增能力单独决策。

## 9. 覆盖账本与本轮验证

### 范围清点

| crate | src `.rs` | tests `.rs` | examples | benches | README |
| --- | ---: | ---: | ---: | ---: | ---: |
| primus_tfhe | 5 | 0 | 0 | 0 | 0 |
| primus_tfhe_glwe | 6 | 2 | 0 | 0 | 0 |
| primus_tfhe_glwe_fourier | 9 | 4 | 2 | 1 | 0 |
| primus_tfhe_glwe_ntt | 12 | 5 | 2 | 2 | 0 |
| primus_tfhe_ntru | 5 | 3 | 0 | 0 | 0 |
| primus_tfhe_ntru_fourier | 11 | 3 | 1 | 2 | 2 |
| primus_tfhe_ntru_ntt | 11 | 3 | 1 | 2 | 2 |
| 合计 | 59 | 20 | 6 | 7 | 4 |

`tests` 包含一份 allocation support 文件；另外 `primus_tfhe/src/backend_support.rs` 有一个内嵌数学 oracle 测试。七份 manifest 均检查；源码共 8,396 行。未发现子目录 AGENTS、build script、生成源码或目标层独立平台实现。

- **完整读取**：上述 59 个源码文件，包括全部公开 API、re-export、私有 BR/PBS/CBS 流程；20 个 test/support 文件、6 个示例、7 个 Criterion benchmark 和 4 份 README。文件清单见下节。
- **调用方**：检索整个 workspace 的 TFHE 导入及文档引用；范围外直接 Rust 调用集中在 `xtask/src/ntru_params.rs`，读取其两路 context/keygen/PBS、参数/LUT 工厂、测量消费边界（1–470 行）与存储估算（493–510 行）。统计展示与频谱分析其余部分不作完整审计。
- **底层抽查**：GLWE/GLev 参数表示、LWE owned/Signed secret 与 encoded `_to` 契约、GLWE NTT trace projection 和 scheme switching；结合 HANDOFF 的有效决定核对 TFHE 消费边界。未声称完整复审四个底层 crate。
- **并行审查**：按 skill 启动 API、数学/性能、验证资产三个只读 lane；子 agent 返回了阶段性观察，最终报告因执行额度错误未完成。主 agent 已自行读取上述目标文件，并复核本文全部引用和结论；不把未返回的 lane 完成状态计入覆盖。
- **保持的决定**：无恢复 raw Ciphertext 包装、NTRU packing、万能 domain/表示 trait；basis 绑定、检查所在层、Fourier table 身份、CBS 可选性、一般 ManyLUT 必须投影等继续有效。
- **未验证范围**：生产安全参数、KDM/circular-security 证明、失败概率、恒时性、非 x86 平台、完整底层 SIMD 差分、性能改善。目标层 feature 运行不等于这些证明。

### 执行结果

环境：`rustc 1.98.0 (88d9e12ae 2026-08-18)`，本机 x86_64；SIMD 使用已安装 nightly。以下命令均在本轮运行，包列表均为上述七个 crate。

| 验证 | 结果 |
| --- | --- |
| `cargo check <七个 -p 参数> --all-targets` | 通过，包含 test/example/bench 的编译 |
| `cargo test <七个 -p 参数>` | 37 passed，0 failed；7 个 crate 的 doctest 均为 0 |
| `cargo clippy <七个 -p 参数> --all-targets -- -D warnings` | 通过 |
| `cargo +nightly check <七个 -p 参数> --all-targets --features simd` | 通过 |
| `cargo +nightly test <七个 -p 参数> --features simd` | 37 passed，0 failed |

未运行 Criterion 计时、nightly Clippy、示例的独立执行或整个 workspace 的测试；本次只交付分析文档，没有源码变更。不是以历史 HANDOFF 验证记录替代本轮结果。

[justfile](justfile)（第 3 行） 的 `simd-packages` 目前没有 TFHE，不能用 `just simd` 代替以上 TFHE feature 检查。实施时应补明确的 TFHE SIMD 入口，或扩展现有包列表并保持耗时可控。

可复制的包选择与验证命令：

```bash
tfhe_packages=(
  -p primus_tfhe
  -p primus_tfhe_glwe
  -p primus_tfhe_glwe_fourier
  -p primus_tfhe_glwe_ntt
  -p primus_tfhe_ntru
  -p primus_tfhe_ntru_fourier
  -p primus_tfhe_ntru_ntt
)
cargo check "${tfhe_packages[@]}" --all-targets
cargo test "${tfhe_packages[@]}"
cargo clippy "${tfhe_packages[@]}" --all-targets -- -D warnings
cargo +nightly check "${tfhe_packages[@]}" --all-targets --features simd
cargo +nightly test "${tfhe_packages[@]}" --features simd
```

### 检查文件清单

以下每项均相对对应 crate 根目录，包含所有受审文件；行号引用对应本轮基线，后续实现后应重新定位。

**primus_tfhe**

- Manifest：`Cargo.toml`。
- src：`backend_support.rs`、`bootstrap.rs`、`error.rs`、`lib.rs`、`lookup_table.rs`。

**primus_tfhe_glwe**

- Manifest：`Cargo.toml`。
- src：`boolean.rs`、`client.rs`、`key.rs`、`lib.rs`、`lookup_table.rs`、`parameters.rs`。
- tests：`lookup_table.rs`、`parameters.rs`。

**primus_tfhe_glwe_fourier**

- Manifest：`Cargo.toml`。
- src：`boolean.rs`、`bootstrapping_key.rs`、`client.rs`、`context.rs`、`error.rs`、`evaluator.rs`、`key.rs`、`lib.rs`、`parameters.rs`。
- tests：`blind_rotation.rs`、`boolean.rs`、`context.rs`、`many_lut.rs`。
- examples：`fourier_basic.rs`、`fourier_keyswitch_bootstrap.rs`。
- benches：`pbs.rs`。

**primus_tfhe_glwe_ntt**

- Manifest：`Cargo.toml`。
- src：`boolean.rs`、`bootstrapping_key.rs`、`circuit_bootstrap_evaluator.rs`、`circuit_bootstrap_key.rs`、`circuit_bootstrap_parameters.rs`、`client.rs`、`context.rs`、`error.rs`、`evaluator.rs`、`key.rs`、`lib.rs`、`parameters.rs`。
- tests：`blind_rotation.rs`、`boolean.rs`、`circuit_bootstrap.rs`、`context.rs`、`many_lut.rs`。
- examples：`ntt_basic.rs`、`ntt_keyswitch_bootstrap.rs`。
- benches：`key_switch.rs`、`pbs.rs`。

**primus_tfhe_ntru**

- Manifest：`Cargo.toml`。
- src：`client.rs`、`key.rs`、`lib.rs`、`lookup_table.rs`、`parameters.rs`。
- tests：`key.rs`、`parameters.rs`、`support/allocations.rs`。

**primus_tfhe_ntru_fourier**

- Manifest：`Cargo.toml`。
- src：`bootstrapping_key.rs`、`circuit_bootstrap_evaluator.rs`、`circuit_bootstrap_key.rs`、`circuit_bootstrap_parameters.rs`、`client.rs`、`context.rs`、`error.rs`、`evaluator.rs`、`key.rs`、`lib.rs`、`parameters.rs`。
- tests：`circuit_bootstrap.rs`、`many_lut.rs`、`pbs.rs`。
- examples：`ntru_fourier_basic.rs`。
- benches：`circuit_bootstrap.rs`、`pbs.rs`。
- 文档：`README.md`、`README.zh_CN.md`。

**primus_tfhe_ntru_ntt**

- Manifest：`Cargo.toml`。
- src：`bootstrapping_key.rs`、`circuit_bootstrap_evaluator.rs`、`circuit_bootstrap_key.rs`、`circuit_bootstrap_parameters.rs`、`client.rs`、`context.rs`、`error.rs`、`evaluator.rs`、`key.rs`、`lib.rs`、`parameters.rs`。
- tests：`circuit_bootstrap.rs`、`many_lut.rs`、`pbs.rs`。
- examples：`ntru_ntt_basic.rs`。
- benches：`circuit_bootstrap.rs`、`pbs.rs`。
- 文档：`README.md`、`README.zh_CN.md`。
