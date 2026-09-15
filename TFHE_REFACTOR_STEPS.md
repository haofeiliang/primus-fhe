# primus_tfhe* 重构实施步骤

制定日期：2026-09-15。
依据：[重构分析报告](TFHE_REFACTOR_REVIEW.md)、[仓库规范](AGENTS.md) 和 [当前交接决定](HANDOFF.md)。

本文把分析建议拆成可独立验收的实施步骤，供明确要求实现时使用。S0、S1 已于 2026-09-15 完成，起始源码基线为 `f9105515cb775baf8a2461306e46f154abef5333`；S2–S9 尚未实施。分析报告基线为 `e493df6`；后续开始修改时仍应重新核对代码，不能把历史测试结果当作当前验证结果。

## 1. 范围、顺序与完成目标

核心目标是降低参数和客户端 API 的使用负担，补齐可复用输出的加密入口，并整理现有 PBS/CBS 实现。保留七个 crate 的职责划分：

| 层次 | crate | 继续承担的职责 |
| --- | --- | --- |
| 公共层 | `primus_tfhe` | LUT 编译、编码元数据、ManyLUT 布局、最小 PBS trait |
| GLWE family | `primus_tfhe_glwe` | 系数密钥、参数、客户端、Boolean 语义 |
| NTRU family | `primus_tfhe_ntru` | 系数密钥、参数、客户端 |
| GLWE 后端 | `primus_tfhe_glwe_ntt`、`primus_tfhe_glwe_fourier` | 表与 context、变换密钥、求值器及 scratch |
| NTRU 后端 | `primus_tfhe_ntru_ntt`、`primus_tfhe_ntru_fourier` | 表与 context、变换密钥、求值器及 scratch |

推荐依次执行 S0–S9；每一步均包含受影响调用方、测试和文档的同步。S9 是总体验收，不是把前面步骤的验证推迟到最后。一个步骤过大时按后端拆成可编译的小批次，但不要留下同一公开 API 的调用方迁移未完成。

| 步骤 | 交付内容 | 依赖 | 对应报告 |
| --- | --- | --- | --- |
| S0 | 当前基线、范围和验证入口确认 | 无 | §9 |
| S1 | CBS / Boolean 契约修正 | S0 | §1 |
| S2 | 客户端泛型与构造器收敛 | S1 | §3.1 |
| S3 | GLWE BSK 与三路 CBS 参数收敛 | S2 | §3.2–3.3 |
| S4 | 两族三类客户端加密 `_to` | S3 | §3.4 |
| S5 | GLWE Boolean 工厂与推荐调用流程 | S4 | §3.5 |
| S6 | 同后端 PBS 阶段复用与输出创建整理 | S5 | §4.1–4.2 |
| S7 | 文件职责、LUT 包装与测试归属整理 | S6 | §4.3–4.4、§7 |
| S8 | 七 crate 文档入口与可运行示例 | S7 | §7 |
| S9 | 全范围验收与维护状态收尾 | S8 | §8–9 |

先完成 S0–S5，可形成第一轮易用性成果；再推进 S6–S9，完成现有能力的整理。第 5 节的扩展不属于核心步骤的完成条件。

## 2. 实施中持续保留的约束

- GLWE 的两种 PBS order 保持独立语义：`BootstrapKeyswitch` 对外使用维数 n，`KeyswitchBootstrap` 对外使用维数 kN。NTRU 保持固定链，不新增虚假的 order 配置。
- 普通 unsigned / padded / centered、Boolean 内部尺度、CBS gadget 尺度分别说明和处理；参数精简不能改变它们的编码关系。
- CBS 从 BR accumulator 分支到投影、trace、scheme switching；其输出留在 accumulator 秘密下，不能复用普通 PBS 的后置 KS/extraction 链。
- NTT 与 Fourier 保持明确表示；Fourier 的无符号整数除法、FFT table 身份及误差前提不能照搬 NTT 的模逆元推理。
- 参数、布局和 basis 检查不能证明实际秘密一致。秘密来源一致性继续是相关公开 API 的调用方契约。
- 可复用的在线求值路径不增加临时密文、秘密复制或首次调用的隐式工作区分配。资源兼容性检查集中于拥有契约的边界，不逐层或逐系数重复。
- 不恢复 `Ciphertext` / `LweBatch` 包装，不引入通用 Backend/Domain trait、空泛型、兼容层或预留 builder。复用已完成的底层原语，不重开底层 crate 的整体重构。

## 3. 核心修改步骤

### S0：确认当前基线与验证范围

**操作：**

1. 阅读根目录及受影响子目录的 `AGENTS.md`，检查 `git status`、暂存和未暂存差异；保留用户修改及暂存状态。
2. 核对报告建议对应的符号仍存在。用 `rg` 搜索 workspace 调用方，范围包括 `xtask`、测试、示例、基准和 README，不限于七个 crate 的 `src/`。
3. 执行第 4 节的七 crate 默认验证，形成当前基线；记录实际工具链与失败范围。若当前代码已偏离报告，先调整对应步骤的实施范围。
4. 确认 SIMD feature 的实际传播。报告基线的 `just simd` 没有覆盖 TFHE；后续使用显式包列表，在 S9 再收敛维护入口。

**完成条件：** 已区分既有失败和本轮变更影响，能确定下一步的直接调用方及验证命令。此阶段不做顺手清理，也不提前采集所有性能数据；性能基线紧邻 S6 的实际修改采集。

#### S0 执行结果（2026-09-15）

**基线与范围：** 开始时工作区和暂存区均干净；已读取根 `AGENTS.md`、HANDOFF 及两份重构文档，未发现受影响子目录的补充 `AGENTS.md`。当前 HEAD 为 `f9105515cb775baf8a2461306e46f154abef5333`，七个 TFHE crate、`xtask`、`Cargo.toml`、`Cargo.lock` 和 `justfile` 相对报告基线 `e493df6` 均无差异。本步只更新实施状态文档，不修改源码、测试或配置。

已用 `rg` 检索 workspace 的符号、导入和文档引用，覆盖 `src`、测试、示例、基准、README 及 `xtask`。报告对应符号仍存在，S1–S9 无需因源码漂移调整范围；本次是基线核对，不是重新完整审查七个 crate。

| 后续步骤 | 当前入口及直接消费范围 |
| --- | --- |
| S1 | GLWE NTT 的 `circuit_bootstrap_{parameters,key,evaluator}.rs`、`context.rs` 和 family `boolean.rs`。CBS 直接消费在 GLWE NTT `tests/circuit_bootstrap.rs`；Boolean 由两路 GLWE 的 re-export、测试、示例及 PBS benchmark 消费。两项公开注释问题均仍存在。 |
| S2 / S4 | 两族 `client.rs`；GLWE 的空 `Key` 泛型、`with_client_key` 及两族 raw `new` 仍存在，三类加密仍只有分配返回入口。迁移覆盖四后端 context/alias、GLWE Boolean，以及 family 的 `tests/lookup_table.rs`、NTRU `tests/key.rs`。 |
| S3 | GLWE 参数仍接收完整 BSK 参数；三路 CBS 仍接收完整 output 参数。调用分布在 family 参数测试、GLWE NTT 参数 fixture、后端测试/示例/基准，以及两路 NTRU 的双语 README。 |
| S5 | 两路 GLWE context 尚无 Boolean 工厂；Boolean 测试、四份 GLWE 示例及两份 PBS benchmark 仍手动组合参数和适配器。 |
| S6 / S7 / S8 | `prepare_small_lwe`、四路 evaluator 的 ManyLUT 流程和输出 clone、现有平铺 CBS/BR 文件、LUT 包装与测试归属仍与报告一致；七 crate 仅两路 NTRU 后端有双语 README。 |
| 范围外调用方 | 唯一直接 Rust 消费文件仍为 `xtask/src/ntru_params.rs`，涉及两路 NTRU context/keygen/PBS、参数/LUT 和 `server_key_bytes` 估算；另有底层 NTRU 双语 README 的 TFHE 链接。后续接口迁移须保留 `cargo check -p xtask --all-targets`。 |

**本次实际验证：** 默认工具链为 `rustc 1.98.0 (88d9e12ae 2026-08-18)`、`cargo 1.98.0 (797e8a9bc 2026-08-05)`，host 为 `x86_64-unknown-linux-gnu`。下表的七包选择均使用第 4 节的完整数组。

| 命令 | 结果 |
| --- | --- |
| `cargo fmt --all -- --check` | 通过，无格式写入 |
| `cargo check "${tfhe_packages[@]}" --all-targets` | 通过，包含测试、示例及基准编译 |
| `cargo test "${tfhe_packages[@]}"` | 37 passed、0 failed、0 ignored；七包 doctest 均为 0 |
| `cargo clippy "${tfhe_packages[@]}" --all-targets -- -D warnings` | 通过 |
| `cargo doc "${tfhe_packages[@]}" --no-deps` | 通过，无警告 |
| `cargo check -p xtask --all-targets` | 通过 |

**SIMD 入口：** 已核对七份 manifest、`justfile` 和 Cargo 解析后的 feature 图。`cargo +nightly tree "${tfhe_packages[@]}" --features simd --depth 0 --format '{p} features=[{f}]'` 确认七包均启用 `default,simd`；相关底层整数、编码、LWE、GLWE/NTRU、lattice、NTT 等 feature 也已传播。两路 GLWE 后端显式转发公共层及 family 的 SIMD；两路 NTRU 后端转发 family 和底层，但不显式转发 `primus_tfhe/simd`，GLWE family 也不显式转发该公共层 feature。因此不能以仅选择一个后端替代七包验证。

`just simd` 仍仅选择 integer、modulus、barrett_derive、factor、rns、decompose 六包；保留第 4 节显式七包 nightly check/test 命令，维护入口调整留在 S9。已安装 nightly 为 `rustc 1.100.0-nightly (bff8e12ff 2026-08-26)`；本步只核对 SIMD 配置，没有重跑 SIMD 编译或测试。

**结论与下一步：** S0 完成，默认验证未发现既有失败，无阻塞项。下一步是 S1 的契约文档修正，验证入口为 `cargo doc -p primus_tfhe_glwe -p primus_tfhe_glwe_ntt --no-deps`，并检查两路 GLWE Boolean re-export 的链接。未执行示例独立运行、Criterion 计时或整个 workspace 测试；性能基线仍在 S6 改动前采集。

### S1：先修复已确认的公开契约问题

**范围：** GLWE NTT 的 CBS 参数/key/evaluator/context 文档，以及 GLWE family 的 Boolean 文档；位置见报告 §1。

**修改：**

1. 在 CBS 密钥生成及 evaluator 组合入口说明：普通 server key 与 circuit key 必须来自同一配套秘密，并满足所用变换表示的前提。明确现有检查只能确认布局和参数兼容。
2. 检查分配返回的 `circuit_bootstrap` 是否完整继承 `_to` 的输入域、输出尺度、噪声及秘密来源前提；通过文档引用或简明说明保持一致。
3. 修正 `BooleanError::InvalidPlaintext` 的有效代表元描述，并区分外部 `0/1`、plaintext modulus、位数以及内部 LUT 尺度。
4. 将实际检查写入 `# Panics`，未检查的数学前提写入 `# Correctness`；不增加无法验证秘密来源的“自动安全检查”。

**验证与完成条件：** 逐项对照实现确认文档真实，相关 rustdoc 能构建；没有把参数相同写成秘密相同。纯文字修正无需新建“错秘密必然失败”测试。

#### S1 执行结果（2026-09-15）

- 已修正 GLWE NTT 的 CBS 参数、key、evaluator、context 文档：生成和组合入口明确配套秘密及 NTT 表示前提，区分兼容性检查与无法检查的秘密来源；分配返回接口继承 `_to` 的输入域、编码、噪声、输出尺度和密钥前提，`# Panics` 对应实际维数/长度断言。
- 已修正 GLWE family Boolean 的有效代表元和位数注释，说明外部模数 4 下的 `0/1` 与内部模数 8 的 LUT 尺度及 PBS 后平移。CBS 输出噪声参数不用于新鲜加密、context 构造分配工作区而在线 `_to` 复用工作区的描述也已澄清。
- 对照 CBS 构造/求值、底层 scheme switching/trace 投影及 Boolean LUT/平移实现核对了契约，并为两后端 Boolean evaluator alias 补充到共享编码说明的链接；七个 Rust 文件仅修改注释，没有签名或执行代码变化。
- `RUSTDOCFLAGS='-D warnings' cargo doc -p primus_tfhe_glwe -p primus_tfhe_glwe_ntt -p primus_tfhe_glwe_fourier --no-deps`、`cargo fmt --all -- --check`、`git diff --check` 均通过；已检查两后端生成的 Boolean re-export 页面及 evaluator 到 family 的链接。
- 本步无新增测试，未重跑数值测试、SIMD 或性能基准；开始时已有的 S0 暂存内容保持不变。S1 完成，无阻塞项，下一步为 S2 的客户端泛型与构造器收敛。

### S2：删除空 Key 泛型，统一客户端构造器

**范围：** 两族 `src/client.rs`，GLWE family Boolean 内部字段，两路 GLWE 的客户端 alias，以及全部调用方。

**修改：**

1. 将 `GlweEncryptor` 收敛为直接借用 `GlweClientKey` 的类型，移除没有第二种实现的 `Key` 泛型及后端 alias 的对应泛型参数。
2. 将 raw 客户端这一小组返回 `Result` 的构造器统一为 `try_new`：GLWE encryptor 的 `with_client_key`、GLWE decryptor 的 `new`、NTRU encryptor/decryptor 的 `new`。
3. 保留 context 的 `encryptor`、`decryptor`、`evaluator` 工厂名。Boolean 自身的构造入口单独核对职责，不把此步扩成所有 `new` 的机械重命名。
4. 同步公开导出、rustdoc、测试、示例和 benchmark，删除失效的未来公钥说明与导入；不保留弃用 alias。

**验证：** 检查两族、四后端及 workspace 调用方。保留两种 keygen 工作流；若解除“消耗完全相同 RNG 流”的偶然限制，必须各自使用配套的 client/server 验证，不能交叉混用。

**完成条件：** 用户无需指定虚假的 Key 泛型；旧构造符号无活跃调用；密钥表示、借用关系和生成行为没有因命名整理而改变。

### S3：收敛 GLWE BSK 与 CBS 输出参数

本步分为两个连续、各自可验证的小批次。

**S3a — GLWE 参数：**

1. 将 `GlweTfheParameters::try_new` 的 `bootstrapping: GgswParameters` 输入改为 `bootstrapping_basis`。
2. 内部使用已有 `GgswParameters::try_with_basis`，从唯一的 accumulator GLWE 描述派生 BSK 参数；固定顺序为 `small_lwe, accumulator_glwe, bootstrapping_basis, key_switching_basis, pbs_order`。
3. 保留普通 GLWE 参数所拥有的 plaintext codec 和噪声信息；删除因重复输入消失而不可达的 mismatch 分支，保留其他真实 basis、模数和维数检查。
4. 同步两种 order 的测试与全部构造调用。KSK 噪声的既有派生方式保持不变。

**S3b — 三路 CBS 参数：**

1. 将 GLWE NTT、NTRU NTT、NTRU Fourier 的 CBS 输出参数输入收敛为 `output_basis`，从 TFHE accumulator 推导输出尺寸。
2. 保留 trace 与 scheme-switch 的完整加密参数；保留需要的输出布局访问能力，移除会误导用户的未使用输出噪声输入。
3. 分别遵循 GLWE 的 output-layout 绑定和 NTRU 的 output-basis 绑定，不为接口外观一致添加无依据的拒绝条件。

**验证：** 参数合法/非法 basis、两种 GLWE order、CBS level=2/3、输出 gadget phase 及 CMUX 消费。复用现有 NTRU CBS 测试；对 GLWE CBS 仅补独立缺口，如错误输出尺寸先拒绝且旧输出不变、奇数 levels 的 padding。

**完成条件：** 调用方不再重复提供 accumulator 描述或无效输出噪声；普通 PBS 与 CBS 的尺度、维数、basis 契约均保持。所有旧签名调用迁移完毕。

### S4：补齐两族客户端的可复用输出入口

**范围：** 两族客户端、后端 alias/公开文档及聚焦的客户端测试。

**修改：**

1. 增加 `encrypt_to(message, output, rng)`、`encrypt_padded_to(message, output, rng)`、`encrypt_centered_to(message, output, rng)`。
2. 复用 `LweSecretKeyRef::encrypt_encoded_to` 等已有能力，保持 Signed / Encoded 私钥表示；用小型私有实现共享真实编码和加密逻辑。
3. 消息转换、范围和输出维数检查全部先于 RNG 采样及写入；正常错误返回 `ClientError`。RNG panic 的部分写入语义引用底层契约。
4. 保留现有分配返回的便利方法及其高效初始化路径，不强制先创建零密文再调用 `_to`。
5. 默认沿用当前 owned 输出类型；仅在已经选定的实际调用方需要借用输出时采用已有 `Lwe` view，不在此步设计 batch 或重写 PBS trait。

**验证：** 使用固定 seed 和有代表性的表驱动测试，覆盖两族、GLWE 两种 order、三种编码的有效边界与错误输入、反复覆盖同一输出。对错误路径同时验证输出和 RNG 状态未改变；输出存储复用及无秘密复制通过实现检查确认，必要时复用现有分配统计 helper 做聚焦验证。

**完成条件：** 连续加密可以复用输出，合法结果正确解密；参数错误发生在采样/写入前，没有为每个 alias 增加重复测试。

### S5：提供 GLWE Boolean 工厂，更新推荐调用流程

**范围：** GLWE 两个 context、Boolean 适配及两个后端的入门示例。

**修改：**

1. 增加 `boolean_encryptor`、`boolean_decryptor`、`boolean_evaluator` 工厂，由 context 传递配套参数并创建已有适配器。
2. 保留可接收定制 bootstrapper 的泛型 `BooleanEvaluator`，说明外部提供的参数必须与 bootstrapper 的编码、维数和模数一致。
3. 更新推荐示例，展示参数 → context → 配套密钥 → LUT/Boolean evaluator → 重复 `_to` 的资源生命周期。
4. 使用已有 `evaluate_binary_to`、`not_to`、`mux_to`；不为六个门重复实现一套 `_to`。

**验证与完成条件：** 两种 order 下六门真值表、NOT、MUX 和重复输出正确；两个后端的示例均能编译运行，调用方无需反复手动传递同一 context 参数。到此可单独验收第一轮 API 改善。

### S6：整理同后端阶段复用与输出创建

**开始前：** 对将改动的路径运行现有 Criterion 基准，固定源码、工具链、CPU、参数与 feature。若将修改 GLWE CBS 实现，先补一个完整 CBS 基准；涉及 Fourier workspace 时覆盖 RustFFT 与 TfheFFT 的等价工作负载。

**实施顺序：** GLWE NTT → GLWE Fourier → NTRU NTT → NTRU Fourier。每个后端分别验证后再迁移相同思路，不同时混入文件搬迁。

**修改：**

1. 保留单 PBS、ManyLUT 和 CBS 各自的公开检查；整理 GLWE 输入准备、BR、普通 PBS 后处理中的实际重复。
2. 优先处理 GLWE NTT 普通 evaluator 与 CBS 的 `prepare_small_lwe` 重复。只在确实集中缓冲区不变量时引入私有工作区结构。
3. 在 NTRU 同后端的单 PBS/ManyLUT 间共享 BR 后的 KS；CBS 使用自己的投影/trace/SS 后处理。
4. 单 PBS 提取一个输出，ManyLUT 提取所需多输出，保持共享一次 BR/KS。初次整理保留 CMUX ping-pong 与零指数分支的既有结构。
5. 将“克隆 input 后完整覆盖”的输出创建改为由输出维数明确构造。单独测量 allocating 路径，不能仅凭删除 clone 宣称加速。

**验证：** 独立 BR oracle、两种 order、ManyLUT count=1/2/4、count=1 与单 PBS 的既有等值关系、所有错误输出先拒绝、拒绝后 evaluator 仍可复用、CBS phase/CMUX。发生工作区调整时验证首次及后续在线调用的分配行为。

**完成条件：** 重复阶段减少且数值分支局部可读，公开检查和输出不变性保留。完整 PBS/CBS 基准不存在无法解释的回退；若某个抽取 helper 导致回退，调整抽取边界或保留独立入口，不以可读性为由忽略证据。删除无收益实验。

### S7：按职责整理文件、共享包装与测试归属

**修改候选及顺序：**

1. GLWE 大型 `bootstrapping_key.rs` 按密钥存储/生成和 blind rotation 划分；NTRU 同名文件主要是 BR 工作区/kernel，可改为 `blind_rotation.rs`。
2. 三路 CBS 聚合到 `circuit_bootstrap/{mod,parameters,key,evaluator}.rs`；GLWE family Boolean 按 `mod/client/evaluator` 拆分。保持 crate root 的公开可发现性，不为每个门建立文件。
3. 只含少量 alias 的文件可并入 `lib.rs`。先确认是否夹带真实 fixture；GLWE NTT `parameters.rs` 不能按空 alias 文件直接处理。
4. 对两族 LUT 包装，只有提取后显著减少已确认的重复且契约仍清晰时，才把公共明文检查/codec 操作移入现有共享层。保留 family/context 入口与跨 crate 必需的 support API。
5. 三个纯 LUT compiler 测试可移到 `primus_tfhe/tests`，客户端测试留在 family。合并 NTRU 单 PBS 与 ManyLUT count=1 的重复时，保留 basis/模数绑定的独立诊断。

**验证与完成条件：** 每组搬迁后检查 import、导出、rustdoc 链接和测试归属，完成受影响 crate 的全 targets 检查。最终文件能按职责定位，测试保护的独立契约不减少；没有明确收益的拆分或共享提取可不实施，并简要记录理由。

ManyLUT 编译期临时列的优化暂缓，除非确认存在频繁动态编译负担；本步不新增在线 scratch 参数，也不把测试整理扩成通用测试框架建设。

### S8：补齐文档入口与可运行示例

**修改：**

1. 为公共层、两族及 GLWE 两后端补对应的中英文 README。公共层说明共享契约，family 说明参数/客户端职责，后端展示完整调用流程，避免五处复制长篇教程。
2. 同步现有两路 NTRU README，统一能力矩阵与跨 crate 链接；修改任一语言版本时同步另一版本。
3. 补可运行的 NTRU CBS → CMUX 示例，分别使用 NTT/Fourier 的真实类型，替代只有 `rust,ignore` 片段的使用说明。
4. GLWE 每后端的 basic/order 示例可在确实更清晰时合并，直接展示 n/kN 外部维数差别，不用宏隐藏操作。
5. 说明普通消息、Boolean、CBS 三类尺度；明确 NTRU message/carry 示例是一次输入的多输出，不代表完整整数系统。`boolean_parameters()` 等开发 fixture 不作为生产默认参数宣传。

**验证与完成条件：** 七 crate 均有明确入口；推荐示例实际运行，文档构建及链接检查通过；能力矩阵准确反映仍未实现的 Fourier GLWE CBS 和 NTRU Boolean。API rustdoc 应已在前面各步骤同步，本步只补全整体阅读路径。

### S9：最终验收与维护状态收尾

1. 执行第 4 节的七 crate 默认/SIMD 验证，并检查 `xtask` 等直接调用方。按跨层影响运行仓库级检查，不因无关失败削弱规则。
2. 补一个可重复执行的 TFHE 验证入口：优先采用现有 justfile 风格新增专用 recipe，或合理扩展已有入口；确认包列表和 feature 确实包含七个 crate。
3. 复核完整 diff 中的 API、数学契约、调用方、测试、示例、benchmark、feature 和双语文档；代码复审使用仓库 `primus-review` skill 并完成相应范围的覆盖账本。
4. 删除本轮废弃导入、兼容遗留、临时测试、调查性 benchmark 和调试输出。保留有长期诊断价值的分配统计与性能 case。
5. 汇报完成步骤、API 变化、实际验证与未验证路径。仅在需要恢复状态时更新 HANDOFF 的当前范围、有效决定和下一步，不复制历史日志或验证输出。

**完成条件：** S1–S8 的交付完整；未实施的条件性整理有理由，可选扩展有明确边界；用户修改与暂存状态保留。未经要求不 stage、commit 或 push。

## 4. 验证执行方法

每一步先对受影响 crate 做窄范围检查，直接调用方迁移完成后再扩大。不要在纯文档任务中无意义重跑完整数值测试，也不要在修改算术后只做编译检查。

```bash
# 在仓库根目录执行；按步骤选择受影响的 crate。
cargo fmt --all
cargo check -p <crate> --all-targets
cargo test -p <crate>
cargo clippy -p <crate> --all-targets -- -D warnings
```

七 crate 集成验收使用 Bash 数组，避免漏掉 family 或公共层：

```bash
tfhe_packages=(
  -p primus_tfhe
  -p primus_tfhe_glwe
  -p primus_tfhe_glwe_ntt
  -p primus_tfhe_glwe_fourier
  -p primus_tfhe_ntru
  -p primus_tfhe_ntru_ntt
  -p primus_tfhe_ntru_fourier
)
cargo check "${tfhe_packages[@]}" --all-targets
cargo test "${tfhe_packages[@]}"
cargo clippy "${tfhe_packages[@]}" --all-targets -- -D warnings
cargo +nightly check "${tfhe_packages[@]}" --all-targets --features simd
cargo +nightly test "${tfhe_packages[@]}" --features simd
cargo doc "${tfhe_packages[@]}" --no-deps
```

这组命令不代替示例的实际运行和性能测量。示例用 `cargo run -p <backend> --example <name>`；性能用受影响 backend 的现有 `pbs` / `circuit_bootstrap` Criterion target。命令中的占位符需换成实际名称，不要求每一步运行全部基准。

仓库级检查使用 `just fmt-check`、`just check`、`just lint`、`just test`、`just simd`。修改前先核对 recipe 的当前范围；TFHE SIMD 专用命令在维护入口确认覆盖前始终保留。

性能结论要求相同工作负载：分配返回与 reused-output 分开，ManyLUT 与多个 PBS 比较时输出数相同，key-switch 内核比较不能代替含 extraction 的完整方案比较。记录重复测量的实际差异和波动，不预设未经测量的提升比例。

## 5. 核心重构之后的独立扩展

以下项目待实际需求明确后单独实施，不作为 S9 的阻塞项，也不在重构过程中顺手加入。

| 项目 | 启动条件与前置 | 独立验收要求 |
| --- | --- | --- |
| Fourier GLWE CBS | 需要补齐 GLWE 两后端 CBS；先完成 S3、S6 | 复用 Fourier trace/SS，独立参数/key/evaluator；验证两种 order、native 归一化、FFT 误差、gadget phase 和 CMUX；补运行示例及完整基准 |
| NTRU Boolean | 需要跨 family 门计算；先稳定 S5 的 Boolean 边界 | 提取真实共用编码/仿射逻辑，避免复制 GLWE 整套实现；两路 NTRU 真值表和链式使用正确 |
| batch client / PBS | 已有多个独立输入的消费需求；先完成 S4、S6 | 明确区别于一输入多函数的 ManyLUT；先串行复用 evaluator；全部布局先检查；Signed 路径复用已有单条 kernel |
| PBS `_assign` | 已有链式原地求值需求；先完成 S6 | 在覆盖输入前完成依赖输入的阶段；禁止 clone 隐藏分配；验证链式结果及拒绝语义 |
| ServerKey 存储查询 | 决定替换 `xtask/src/ntru_params.rs` 的既有手写公式 | 优先复用 `Size` 或明确定义 `coefficient_bytes`；区分实际系数存储、allocator 占用及 CBS live heap；同步 xtask 消费方 |

若选择算法补充，优先评估 Fourier GLWE CBS。公钥客户端、独立 KSK 噪声、small integer/message-carry 类型层继续等待明确需求。NTRU packing、序列化、GPU、多位 BR 不纳入本计划；特别是 packing 不能被重新引入为 CBS 的前置任务。

## 6. 后续会话的使用方式

每次推进一个步骤或同一依赖链上的少量步骤。可直接使用以下指令：

> 按 TFHE_REFACTOR_STEPS.md 执行 S2。先核对当前状态和相关规范，在本步骤内完成源码、workspace 调用方、测试和文档同步，运行对应验证。不要进入可选扩展，也不要提交代码。

每次交付说明本步是否完成、实际验证结果以及剩余阻塞项。若执行时发现报告前提已改变，先以当前代码修正该步骤；不要为了符合旧计划制造抽象或恢复已删除能力。
