# TFHE R1–R4 整理结果

**R1–R4 已完成（2026-09-20）**。本轮从 `cba9c01` 开始整理七个 `primus_tfhe*` crate，
R1–R3 实现提交为 `458ccce`；R4 补充既有 CBS 回归断言，完成复核、完整验证和文档收尾。原实施清单由 Git 保存，
本文件只保留最终决定、已知成本和恢复入口，不再作为待执行计划。

| 步骤 | 交付 | 记录 |
| --- | --- | --- |
| R1 | 参数、错误、CBS 参数归属与共享 LUT 构造收敛 | `618768d` |
| R2 | evaluator 所有权、工作区与重复计算整理 | `ba85493` |
| R3 | 模块、默认/显式编码接口、客户端/服务端示例与资产整理 | `458ccce` |
| R4 | 全链验收与交接 | 本文 |

## 最终结构与接口决定

| 层 | 职责及边界 |
| --- | --- |
| `primus_tfhe` | LUT 布局/编译、量化、Boolean 算法、小型 PBS 接口和桶映射 |
| `primus_tfhe_glwe` / `primus_tfhe_ntru` | 家族参数、客户端秘密与编解码、参数及操作错误 |
| 四个数值后端 | 变换表示、求值密钥、BR/KS/CBS/MVB 执行与可变工作区 |
| `primus_decompose` | `DecompositionConfig` 及分解基构造；TFHE 各层重新导出同一类型 |

- Config 表示用户选择，Parameters 保存校验结果；Context 只持有公开参数和不可变变换表，
  Evaluator 持有可变工作区。ClientKey 与 ServerKey 分开，后者聚合 BR/KS 及可选 CBS 材料。
- 保留普通/MVB/CBS evaluator、私钥/公钥 Encryptor、独立 Decryptor 和 Boolean 客户端。
  AccumulatorClient 负责累加器秘密域的加解密；普通密文分配归公开 context，CBS 控制由 evaluator 分配。
  未新增 Session、EvaluationKey 包装或统一数值表示的 trait。
- GLWE 高层使用单一模数类型 `TfheParameters<T, M>`，仍检查实际 q/t、环布局、分解基和秘密分布。
  完整 PBS 链要求输入与累加器 q 相等；共享 raw LUT 继续允许独立模数。
- GLWE 共享 CBS 数学参数归家族层，数值表示由后端负责。GLWE key 绑定输出布局，保留同层数
  不同输出 basis 的高级入口；NTRU CBS 从 key 取得完整参数，不再允许另外传入冲突的 basis。
- 普通、odd-full 和 interleaved 的编码构造共用共享 LUT 层。家族 `*_fn/slice` 默认使用
  `input_plaintext_codec()`，`*_with_codec_*` 保留独立输出编码；MVB 继续使用显式 Scaled codec。
  回调顺序、域检查、负循环布局和输出尺度保持原契约。
- 错误按操作归属：参数错误保留 BR/KS/trace 等角色；ContextError 保留 FFT/NTT 原因；
  KeyGenerationError 直接接收客户端不兼容、CBS 参数和 sparse 构造错误；客户端转换归 ClientError。
  稀疏错误集中于映射、秘密支持和控制存储，不增加包揽所有操作的总错误。
- 四后端 MVB 程序与执行位于 `factorized`；NTRU sparse 按 `key` / `blind_rotation` 分开。
  常用类型保持根导出，底层表示通过 `key`、`circuit_bootstrap`、`sparse` 等模块查找。

公开用法统一从[任务选择表](../crates/primus_tfhe/README.zh_CN.md#选择同态操作)、
[双方职责](../crates/primus_tfhe/README.zh_CN.md#客户端与服务端边界)、
[错误边界](../crates/primus_tfhe/README.zh_CN.md#错误边界)与
[编码约定](../crates/primus_tfhe/README.zh_CN.md#编码与密钥契约)进入；后端 README 补充表示差异。

## 资源生命周期与保留的成本

- MVB/CBS 可消费普通 evaluator、借用普通 PBS 操作并回收；调用方无需同步内部模式或 basis。
  从普通 evaluator 转入时保留原工作区，在线交替及回收零分配。
- 独立 GLWE BR→KS CBS 省去返回 KS 工作区；其 `bootstrapper_mut()` 为 `None`，显式转回普通
  evaluator 才补分配。KS→BR 必须保留前置 KS。从完整普通 evaluator 转入则保留原 KS 资源。
- GLWE BR、scheme-switch 和 CMUX 串行共享外积 scratch；布局在正常返回和 unwind 时恢复。
  NTRU 用私有枚举配对控制材料与 scratch，CBS trace 复用 BR 外积空间。
- Fourier sparse+CBS keygen 复用一次 accumulator 秘密变换，保持固定客户端后的 map-only 重试和
  临时秘密擦除。NTT 同类原型在完整生成计时中退化，已撤回；没有长期秘密缓存。

下面是 R1/R2 **历史固定配置测量**，R4 未重新计时，也不将构造内存收益解释为普遍加速：

| 项目 | 保留的结论或限制 |
| --- | --- |
| GLWE 独立 CBS，u64/N=1024 | BR→KS 少 89,800 B；KS→BR 少 33,792 B |
| NTRU CBS，u64/N=1024 | NTT/Fourier 分别少 25/33 KiB |
| Native LUT 构造，N=1024/t=255/k=4 | 三轮中位数增加约 4.4%（0.06 μs），保留去重实现及该成本 |
| NTRU NTT SIMD CBS | 仍有约 2%～3% 的构建间回退；恢复独立 trace scratch 未改善，原因未定位 |
| NTT sparse+CBS keygen 原型 | SIMD 两轮增加约 2.8%～2.9%，隔离后撤回 |
| Fourier sparse+CBS keygen | 保留去重；默认配置没有时间改善证据，SIMD 测量不能全部归因于一次 FFT |

完整参数、测量方法、CSV 和隔离对照见[成本记录](tfhe-refactor-costs.md)。
R3 将重复 CBS 参数矩阵移至家族层，TFHE 测试由 87 减至 86；本机耗时基本持平。
19 个持久 benchmark target 及其工作负载保留，历史 n=512 fixture 只在 bench 使用。
14 个示例区分双方职责、独立参数构造并复用缓冲；示例不是生产安全参数推荐。

## R4 复核与实际验证

复核范围为 `cba9c01..458ccce` 的改动及相关契约、调用方和验证资产，
不是重新进行所有底层数值内核或密码学安全证明。未发现需要修改实现的确认缺陷。
独立 GLWE BR→KS CBS 先前只有示例覆盖在线执行；R4 在两后端既有测试中直接验证
缺 KS 形态的首调用 CBS/CMUX 零分配与完整解码，再执行原来的回收和交替检查，测试入口数量不变。

| 复核链 | 核对内容 |
| --- | --- |
| 共享/家族参数、错误、LUT、客户端与根导出 | q/t/basis/布局检查、错误来源、默认与显式编码、调用方迁移 |
| GLWE 后端与 lattice 外积 context | 两种 order、KS 资源缺省、消费/借用/回收、重绑恢复与 ternary 控制布局 |
| NTRU 后端与 automorphism/trace | 控制和 scratch 配对、系数域投影、CBS 参数来源及不支持组合的拒绝 |
| 示例、测试、基准与双语文档 | 双方职责、非恒定 CMUX/独立相位、零分配与采样前错误检查、去重覆盖和链接 |

在 x86_64 Linux、rustc 1.98.0 / nightly 1.100.0（2026-08-26），沿用仓库 CPU flags，重新执行：

| 检查 | 结果 |
| --- | --- |
| `just tfhe` / `just tfhe-simd` | 默认/SIMD 各 86 项测试，all-targets 检查、严格 Clippy 通过；默认文档通过 |
| `cargo check --workspace --all-targets` | 通过，含 xtask 和其余 workspace 消费者 |
| decompose/lattice/GLWE/NTRU 四个底层包 | 默认/SIMD 各 97 项测试及 all-targets 严格 Clippy 通过 |
| 七个 TFHE 与上述四包的严格公开/私有 rustdoc | `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --document-private-items` 通过 |
| 四后端全部 14 个 release 示例 | 默认/SIMD 均通过，包括两种 GLWE order 与示例选择的 FFT；测试另覆盖两种 FFT |
| 格式、diff、双语章节及相关 Markdown 链接/锚点 | 通过；无新增测试入口、基准或临时源码 |

全矩阵之后补充的两份 CBS 断言，已单独重跑默认/SIMD 各 4 项 CBS 测试及严格 Clippy，均通过。

测试包含现有 binary/ternary/sparse 普通与交错 PBS、Boolean、CBS/CMUX、MVB、
独立整数/相位参考、不同输出编码、脏 scratch、首调用/重复调用零分配与回收边界。
新增 shared-trace 入口的错误 scratch 长度/错误外积工作区有写前检查，未单列分支测试。
这不是任意字宽、N、basis、噪声参数和算法组合的穷举验证；未测非 x86 或真实 GitHub CI 成本。

## 后续边界

本轮结束，不再派生整理阶段。已有支持范围见[后端覆盖](tfhe-backend-coverage.md)，
新算法由用户按[候选清单](tfhe-next.md)另行选择。

NTRU sparse CBS/MVB、sparse ternary、automorphism BR 和 packing 未因本轮开放。
ManyLUT 量化器缓存、factorized 几何预存、NTRU Fourier gadget 常数准备仍需独立收益证据。
条件采样分布、安全参数、噪声尾界和恒时性未获得本轮认证；Fourier 系数域客户端优化仍暂缓。
