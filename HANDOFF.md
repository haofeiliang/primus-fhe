# Workspace 开发交接

本文只保存当前阶段、有效工作边界、未决项与恢复入口。恢复时先核对 Git 状态；历史报告中的验证结果不代表当前结果。

## 当前状态与下一步

- `primus_lattice`、`primus_lwe`、`primus_glwe`、`primus_ntru` 的既有整理和已批准原语补充基本完成；不因 TFHE 重构重新开启其整体重构。
- 七个 `primus_tfhe*` crate 的源码、API、测试、示例、基准、feature 和文档分析已完成，覆盖边界见 [TFHE_REFACTOR_REVIEW.md](TFHE_REFACTOR_REVIEW.md) §9。
- [TFHE_REFACTOR_STEPS.md](TFHE_REFACTOR_STEPS.md) 的 S0–S5 已完成：两族已接入 `LwePublicKey`，统一客户端 `try_new`；GLWE BSK / 三路 CBS 输出参数已收敛；公钥和私钥客户端均支持三类加密 `_to`；两路 GLWE context 已提供 Boolean 工厂。S6–S9 尚未实施，下一步为 S6：先测量目标路径，再按后端整理 PBS 阶段复用和输出创建。
- GLWE NTT 与两路 NTRU 已有 CBS；Fourier GLWE CBS 尚未实现。NTRU packing 按用户决定排除，不是 CBS 的前置工作；其他可选扩展见步骤文档 §5。

## 已审范围索引

| 范围 | 恢复时应理解的边界 |
| --- | --- |
| 基础 crate | 已完整复审 data、distr、gcd、integer、reduce、modulo、modulus、barrett_derive、factor、poly、ntt、fft、rns（省略 `primus_` 前缀）；后续变化以 Git 为准。 |
| encoding / lattice | encoding 已完整覆盖，跨表示调用方按边界抽查；lattice 已覆盖类型/API/宏、算术、extraction、CMUX/外积及维护材料，并同步共享置换和 NTRU 外积工作区。 |
| LWE / GLWE / NTRU | LWE 包括私钥、公钥、batch、KS 和 Signed 路径；GLWE 包括自同构、trace/投影、packing、SS；NTRU 包括擦除、basis、常数 gadget、自同构、trace/投影、同秘密 SS，不含 packing。定向后续修改不代表再次全量复审全部依赖。 |
| TFHE | 七 crate 分析报告已覆盖目标层；底层仅按消费契约抽查，未重做完整底层审计、性能测量或安全证明。 |

## 当前 TFHE 工作必须保留的边界

- 普通 PBS 的输出 LWE、Boolean 内部尺度与 CBS gadget 尺度分别处理；GLWE 保留两种 order，NTRU 保留固定链。不能因 API 整齐改变秘密域和外部维数。
- GLWE BSK 从 accumulator 与 basis 派生；CBS 输出只接收 basis、从 accumulator 派生布局，trace/SS 保留完整加密参数。GLWE CBS key 绑定输出布局，NTRU CBS key 绑定完整输出 basis。
- CBS 保持可选独立参数/key/evaluator。一般 ManyLUT 不满足前缀展开的零尾前提，应走投影；NTRU CBS 留在 `f_acc` 下，不走普通 PBS 的后置 KS/extraction。
- 布局或 basis 相同不能证明实际秘密一致；Fourier table 身份、输入规范表示和噪声预算仍需遵守相应公开契约。NTT 模逆元与 Fourier 无符号整数除法不能共用误差结论。
- 不恢复 raw Ciphertext、LweBatch 或万能 domain/表示包装；复用底层已有原语。参数、布局和 basis 的检查留在拥有契约的边界。

- TFHE 公钥绑定外部 LWE 秘密：GLWE 按 order 使用 n 或 kN，NTRU 使用客户端二进制前缀。复用 LWE 公钥，不新增 NTRU 环公钥。生成直接借用 Signed/Encoded 视图；公钥总噪声及 PBS 输入余量需独立评估，不能把单项采样器当作总噪声。
- 两族三类客户端 `_to` 直接复用底层 LWE 内核，消息与维数错误先于采样/写入；输出遵循 raw LWE 的 body 布局前提。分配返回接口保留各自的高效初始化路径。

## 按需读取的技术决定

原 HANDOFF 中跨 crate 的长期决定已迁入 [实现决定参考](.agents/references/implementation-decisions.md)。按涉及的 crate/符号读取对应章节，不要求每次完整加载。

区分三类信息：用户明确的范围边界应遵守；数学前提应对照当前契约；既有实现与性能选择可在前提改变后重新验证。新证据可以支持调整实现，历史偏好不自动成为永久禁令。

## 未决项及触发条件

以下是既有未决记录，本次指令整理未重新审计这些源码；相关工作开始时应核对当前实现。

| 项目 | 当前记录 / 后续触发条件 |
| --- | --- |
| CRT Gaussian 规范编码 | `primus_glwe_rns::CrtGlweParameters::new` 对 `q_i <= floor(12σ)` 可能产生非规范 residue；处理该参数边界时核对支持集检查。 |
| GLWE RNS 测试 | `tests/glev.rs::test_key_switching` 曾仅打印解码结果；整理该 crate 时确认并补独立断言或删除重复案例。 |
| reduce 文档 | `ReduceMulAddSlice` 曾称五种 fused 形态都需要而生产调用只有三种；crate 概览漏列 `reduce_once`、double、mul-add。整理该 crate 时核对。 |
| NTRU SS/CBS 参数与安全 | f/f² 误差放大、KDM/circular-security 假设及生产失败概率需要独立论证，功能测试不构成证明。 |
| 恒时与平台 | 未做全库恒时证明或非 x86 全量验证；拒绝采样/逆元不承诺恒时，平台内核变化后须针对性验证。 |

## 验证与恢复入口

- TFHE 各步骤的验证和显式七包 SIMD 命令见实施步骤文档 §4。分析基线的 `just simd` 未覆盖 TFHE；实际执行前核对当前 recipe，不能仅凭命令名认定覆盖。
- 修改外积时还应覆盖 lattice、NTRU 及两路 NTRU TFHE；性能复测使用相应外积、NTRU primitives 和 TFHE PBS/CBS 基准，固定参数、CPU、工具链和 feature。
- 公开接口入口：[LWE](crates/primus_lwe/README.zh_CN.md)、[GLWE](crates/primus_glwe/README.zh_CN.md)、[NTRU](crates/primus_ntru/README.zh_CN.md)、[lattice](crates/primus_lattice/README.zh_CN.md)、[NTRU NTT TFHE](crates/primus_tfhe_ntru_ntt/README.zh_CN.md)、[NTRU Fourier TFHE](crates/primus_tfhe_ntru_fourier/README.zh_CN.md)。
