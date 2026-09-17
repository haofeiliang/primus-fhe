# Workspace 开发交接

恢复时先检查 Git 状态，再读当前任务的专项文档。开发规范见 [AGENTS](AGENTS.md)；历史验证不代表当前结果。

## 当前任务

- 旧 S0–S9 及 LUT/PBS 的 **P1–P4 已完成**；[完成索引](docs/tfhe-plan.md)只用于恢复，不重开旧步骤。基础 crate 的既有整理也不自动重启。
- **T1–T3 已完成**：[经典 GLWE ternary PBS](docs/tfhe-ternary.md#6-实施顺序与完成条件)已接入 NTT/Fourier 两后端，含两种 order、普通/交错 LUT、公钥客户端与 NTT CBS/MVB。small-LWE 分布选择 ternary；binary 路径保留。
- GLWE 公共层与两个后端统一使用 `Encryptor`、`Decryptor`、`ClientKey`、`EncryptionKey`、`PbsOrder` 和 `TfheParameters`；底层保留数学/表示前缀。参数以 `accumulator_glwe`、`blind_rotation_ggsw` 和 `external_lwe_dimension` 区分角色。`ClientKey::generate` 负责系数域密钥生成；客户端统一编码后由 `EncryptionKey` 加密。Boolean 客户端以 `try_new` 构造，保留私钥/公钥加密并直接使用 `LweCiphertext`；普通 LUT 从 `context.parameters()` 编译，NTT 专属 MVB 仍由 context 准备。入口见 [GLWE README](crates/primus_tfhe_glwe/README.zh_CN.md)。
- 采用融合式 `ACC += (GGSW(s⁺)-X^-α GGSW(s⁻)) ⊠ ((X^α-1)ACC)`。每坐标两份控制、一次外积；负指数取自同一量化结果。两后端保留完整组合 GGSW 工作区，NTT 要求 `MonomialNttTable`。低层 BR context 从 BSK 构造，控制迭代器显式区分 binary 与 ternary 对。
- n=728 完整 PBS 的默认/SIMD 成本、密钥和 scratch 见专项文档；不将等算术成本解释为等安全或等失败率。下一算法由用户按[候选清单](docs/tfhe-next.md)选择，不自动启动。

## 有效边界与未决项

- Ternary 首批为 GLWE NTT/Fourier；NTRU ternary、桶聚合稀疏 ternary 分开安排。Automorphism BR 暂缓；NTRU packing 按用户决定排除。
- 已实现能力以 [TFHE README](crates/primus_tfhe/README.zh_CN.md)为准。稀疏 CBS 仍拒绝；MVB 当前限定 GLWE NTT、奇数 q、Rounded 前半区输入和 Scaled 输出。
- [稀疏 PBS](docs/tfhe-sparse-pbs.md)的条件映射分布及完整安全/尾界、[MVB](docs/tfhe-mvb.md)的相关噪声、[居中/shift](docs/tfhe.md#p1r-取整策略取舍)正式接入均未完成理论认证或实现扩展，功能测试不关闭这些问题。
- 历史 n=512 的稀疏测量不能当作当前 n=728 的结果；参数与测量入口见各专项文档和[测量索引](docs/benchmarks/tfhe.md)。

## 按目标恢复

| 目标 | 入口 |
| --- | --- |
| LUT、编码、量化、秘密域与后处理 | [TFHE 设计总览](docs/tfhe.md) |
| 下一算法与启动条件 | [候选清单](docs/tfhe-next.md)、[ternary 设计](docs/tfhe-ternary.md) |
| 非 TFHE 的既有选择与待核实问题 | [实现决定参考](.agents/references/implementation-decisions.md)，只读相关章节 |
| 验证 | [justfile](justfile)：`just tfhe` 覆盖七包默认 check/Clippy/test/doc 与 xtask；`just tfhe-simd` 覆盖七包 nightly SIMD。原 `just simd` 不覆盖全部 TFHE |

修改外积等底层原语时，额外检查相应 lattice、GLWE/NTRU 与 TFHE 消费者。尚未做全库恒时证明、非 x86 全量验证或生产安全认证。
