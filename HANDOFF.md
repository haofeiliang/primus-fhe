# Workspace 开发交接

恢复时先检查 Git 状态，再读当前任务的专项文档。开发规范见 [AGENTS](AGENTS.md)；历史验证不代表当前结果。

## 当前任务

- **TFHE R1–R4 已完成**：[整理结果与验收](docs/tfhe-refactor-plan.md)。R3 已提交为 `458ccce`，R4 的两份 CBS 回归补充和文档收尾尚未提交；数值实现未再变动。默认/SIMD 全链及相关底层验证通过，范围与限制见结果文档。后续等待用户选择，不自动重启整理或提交。
- **B1–B8 已完成，B8.3 已提交为 `cba9c01`**：[后端补齐计划](docs/tfhe-backend-plan.md)。旧 S0–S9、[P1–P4](docs/tfhe-plan.md)、[T1–T3](docs/tfhe-ternary.md)均不自动重启；只按本次目标读取完成记录。
- 新算法由用户按[候选清单](docs/tfhe-next.md)选择。本轮不扩展未验收组合，不重开底层全库整理；局部原语变更须有明确的资源或维护收益。

## 有效边界与未决项

- R1 的 Native `N=1024,t=255,k=4` 构造成本增加约 4.4%（0.06 μs）；R2 的 NTRU NTT SIMD CBS 仍有约 2%～3% 整体构建间回退，恢复独立 trace scratch 未改善，故保留共享的 25 KiB 内存收益。NTT keygen 原型已撤回。方法、隔离对照及边界只在[成本记录](docs/tfhe-refactor-costs.md)维护，不声称零回退或普遍加速。

- GLWE/NTRU 两族均已支持经典 ternary；桶聚合 ternary 另行设计。Automorphism BR 暂缓；NTRU packing 按用户决定排除。
- 已实现能力以 [TFHE README](crates/primus_tfhe/README.zh_CN.md)为准。GLWE 两后端均已接入稀疏 CBS；MVB 采用 Rounded 前半区输入和 unsigned Scaled 输出；GLWE/NTRU NTT 使用奇数 q，GLWE Fourier 支持 u32/u64 Native 偶尺度及经典/稀疏密钥。NTRU Fourier 支持相同 Native 偶尺度与字宽、经典 binary/ternary BR，以及奇数重量 binary 桶聚合普通/ManyLUT；两 NTRU 后端均拒绝 sparse CBS/MVB。Scaled 数值标志不可直接送入 Boolean 门或沿用原输入编码。
- 连续因子存储减少分配，但没有统一在线收益：固定 CPU 的两轮 GLWE 17 输出对照中，BK 慢约 3%，KB 接近；具体原因未定位。[测量与复现](docs/tfhe-mvb.md#连续因子存储的成本对照)保留该限制；B3.2 比较当前 NTRU 算法选择，未比较 NTRU 存储变更前后。
- [稀疏 PBS](docs/tfhe-sparse-pbs.md)的条件映射分布及完整安全/尾界、[MVB](docs/tfhe-mvb.md)的相关噪声、[居中/shift](docs/tfhe.md#p1r-取整策略取舍)正式接入均未完成理论认证或实现扩展，功能测试不关闭这些问题。
- 历史 n=512 的稀疏测量不能当作当前 n=728 的结果；参数与测量入口见各专项文档和[测量索引](docs/benchmarks/tfhe.md)。

## 按目标恢复

| 目标 | 入口 |
| --- | --- |
| 当前类型、错误、工作区与使用方式整理 | [R1–R4 整理结果](docs/tfhe-refactor-plan.md)，已完成 |
| LUT、编码、量化、秘密域与后处理 | [TFHE 设计总览](docs/tfhe.md) |
| 已有后端能力、组合与测量 | [B1–B8 完成入口](docs/tfhe-backend-plan.md)、[测量索引](docs/benchmarks/tfhe.md) |
| 下一算法与启动条件 | [候选清单](docs/tfhe-next.md)、[ternary 设计](docs/tfhe-ternary.md) |
| 非 TFHE 的既有选择与待核实问题 | [实现决定参考](.agents/references/implementation-decisions.md)，只读相关章节 |
| 验证 | [justfile](justfile)：`just tfhe` 覆盖七包默认 check/Clippy/test/doc 与 xtask；`just tfhe-simd` 覆盖七包 nightly SIMD。原 `just simd` 不覆盖全部 TFHE |

共享测试辅助位于 `test-support/`，以 dev-dependency 引入，两条 TFHE recipe 同时检查它们；不再用跨 crate 的 `#[path]`，以兼容 rust-analyzer。分配计数 allocator 由测量程序显式注册。

修改外积等底层原语时，额外检查相应 lattice、GLWE/NTRU 与 TFHE 消费者。尚未做全库恒时证明、非 x86 全量验证或生产安全认证。
