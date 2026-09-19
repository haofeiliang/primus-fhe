# Workspace 开发交接

恢复时先检查 Git 状态，再读当前任务的专项文档。开发规范见 [AGENTS](AGENTS.md)；历史验证不代表当前结果。

## 当前任务

- **B8.1–B8.2 NTRU NTT 桶聚合完整 PBS 已完成，下一步 B8.3，不自动启动**：[采样、相位、API 与成本](docs/tfhe-ntru-sparse.md)。B8.1 已提交为 `7b7cea3`；本轮 B8.2 尚未提交。固定可逆二元客户端入口只重采 map，系数 NGSW key 接入原有 `ServerKey`/evaluator，初始化、所有桶和返回 KS 复用外积 scratch。普通/ManyLUT 的独立旋转/相位、奇偶桶数/空桶、错误边界及首调用零分配通过；sparse CBS（含独立材料）和 MVB 明确拒绝。n=728、h=32、N=1024 默认/SIMD 对照：在线快约 39%–67%，keygen 约为经典的 3.20–3.31 倍，key 约大 3.08 倍；u64 sparse 无一致 SIMD 收益。`just tfhe`（严格 rustdoc）、`just tfhe-simd`、workspace all-targets check 和两种 release 示例通过。条件秘密/公开映射的安全及完整失败率未认证；Fourier 必须独立检查奇数重量、稳定性及聚合/完整链误差。
- **B7.1–B7.4 NTRU 经典 ternary 已完成，B7.4 提交为 `c25ba42`**：[秘密采样、融合单步与完整链](docs/tfhe-ntru-ternary.md)。两后端支持 binary/ternary，成对 NGSW 控制使用一次融合外积并复用 scratch；普通/ManyLUT、公钥、Boolean、CBS、MVB 代表组合及首调用零分配通过。n=800 的 u32/u64 完整成本见专项：ternary PBS 比 binary 慢约 27%–71%，server keygen 约两倍；原 u32 binary 前后约 −2.0%～+1.7%。Native 固定偶数重量拒绝，条件分布和完整失败率未认证。
- **B6.1–B6.3 GLWE sparse CBS 已完成**：[NTT 参数与接入](docs/tfhe-sparse-cbs.md)、[Fourier 独立误差与接入](docs/tfhe-cbs.md#7-b63-fourier-sparse-cbs)。两后端复用普通 evaluator 的 classic/sparse BR 及所选 scratch，共用 trace/scheme switch；稀疏 server-key 工厂均接受可选 CBS 配置并返回 `KeyGenerationError`。Fourier 两 FFT/order/seed 的 u64 输出 `(8,3)` 通过聚合 FFT、逐级 Native halving、逐层相位、非恒定 CMUX 与零分配验收；`(9,3)` 未纳入通过配置，默认/SIMD 数值差异分别记录。原型与临时 trace 访问器已清理，现有测试及 CBS bench 承担正式回归。默认/SIMD TFHE 检查、严格 rustdoc、两种 release 示例和基准通过；本组 Fourier 稀疏链多数场景慢 7%–24%，server key 约大 3.09 倍，保持显式选择。
- **B5.1–B5.4 已完成，B5.4 提交为 `18a1288`**：两族 Native 偶尺度 Fourier MVB 的[表示与独立误差](docs/tfhe-mvb-fourier.md)、[应用/组合/成本](docs/tfhe-mvb-fourier-costs.md)已验收。GLWE 支持经典 binary/ternary 和 sparse binary、两种 order；NTRU 经典 ternary 已在 B7.4 接入。3/17 阈值的默认/SIMD 等编码对照、误差、资源与示例已记录；不从功能样本推断任意因子/参数精度或自动选择算法。
- **B4 及后续内核优化已提交为 `1f6bab2`**：Fourier sparse 完整基准、常数准备与 NTT 系数 GGSW 优化见[稀疏 PBS](docs/tfhe-sparse-pbs.md)。Native/Barrett 加减保留普通循环，Shoup u64 原地乘法改用普通循环；[u64 测量与取舍](docs/simd-u64.md)保留微基准退化和完整消费者无稳定收益的边界，Native 后续原型已撤回。历史验证与具体性能前提见专项，不自动重开优化。
- **B3 已完成**：NTRU NTT MVB 的算法、布局和成本见[NTRU 测量](docs/tfhe-mvb-ntru.md)；GLWE NTT sparse×Boolean/bivariate/odd-full 已完成两种 order 的受控误差、门链、相位/解码与首调用零分配验收，见[分步计划](docs/tfhe-backend-plan.md)。
- **B2.1–B2.2 已完成**：Boolean 门算法、LUT 和 LWE 工作区由 `primus_tfhe` 共享，四后端提供 Boolean 工厂，保留独立加解密器及私钥/公钥加密。客户端错误归 family `BooleanError`，求值器构造归共享 `TfheEvaluationError`。共同真值表、混合门链、错误边界和 NTRU 首调用零分配通过；NTRU 覆盖 NTT 与两种 FFT，默认/SIMD 检查和测试通过。见[公共用法](crates/primus_tfhe/README.zh_CN.md#boolean-门)。
- **GLWE NTT 系数域加解密已接入**：[算法、性能与误差](docs/glwe-coefficient-client.md)。在 `NttGlweSecretKey` 增加三个固有方法，NTT `AccumulatorClient` 改用 N 系数、析构时擦除的 scratch；高层接口不变，保持精确等价和在线零分配。u64 Fourier 原型真实相位噪声 RMS 增加约 6%–13%，按用户决定暂不接入；不重开全底层整理。
- **B1.1–B1.7 已完成**：[分步计划](docs/tfhe-backend-plan.md)、[高层接口与成本验收](docs/tfhe-api-costs.md)。四后端使用具名配置、自动建表、带可选 CBS 的 `ServerKey`、绑定消费与 accumulator 客户端；GLWE NTT 的 CBS 参数现在也绑定输入明文模数。默认/SIMD、严格 rustdoc、底层回归及九个 release 示例通过；四后端完整消费首调用零分配，复用 scratch 省去独立 CMUX 缓冲。对 `66ae701` 的当前时间/资源对照已记录；NTRU NTT 微型 fixture 对资源放置敏感，不声称所有负载等时。稀疏 CBS 后续已在 B6 接入，正式尾界未认证；逐系数 RevHomTrace 保留，共享 automorphism 优化暂缓。
- 旧 S0–S9 及 LUT/PBS 的 **P1–P4 已完成**；[完成索引](docs/tfhe-plan.md)只用于恢复，不重开旧步骤。基础 crate 的既有整理也不自动重启。
- **T1–T3 已完成**：[经典 GLWE ternary PBS](docs/tfhe-ternary.md#6-实施顺序与完成条件)已接入 NTT/Fourier 两后端，含两种 order、普通/交错 LUT、公钥客户端与 NTT CBS/MVB。small-LWE 分布选择 ternary；binary 路径保留。
- GLWE 公共层与两个后端统一使用 `Encryptor`、`Decryptor`、`ClientKey`、`EncryptionKey`、`PbsOrder` 和 `TfheParameters`；底层保留数学/表示前缀。参数以 `accumulator_glwe`、`blind_rotation_ggsw` 和 `external_lwe_dimension` 区分角色。`ClientKey::generate` 负责系数域密钥生成；客户端统一编码后由 `EncryptionKey` 加密。Boolean 客户端以 `try_new` 构造，保留私钥/公钥加密并直接使用 `LweCiphertext`；普通 LUT 从 `context.parameters()` 编译，MVB 由对应后端 context 准备。入口见 [GLWE README](crates/primus_tfhe_glwe/README.zh_CN.md)。
- NTRU 公共层与两个后端采用相同高层名称；参数以 `blind_rotation`、`accumulator_ntru`、`ntru_key_switching` 区分角色，普通 LUT 由参数编译。客户端统一编码，密钥错误共享；可逆性/稳定性拒绝采样仍属于后端，生成入口使用 `try_`。入口见 [NTRU README](crates/primus_tfhe_ntru/README.zh_CN.md)。
- 采用融合式 `ACC += (GGSW(s⁺)-X^-α GGSW(s⁻)) ⊠ ((X^α-1)ACC)`。每坐标两份控制、一次外积；负指数取自同一量化结果。两后端保留完整组合 GGSW 工作区，NTT 要求 `MonomialNttTable`。低层 BR context 从 BSK 构造，控制迭代器显式区分 binary 与 ternary 对。
- n=728 完整 PBS 的默认/SIMD 成本、密钥和 scratch 见专项文档；不将等算术成本解释为等安全或等失败率。下一算法由用户按[候选清单](docs/tfhe-next.md)选择，不自动启动。

## 有效边界与未决项

- GLWE/NTRU 两族均已支持经典 ternary；桶聚合 ternary 另行设计。Automorphism BR 暂缓；NTRU packing 按用户决定排除。
- 已实现能力以 [TFHE README](crates/primus_tfhe/README.zh_CN.md)为准。GLWE 两后端均已接入稀疏 CBS；MVB 采用 Rounded 前半区输入和 unsigned Scaled 输出；GLWE/NTRU NTT 使用奇数 q，GLWE Fourier 支持 u32/u64 Native 偶尺度及经典/稀疏密钥。NTRU Fourier 支持相同 Native 偶尺度与字宽，以及经典 binary/ternary BR。Scaled 数值标志不可直接送入 Boolean 门或沿用原输入编码。
- 连续因子存储减少分配，但没有统一在线收益：固定 CPU 的两轮 GLWE 17 输出对照中，BK 慢约 3%，KB 接近；具体原因未定位。[测量与复现](docs/tfhe-mvb.md#连续因子存储的成本对照)保留该限制；B3.2 比较当前 NTRU 算法选择，未比较 NTRU 存储变更前后。
- [稀疏 PBS](docs/tfhe-sparse-pbs.md)的条件映射分布及完整安全/尾界、[MVB](docs/tfhe-mvb.md)的相关噪声、[居中/shift](docs/tfhe.md#p1r-取整策略取舍)正式接入均未完成理论认证或实现扩展，功能测试不关闭这些问题。
- 历史 n=512 的稀疏测量不能当作当前 n=728 的结果；参数与测量入口见各专项文档和[测量索引](docs/benchmarks/tfhe.md)。

## 按目标恢复

| 目标 | 入口 |
| --- | --- |
| LUT、编码、量化、秘密域与后处理 | [TFHE 设计总览](docs/tfhe.md) |
| 下一算法与启动条件 | [候选清单](docs/tfhe-next.md)、[ternary 设计](docs/tfhe-ternary.md) |
| 非 TFHE 的既有选择与待核实问题 | [实现决定参考](.agents/references/implementation-decisions.md)，只读相关章节 |
| 验证 | [justfile](justfile)：`just tfhe` 覆盖七包默认 check/Clippy/test/doc 与 xtask；`just tfhe-simd` 覆盖七包 nightly SIMD。原 `just simd` 不覆盖全部 TFHE |

共享测试辅助位于 `test-support/`，以 dev-dependency 引入，两条 TFHE recipe 同时检查它们；不再用跨 crate 的 `#[path]`，以兼容 rust-analyzer。分配计数 allocator 由测量程序显式注册。

修改外积等底层原语时，额外检查相应 lattice、GLWE/NTRU 与 TFHE 消费者。尚未做全库恒时证明、非 x86 全量验证或生产安全认证。
