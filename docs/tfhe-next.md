# TFHE 后续算法候选

本文承接 [P1–P4](tfhe-plan.md)，记录值得补充的能力、应用价值与启动条件，避免把论文清单当作必须全部实现的计划。**ternary LWE secret 的经典 GLWE PBS 已完成**，具体设计与测量见 [ternary 专项](tfhe-ternary.md)。当前实施状态以 [HANDOFF](../HANDOFF.md) 为准。

已有算法在四个后端的覆盖差异、可直接补齐项和组合前置条件见[后端覆盖与补齐路线](tfhe-backend-coverage.md)，执行任务见 [B1–B8 分步计划](tfhe-backend-plan.md)。

## 1. 优先级与应用目标

| 顺序 | 候选 | 解决的问题 | 建议的首个交付范围 |
| --- | --- | --- | --- |
| 已完成 | Ternary LWE secret | 支持实际 BR 秘密取 `-1/0/1`，扩展密钥分布与参数选择 | 经典 GLWE NTT/Fourier；每系数两份控制 GGSW、一次融合外积；普通、交错 PBS 与已有组合入口 |
| 2 | 通用 FDFB | 支持无 padding bit 的完整消息空间，包括二次幂明文模数上的任意函数 | 先选择一种两阶段方案，显式管理中间编码、偏移与噪声；不同时实现全部变体 |
| 2 | Digit / bit extraction | 将单个多位整数拆成低基数数字或比特，供大 LUT、比较、进位、S-box 等使用 | 明确输入位宽、基数、输出编码；与 FDFB 一起选择算法及共享计算 |
| 3 | HLUT / LFBS | 单个累加器装不下的多数字、大输入域函数 | 固定一个 8-bit S-box 或两个 4-bit 输入的函数做原型对照，再选择正式路线 |
| 按延迟需求 | Multi-bit BR | 利用多核降低单次 PBS 延迟 | 小 grouping factor、明确密钥增长和线程数；保持经典路径作为参照 |
| 按精度需求 | Extended / sorted PBS | 扩展有效旋转域，或减少执行的外积 | 先复现虚拟旋转域、专用量化与排序/剪枝条件，再考虑正式布局 |
| 按吞吐需求 | Amortized bootstrapping | 大量独立密文一起处理时降低每个输入的成本 | 先有真实批量工作负载，再选择 packing 与摊销路线 |
| 按误差预算 | Drift mitigation | 改善模切漂移或不利输入下的量化误差 | 与具体秘密分布、公开质量测试及零加密重随机化一起研究 |

这里的优先级是工程建议，不是对论文优劣的统一排名。比较时固定功能、输入/输出表示、目标失败率与安全目标，分别报告在线成本、keygen、密钥大小和工作区。

## 2. Ternary：经典 GLWE 已完成

用户提出的融合分解为首选，每个系数两份控制 GGSW、一次外积；准确恒等式、噪声递推、与 Joye–Paillier 组合控制的区别及 T1–T3 只在 [ternary 专项](tfhe-ternary.md)维护。NTRU 还需处理可逆秘密与 padding，桶聚合稀疏 ternary 还需隐藏正负 selector，均独立安排。

## 3. Full-domain 与数字拆分

已有 `try_new_odd_full_domain` 解决奇数明文模数的特定全域编程；它不覆盖二次幂明文模数上的任意无 padding 函数。**全域**和**大域**也不同：前者解决负循环的符号约束，后者解决 LUT 容量及输入精度。

优先研究 [Fast and Accurate: Efficient Full-Domain Functional Bootstrap and Digit Decomposition for Homomorphic Computation](https://eprint.iacr.org/2023/645) 的 FDFB-Compress 及数字拆分，参照[作者实现](https://github.com/msh086/FDFB-TCHES-2024)。两阶段方案与当前普通 PBS 容易组合，但中间尺度、偏移、压缩后的区间宽度和误差余量必须进入契约。

设计边界：

- 由独立编译产物保存多阶段 LUT 与中间编码，不给普通 `LookupTable` 添加一个含义不清的 `full_domain` 开关。
- Digit extraction 明确 `Enc(x) → Enc(x₀), …, Enc(xᵣ)` 的基数与有效域。已有 CBS 转换密文表示，不自动完成任意多位整数的 bit extraction。
- Select、CancelSign 等路线需要的 packing / encrypted LUT 按选定算法补齐；PBS 次数不是唯一成本指标。

## 4. 大 LUT：先对照 HLUT 与 LFBS

### HLUT

[Decomposition of Large Look-Up Tables for Fast Homomorphic Evaluation](https://www.nicolasbon.com/assets/pdf/26HLUT.pdf)（TCHES 2026）将大函数分解为小素数域上的 LUT 和线性运算；[作者 artifact](https://github.com/CryptoExperts/artifact-HLUT-TCHES) 可作为预计算产物与验证入口。

它与现有小奇数模数全域 PBS 比较接近，适合作为低接入成本候选。首个原型优先导入一个固定函数的离线分解，不先开发通用分解器。须计入离线搜索/线性系统求解成本、数字表示转换，以及在线线性组合放大的误差；不能把论文中不同失败率设置的耗时直接比较。

### LFBS

[Leveled Functional Bootstrapping via External Product Tree](https://eprint.iacr.org/2025/022) 通过加密单项式 selector 与外积树评价多数字函数。同一输入的 selector 可复用，但树的工作量和 LUT 存储仍随输入数字数增长；少量 BR 不意味着整个算法只有少量运算。

现有 `GGSW(m)` 型 CBS 输出不等于它需要的 `GGSW(X^Encode(m))`。应先明确 monomial selector 的生成，再核对 GLWE packing、trace、scheme switching 和外积树。现有 GLWE packing 与 GLev→GGSW scheme switching 可复用，但这不代表 LFBS 流程已经齐全。Packing 中可能使用 automorphism，与暂缓的 **automorphism BR** 是不同工作。

### 选择标准

用同一个固定函数、输入编码、输出编码和误差目标比较：

1. 输入拆分/表示转换、完整在线耗时与吞吐。
2. 离线编译、LUT/selector/key 大小、工作区。
3. selector 跨多个函数复用后的收益。
4. 所需新增原语与维护成本。

实现一条有明确收益的路线即可；[WoP / functional bootstrapping](https://eprint.iacr.org/2021/729.pdf) 保留为比较依据，不据此同时开启第三套大 LUT 框架。

## 5. 性能方向的启动条件

- **Multi-bit：** 对 binary 的分组大小 `g`，典型扩展密钥每组保存约 `2^g-1` 个控制，外积轮数约降为 `n/g`。收益与并行度、缓存和密钥带宽有关，适合先做 CPU 多核测量。依据见 [Joye–Paillier §4](https://marcjoye.github.io/papers/JP22ternary.pdf) 与 [TFHE-rs 的 parallelized PBS](https://docs.zama.org/tfhe-rs/0.8/guides/parallelized_pbs)。独立 PBS 的线程调度不需要先实现 multi-bit。
- **Extended / sorted：** [Accelerating TFHE with Sorted Bootstrapping Techniques](https://eprint.iacr.org/2025/2214) 及[作者 artifact](https://github.com/zama-ai/tfhe-rs/tree/artifact_asiacrypt_2025/) 是 GLWE 候选；NTRU 的扩展另见 [2026/1447](https://eprint.iacr.org/2026/1447)。需要对应的扩展累加器、旋转规则和量化/剪枝设计，不是给当前 `a_i` 排序即可。优先由高输入精度需求触发。
- **Amortized：** [Fast amortized bootstrapping with small keys and polynomial noise overhead](https://eprint.iacr.org/2025/686) 面向独立输入的批量摊销。与同一输入多输出的 MVB、普通 batch API 分开；没有实际批量规模与 packing 成本依据时暂缓。
- **Drift mitigation：** [2024/1718](https://eprint.iacr.org/2024/1718) 的公开质量测试和零加密重随机化值得研究，不将其归入一个 rounding-mode enum。先依据目标秘密分布验证统计前提；既有固定 half-shift 的反例与限制仍有效，见 [P1.R](tfhe.md#p1r-取整策略取舍)。

## 6. 保留但暂缓

| 方向 | 暂缓原因 / 重新启动条件 |
| --- | --- |
| Automorphism BR | 用户已明确短期不需要；以后面向 Gaussian 等更广秘密分布时，再研究 [Bootstrapping (T)FHE Ciphertexts via Automorphisms](https://eprint.iacr.org/2025/163) |
| Recursive FDFB | 依赖额外的大 LUT / extended 技术，先完成一个基础 FDFB；参考 [2025/1255](https://eprint.iacr.org/2025/1255) 与[作者实现](https://github.com/SNUCP/fast-fdfb) |
| 素数分圆环上的 FDFB | 改变环、变换与提取契约，无法视为现有 LUT 的小扩展；[论文入口](https://www.sciencedirect.com/science/article/pii/S0304397525003305) |
| Binary-NTT shallow | [2026-1730.pdf](../temp/2026-1730.pdf) §5 单独研究；P3 交付的是 §4 稀疏 PBS，不能标成整篇论文均已实现 |

## 7. 共享库的边界

继续保留普通、交错、双输入和固定尺度分解式 LUT 的明确含义。新增算法只有在存在新的编译产物、密钥布局或执行契约时才新增类型；不预先引入覆盖所有 PBS 的策略 trait。

- 秘密分布与 BR 控制属于后端，LUT 不增加 ternary 标志。
- 多阶段算法保存真实中间编码、密钥域及缓冲区要求，不假设所有阶段都是普通 PBS。
- 加密 LUT、packing、selector 转换是具体算法的依赖，按实际消费者补齐。
- 测试保护代数、布局与端到端契约；大型统计和论文复现实验留在独立测量中，不扩张默认 CI。


## 8. 应用驱动的工程补充

以下不属于新密码算法，按实际调用需求安排：

- Fourier GLWE CBS、NTRU Boolean：复用已有原语，分别验证表示/输出尺度与完整链。
- Batch client/PBS、PBS `_assign`：明确独立输入调度、缓冲区别名与覆盖顺序，复用 evaluator，不用 clone 隐藏分配。
- ServerKey 存储量查询：可替换 `xtask/src/ntru_params.rs` 的手写公式，区分系数载荷、allocator 请求量与进程内存。
- 独立 KSK 噪声分析、整数/message-carry 层、序列化和 GPU 等，等待具体需求，不扩入 ternary 任务。
