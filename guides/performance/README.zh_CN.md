# 性能取舍与测量

[English](README.md) | 简体中文

当前 API 和契约见[开发指南](../development/README.zh_CN.md)。本目录保存性能选择、成本及可复现证据。
每份报告注明版本、参数和实测范围；历史结果不代表当前验证，也不是安全保证。

## 保留的选择与限制

| 主题 | 决策与依据 |
| --- | --- |
| 系数算术 | 在各自约束内保留 NTRU pair、有界 NTT pair、GLWE u64 分组累加与紧凑桶末约简，以及 NTRU Fourier u64 四路累加。见[算术报告](sparse-arithmetic.md)，尤其是当前[分组与约简联合复评](sparse-arithmetic.md#combined-7-g-and-7-l-reassessment)和 [Fourier 复评](sparse-arithmetic.md#current-source-four-way-reassessment)。不同基线的收益不能相加。 |
| 布局与批处理 | 保留 NTRU LUT 内部双输入盲旋转。聚合 tiles、首桶特化、流式外积及 GLWE tile-major 密钥在受测负载中不足以采纳。见[布局与批处理](sparse-layout-and-batching.md)。 |
| 参数 | GLWE NTT 副本/桶数与分解候选仅适用于已验收消费者，默认配置不变。PBS 通过不能证明 CBS 输出尺度有效。见[证据索引](#证据索引)中的三份参数报告。 |
| 共享投影 | 一级原型已撤回：完整请求的小幅收益不足以抵偿存储、接口和误差契约成本。[研究报告](shared-projection-analysis.md)保留推导和负面结果。 |
| 工作区存储 | 跨请求复用与跨阶段共用地址分别决策。按角色保留必要缓冲；更少内存或相同形状不能证明更快。见[工作区测量](workspace-measurements.md)及 [sparse scratch 对照](sparse-baseline.md#aggregate-scratch-address-comparison)。 |
| 论文对照 | Algorithm 2、OpenFHE 和 HEXL 测量有明确的适配边界。绝对延迟不能证明与尚未取得的作者 sparse 实现等价。见[论文对照](sparse-paper-comparison.md)。 |

## 证据索引

| 报告 | 回答的问题 |
| --- | --- |
| [TFHE 基线](tfhe-baseline.md) | 前轮整理中的基准覆盖、setup、对齐与容器测量 |
| [工作区测量](workspace-measurements.md) | 借用资源、参数共享、返回缓冲与存储成本 |
| [Sparse 基线](sparse-baseline.md) | 完整请求、阶段诊断、保留/峰值 heap 与 aggregate scratch |
| [Sparse 算术](sparse-arithmetic.md) | Pair/四路累加、惰性范围与紧凑约简 |
| [Sparse 布局与批处理](sparse-layout-and-batching.md) | Tiles、首桶、流式处理、源布局和 LUT 双输入旋转 |
| [论文对照](sparse-paper-comparison.md) | 参数/操作对齐、OpenFHE、扩展存储与 HEXL |
| [副本与桶数参数](sparse-parameter-measurements.md) | 匹配、重试分布、内存与固定 basis 候选 |
| [分解参数](sparse-decomposition-measurements.md) | 各角色误差预算与有限候选筛选 |
| [消费者验收](sparse-consumer-measurements.md) | PBS/ManyLUT/MVB、反馈及 CBS→CMux，包含失败尺度 |
| [共享投影](shared-projection-analysis.md) | Reverse trace 成本、任意尾部误差与已撤回原型 |

## 测量方法

1. 固定比较边界：源码版本、机器/CPU、工具链、feature、参数和完整操作。算术/布局实验保留同一逻辑密钥、公开 bucket 图、输入和 LUT；参数研究另行说明匹配、误差与材料差异。
2. 采样前编译并保存两版程序。每次迭代在已准备的缓冲上测一个具名工作负载，无关 setup、分配、验证和诊断探针放在计时外。候选改变构造时，单独报告构造成本。
3. 在固定 CPU 上用独立进程交替运行两版，记录样本数、预热、测量设置及 benchmark ID。保留控制组、不利观察和复测；单进程的 Criterion 区间不能覆盖进程间波动。
4. 使用独立 oracle 或适用的精确捕获验证数学等价性。Gadget 消费者需要每层尺度正确时，仅检查解密不足。明确已测与未测路径。
5. 以可重复的**完整请求**收益，结合数值范围、保留/峰值存储、代码体积、接口和维护成本决策。仅阶段加速或分配次数减少不足以采纳。不设统一百分比门槛，说明具体取舍为何值得。

计数器只代表其声明的范围：分配流量不是保留 heap 或峰值，请求 heap 不是 RSS，墙钟时间不能单独确定 cache 写回或带宽原因。阶段探针与验收计时分开。各报告的命令、seed、参数及限制保留在结果旁；验证命令和普通 CI 见[测试指南](../development/testing.md)。

## 数据与工具

原始测量表放在 [data/](data/)，对应报告解释 CSV 列及比较方式。独立[投影 oracle](tools/shared_projection_oracle.py)的用法见[投影研究](shared-projection-analysis.md#oracle-与进入原型的条件)。证据资产随报告维护，不保留临时候选实现，也不把实验加入普通 CI。

复评时扩展对应主题报告；阶段进度与本地实施计划不放在此目录。公开契约仍在 rustdoc/README，局部算法理由仍在实现旁。
