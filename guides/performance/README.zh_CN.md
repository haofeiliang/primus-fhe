# 性能取舍与测量

[English](README.md) | 简体中文

本目录记录性能选择、成本和历史证据。当前 API 与契约见[开发指南](../development/README.zh_CN.md)。每份报告注明版本、负载和限制；历史测量不代表当前验证或安全保证。

## 主题报告

| 报告 | 决策与范围 |
| --- | --- |
| [Sparse 算术](sparse-arithmetic.md) | 在各自数值和负载边界内保留 pair/group/四路累加及紧凑约简。复评保留不利结果，不同基线的收益不能相加。 |
| [Sparse 布局与批处理](sparse-layout-and-batching.md) | 保留 NTRU LUT 双输入盲旋转。Tiles、首桶特化、流式处理、tile-major 密钥和共享投影在受测负载下不足以抵偿成本。 |
| [Sparse 参数与消费者](sparse-parameters.md) | 副本/桶数与分解候选改变匹配、存储和误差预算。PBS 通过不能证明 CBS 输出尺度有效，也不构成安全性或 DFR 估计。 |
| [准备与工作区测量](workspace-measurements.md) | 准备状态、对齐与 scratch 共享分别评估。更少内存或相同缓冲形状不能证明完整请求更快。 |
| [论文对照](sparse-paper-comparison.md) | 区分论文表格、较早 Primus/OpenFHE 研究和后来取得的作者 fork/HEXL 实验。参数、采样、返回路径和构建存在差异；后者原始记录已不保留。 |
| [Fourier 首项覆盖](fourier-first-write.md) | 保留清零后累加。首项覆盖对已测 binary PBS/classic CBS 有益，但 sparse CBS 和进程间波动不足以支持全局替换。保留全部 54 组有效构建配对，包括一组 FFT plan 不一致的结果。 |

## 当前基准

基准位于所属后端或 LUT crate。使用 [TFHE 基准命令](../development/testing.md#tfhe-benchmarks)和[高精度 LUT 命令](../development/testing.md#high-precision-lut-benchmarks)；feature 与计时边界见该指南及各 crate 的 bench 文件。[参数目录](../development/tfhe-parameters.md#current-backend-benchmarks)说明现行配置。历史负载 ID 是证据标签，不是当前 target；无需恢复已删除的集中 runner 和报告工具。

## 测量方法

1. 固定版本、二进制、CPU、工具链、feature、参数和完整操作，确认产物包含预期实现；区分参数变化与算术/布局变化。
2. 每次迭代测一个请求，无关准备和检查放在计时外，构造成本单独记录。验证实际数值契约；仅解密不足时，还须检查 gadget 输出尺度。
3. 控制运行顺序并比较独立进程。保留不利结果、未修改路径的控制组和复测；单进程置信区间不能衡量进程间波动。
4. 根据可重复的完整请求收益，结合数值范围、存储、代码体积和维护成本决策；仅阶段加速或分配减少不足以采纳。

历史 CPU 4/8 测量来自**同一台** Ryzen 9 9955HX3D 的两个 L3 组（96/32 MiB），不是独立平台。混合结果不能证明普遍回退或 cache 写回原因。分配流量不是保留 heap、峰值或 RSS；耗时本身不能诊断内存流量。各报告将测量设置、未测路径与结果放在一起。

## 证据限制

[data/](data/) 中六份 CSV 分属算术、工作区和 Fourier 报告，由对应报告解释字段与来源。临时候选、原始二进制和部分适配源码已不保留；历史摘要不承诺完整复现。按 LUT 内容裁剪选择的旧测量，不能当作当前固定完整树的测量。

复评在对应主题报告中进行，保留比较边界。普通验证归[测试指南](../development/testing.md)，公开契约归 rustdoc/README，局部算法理由放在代码旁。
