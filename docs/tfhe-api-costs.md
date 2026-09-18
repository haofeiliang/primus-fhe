# B1.7：TFHE 高层接口验收

B1.4–B1.7 将四后端常用工作流收拢为数学配置 → context → 配套密钥 → 按用途创建 evaluator → 复用输入/输出。
公开用法及错误职责见[公共 README](../crates/primus_tfhe/README.zh_CN.md)，后续算法按[分步计划](tfhe-backend-plan.md)推进。
本文保存接口整理的成本对照与下层边界，不替代算法噪声或安全分析。

## 接口和下层边界

本轮检查四后端 context、key、accumulator client、CBS 参数/密钥/evaluator，以及两族公共参数与错误；
追踪直接调用的 GLWE/NTRU 秘密转换、加解密、scheme switch、lattice 外积与工作区，并核对示例和双语 README。
没有重新进行无关底层模块的完整审查。

- 保留现有类型分工：`ServerKey` 持有可选 CBS 组件，普通 PBS、CBS、MVB 分别准备工作区；
  `AccumulatorClient` 绑定环秘密及转换缓冲。没有增加能力 trait、总 context 或新的密文包装。
- B1.6 已深入 `primus_glwe`：删除两个仅包装外积工作区的 scheme-switch context。
  现有 lattice 外积 context 仍拥有真实的布局和 scratch 契约；GLWE 仅切换分解层数，NTRU 直接复用 BR 工作区。
- B1.7 统一 GLWE NTT 的 CBS 参数绑定：与另三个后端相同，保存输入明文模数，拒绝跨 `t` 使用已准备的参数。
  既有测试增加一次错误域绑定断言；GLWE 的同层数输出 basis 复用仍支持。
  同时修正 NTRU 家族 README 的错误归属，补全 GLWE NTT 导入秘密转换的值域契约引用。
- **已另行验证的下层工作**：GLWE 系数域加解密原语。现有客户端先生成整个变换域密文，再转回系数；
  解密又变换整个系数密文。NTT 直接在 NTT 域采样 mask，可省去 body 正变换；Fourier 在系数域采样，
  保留原始 mask 可减少往返变换。两者系数域解密均可避免 body 正变换。
  [独立原型验证](glwe-coefficient-client.md)确认完整耗时、scratch 和在线零分配收益；NTT 精确等价，
  NTT 已随后接入底层固有方法和 `AccumulatorClient`；u64 Fourier 真实相位噪声有所增加，按用户决定暂不接入。
  这是已有路径，未因本次封装增加变换；不阻塞 B2.1，也不自动推广到需要整多项式乘 `f`/`f⁻¹` 的 NTRU。

TFHE 的秘密域、可选 CBS 和 evaluator 绑定留在 TFHE 层；底层继续显式表达模数、basis、表示及工作区。
目前没有证据支持全面重构 `primus_lattice`、`primus_glwe` 或 `primus_ntru`。

## 测量方法

2026-09-18，AMD Ryzen 9 9955HX3D，固定逻辑 CPU 2；前后均为
`rustc 1.100.0-nightly (bff8e12ff 2026-08-26)`、Criterion 0.8.2、仓库 `target-cpu=native`。
分别测默认与 SIMD。源码基线 **`66ae701`**，改造后为 `e025ba6` 加本轮绑定/注释收尾；算术内核未修改。
两份源码使用相同外部依赖版本，独立 target。构建、测试与耗时采样不并行。

- 复用四后端 `benches/pbs.rs` 的 `complete_pbs_reused_output$`：GLWE 两种 order、Fourier 两种 FFT；
  保留原参数，GLWE 的 n=512/N=1024、NTRU 的 n=800/N=1024 只是前后等价负载，不用于方案间安全比较。
- 复用 [B1.3 CBS](tfhe-cbs.md#4-在线时间与操作数) 的完整负载：n=728/N=1024、三层输出，两种 order/FFT。
- 完整消费用临时诊断复刻四后端 CBS 示例：GLWE Fourier 采用 B1.3 的 TfheFFT/BK profile；
  GLWE NTT 为 n=4/N=256/BK，NTRU 两后端为 n=16/N=256（Fourier 用 RustFFT），均为 u64。
  其余数学配置与对应示例一致，seed=`0xB17`。每轮交替两个已加密输入，计算一次 CBS→CMUX；
  setup、加密、解密、分配均在计时之外。基线显式准备消费 scratch，改造后使用绑定接口。
  加解密两端均复用等价工作区，先验证 `0→1→0` 和首调用/后续零分配。
- Criterion 采用 1 s 预热、3 s 测量、10,000 resamples。PBS GLWE 基准自身固定 10 samples，
  其余为 20 samples。结果取均值及 95% CI，见[计时 CSV](benchmarks/tfhe-b1.7.csv)。
  复测仅针对首轮明显波动项，记录原样保留，不择优替换。

现有基准可在两份源码中用相同命令重建：

```sh
# 每个包分别执行，default 不传 --features，SIMD 传 --features simd。
taskset -c 2 cargo +nightly bench -p primus_tfhe_glwe_ntt --bench pbs -- \
  'complete_pbs_reused_output$' --sample-size 20 --warm-up-time 1 \
  --measurement-time 3 --nresamples 10000 --save-baseline b17_before_default --noplot
# 另三个包替换为 primus_tfhe_glwe_fourier / primus_tfhe_ntru_ntt / primus_tfhe_ntru_fourier。
taskset -c 2 cargo +nightly bench -p primus_tfhe_glwe_fourier --bench circuit_bootstrap -- \
  '/complete$' --sample-size 20 --warm-up-time 1 --measurement-time 3 \
  --nresamples 10000 --save-baseline b17_before_default --noplot
```

改造后使用 `b17_after_default`，SIMD 对应 `b17_{before,after}_simd`。
临时消费/资源诊断不加入 CI 或常规 benchmark；复测按上述 fixture 与计时边界重建等价 harness。

## 在线结果与诊断

首轮完整 PBS 的默认差异为 −2.65%～+1.78%；完整 Fourier CBS 在默认/SIMD 下为 −0.81%～+2.21%。
SIMD PBS 首轮 GLWE NTT/BK 为 +7.03%，TfheFFT/KB 为 −12.60%；交换先后顺序复测两轮后，
前者为 +3.19%、+0.90%，后者为 −0.86%、−0.49%。NTT/KB 本身也在 +0.10%～+3.57% 波动。
这些结果不支持将首轮差异解释为封装开销或 SIMD 收益。

完整 CBS→CMUX 首轮均值如下，单位 µs，每格为 **基线 → 改造后**：

| 后端与 fixture | 默认 | SIMD |
| --- | ---: | ---: |
| GLWE NTT，n=4/N=256 | 152.50 → 152.95 | 101.76 → 100.08 |
| GLWE Fourier，n=728/N=1024 | 15,007.83 → 14,869.90 | 14,823.31 → 14,719.83 |
| NTRU NTT，n=16/N=256 | 105.17 → 109.21 | 76.70 → 82.40 |
| NTRU Fourier，n=16/N=256 | 60.52 → 60.97 | 60.74 → 60.58 |

NTRU NTT 小 fixture 的差异需要保留说明：

1. 确认前后输入完全一致，均没有被跳过的零旋转；BR、trace、外积内核未改，生成代码的底层调用集合/次数相同。
2. 分项诊断把差异定位到 CBS；绑定 CMUX 与 raw CMUX 均约 1 µs，换回独立消费工作区未消除差异。
3. 同一改造后 SIMD 可执行文件中，首次创建的绑定 evaluator 为 **79.20 µs**，
   另建一个同样绑定 `ServerKey` 的 evaluator 为 **74.56 µs**；独立栈参数版本为 **77.62 µs**。
   第二个 evaluator 同时改变 scratch 分配位置，因此“栈参数较快”不能单独归因于参数存储位置。

这一小负载对资源放置敏感，尚不能将差异稳定归因于接口绑定。未保留无明确收益的引用拆分、
内联或缓存参数试验，也未为追逐单一分配布局加入 clone、padding 或新类型。
本轮没有确认新增变换、在线分配或可归因于封装的热路径回退；不承诺任意分配布局、参数和机器下等时。

## 资源

[资源 CSV](benchmarks/tfhe-b1.7-resources.csv) 记录调用线程的分配次数、累计请求、释放、构造后净请求与峰值。
排除 allocator 元数据、context/table、计时框架、输入/候选/解码输出；密钥行包含一对 client/server，
CBS 基线还包含独立 CBS 参数与 key。峰值是该构造闭包内部的净请求高水位，不是进程 RSS。
默认/SIMD 的请求统计相同。构造只作资源统计，不用单次构造时间声称提速。

| 后端 | PBS-only 密钥净堆字节（前后相同） | CBS-enabled 密钥净堆字节：前 → 后 | 整组密钥内联大小：前 → 后 |
| --- | ---: | ---: | ---: |
| GLWE NTT | 186,640 | 420,248 → 422,248 | 2,936 → 784 |
| GLWE Fourier | 143,243,232 | 144,724,400 → 144,726,320 | 2,632 → 720 |
| NTRU NTT | 188,656 | 309,032 → 311,048 | 2,504 → 496 |
| NTRU Fourier | 225,568 | 372,688 → 374,576 | 2,376 → 496 |

堆字节增长主要是 CBS 参数/组件由调用方栈上移入 `Box`。将净堆与对象内联大小合计，
GLWE NTT 减少 152 B，其余增加 8 B；密文数组载荷不变。PBS-only 不生成 CBS 材料。
复用密钥变换使 CBS 构造累计请求量降低，但各后端峰值略升约 4–10 KiB，不能称为峰值内存优化。

下表均为净堆字节；PBS/CBS evaluator、控制输出与 accumulator client 的等价存储前后相同：

| 后端 | PBS evaluator | CBS evaluator | 控制输出 | Accumulator client | 省去的独立 CMUX scratch |
| --- | ---: | ---: | ---: | ---: | ---: |
| GLWE NTT | 29,224 | 66,600 | 16,384 | 6,144 | 8,448 |
| GLWE Fourier | 138,952 | 304,840 | 98,304 | 57,344 | 33,792 |
| NTRU NTT | 10,496 | 27,136 | 4,096 | 6,144 | 6,400 |
| NTRU Fourier | 14,592 | 33,280 | 4,096 | 14,336 | 6,400 |

四后端首调用和复用的 CBS→CMUX→解密均为零分配；既有集成测试还覆盖 accumulator 加密、
`external_product_to` 与不同输出/SS 分解层数切换。原语及高级显式组合入口保留。

## 验证范围

以下验证全部通过：`RUSTDOCFLAGS='-D warnings' just tfhe`、`just tfhe-simd`，并补 GLWE 底层 check/Clippy/严格 rustdoc、
GLWE/NTRU/lattice 默认与 SIMD 测试，以及四后端 basic/CBS 和 GLWE NTT MVB 共九个 release 示例。
本轮没有增加测试矩阵或持久 benchmark 负载。小 fixture 与 n=728 测量均不是安全参数认证；
稀疏 CBS、生产失败概率和非 x86 性能不在本轮结论内。
