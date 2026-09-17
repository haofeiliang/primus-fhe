# 实现决定参考

按涉及的 crate/符号读取对应章节；这些是既有数学边界、实现取舍和未决记录，不是每次都要加载的全仓库规则。当前任务与用户排除项见 [HANDOFF](../../HANDOFF.md)，开发规范见 [AGENTS](../../AGENTS.md)。参数、调用方、平台或证据变化后可重新评估；公开契约及局部理由有可靠落点后，删除这里的重复记录。

## 基础算术的仍有效决定

- `primus_reduce` 是推荐的 modulus-side 接口；`primus_modulo` 保持 value-side 薄镜像，
  不为其增加 residue wrapper、context、兼容别名或第二层检查。
- 切片逆元保持无额外 scratch；等长与 DCRT/RNS 布局由调用方或更高层维持，不下沉为热路径重复检查。
  `LazyReduceSubSlice` / `LazyReduceNegSlice` 按后续用途保留，不为机械转发重复测试。
- `ReduceDotProduct` 保持输入小于目标模数的通用契约；RNS 的额外范围要求在转换操作的
  `Correctness` 中说明，BFV 解码引用它，不新增能力 trait 或逐系数预约简。
- `CompactModulus(value)` / `UintModulus(value)` 有意保留无检查 tuple 构造，由 `new` 检查边界。
  `NativeModulus` 保持 wrapping 语义；不可逆错误不能伪造一个不可表示的显式模数值。
- Barrett 模数上界参与点积累加界证明，放宽前必须重新证明并测量；SIMD 生成的
  `Into<SimdBarrettModulus<_>>` 暂保留，不因 `From` 同样合法而改动。
- `primus_data` 仅抽象连续存储和切片访问，不扩成通用容器框架；`aligned-vec` 保持可选。
- 无符号 XGCD 保持 `a*x - b*y = gcd(x,y)`、`x >= y` 的契约；定宽无分配不等于恒时。
  保留独立 oracle，不再添加同用途的大整数 dev 依赖。
- `Integer` 的显式能力约束和 `AsFrom` / `AsInto` / `AsCast` 有意保留，不改为 `az` / `AsPrimitive`。
  原生整数算术包装不重复测试标准库；`BigUint` 布局由调用方维持，`bit_width` 保持 `u32`。
- SIMD 泛型保留关联 lane/array/mask，不固定 ISA lane 数；继续使用 nightly `portable_simd`。
  曾比较 `widening_mul` 低半部分与独立乘法，但决定暂不修改；新工具链和真实规模测量后再评估。
- `u128` 的 `DivRemScalar` 与 256/128 除法继续独立于通用 division 模块；Knuth D 商估计
  最多修正两次。修改前用独立任意精度 oracle 覆盖边界，并重测 `div_rem_scalar`。

## 多项式、变换与 RNS 的仍有效决定

- `primus_poly` 已接受 `naive_mul_to` 非零旧输出、SIMD butterfly tail、monomial 边界、
  合数模数非零不可逆值的残余测试缺口；相关实现变化时重新评估。
- `MonomialNttTable` 恰有 N 个 roots 是实现不变量，不每次检查；任意系数 monomial 变换的
  `coeff` 须在 `[0,q)`，不由变换负责约简。NTT `N=1` 不支持，边界检查不放入 transform 热路径。
- 非 x86_64 U64 的 scalar32/scalar64 构建及 lazy 语义有意保留；cfg/dispatch/预计算变化后做交叉检查。
- 比较 NTT 性能须固定实际 backend 和编译 target；只强制 dispatch 不能隔离 ISA。
  Zen 5 的 U32 AVX2 结果不能推广到 U64 大长度或其他 CPU；改 dispatch 前需 AVX2-only CPU 复测。
- FFT `N=2` 有意不支持，不保留恒等变换特例；TFHE unordered plan 为实测选择，调用方共享
  确切 table，不能混用独立 table 的数据/scratch。批量 Fourier 形状仍由上层保证。
- 内置 FFT scratch 在 Drop 时擦除，长寿命 engine 可显式 `zeroize_scratch`；不每次变换擦除，
  不为内置后端的生命周期要求扩大通用 `FftTable` trait。
- `wrapping_decompose_to` 和单模数 `RNSBase::extend` 按后续用途保留；`HybridRNS` 保留通用
  Q/P 能力，不因当前主要用于 GLWE RNS key switching 而收窄未来 BFV/BGV 用途。
- SIMD Barrett 短点积不足 `16 * LANE_COUNT` 累加块时走 scalar；改变阈值前重测代表性模数数量。
- 系数/NTT 自同构置换分别由 `primus_poly::CoeffAutomorphismPermutation` 和
  `primus_ntt::NttAutomorphismPermutation` 共享，不在 GLWE/NTRU 重新复制。

## Lattice、编码与 LWE 的仍有效决定

- 低层求值 context 保持工作区职责；不为减少参数而恢复 `NttGadgetDomain`、混入 basis/table/modulus
  或引入万能表示 trait。NTT CMUX 的局部 `too_many_arguments` 豁免有意保留。
- RNS `sub_mul_scalar_assign` 暂不提供；字节接口不增加假想 Data/显式大小端变体；
  `inverse_extract` 名称保留，不改为 `sample_upsert`。
- lattice 保留宏类型矩阵和独立数学契约测试，不恢复机械存储/切片转发、重复往返检查。
  基础算术基准归 modulus/factor，组合运算覆盖 GLWE/NTRU × Fourier/NTT；RNS 未扩成 hybrid 算法基准。
- 固定 key/scratch 微基准不替代完整 key 顺序读取、BR/KSK/PBS 测量；不同模数/位宽的功能工作负载
  不是等安全参数比较，也不是方案排名。未新增专用 AVX-512 路径，继续复用已有 dispatch/SIMD 内核。
- `IntegerScale` 移位量保持 `u32`；Rounded 标量、切片、累加循环保留各自优化形态，
  不为形式统一强行合并；私钥分布由方案选择，不恢复 `SecretKeyDistr::Default`。
- LWE 单系数 digit iterator 暂缓；私钥 batch 复用单条，公钥 batch 保留分块，KSK 输出私钥
  保持 Encoded；不恢复 `LweBatch`。Signed 点积保持独立 trait，不并入通用点积/整数 trait。
- Native/PowOf2/Barrett 标量点积保留 iterator；短 phase 的小幅差异须用未改动的 Encoded 对照
  排除代码布局波动，不恢复没有稳定收益的实验内核。

## GLWE、NTRU 与 TFHE 的仍有效决定

- 推荐配对生成有符号系数私钥和变换私钥；GLWE 仅返回变换形式的 `generate` 已删除。
  NTRU 拒绝采样复用系数、变换和逆元存储，不能在每次重试重新分配候选转换结果。
- 普通 NTRU 保留非二元私钥；两路 NTRU TFHE 在接受客户端私钥时检查实际二元系数及零填充，
  分布标签不能代替 CMUX 控制位前提。清零覆盖私钥、私有工作区和失败展开路径。
- NTRU KSK 与 Fourier GLWE BSK 持有实际 basis；GLev/NLev 参数可接受已有 basis。
  不把 basis 当成重复在线入参，也不能以层数相同替代基一致性。
- 使用真实常数 `NLev[1]` 初始化 NTRU accumulator，不恢复 unit 私钥生成 KSK 的绕行；
  常数 gadget 批量加密在低层集中检查，不恢复 TFHE 调用方手写常数多项式循环。
- 部分展开是“目标消息前 count 项可能非零、其余为零”，count 为不大于 N 的 2 的幂；
  不恢复公开选择 plan。任意索引的 reverse-trace 投影单独保留，不与前缀展开混为一条数值路径。
- NTT reverse trace 用模逆元；Fourier 对无符号系数代表元做向下取整整数除法，不是复数除法。
  NTRU 还须计入 f 加权误差；两条路径不能直接共用噪声结论。
- NTRU scheme switching 限于同一秘密：用 `NGSW_f[f]` 将 `NLev_f[m]` 转为 `NGSW_f[m]`，
  key/output basis 独立。不补跨秘密切换或 NGSW×NGSW；逐行自同构也不能直接保留 NGSW 语义。
- 两路 NTRU CBS 是可选独立参数/key/evaluator：一次 BR 后投影一般 ManyLUT，再经 NLev→NGSW。
  一般 LUT 不满足目标消息零尾，不能改用前缀展开；结果留在 `f_acc` 下，不走普通 PBS 的
  `f_acc→f_client` KSK/extraction，也不依赖 packing。普通 PBS/ManyLUT 与 Boolean/CBS 输出尺度保持区分。
- NTRU packing（同源 RevHomTrace 与独立 LWE packing KSK）按用户决定排除，尚未实施；
  不因其它原语完成而自动开始。一般 LWE 的非零 body 不能直接复制成 NTRU 平凡加密，设计须考虑 `NLev[1]`。

## NTRU 外积的性能决定

- `FourierNtruExternalProductContextRefMut` / `NttNtruExternalProductContextRefMut` 是 lattice 私有借用视图；
  变换输出直接作为 accumulator，NTT 系数输出和 KSK 在输出内累加后原地逆变换。
- Fourier 系数路径保留复数 accumulator；CMUX 的 output 在分解时仍存差值，不能提前清零。
  owning context 因而仍保留 accumulator 容量，此改动减少复制，不承诺减少工作区容量。
- NTT 系数入口转发公开变换入口曾出现实测回退；各入口直接调用同一私有 kernel 的形态有意保留。
  不恢复无收益的 inline 提示。完整 KSK 未测得显著加速，不因少一次复制就宣称明显收益。


## 待核实事项

以下从旧 HANDOFF 迁入，本次仅整理记录，未重新审查源码；在对应工作开始时核对。

| 范围 | 既有问题 / 触发条件 |
| --- | --- |
| CRT Gaussian 编码 | `primus_glwe_rns::CrtGlweParameters::new` 在 `q_i <= floor(12σ)` 时可能产生非规范 residue；处理参数边界时核对支持集检查 |
| GLWE RNS 测试 | `tests/glev.rs::test_key_switching` 曾仅打印解码结果；整理该 crate 时确认，补独立断言或删除重复案例 |
| reduce 文档 | `ReduceMulAddSlice` 曾称五种 fused 形态都需要而生产调用只有三种；概览漏列 reduce_once、double、mul-add；整理该 crate 时核对 |
| NTRU SS/CBS | f/f² 误差放大、KDM/circular-security 假设与生产失败率尚需独立论证 |
| 恒时与平台 | 未完成全库恒时证明或非 x86 全量验证；拒绝采样/逆元不承诺恒时，平台内核变化后针对性验证 |
