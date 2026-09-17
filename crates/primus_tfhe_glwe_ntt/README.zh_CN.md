# primus_tfhe_glwe_ntt

[English](README.md) | 简体中文

基于 GLWE、采用显式域模数的 TFHE 后端。支持两种 PBS order、ManyLUT、分解式 MVB、Boolean 门及私钥/公钥客户端。
完整能力与编码约定见[公共指南](../primus_tfhe/README.zh_CN.md)，
参数与秘密域见 [GLWE family](../primus_tfhe_glwe/README.zh_CN.md)。

## 运行完整示例

```sh
cargo run -p primus_tfhe_glwe_ntt --example ntt_basic
```

[示例源码](examples/ntt_basic.rs) 用相同流程运行两种 order：参数 → context → 配套密钥
→ 公钥 encryptor / client decryptor → 编译 LUT → 复用 evaluator 与输出。
涵盖单 PBS、`t_in=4 → t_out=8` 的双输出 ManyLUT、客户端 `encrypt_padded_to`、Boolean 门、NOT 和 MUX。

`BootstrapKeyswitch` 的外部密文维数为 `n`，`KeyswitchBootstrap` 为 `kN`。
示例打印并检查这两个维数（4 和 256），输入和输出均遵循选定的外部秘密域。
所有 fixture 的维数、噪声和分解参数仅用于功能演示，不是生产安全或失败概率建议。

## Context 与复用

`TfheContext::try_new` 检查 NTT 长度和模数。NTT 域密钥与值必须采用所传 table 的表示。
`boolean_parameters()` 是开发 fixture，不是经过论证的默认参数；示例直接选取自己的小参数。

前半区 LUT 使用 `compile_lookup_table_fn` / `compile_lookup_table_slice`，多输出使用
`compile_interleaved_lookup_table_*`，第一个参数均为输出 `RoundedCodec`。输出尺度不同时，
用 `decrypt_phase` 与该 codec 解码。输入采用 unsigned padded 编码，并考虑 ManyLUT 较低的
旋转分辨率。Evaluator 持有可变 scratch，创建一次后复用 `apply_lookup_table_to` /
`apply_interleaved_lookup_table_to`；这些入口在写入前检查全部输出维数。

奇数全域使用 context 的 `compile_odd_full_domain_lookup_table_fn` / `_slice` 与普通
`encrypt`，复用现有单输出 evaluator。条件见[共享契约](../primus_tfhe/README.zh_CN.md#奇数全域-pbs)。

`t=4` 时使用 `boolean_encryptor`、`boolean_decryptor`、`boolean_evaluator`，由适配器处理
内部模 8 的 LUT 尺度。通过 `evaluate_binary_to`、`not_to`、`mux_to` 重复求值。

低层 `NttGlweBootstrappingKey<T, LM>` 保留输入模数类型 `LM`，与 accumulator 模数独立。
密钥生成时准备普通 PBS 量化参数；ManyLUT 在系数循环前按旋转步长准备转换。
高层 context 保持既有参数约束。

## 固定尺度分解式 MVB

使用 unsigned `ScaledCodec` 编译一次，随后复用独立 evaluator：

```rust,ignore
use primus_encoding::ScaledCodec;

let codec = ScaledCodec::new(2u32, context.parameters().glwe().cipher_modulus());
// 此例要求 t_in >= 8，并具备足够的输入和输出噪声余量。
let lut = context.compile_factorized_lookup_table_fn(
    &codec, 4, 3, |m, i| u32::from(m > i),
)?;
let mut evaluator = context.factorized_evaluator(&server_key)?;
let mut outputs = vec![LweCiphertext::zero(context.parameters().ciphertext_lwe_dimension()); 3];
let input = encryptor.encrypt_padded(2, &mut rng)?;
evaluator.apply_lookup_table_to(&input, &lut, &mut outputs);
assert_eq!(codec.decode_value(decryptor.decrypt_phase(&outputs[1])?), 1);
```

codec 后依次是输入前缀长度和有效输出数。编译返回借用本 context 的
`NttFactorizedLookupTable`；即使 q、N 相同，换一个 context 实例执行也会拒绝。
低层调用方可先编译 `FactorizedLookupTable`，再交给 `NttFactorizedLookupTable::new` 消费。
NTT 预处理原地变换因子，不保留其系数域副本。

两种 order 均支持经典/稀疏密钥。BK 共享一次 BR，再逐输出乘法和 KS；KB 先共享
输入 KS，再 BR 和逐输出乘法。任意正输出数均保持旋转步长 1。`_to` 在写入前检查
context、输入、输出数量和全部输出维数，在线零分配。额外工作区仅为一个包含
`(d+1)*N` 个系数的 NTT GLWE，与输出数量无关；普通 evaluator 不变。
程序保存 `(output_count+1)*N` 个系数。

相位解码使用输出 codec。因子范数会放大 BR 噪声；串联 PBS 时还需考虑 Scaled 与
Rounded 中心差异。见[共享契约](../primus_tfhe/README.zh_CN.md#固定尺度分解式-mvb)及
[功能测试](tests/factorized_pbs.rs)。

运行[阈值示例](examples/mvb_thresholds.rs)：

```sh
cargo run -p primus_tfhe_glwe_ntt --release --example mvb_thresholds
```

示例把 `0..64` 的一个加密分数转换为 17 个数值阈值标志，复用编译产物和全部密文缓冲区。
N=1024 时，交错布局仅为每个输出留下 32 个位置，无法容纳 64 个输入。
每个阈值的差分因子仅有两项、一范数为 2，限制其噪声放大。
交错容量和输入噪声余量足够时优先考虑交错；分解式以更大的程序/构造成本保留步长 1。
实测与选择条件见 [P4.3 记录](../../docs/tfhe-mvb.md#8-p43-测量与应用选择)。

## 实验性稀疏 PBS

将 **small-LWE** 分布设为 `SecretKeyDistr::fixed_hamming_weight_binary(n, h)`，
显式生成稀疏 server key：

```rust,ignore
let mut generator = KeyGenerator::new(&context);
let client_key = generator.generate_client_key(&mut rng);
let server_key = generator.try_generate_sparse_server_key(&client_key, 3, 2 * h, &mut rng)?;
let mut evaluator = context.evaluator(&server_key)?;
evaluator.apply_lookup_table_to(&input, &lut, &mut output);
// 同一 evaluator 支持 apply_interleaved_lookup_table_to。
```

两种 order 均以该 small 秘密进行盲旋转。`BootstrapKeyswitch` 的外部维数仍为 `n`，
`KeyswitchBootstrap` 仍为 `kN`。普通/交错 PBS 共用既有 LUT 编译、输出 codec、KS 和提取，
`_to` 调用零分配。Evaluator 只为所选算法分配 scratch，在盲旋转入口分派一次。
原有密钥工厂继续生成经典密钥。需要低层密钥的调用方通过 `ServerKey::bootstrapping_key()`
返回的 `BootstrappingKey::{Classic, Sparse}` 选择对应类型。

生成入口检查实际二元系数和重量，固定同一秘密最多尝试八个独立公开桶映射，错误时不返回部分密钥。
实验参数采用三个副本、`2*h` 个桶。系数域 GGSW 加密私有选择位，每桶另有一个 dummy；
未占用桶的 dummy 加密 1。私有匹配缓冲区在释放时擦除。

低层普通盲旋转使用 `try_generate_sparse_bootstrapping_key` 返回的 `SparseGlweBootstrappingKey`，
配套 `SparseGlweBlindRotationContext::new(&key)`，调用 `ntt_blind_rotate_lookup_table_to`。
输入为 small-LWE 和已编码多项式，输出为 accumulator GLWE，旋转步长为 1。

稀疏聚合噪声和交错旋转步长需要单独预算。这些参数尚无经认证的安全等级或完整 PBS 失败率，
见 [P3 契约与测量](../../docs/tfhe-sparse-pbs.md#p35-完整-pbs-接入与验收)。

## Circuit bootstrapping

CBS 要求经典 server key；稀疏密钥返回
`CircuitBootstrapEvaluationError::UnsupportedSparseBootstrapping`，其 gadget 尺度噪声尚未验收。
可选 CBS 使用 `CircuitBootstrapParameters::try_new(context.parameters(),
output_basis, trace, scheme_switch)`、`generate_circuit_bootstrap_key` 和
`circuit_bootstrap_evaluator`。普通与 CBS key 必须来自同一 client key 和 NTT 表示。
输出 basis 定义 GGSW gadget 尺度，输出布局从 accumulator 派生；circuit key 绑定
输出布局及 trace/scheme-switch basis。CBS 保留 accumulator secret，跳过普通 PBS
后处理；投影与 CMUX 消费见 [CBS 集成测试](tests/circuit_bootstrap.rs)。
Trace/SS 噪声与秘密相关消息假设需要独立评估。

## 验证与性能

```sh
cargo test -p primus_tfhe_glwe_ntt
cargo clippy -p primus_tfhe_glwe_ntt --all-targets -- -D warnings
cargo +nightly test -p primus_tfhe_glwe_ntt --features simd
cargo bench -p primus_tfhe_glwe_ntt --bench pbs
cargo bench -p primus_tfhe_glwe_ntt --bench circuit_bootstrap
cargo bench -p primus_tfhe_glwe_ntt --bench sparse_pbs
cargo bench -p primus_tfhe_glwe_ntt --bench mvb
```

`pbs` 复用输出，覆盖两种 order、3/4 输出 ManyLUT 与独立 PBS 的对照，以及 Boolean AND/MUX。
BR 和密钥切换阶段用于定位开销；系数提取的基准集中在 `primus_lattice`。
`circuit_bootstrap` 测量两种 order、2/3 输出层数下的完整 CBS。

`sparse_pbs` 在同一固定重量客户端秘密下，对照经典/稀疏完整 PBS：两种 order、普通与三输出
交错 LUT，以及完整 server key 生成（`n/h/N=728/32/1024`，共 10 项）。PBS 计时前准备输入、evaluator 和输出，
每次迭代处理四个加密输入中的一个。内存、小参数诊断及默认/SIMD 结果见
[P3 测量记录](../../docs/tfhe-sparse-pbs.md#p35-完整-pbs-接入与验收)。

`mvb` 在相同 Scaled 阈值输出下比较独立 PBS、交错 ManyLUT 与分解式 MVB，覆盖
两种 order 和经典/稀疏密钥。共 20 项在线负载（三输出可比较组和交错容量不足的
17 输出组）与 7 项构造/预处理负载。在线计时包括 KS 与提取；内存和误差另行测量。
这些成本参数的 small-LWE 维数为 728，不是已认证的生产参数。
