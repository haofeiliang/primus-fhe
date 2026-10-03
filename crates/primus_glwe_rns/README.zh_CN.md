# primus_glwe_rns

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

有序 RNS 基上的 GLWE 加密与求值，分别使用 CRT 系数表示和 DCRT NTT 表示。本 crate 提供 BFV 尺度的系数加密、gadget 乘法、自同构、trace、展开与密钥切换。它是构建模块，不是完整的 BFV/BGV/CKKS 方案。

## 推荐流程

1. 选择有序、两两互素的 NTT 素数，构造一个 `DcrtTable`；每个素数须满足 [NTT 条件](../primus_ntt/README.zh_CN.md#构造约束)。
2. 用维数 k、多项式长度 N、明文模数 t、辅助解码模数 gamma、有序密文模数、秘密分布和噪声构造 `CrtGlweParameters`。需要处理无效参数时使用 `try_new`，已知合法配置可使用 `new`。其 [`BfvRnsCodec`](../primus_encoding/README.zh_CN.md#编码契约) 提供缩放与恢复条件检查。
3. 生成有符号系数 `GlweSecretKey`，通过 `DcrtGlweSecretKey::from_coeff_secret_key` 转换，使用 `try_bind(&parameters, &table)` 绑定一次，之后通过返回的 `DcrtGlweSecretKeyContext` 加密和解密。
4. 使用参数的长度访问器分配密文，复用加密输出及 `DcrtGlweDecryptWorkspace`；`decrypt_to` 还复用调用方的明文输出。

下面的小参数用于演示系数加密和存储复用，不代表安全参数。片段需要直接依赖 `primus_glwe_rns`、`primus_lattice`、`primus_modulus`、`primus_ntt`、`primus_poly` 和 `rand`：

```rust
use primus_glwe_rns::{
    CrtGlweParameters, DcrtGlweCiphertext, DcrtGlweDecryptWorkspace,
    DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr,
};
use primus_modulus::BarrettModulus;
use primus_ntt::UintDcrtTable;
use primus_poly::{PolyLength, Polynomial};

let moduli = [998_244_353u32, 1_004_535_809].map(BarrettModulus::new);
let table = UintDcrtTable::new(PolyLength::new(32), &moduli).unwrap();
let parameters = CrtGlweParameters::new(
    primus_lattice::GlweDimension::new(2), 32, BarrettModulus::new(17), BarrettModulus::new(65_537),
    &moduli, SecretKeyDistr::UniformBinary, 3.2,
);
let mut rng = rand::rng();
let coefficient_key = GlweSecretKey::generate(
    parameters.size().glwe_size(), parameters.secret_key_sampler(), &mut rng,
);
let key = DcrtGlweSecretKey::from_coeff_secret_key(&coefficient_key, &table);
let mut ciphertext = DcrtGlweCiphertext::<Vec<u32>>::zero(parameters.rns_glwe_len());
let mut workspace = DcrtGlweDecryptWorkspace::new(parameters.size());
let message = Polynomial::new(vec![3u32; parameters.poly_length().get()]);

let context = key.try_bind(&parameters, &table).unwrap();
context.encrypt_to(&message, &mut ciphertext, &mut rng);
let decoded = context.decrypt(&ciphertext, &mut workspace);
assert_eq!(decoded.as_ref(), message.as_ref());
```

## 编码与表示

`encrypt_to` 使用 unsigned BFV 缩放，`encrypt_centered_to` 使用中心提升；消息包含 N 个 `[0,t)` 内的规范值。`encrypt_crt_to` 接受已约简到各 CRT 模数的未缩放明文提升，并施加 `floor(Q/t)` 缩放；不要传入 codec 已缩放的输出。这些接口覆盖写入 DCRT 密文输出；`encrypt_zeros_to` 加密零。`phase_to` 写入 DCRT 相位，`decrypt` 分配明文输出，`decrypt_to` 复用输出；解密恢复系数并解码。`DcrtGlwePublicKey` 支持公钥加密，其噪声预算包含额外的公钥误差项。

m 个模数下，普通密文包含 `(k+1)*m*N` 个元素，顺序为 `[component][modulus][coefficient/evaluation]`；gadget 在外层增加 row/level。使用 `RnsGlweSize` / `RnsGadgetSize` 及多项式/密文迭代器，避免自行推算切片长度。CRT 与 DCRT 形状相同、算术含义不同，见[密文布局](../primus_lattice/README.zh_CN.md#存储与布局)。

## 参数组合

`CrtGlweParameters` 接收 `GlweDimension`，gadget 构造接收 `DecompositionBaseLog` 和 `Option<DecompositionLevelCount>`。参数访问器返回这些已验证单位，在原始存储或数值边界用 `.get()` 提取整数。

上面的普通构造器一次准备全部部件。只需要 gadget 加密，或需要独立选择编码时，可显式准备和组合：

- `CrtGlweParametersInner::try_new(size, &base_q, secret_distribution, noise)` 准备布局及采样器，无需 t 或 gamma。固定秘密权重对应完整 kN 个有符号系数，之后才向各模数复制；秘密及噪声支持范围必须小于每个 q_i。用 `Arc` 包裹结果，即可共享这些预计算。
- `CrtGlevParameters::try_from_parts(shared_inner, base_q, basis)` 将有序 `RNSBase` 和 `BigUintApproxSignedBasis` 移入 gadget 参数。缓存各层权重前，检查采样器的有序模数、basis 的精确乘积模数及 limb 宽度、radix < 每个 q_i，以及组合 gadget 长度；无需 BFV codec。
- `CrtGlweParameters::try_from_parts(shared_inner, codec)` 绑定普通 BFV 编码，检查 codec 的有序模数及新鲜私钥密文恢复余量。Codec 拥有自己的 RNS 基与转换数据，共享采样状态不再保存另一份 base 或转换器。

`CrtGlweParameters::try_new` 和 `try_from_parts` 通过 `CrtGlweParametersError<T>` 报告错误并保留底层原因。`CrtGlevParameters::try_with_glwe_params` 仍可便捷地从已有普通参数派生 gadget，并共享其采样器。Gadget 构造返回 `CrtGlevParametersError`，其中 `Layout` 变体报告长度溢出。不同噪声角色需要独立准备采样状态。

派生 gadget 还与普通 codec 共享不可变的 `RNSBase` 表及模数值缓存，codec 内部转换器也共享该基。BFV 的 `floor(Q/t)` 因子与 gadget 的各层重组 residues 用途不同，仍分别保存。参数克隆共享采样器和基表，但仍复制 codec 或 gadget 专用的权重。普通加密直接使用 `delta_factor_mod_q()`，不再缓存另一份原始 delta residues。

普通参数构造将噪声采样器的最大幅度传给 `BfvRnsCodec::validate_noise_bound`，按 unsigned 提升验证新鲜私钥密文的恢复条件，因此也覆盖 centered 提升。恢复余量不足时返回 `CrtGlweParametersError::Encoding`。公钥加密及同态求值须使用完整相位噪声界；参数构造不覆盖这些额外噪声贡献。

## 求值资源

两种参数均通过 `inner()` 暴露采样状态。公钥生成使用 `DcrtGlwePublicKey::new(&secret, parameters.inner(), parameters.base_q(), &table, rng)`，其零加密无需 codec。DCRT 和 hybrid 密钥切换生成同样接收 `input_parameters.inner()`，不再接收普通 BFV 参数。这些准备操作在消耗随机数前验证有序模数；hybrid 生成还检查输入采样状态所提供的密钥噪声是否适用于辅助 P 模数。

`DcrtGadgetDomain::try_new` 绑定 gadget 参数与 table，检查多项式长度和有序模数；普通 DCRT 密钥切换使用此域。Hybrid 切换通过 `HybridRnsKeySwitchDomain::try_new` 绑定完整 Q/P 基，分区及 ModUp/ModDown 契约见 [`primus_rns`](../primus_rns/README.zh_CN.md#hybrid-rns)。

`try_bind` 检查普通参数、table、密钥的布局和有序模数，返回 `RnsDomainError`；公钥使用相同绑定流程。Gadget 加密通过 `try_bind_gadget(&domain)` 绑定：秘密密钥返回 `DcrtGlevEncryptor`，公钥返回 `DcrtGgswEncryptor`。GLev encryptor 通过 `encrypt_crt_to` 接收系数消息，通过 `encrypt_dcrt_to` 接收 NTT 消息，只施加 gadget 权重，不进行 BFV 明文缩放。GGSW encryptor 的 `encrypt_monomial_ggsw` / `encrypt_monomial_ggsw_to` 分别分配或复用输出。消息和密钥行之间复用绑定。

一次性构造 `DcrtGlweKeySwitchEvaluator::try_new(&key, &domain)` 或 `HybridRnsGlweKeySwitchEvaluator::try_new(&key, &domain)`。Evaluator 借用密钥及 domain，拥有 scratch；在线调用仅需 `key_switch_to(&input, &mut output)`。普通绑定检查 gadget 布局、有序 Q 和分解 radix；hybrid 绑定检查 N、有序 QP、Q/P 分界及实际分区宽度。密钥不复制完整参数、table 或转换器。

Client 根据秘密生成求值密钥，交给 server。按已绑定布局复用操作对应的 `*Workspace`；形状和模数检查不能证明实际秘密一致、系数规范或噪声余量。CRT 与 DCRT trace/展开接口的输入、输出与归一化契约分别见 rustdoc。

CRT 自同构复用 `primus_poly::CoeffAutomorphismPermutation`，DCRT 复用 `primus_ntt::NttAutomorphismPermutation`。有序模数分量和所有密钥行共享同一映射；RNS 层负责分量遍历与密钥切换，共有 helper 负责系数符号和 bit-reversed 点值顺序。Trace 和展开继续复用这些自同构密钥及工作区。

两种表示均提供 `expand_coefficients_to` 和 `expand_partial_coefficients_to`，复用串行工作区。并行版本以 `_parallel_to` 结尾，复用预分配的 `CrtGlweExpandCoeffSyncPool` 或 `DcrtGlweExpandCoeffSyncPool`。

## Feature 与进一步阅读

默认 features 为空，`simd` 向算术依赖转发 nightly SIMD。本 crate 已启用所需的 RNS features，无需另设 `rns` 开关。

[公开 API 源码](src/lib.rs) · [RNS 基与转换](../primus_rns/README.zh_CN.md) · [库使用导航](../../guides/development/README.zh_CN.md) · [验证覆盖](../../guides/development/testing.md)
