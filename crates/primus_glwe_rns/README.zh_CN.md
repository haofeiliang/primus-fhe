# primus_glwe_rns

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

有序 RNS 基上的 GLWE 加密与求值，分别使用 CRT 系数表示和 DCRT NTT 表示。本 crate 提供 BFV 尺度的系数加密、gadget 乘法、自同构、trace、展开与密钥切换。它是构建模块，不是完整的 BFV/BGV/CKKS 方案。

## 推荐流程

1. 选择有序、两两互素的 NTT 素数，构造一个 `DcrtTable`；每个素数须满足 [NTT 条件](../primus_ntt/README.zh_CN.md#构造约束)。
2. 用维数 k、多项式长度 N、明文模数 t、辅助解码模数 gamma、有序密文模数、秘密分布和噪声构造 `CrtGlweParameters`。需要处理无效参数时使用 `try_new`，已知合法配置可使用 `new`。其 [`BfvRnsCodec`](../primus_encoding/README.zh_CN.md#编码契约) 提供缩放与恢复条件检查。
3. 生成有符号系数 `GlweSecretKey`，通过 `DcrtGlweSecretKey::from_coeff_secret_key` 转换，使用 `try_bind(&parameters, &table)` 绑定一次，之后通过返回的 `DcrtGlweSecretKeyContext` 加密和解密。
4. 使用参数的长度访问器分配密文，复用加密输出及 `DcrtGlweDecryptWorkspace`；`decrypt_inplace` 还复用调用方的明文输出。

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
context.encrypt_plaintext_inplace(&message, &mut ciphertext, &mut rng);
let decoded = context.decrypt(&ciphertext, &mut workspace);
assert_eq!(decoded.as_ref(), message.as_ref());
```

## 编码与表示

`encrypt_plaintext_inplace` 使用 unsigned BFV 缩放，`encrypt_centered_plaintext_inplace` 使用中心提升；消息包含 N 个 `[0,t)` 内的规范值。`encrypt_inplace` 接受已约简到各 CRT 模数的未缩放明文提升，并施加 `floor(Q/t)` 缩放；不要传入 codec 已缩放的输出。这些接口均输出 DCRT 密文。`phase_inplace` 返回 DCRT 相位，解密再恢复系数并解码。`DcrtGlwePublicKey` 支持公钥加密，其噪声预算包含额外的公钥误差项。

m 个模数下，普通密文包含 `(k+1)*m*N` 个元素，顺序为 `[component][modulus][coefficient/evaluation]`；gadget 在外层增加 row/level。使用 `RnsGlweSize` / `RnsGadgetSize` 及多项式/密文迭代器，避免自行推算切片长度。CRT 与 DCRT 形状相同、算术含义不同，见[密文布局](../primus_lattice/README.zh_CN.md#存储与布局)。

## 求值资源

`CrtGlweParameters` 接收 `GlweDimension`，gadget 构造接收 `DecompositionBaseLog` 和 `Option<DecompositionLevelCount>`。参数访问器返回这些已验证单位，在原始存储或数值边界用 `.get()` 提取整数。

`CrtGlweParameters::try_new` 通过 `CrtGlweParametersError<T>` 区分布局、RNS 基、编码、秘密采样和噪声错误，并保留底层原因。固定秘密权重对应完整 kN 个有符号系数，之后才向各 RNS 模数复制；秘密及噪声支持范围必须小于每个密文模数。普通参数与 gadget 参数共享已准备的采样状态；普通参数保留 BFV codec/缩放，gadget 参数持有分解 basis 和缓存权重。

构造还将噪声采样器的最大幅度传给 `BfvRnsCodec::validate_noise_bound`，按 unsigned 提升验证新鲜私钥密文的恢复条件，因此也覆盖 centered 提升。恢复余量不足时返回 `CrtGlweParametersError::Encoding`。公钥加密及同态求值须使用完整相位噪声界；参数构造不覆盖这些额外噪声贡献。

`CrtGlevParameters::try_with_glwe_params` 准备乘积 Q 下的 gadget 分解，并在分配前检查组合长度；`CrtGlevParametersError::Layout` 报告长度溢出。`DcrtGadgetDomain::try_new` 绑定参数与 table，检查多项式长度和有序模数；普通 DCRT 密钥切换使用此域。Hybrid 切换通过 `HybridRnsKeySwitchDomain::try_new` 绑定完整 Q/P 基，分区及 ModUp/ModDown 契约见 [`primus_rns`](../primus_rns/README.zh_CN.md#hybrid-rns)。

`try_bind` 检查普通参数、table、密钥的布局和有序模数，返回 `RnsDomainError`；公钥使用相同绑定流程。Gadget 加密通过 `try_bind_gadget(&domain)` 绑定：秘密密钥返回 `DcrtGlevEncryptor`，公钥返回 `DcrtGgswEncryptor`。消息和密钥行之间复用绑定。

一次性构造 `DcrtGlweKeySwitchEvaluator::try_new(&key, &domain)` 或 `HybridRnsGlweKeySwitchEvaluator::try_new(&key, &domain)`。Evaluator 借用密钥及 domain，拥有 scratch；在线调用仅需 `key_switch_to(&input, &mut output)`。普通绑定检查 gadget 布局、有序 Q 和分解 radix；hybrid 绑定检查 N、有序 QP、Q/P 分界及实际分区宽度。密钥不复制完整参数、table 或转换器。

Client 根据秘密生成求值密钥，交给 server。按已绑定布局复用操作对应的 `*Workspace`；形状和模数检查不能证明实际秘密一致、系数规范或噪声余量。CRT 与 DCRT trace/展开接口的输入、输出与归一化契约分别见 rustdoc。

## Feature 与进一步阅读

默认 features 为空，`simd` 向算术依赖转发 nightly SIMD。本 crate 已启用所需的 RNS features，无需另设 `rns` 开关。

[公开 API 源码](src/lib.rs) · [RNS 基与转换](../primus_rns/README.zh_CN.md) · [库使用导航](../../guides/development/README.zh_CN.md) · [验证覆盖](../../guides/development/testing.md)
