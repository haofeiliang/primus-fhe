# primus_glwe_rns

[English](README.md) | 简体中文

> [!WARNING]
> 本 crate 属于实验性的 [Primus FHE](../../README.zh_CN.md) workspace。其 API 和数值契约尚不稳定，可能随时发生不兼容修改。

有序 RNS 基上的 GLWE 加密与求值，分别使用 CRT 系数表示和 DCRT NTT 表示。本 crate 提供 BFV 尺度的系数加密、gadget 乘法、自同构、trace、展开与密钥切换。它是构建模块，不是完整的 BFV/BGV/CKKS 方案。

## 推荐流程

1. 选择有序、两两互素的 NTT 素数，构造一个 `DcrtTable`；每个素数须满足 [NTT 条件](../primus_ntt/README.zh_CN.md#构造约束)。
2. 用维数 k、多项式长度 N、明文模数 t、辅助解码模数 gamma、有序密文模数、秘密分布和噪声构造 `CrtGlweParameters`。其 [`BfvRnsCodec`](../primus_encoding/README.zh_CN.md#编码契约) 提供缩放与恢复条件检查。
3. 生成有符号系数 `GlweSecretKey`，通过 `DcrtGlweSecretKey::from_coeff_secret_key` 转换，后续保持同一 table 与模数顺序。
4. 使用参数的长度访问器分配密文，复用加密输出及 `DcrtGlweDecryptWorkspace`；`decrypt_inplace` 还复用调用方的明文输出。

下面的小参数用于演示系数加密和存储复用，不代表安全参数。片段需要直接依赖 `primus_glwe_rns`、`primus_modulus`、`primus_ntt`、`primus_poly` 和 `rand`：

```rust
use primus_glwe_rns::{
    CrtGlweParameters, DcrtGlweCiphertext, DcrtGlweDecryptWorkspace,
    DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr,
};
use primus_modulus::BarrettModulus;
use primus_ntt::UintDcrtTable;
use primus_poly::Polynomial;

let moduli = [998_244_353u32, 1_004_535_809].map(BarrettModulus::new);
let table = UintDcrtTable::new(5, &moduli).unwrap();
let parameters = CrtGlweParameters::new(
    2, 32, BarrettModulus::new(17), BarrettModulus::new(65_537),
    &moduli, SecretKeyDistr::UniformBinary, 3.2,
);
let mut rng = rand::rng();
let coefficient_key = GlweSecretKey::generate(
    parameters.size().glwe_size(), parameters.secret_key_sampler(), &mut rng,
);
let key = DcrtGlweSecretKey::from_coeff_secret_key(&coefficient_key, &table);
let mut ciphertext = DcrtGlweCiphertext::<Vec<u32>>::zero(parameters.rns_glwe_len());
let mut workspace = DcrtGlweDecryptWorkspace::new(parameters.size());
let message = Polynomial::new(vec![3u32; parameters.poly_length()]);

key.encrypt_plaintext_inplace(&message, &mut ciphertext, &parameters, &table, &mut rng);
let decoded = key.decrypt(&ciphertext, &parameters, &table, &mut workspace);
assert_eq!(decoded.as_ref(), message.as_ref());
```

## 编码与表示

`encrypt_plaintext_inplace` 使用 unsigned BFV 缩放，`encrypt_centered_plaintext_inplace` 使用中心提升；消息包含 N 个 `[0,t)` 内的规范值。`encrypt_inplace` 接受已经编码的 CRT 系数，不执行明文缩放；两者均输出 DCRT 密文。`phase_inplace` 返回 DCRT 相位，解密再恢复系数并解码。`DcrtGlwePublicKey` 支持公钥加密，其噪声预算包含额外的公钥误差项。

m 个模数下，普通密文包含 `(k+1)*m*N` 个元素，顺序为 `[component][modulus][coefficient/evaluation]`；gadget 在外层增加 row/level。使用 `RnsGlweSize` / `RnsGadgetSize` 及多项式/密文迭代器，避免自行推算切片长度。CRT 与 DCRT 形状相同、算术含义不同，见[密文布局](../primus_lattice/README.zh_CN.md#存储与布局)。

## 求值资源

`CrtGlevParameters::try_with_glwe_params` 准备乘积 Q 下的 gadget 分解。`DcrtGadgetDomain::try_new` 绑定参数与 table，检查多项式长度和有序模数；普通 DCRT 密钥切换使用此域。Hybrid 切换通过 `HybridRnsKeySwitchDomain::try_new` 绑定完整 Q/P 基，分区及 ModUp/ModDown 契约见 [`primus_rns`](../primus_rns/README.zh_CN.md#hybrid-rns)。

Client 根据秘密生成求值密钥，交给 server。按已绑定布局复用操作对应的 `*Workspace`；形状和模数检查不能证明实际秘密一致、系数规范或噪声余量。CRT 与 DCRT trace/展开接口的输入、输出与归一化契约分别见 rustdoc。

## Feature 与进一步阅读

默认 features 为空，`simd` 向算术依赖转发 nightly SIMD。本 crate 已启用所需的 RNS features，无需另设 `rns` 开关。

[公开 API 源码](src/lib.rs) · [RNS 基与转换](../primus_rns/README.zh_CN.md) · [库使用导航](../../guides/development/README.zh_CN.md) · [验证覆盖](../../guides/development/testing.md)
