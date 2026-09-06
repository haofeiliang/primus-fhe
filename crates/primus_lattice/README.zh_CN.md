# primus_lattice

[English](README.md) | 简体中文

`primus_lattice` 为 [Primus FHE](../../README.md) 提供密文存储、表示转换和底层格运算，由 GLWE/NTRU × Fourier/NTT 四条 TFHE 路径以及 RNS GLWE 实现共同使用。

本 crate 持续开发中，不承诺稳定 API。密钥生成、加密参数、编码策略、噪声管理和完整同态计算由 [`primus_glwe`](../primus_glwe)、[`primus_ntru`](../primus_ntru)、[`primus_glwe_rns`](../primus_glwe_rns) 等更高层负责。

## 密文类型

以下用 `N` 表示多项式长度，`k` 表示 GLWE 掩码维数，`L` 表示 gadget 分解层数，`m` 表示 RNS 模数数量。多项式运算使用模 `X^N + 1` 的负循环环。

| 类型族 | 系数形式的布局 | 支持的表示 |
| --- | --- | --- |
| `Lwe` | 标量掩码，后接一个 body 标量 | 系数 |
| `MultiMsgLwe` | 按常数项抽取顺序排列的长度为 `N` 的掩码，后接保留的 body 系数 | 打包的 RLWE 样本 |
| `Glwe` | `k` 个掩码多项式，后接一个 body 多项式 | 系数、NTT、Fourier、CRT/DCRT |
| `Rlwe` | 一个掩码多项式，后接一个 body 多项式 | 系数、NTT、CRT/DCRT |
| `Glev` / `Rlev` | 按分解顺序排列的 `L` 个 GLWE/RLWE 密文 | 系数、NTT、CRT/DCRT；GLev 另有 Fourier |
| `Ggsw` / `Rgsw` | `k+1` 行 GLev / 两行 RLev | 系数、NTT、CRT/DCRT；GGSW 另有 Fourier |
| `Ntru` | 单个多项式 `h`，在秘密多项式 `f` 下的相位为 `f*h` | 系数、NTT、Fourier |
| `Nlev` / `Ngsw` | 按分解顺序排列的 `L` 个 NTRU 多项式 | 系数、NTT、Fourier |
| `TruncatedGlwe` | 完整掩码多项式，后接 body 的一个前缀 | 系数 |
| `BigUintGlwe` | GLWE 多项式，每个系数用固定宽度的小端 limb 序列表示 | 多 limb 系数 |

类型通过对应模块导出，例如 `glwe::Glwe`、`ggsw::NttGgsw`、`ngsw::FourierNgsw`。前缀表示数据形式。`Torus*` 是系数类型在 native torus 场景下的别名，不会强制模数，也不执行编码。

NLev 与 NGSW 的存储形状相同，但语义不同：`beta` 的 NLev 各层相位为 `v_i*beta`，而 `beta` 的 NGSW 各层相位为 `v_i*f*beta`。它们适用的 gadget product 不同，因此保留为独立类型。

## 存储与布局

密文包装类型以存储 `S` 为泛型，通过 [`primus_data`](../primus_data/README.zh_CN.md) 访问数据。各运算要求相应的只读、可变或拥有存储能力。借用形式直接操作调用方的切片。

- 普通 GLWE 占 `(k+1)*N` 个元素，GLev 占 `L*(k+1)*N`，GGSW 占 `(k+1)*L*(k+1)*N`。
- CRT 的每个多项式由 `m` 个连续的长度为 `N` 的系数块组成。DCRT 保持相同的分块结构，但块内为 NTT 数据。嵌套 gadget 顺序为 `[row][level][component][modulus][coefficient/evaluation]`。
- Fourier 多项式包含 `N/2` 个复数元素，顺序由后端定义。密文使用归一化 torus 变换；参与乘法的多项式必须使用对应接口要求的缩放。
- BigUint 在每个多项式内部按系数排列，每个系数使用固定宽度的小端 limb 序列。

`GlweSize`、`GadgetSize`、`RnsGlweSize` 和 `RnsGadgetSize` 计算经过检查的长度，拒绝无效数量、不支持的多项式大小和扁平长度溢出。它们不验证实际缓冲区、变换表是否可用、模数是否适合或参数是否安全。分配时应优先使用这些类型的长度访问器，避免重复书写布局公式。

## 运算与所有权

| 运算族 | 主要接口 |
| --- | --- |
| 基础算术 | `add_assign`、`sub_assign`、`neg_assign` 及相应输出形式 |
| Scalar/factor 算术 | `mul_scalar_*`、`mul_factor_*` 及支持的融合累加 |
| 多项式运算 | 系数形式的单项式操作；NTT、Fourier、DCRT 形式的多项式乘法与累加 |
| 明文与 gadget 更新 | `add_plaintext_assign`、`set_trivial`、`add_gadget_diagonal_assign` |
| 表示转换 | `into_ntt_form`、`write_ntt_form`、逆变换到系数形式、`write_fourier_form`、`write_torus_form` |
| 样本抽取 | `extract_lwe_at_to`、紧凑抽取、打包 RLWE 抽取、`inverse_extract_glwe_to` |
| 外积 | Fourier/NTT GGSW 与 NTRU gadget product；DCRT GLev 多项式乘法和 GGSW 乘法 |
| CMUX | GGSW/NGSW 的 `cmux_to`、`cmux_k_to`、`cmux_monomial_to` |

实际支持的接口取决于类型和表示；此表是运算族概览，不表示每个类型都具有全部方法。RNS scalar/factor 参数使用按模数顺序排列的 `primus_rns::Residues` 和 `ResidueFactors`。

`*_assign` 原地修改接收者，`*_to` 写入独立输出，`add_*_assign` 累加到已初始化的存储。消费式算术和转换可以复用可变存储，而返回新抽取样本的分配式接口会分配结果；不能仅凭没有后缀就认定方法不分配，应以方法契约为准。

完整 GLWE 抽取把全部掩码多项式展平为 LWE 掩码。紧凑抽取要求省略的秘密密钥后缀为零。`MultiMsgLwe` 只能表示单个 RLWE 掩码，从截断 GLWE 转换时要求 `k == 1`。逆抽取嵌入常数项 LWE 样本，并把未使用的存储填零；它不会恢复原 GLWE 明文的全部系数。

## 正确性与工作区契约

原始构造器和可变访问不保证密文有效。调用方必须提供兼容的密钥、编码、维数、精确缓冲区长度、模数顺序、分解基和变换约定。除非方法明确允许其他范围，模运算输入必须是规范剩余类；native 模数下，底层整数的所有值均为规范值。

检查应集中在拥有这些参数的最高层。本 crate 有意省略许多检查：debug assertion 仅用于诊断，错误切片可能 panic，也可能只处理公共前缀或完整分块而不报错。调用没有 panic 并不证明正确性。各方法的 rustdoc 说明具体的 `Correctness` 和 `Panics` 契约。

| 工作区 | 绑定的内容 |
| --- | --- |
| `FourierGlweExternalProductContext` / `NttGlweExternalProductContext` | 通过 `GadgetSize` 绑定 GLWE 布局和分解层数 |
| `FourierNtruExternalProductContext` / `NttNtruExternalProductContext` | 标量 NTRU gadget product 的多项式长度 |
| `DcrtGlevMulContext` | RNS gadget 布局和 BigUint limb 宽度要求 |

Context 提供可复用 scratch，不是已经验证的 basis/table/modulus domain。GLWE context 支持在 GLWE 形状不变时 `rebind`，以及缓冲区大小变化时 `resize`。DCRT 的兼容性还包括 RNS 模数乘积的 limb 宽度。拥有参数的调用方必须先建立兼容性，再进入内核。

覆盖式外积会初始化累加器，其他 scratch 也会先写后读，因此合法调用之间不需要手动 reset。累加接口保留原输出，要求输出已初始化。CMUX 的选择语义还要求控制密文加密比特；`cmux_k_to` 要求至多一个控制比特为一。噪声增长和可解密性仍由更高层负责。

## 示例

借用存储，把已经编码的多项式加到 body，再在显式模数下抽取第二个系数：

```rust
use primus_lattice::{GlweSize, glwe::Glwe, lwe::Lwe};
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;

let size = GlweSize::new(2, 4);
let modulus = BarrettModulus::new(97u32);
let mut storage = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
assert_eq!(storage.len(), size.glwe_len());
let mut ciphertext = Glwe::new(storage.as_mut_slice());
let plaintext = Polynomial::new([10, 20, 30, 40]);
ciphertext.add_plaintext_assign(&plaintext, modulus);

let mut sample: Lwe<Vec<u32>> = Lwe::zero(size.mask_len());
ciphertext.extract_lwe_at_to(1, &mut sample, size.poly_length(), modulus);
assert_eq!(sample.a(), &[2, 1, 93, 94, 6, 5, 89, 90]);
assert_eq!(sample.b(), 30);
```

此示例展示布局和算术，不执行随机加密，也不提供安全参数选择。

## Features

默认不启用任何 feature。

- `rns` 启用 CRT/DCRT 密文、对应乘法工作区，以及 `BigUintGlwe` 的 CRT 转换。
- `simd` 启用算术依赖中的 nightly SIMD 支持，不会自动启用 `rns`；RNS SIMD 运算需要同时启用两者。
- `BigUintGlwe`、`RnsGlweSize` 和 `RnsGadgetSize` 不依赖 `rns` feature。

## 测试与基准

在 workspace 根目录运行：

```sh
cargo test -p primus_lattice
cargo test -p primus_lattice --features rns
cargo clippy -p primus_lattice --all-targets --features rns -- -D warnings
cargo +nightly test -p primus_lattice --features rns,simd
cargo doc -p primus_lattice --no-deps --features rns
```

[测试说明](tests/README.md) 列出了独立契约与测试文件的对应关系。[基准说明](benches/README.md) 描述了可独立运行的 GLWE/NTRU × Fourier/NTT、样本抽取和 RNS 目标。基准用于隔离热工作区下的 lattice 运算，完整 PBS 和连续读取密钥的成本应在更高层测量。基础模算术与 factor 运算的基准由其所属 crate 维护。
