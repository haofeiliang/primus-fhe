# Primus FHE

[English](README.md) | 简体中文

Primus FHE 是一个实验性的 Rust 全同态加密 workspace，提供算术和格密码基础组件、LWE/GLWE/NTRU 加密与求值原语，以及基于 GLWE 和 NTRU、分别使用 NTT 和 Fourier 表示的 TFHE 后端。

> [!WARNING]
> API、数据表示、算法和 crate 边界尚不稳定，可能随时发生不兼容修改，且不提供弃用过渡期。示例与基准参数用于功能验证，不是经过认证的安全参数或失败概率建议。本项目不声明已达到生产可用状态。

## 使用入口

- **计算加密函数：**先阅读 [TFHE 操作与编码指南](crates/primus_tfhe/README.zh_CN.md)，再运行下方的后端示例。
- **使用加密与求值原语：**从 [LWE](crates/primus_lwe/README.zh_CN.md)、[GLWE](crates/primus_glwe/README.zh_CN.md) 或 [NTRU](crates/primus_ntru/README.zh_CN.md) 开始。这些 crate 提供 TFHE 工作流依赖的密钥和底层操作。
- **开发算术或方案组件：**按下方 workspace 导航阅读对应 crate 的 README 和 rustdoc。

示例区分客户端密钥生成与加密、服务端求值、客户端解密，展示 context、evaluator 和输出缓冲区的复用。普通 LUT 编译默认沿用输入的明文 codec；显式 codec 变体支持不同的输出明文模数。

## TFHE 后端

| 家族 | NTT：显式有限域模数 | Fourier：原生字宽模数 |
| --- | --- | --- |
| [GLWE 参数与客户端](crates/primus_tfhe_glwe/README.zh_CN.md) | [primus_tfhe_glwe_ntt](crates/primus_tfhe_glwe_ntt/README.zh_CN.md) | [primus_tfhe_glwe_fourier](crates/primus_tfhe_glwe_fourier/README.zh_CN.md) |
| [NTRU 参数与客户端](crates/primus_tfhe_ntru/README.zh_CN.md) | [primus_tfhe_ntru_ntt](crates/primus_tfhe_ntru_ntt/README.zh_CN.md) | [primus_tfhe_ntru_fourier](crates/primus_tfhe_ntru_fourier/README.zh_CN.md) |

四后端均支持 LWE 私钥/公钥客户端、经典 binary/ternary 私钥、可编程自举（PBS）、交错 ManyLUT、有界双输入 LUT、奇数明文模数全域单输出 LUT、Boolean 门、可供 CMUX 使用的电路自举（CBS），以及固定尺度分解式多值自举（MVB）。ManyLUT 和 MVB 对同一个加密输入计算多个函数。Fourier 支持 RustFFT 和 TfheFFT，并保留各自的精度要求。

固定重量二元稀疏 PBS 属于实验性能力。GLWE 两后端支持 sparse PBS、CBS 和 MVB；NTRU 两后端支持 sparse 普通/交错 PBS，但拒绝 sparse CBS/MVB。NTRU 要求私钥在环内可逆；其 Fourier 后端还检查数值稳定性，固定重量二元私钥必须具有奇数重量。编码和组合边界见[共享能力指南](crates/primus_tfhe/README.zh_CN.md#crate-分工与能力)。

在仓库根目录运行基础端到端示例：

```sh
cargo run -p primus_tfhe_glwe_ntt --release --example ntt_basic
cargo run -p primus_tfhe_glwe_fourier --release --example fourier_basic
cargo run -p primus_tfhe_ntru_ntt --release --example ntru_ntt_basic
cargo run -p primus_tfhe_ntru_fourier --release --example ntru_fourier_basic
```

各后端 README 还提供 CBS → CMUX、MVB 阈值和稀疏 PBS 示例。参数、输出编码和可组合的操作均需显式确定，接口不会从 raw 密文推断这些信息。

## Workspace 导航

| 层次 | Crate 与职责 |
| --- | --- |
| 存储与整数 | [primus_data](crates/primus_data/README.zh_CN.md)：连续存储；[primus_integer](crates/primus_integer/README.zh_CN.md)：整数 trait 与多 limb 算术；[primus_gcd](crates/primus_gcd/README.zh_CN.md)：GCD 与模逆 |
| 模算术 | [primus_reduce](crates/primus_reduce/README.zh_CN.md)：模数侧 trait；[primus_modulus](crates/primus_modulus/README.zh_CN.md)：模数实现；[primus_factor](crates/primus_factor/README.zh_CN.md)：乘法预计算；[primus_barrett_derive](crates/primus_barrett_derive/README.zh_CN.md)：常量 Barrett 模数 |
| 多项式与变换 | [primus_poly](crates/primus_poly/README.zh_CN.md)：多项式表示与算术；[primus_ntt](crates/primus_ntt/README.zh_CN.md)：精确变换；[primus_fft](crates/primus_fft/README.zh_CN.md)：Fourier 表与可复用 scratch |
| 分解与 RNS | [primus_decompose](crates/primus_decompose/README.zh_CN.md)：有符号 gadget 分解；[primus_rns](crates/primus_rns/README.zh_CN.md)：剩余类基、转换与 hybrid RNS |
| 采样与编码 | [primus_distr](crates/primus_distr/README.zh_CN.md)：私钥/噪声分布；[primus_encoding](crates/primus_encoding/README.zh_CN.md)：Rounded、Scaled 和 BFV RNS 系数编码 |
| 密文表示 | [primus_lattice](crates/primus_lattice/README.zh_CN.md)：存储、算术、提取、gadget 乘法、CMUX 和可复用工作区 |
| 加密与求值 | [primus_lwe](crates/primus_lwe/README.zh_CN.md)、[primus_glwe](crates/primus_glwe/README.zh_CN.md)、[primus_ntru](crates/primus_ntru/README.zh_CN.md)：密钥与方案原语；[primus_glwe_rns](crates/primus_glwe_rns/src/lib.rs)：CRT/DCRT GLWE 和 hybrid-RNS 密钥切换 |
| TFHE | [primus_tfhe](crates/primus_tfhe/README.zh_CN.md)：共享 LUT、PBS trait 和 Boolean 求值；上方两个家族 crate 与四个后端负责绑定参数、密钥和执行过程 |

RNS 与编码组件提供基础能力，目前没有完整的 BFV、BGV 或 CKKS 应用后端。`test-support/` 保存开发阶段共享的测试 fixture 和分配计数工具。数学契约由 rustdoc 说明；跨层 TFHE 实现依据及保留的性能取舍见[实现说明](crates/primus_tfhe/IMPLEMENTATION.md)。

## 构建与测试

默认 features 使用 stable Rust。在 workspace 根目录执行：

```sh
cargo check --workspace --all-targets
cargo test --workspace
cargo doc --workspace --no-deps
```

Portable SIMD 需要 nightly。以下命令检查并测试整个 workspace 的所有 features，包括 SIMD 和可选 RNS 路径：

```sh
cargo +nightly clippy --workspace --all-targets --all-features -- -D warnings
cargo +nightly test --workspace --all-features
```

[justfile](justfile) 提供局部验证入口：

| 命令 | 覆盖范围 |
| --- | --- |
| `just tfhe` | 七个 TFHE crate 与测试辅助：默认检查、Clippy、测试/doctest 和文档 |
| `just tfhe-simd` | 相同包的 nightly SIMD 检查、Clippy 和测试/doctest |
| `just simd` | 指定算术 crate 的 nightly SIMD 检查、Clippy 和 nextest |

`just` 为可选工具；调用 nextest 的流程还需安装 `cargo-nextest`。[CI 工作流](.github/workflows/ci.yml)定义全 workspace 验证：格式检查、stable 默认配置与 nightly 全 features 的 all-target Clippy、测试和 doctest，以及包含私有项的严格 nightly rustdoc。本地 `just ci` 组合默认 workspace 与局部 SIMD 流程，并不等同于 CI 的全 features 矩阵。

仓库配置了 `target-cpu=native`，本地产物可能使用其他 CPU 不支持的指令；CI 会清除该设置。基准命令及负载参数随各 crate 的 benchmark 保存；性能测量应与编译、测试分开执行。

## 许可证

Primus FHE 可由你选择使用以下任一许可证：

- [Apache License, Version 2.0](LICENSE-APACHE-2.0)
- [MIT License](LICENSE-MIT)
