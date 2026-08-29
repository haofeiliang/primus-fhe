# Primus FHE

[English](README.md) | 简体中文

Primus FHE 是一个实验性的 Rust workspace，用于探索全同态加密实现及其所需的算术基础设施。

> [!WARNING]
> Primus FHE 目前处于早期实验阶段。其 API、数据表示、算法和 crate 边界均不稳定，
> 可能随时发生破坏性修改，且不提供弃用过渡期。本项目不声明已达到生产可用状态或已通过安全审查。

## 概览

workspace 目前包括：

- 底层存储、整数、模运算、分解、RNS、NTT 和 Fourier 基础组件；
- 面向 LWE、GLWE 和 NTRU 方案的格密码密文抽象；
- 基于 GLWE 和 NTRU 的 TFHE 实验性实现，包括 NTT 和 Fourier 后端。

随着各 crate 及其公开契约的审查推进，文档将逐步完善。目前以下基础 crate 已有独立的 README：

- [`primus_data`](crates/primus_data/README.zh_CN.md)：连续存储 trait；
- [`primus_gcd`](crates/primus_gcd/README.zh_CN.md)：定宽整数的 GCD 和模逆运算；
- [`primus_integer`](crates/primus_integer/README.zh_CN.md)：整数 trait、定宽多 limb
  运算和可选的 SIMD 抽象。

## 构建与测试

workspace 的默认配置可使用 stable Rust 构建：

```text
cargo check --workspace --all-targets
cargo test --workspace
```

portable SIMD 支持目前需要 nightly Rust。仓库的 `justfile` 提供完整的 SIMD 检查、
lint 和测试流程：

```text
just simd
```

仓库已配置 `target-cpu=native`，因此本地构建的产物可能使用旧款或其他 CPU
不支持的指令。

## 许可证

Primus FHE 可由你选择使用以下任一许可证：

- [Apache License, Version 2.0](LICENSE-APACHE-2.0)
- [MIT License](LICENSE-MIT)
