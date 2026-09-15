# primus_tfhe

[English](README.md) | 简体中文

公共 LUT 编译、编码元数据及 PBS trait 层，供 GLWE 和 NTRU 两族复用。
本 crate 不持有客户端密钥、变换 table 或 evaluator 工作区。完整使用流程从下面的后端示例开始。

## Crate 分工与能力

| Family | NTT 后端 | Fourier 后端 |
| --- | --- | --- |
| [GLWE 参数与客户端](../primus_tfhe_glwe/README.zh_CN.md) | [GLWE NTT](../primus_tfhe_glwe_ntt/README.zh_CN.md) | [GLWE Fourier](../primus_tfhe_glwe_fourier/README.zh_CN.md) |
| [NTRU 参数与客户端](../primus_tfhe_ntru/README.zh_CN.md) | [NTRU NTT](../primus_tfhe_ntru_ntt/README.zh_CN.md) | [NTRU Fourier](../primus_tfhe_ntru_fourier/README.zh_CN.md) |

| 后端 | 密文模数 | PBS / ManyLUT | Boolean 门 | CBS |
| --- | --- | --- | --- | --- |
| GLWE NTT | 显式域模数 | 支持 | 支持 | 支持 |
| GLWE Fourier | 原生 torus | 支持 | 支持 | 未实现 |
| NTRU NTT | 显式域模数 | 支持 | 未实现 | 支持 |
| NTRU Fourier | 原生 torus | 支持 | 未实现 | 支持 |

四后端均支持私钥和 LWE 公钥客户端。Fourier 后端支持 RustFFT 与 TfheFFT。
参数和 API 仍处于实验阶段；示例及 benchmark fixture 不是生产安全参数或失败概率建议。

## LUT 与资源生命周期

1. Family 参数描述外部 LWE 和 accumulator 环。
2. 后端 context 绑定参数与 NTT/FFT table，并生成配套的 client/server key。
3. 通过 family 参数或 context 编译 `LookupTable` / `ManyLookupTable`。
   evaluator 创建一次，在线 `_to` 调用复用其 scratch。
4. 调用方输出分配一次，后续加密与求值重复使用同一存储。

单函数或切片为 `0..ceil(t/2)` 输入域编程，输出属于 `0..t`。
另一半遵循负循环扩展，不能独立编程。ManyLUT 的 `output_count` 必须是非零的
2 的幂，并满足 `ceil(t/2) <= N/output_count`。callback 接收 `(input, output_index)`，
切片按输入优先排列。所有输出共享一次盲旋转（BR）和密钥切换，再分别提取。
输出越多，旋转分辨率与输入噪声余量越低。这是一个输入求多个函数，不是独立密文批处理。

### 旋转布局

令 `D` 为已编程前缀长度，`s = output_count`（普通 LUT 为 1），`M = N/s`。
消息先编码为 `E(m) = round(m*q_in/t) mod q_in`，再映射到虚拟中心
`R(E(m), q_in, 2M)`，其中 `R(x,q,L) = floor((x*L + floor(q/2))/q) mod L`，
两次舍入遇到中点均向上。Native 的 `q_in` 为 `2^T::BITS`。合并两次舍入可能改变表内容。

编译器选择最近中心的值，中点相等时选择较大的中心；最后在 `min(R(E(D), q_in, 2M), M)`
追加值为 `-f(0)` 的中心以终止编程前缀，其后的系数不是额外的输入域。
raw 输出必须已经是 `q_acc` 下的规范值，越界值会被拒绝。
累加器模数与输出尺度均独立于 `q_in`。

四后端逐个将 LWE 系数量化为 `s*R(x, q_in, 2N/s)`，旋转指数为
`-R_s(b) + sum(R_s(a[i])*secret[i])`，不能替换为对解密相位的一次量化。
旋转量是 `s` 的倍数，保留 `s*r+j` 上的各输出列；提取系数 `j` 时按负循环符号读取该列。

## 编码与密钥契约

| 接口 | 输入 / 输出含义 |
| --- | --- |
| 普通 `encrypt` | `0..t` 范围的 unsigned 消息 |
| `encrypt_padded` | 相同 unsigned 尺度，输入限制为 `0..ceil(t/2)`，供普通 LUT 使用 |
| `encrypt_centered` | 接收 `0..t` 的模代表元；上半区表示负数，例如 `t=4` 时 `3` 表示 `-1` |
| GLWE Boolean | 外部 `false/true` 对应模 4 下的 `0/1`；内部 LUT 使用 rounded 模 8 尺度的正负值，随后平移恢复外部编码 |
| CBS | 普通 unsigned LWE 输入转为指定 gadget 尺度的 GGSW/NGSW，秘密为 accumulator secret；`0/1` 输入可生成 CMUX 控制 |

客户端解密返回 `0..t` 中的规范代表元。Centered 加密不能替代普通 LUT 的 unsigned
输入契约。PBS 保留 LUT 的输出尺度，不会自动把 Boolean 或 gadget 输出改为普通消息编码。

原始 `LweCiphertext` 不记录秘密、编码或噪声。调用方必须使用配套密钥、显式模数下的
规范系数，并保证噪声余量。LUT 与维数错误在写入输出前拒绝，但这些检查不能验证实际
秘密一致性。Fourier 密钥和 evaluator 必须使用同一 FFT table 实例。

最小 trait 为 `ProgrammableBootstrap` 和 `ProgrammableBootstrapMany`。
Encoded LUT compiler 与 `backend_support` 服务于后端实现；普通应用使用 context/family 编译入口。

## 验证

在 workspace 根目录运行：

```sh
just tfhe
just tfhe-simd
```

这两个 [recipe](../../justfile) 覆盖七包默认 / nightly SIMD 的 check、Clippy 和测试；
`tfhe` 还检查 `xtask` 调用方并构建文档。`just ci` 执行 workspace 检查及底层、TFHE 两组 SIMD 检查。
各后端 README 提供可运行示例与 Criterion 命令。
共享 raw 输出 LUT 的构造基准包含分配与释放：

```sh
cargo bench -p primus_tfhe --bench lookup_table
```

## 保留模数类型的旋转量化

raw LUT 编译接收独立的输入模数类型和 accumulator 模数类型。
`backend_support::RotationQuantizer::new(input_modulus, two_n, window)` 准备固定
模数对的转换，`exponent(value)` 无分配复用。GLWE 密钥和 NTRU 参数在构造时
缓存普通 PBS 量化；ManyLUT 在系数循环前按步长准备，先在 `two_n/window`
个位置内舍入，再乘 `window`。仅描述模数域的元数据仍使用 `Option<T>`。
