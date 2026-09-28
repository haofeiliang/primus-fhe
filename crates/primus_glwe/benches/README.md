# primus_glwe validation and benchmarks

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> [Primus FHE](../../../README.md) is experimental; its APIs and numerical contracts are unstable and may change incompatibly at any time.

## Source and tests

[Secret keys](../src/secret_key), [public keys](../src/public_key), [key switching](../src/key_switch), [automorphism](../src/automorphism), [trace/packing](../src/trace), [packing key switching](../src/packing_key_switch) and [scheme switching](../src/scheme_switch) contain the public contracts and implementation details.

Tests are grouped by operation: ordinary key workflows, gadget phases and external products, constant-batch equivalence, CMUX, key switching, automorphism, scheme switching, and trace/expansion/packing. `tests/common` holds the small schoolbook phase oracle shared by evaluation tests. Boundary rejection and capacity zeroization have dedicated test binaries. Fourier constant batches, automorphism, trace, packing key switching and scheme-switching tests exercise both RustFFT and tfhe-fft.

```sh
cargo test -p primus_glwe
cargo clippy -p primus_glwe --all-targets -- -D warnings
cargo +nightly test -p primus_glwe --features simd
```

## Benchmarks

```sh
cargo bench -p primus_glwe --bench encryption
cargo bench -p primus_glwe --bench primitives
cargo bench -p primus_glwe --bench key_conversion
# Check every case without collecting timing samples:
cargo bench -p primus_glwe -- --test
```

All benches use `(k, N) = (1, 1024)` and `(2, 4096)`. Each iteration performs one operation with reusable output/scratch; key/table construction and allocation remain outside timing. Parameters and fixed seeds are recorded in the bench sources. These workloads track regressions rather than compare matched security; they are not security parameter recommendations.

| Bench | Work measured |
| --- | --- |
| [encryption](encryption.rs) | Secret/public encryption, secret decryption (including coefficient NTT paths), GLev/GGSW generation and batches of 8 constant GGSWs; includes sampling, coding and required transforms |
| [primitives](primitives.rs) | Ordinary/reverse trace; projection and partial expansion for 8 and `N/8` coefficients; full expansion; packing 1, 8 and `N` LWEs; direct Fourier automorphism on both FFT backends |
| [key_conversion](key_conversion.rs) | Independent-key packing of 1, 8 and `N` LWEs (input dimension 512; single-LWE cases cover bases `2^3` and `2^10`); NTT/Fourier GLev-to-GGSW scheme switching |

Ordinary and reverse trace measure their respective API scales. Projection/partial expansion use the same encrypted zero-tail message and report output-message throughput. Codec variants are benchmarked in `primus_encoding`.
