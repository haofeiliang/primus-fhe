# Barrett storage and slice dispatch

The [README](README.md) defines user-facing modulus choices and arithmetic contracts. Native dispatch is distinct from the optional nightly portable-SIMD feature.

`BarrettModulus` stores the little-endian limbs `[low, high]` of `floor(B² / modulus)`, where `B = 2^T::BITS`. The two spare modulus bits permit its dot-product kernels to accumulate 16 products before reduction. `CompactModulus` and `UintModulus` store only the modulus.

`BarrettModulus::reduce_add_mul_slice_assign` and `reduce_mul_add_slice_to` can also select native x86_64 acceleration in stable builds: AVX-512F for `u32`, and AVX-512F + AVX-512DQ for `u64`. For `u64` moduli below `2^50`, this path additionally selects an integer IFMA kernel when AVX-512IFMA is available. These kernels take precedence for slices of at least 32 elements whether or not `simd` is enabled; other cases retain the scalar or portable-SIMD fallback. Inputs and outputs remain canonical residues; no extra precomputed storage or scratch is required.

Derived Barrett contexts also use the native multiply-add kernels, but preserve their constant-modulus fallbacks for power-of-two moduli, `u16`, and `u64` moduli at or above `2^50`. For derived `u64`, native dispatch requires IFMA; otherwise it retains the original fallback. This avoids replacing compiler-specialized constant arithmetic with a slower runtime-modulus kernel. See [the derive crate](../primus_barrett_derive/README.md).

For matched workloads and reproduction commands, use the [benchmark guide](benches/README.md). Dispatch eligibility is an implementation choice, not a promise of faster execution for every input or machine.
