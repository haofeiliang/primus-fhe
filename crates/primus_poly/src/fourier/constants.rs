//! CPU feature detection for Fourier SIMD — evaluated once on first access.

#[cfg(target_arch = "x86_64")]
use std::sync::LazyLock;

/// AVX2 + FMA available on this x86_64 CPU.
#[cfg(target_arch = "x86_64")]
pub static HAS_AVX2_FMA: LazyLock<bool> =
    LazyLock::new(|| is_x86_feature_detected!("avx2") && is_x86_feature_detected!("fma"));

/// AVX-512F available on this x86_64 CPU.
#[cfg(target_arch = "x86_64")]
pub static HAS_AVX512F: LazyLock<bool> = LazyLock::new(|| is_x86_feature_detected!("avx512f"));
