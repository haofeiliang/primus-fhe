use criterion::Criterion;
use primus_lwe::LweParameters;
use primus_modulus::PowOf2Modulus;
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_reduce::RingContext;
use primus_test_allocations::{Allocations, measure};
use primus_tfhe_ntru::{CircuitBootstrapConfig, DecompositionConfig, TfheParameters};

pub const N: usize = 1024;
pub const DIMENSION: usize = 64;
pub const Q: u64 = 1_125_899_906_826_241;
pub const CONFIG: crate::LookupTableConfig = crate::LookupTableConfig {
    input_chunk_count: 7,
    output_chunk_count: 3,
    coefficient_chunk_count: 5,
};
pub const FULL: DecompositionConfig = DecompositionConfig {
    log_basis: 8,
    level_count: None,
};

// Explicit functional fixture: all coordinates have sigma=0.7, and q is 2^24.
// Backend Q and transform arithmetic remain different; this is not a security comparison.
pub fn parameters<M: RingContext<u64>>(modulus: M) -> TfheParameters<u64, M, PowOf2Modulus<u64>> {
    let ring = NtruParameters::new(N, 8, modulus, SecretKeyDistr::SparseTernary, 0.7);
    TfheParameters::try_new(
        LweParameters::new(
            DIMENSION,
            8,
            PowOf2Modulus::new(1 << 24),
            SecretKeyDistr::UniformBinary,
            0.7,
        ),
        NlevParameters::with_ntru_params(&ring, FULL.log_basis, None),
        FULL,
        0.7,
    )
    .unwrap()
}
pub fn cbs() -> CircuitBootstrapConfig {
    CircuitBootstrapConfig {
        output: DecompositionConfig {
            log_basis: 8,
            level_count: Some(3),
        },
        trace: FULL,
        trace_noise_standard_deviation: 0.7,
        scheme_switch: FULL,
        scheme_switch_noise_standard_deviation: 0.7,
    }
}
pub fn digit(x: usize, output: usize) -> u64 {
    (((x * x + 3 * x + x / 17 + x / 257 + 7) >> (2 * output)) & 3) as u64
}

// Report retained requested heap, not temporary allocation volume or process RSS.
pub fn heap(name: &str, allocation: Allocations) {
    eprintln!(
        "memory,{name},{}",
        allocation.allocated_bytes - allocation.released_bytes
    );
}

// One invocation is one named operation, with no manual timing amplification.
// Allocation instrumentation runs once before Criterion and is disabled while timing.
pub fn bench(c: &mut Criterion, name: &str, mut run: impl FnMut()) {
    let (_, online) = measure(&mut run);
    assert_eq!(online.count, 0, "{name}: online allocation");
    eprintln!("online_allocations,{name},{}", online.count);
    c.bench_function(name, |b| b.iter(&mut run));
}
