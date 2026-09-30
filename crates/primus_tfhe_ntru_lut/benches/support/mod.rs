// Shared public LUT geometry, cleartext function and creation measurement.
// Backend modules keep their concrete transform/context/evaluator types.

use std::hint::black_box;

use criterion::Criterion;
use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_test_allocations::Allocations;
use primus_tfhe_ntru::TfheParameters;
use primus_tfhe_ntru_lut::{HighPrecisionLookupTable, LookupTableConfig};

pub mod fourier;
pub mod ntt;

pub const CONFIG: LookupTableConfig = LookupTableConfig {
    input_chunk_count: 8,
    output_chunk_count: 8,
    coefficient_chunk_count: 5,
};
pub const INPUT: usize = 0b10_10_10_11_11_00_11_01;

/// Two public functions with identical geometry but different subtable reuse.
#[derive(Clone, Copy)]
pub enum Workload {
    /// The teaching example has repeated low-output polynomials.
    Polynomial,
    /// A fixed seed defines a dense mapping independently of key-generation RNG.
    Dense,
}

impl Workload {
    // Keeps the structured-workload ID unchanged and distinguishes the dense workload.
    pub fn suffix(self) -> &'static str {
        match self {
            Self::Polynomial => "",
            Self::Dense => "/dense_seed42",
        }
    }

    // Return one two-bit output chunk. Dense uses the SplitMix64 output mixer
    // on x+seed+gamma, rather than stateful sampling in an output-major callback.
    // This fixes the mapping across word widths, backends and callback order.
    pub fn digit<T: FheUint>(self, x: usize, output: usize) -> T {
        let x = x as u64;
        let value = match self {
            Self::Polynomial => x * x + 3 * x + 7,
            Self::Dense => {
                let mut z = x.wrapping_add(42).wrapping_add(0x9e37_79b9_7f4a_7c15);
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                z ^ (z >> 31)
            }
        };
        T::as_from((value >> (2 * output)) & 3)
    }
}

// Comparing full views also checks that deduplication preserves logical prefix
// access. This is fixture validation only, outside construction/evaluation timing.
pub fn check_repetition<T: FheUint>(table: &HighPrecisionLookupTable<T>, workload: Workload) {
    let expected = match workload {
        Workload::Polynomial => [1, 1, 1, 1, 1, 4, 16, 64],
        Workload::Dense => [64; 8],
    };
    for (output, count) in expected.into_iter().enumerate() {
        let mut unique = Vec::new();
        for prefix in 0..table.polynomials_per_output() {
            let polynomial = table.polynomial(output, prefix);
            if !unique.contains(&polynomial) {
                unique.push(polynomial);
            }
        }
        assert_eq!(unique.len(), count);
    }
    eprintln!(
        "unique_polynomials,{},{}",
        workload.suffix(),
        table.unique_polynomial_count()
    );
}

// Report retained requested heap, not temporary allocation volume or RSS.
pub fn heap(name: &str, allocation: Allocations) {
    eprintln!(
        "memory,{name},{}",
        allocation.allocated_bytes - allocation.released_bytes
    );
}

// Public LUT creation is independent of the transform engine; Native is registered
// only once per word width, even though evaluation covers both FFT engines.
pub fn benchmark_lut_creation<T: FheUint, M: RingContext<T>, LM: RingContext<T>>(
    c: &mut Criterion,
    name: &str,
    parameters: &TfheParameters<T, M, LM>,
    workload: Workload,
) {
    c.bench_function(&format!("{name}/create_lut_and_drop"), |b| {
        b.iter(|| {
            black_box(
                HighPrecisionLookupTable::try_new(black_box(parameters), CONFIG, |x, output| {
                    workload.digit::<T>(x, output)
                })
                .unwrap(),
            )
        });
    });
}
