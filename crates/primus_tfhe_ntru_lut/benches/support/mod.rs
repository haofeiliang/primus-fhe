// Shared public LUT geometry, cleartext function and compilation measurement.
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

// Match the teaching examples; widening before multiplication also works on
// 32-bit hosts. Each callback returns a single radix-four output digit.
pub fn digit<T: FheUint>(x: usize, output: usize) -> T {
    let x = x as u64;
    T::as_from(((x * x + 3 * x + 7) >> (2 * output)) & 3)
}

// Report retained requested heap, not temporary allocation volume or RSS.
pub fn heap(name: &str, allocation: Allocations) {
    eprintln!(
        "memory,{name},{}",
        allocation.allocated_bytes - allocation.released_bytes
    );
}

// Compilation is independent of the transform engine; Native is registered
// only once per word width, even though evaluation covers both FFT engines.
pub fn compile<T: FheUint, M: RingContext<T>, LM: RingContext<T>>(
    c: &mut Criterion,
    name: &str,
    parameters: &TfheParameters<T, M, LM>,
) {
    c.bench_function(&format!("{name}/compile_and_drop"), |b| {
        b.iter(|| {
            black_box(
                HighPrecisionLookupTable::try_new(black_box(parameters), CONFIG, digit::<T>)
                    .unwrap(),
            )
        });
    });
}
