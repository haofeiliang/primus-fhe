// Shared public LUT geometry, cleartext function and creation measurement.
// Backend modules keep their concrete transform/context/evaluator types.

use std::hint::black_box;

use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_tfhe_benchmarks::measurement::{Case, Group, metadata};
use primus_tfhe_ntru::PbsParameters;
use primus_tfhe_ntru_lut::{ChunkFormat, HighPrecisionLookupTable, LookupTableConfig};

mod diagnostics;
#[cfg(all(
    feature = "ntru-fourier",
    any(feature = "rustfft", feature = "tfhe-fft")
))]
pub mod fourier;
#[cfg(feature = "ntru-ntt")]
pub mod ntt;

pub const CHUNKS: ChunkFormat = ChunkFormat::new(2);
pub const CONFIG: LookupTableConfig = LookupTableConfig {
    input_chunk_count: 8,
    output_chunk_count: 8,
    coefficient_chunk_count: 5,
};
pub const INPUT: usize = 0b10_10_10_11_11_00_11_01;

/// Public functions with identical geometry but different selection structure.
#[derive(Clone, Copy)]
pub enum Workload {
    /// The teaching example has repeated low-output polynomials.
    Polynomial,
    /// A fixed seed defines a dense mapping independently of key-generation RNG.
    Dense,
    /// All outputs share one choice on chunk 6; high chunks 5 and 7 are irrelevant.
    Shared,
}

impl Workload {
    /// Geometry and function structure distinguish general lookup from repeated tables.
    pub fn metadata(self) -> serde_json::Value {
        serde_json::json!({"chunk_bits": CHUNKS.bits(), "input_chunks": CONFIG.input_chunk_count,
            "coefficient_chunks": CONFIG.coefficient_chunk_count, "output_chunks": CONFIG.output_chunk_count,
            "function": match self { Self::Polynomial => "x*x+3*x+7 mod 2^16", Self::Dense => "SplitMix64 seed42", Self::Shared => "(m0+m6)%4 repeated eight times" },
            "unique_polynomials_per_output": match self { Self::Polynomial => [1,1,1,1,1,4,16,64], Self::Dense => [64;8], Self::Shared => [4;8] }})
    }

    // Keep the teaching-example ID unchanged; label the two diagnostic mappings.
    pub fn suffix(self) -> &'static str {
        match self {
            Self::Polynomial => "",
            Self::Dense => "/dense_seed42",
            Self::Shared => "/shared_middle_chunk",
        }
    }

    // Return one two-bit output chunk. Dense uses the SplitMix64 output mixer
    // on x+seed+gamma, rather than stateful sampling in an output-major callback.
    // This fixes the mapping across word widths, backends and callback order.
    pub fn digit<T: FheUint>(self, x: usize, output: usize) -> T {
        let x = x as u64;
        let value = match self {
            Self::Polynomial => x * x + 3 * x + 7,
            Self::Shared => {
                // Identical output digits expose sharing and a public choice
                // moved past the omitted first layer. Low rotations still
                // select m_0; m_6 supplies the high-chunk addition.
                return T::as_from(
                    (CHUNKS.chunk(x, 0) + CHUNKS.chunk(x, 6)) & CHUNKS.mask() as u64,
                );
            }
            Self::Dense => {
                let mut z = x.wrapping_add(42).wrapping_add(0x9e37_79b9_7f4a_7c15);
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                z ^ (z >> 31)
            }
        };
        T::as_from(CHUNKS.chunk(value, output))
    }
}

// Comparing full views also checks that deduplication preserves logical prefix
// access. This is fixture validation only, outside construction/evaluation timing.
pub fn check_repetition<T: FheUint>(table: &HighPrecisionLookupTable<T>, workload: Workload) {
    let expected = match workload {
        Workload::Polynomial => [1, 1, 1, 1, 1, 4, 16, 64],
        Workload::Dense => [64; 8],
        Workload::Shared => [4; 8],
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
}

// Public LUT creation is independent of the transform engine; Native is registered
// only once, alongside evaluation with the primary FFT engine.
pub fn benchmark_lut_creation<T: FheUint, M: RingContext<T>, LM: RingContext<T>>(
    c: &mut Group<'_>,
    case: &Case<'_>,
    parameters: &PbsParameters<T, M, LM>,
    workload: Workload,
) {
    let input_codec = RoundedCodec::new(
        CHUNKS.plaintext_modulus(),
        parameters.as_ref().external_lwe().cipher_modulus(),
    );
    let poly_length = parameters.as_ref().poly_length();
    let ring_modulus = parameters.as_ref().accumulator_ntru().cipher_modulus();
    c.throughput(criterion::Throughput::Elements(1));
    c.bench_function(case.id(), |b| {
        metadata::record("high_precision_lut", case, || {
            serde_json::json!({
                "poly_length": poly_length.get(),
                "lut": workload.metadata(),
                "q": parameters.as_ref().external_lwe().cipher_modulus().explicit_value().map(|q| q.to_string()), "Q": ring_modulus.explicit_value().map_or_else(|| format!("2^{}", T::BITS), |q| q.to_string()),
                "outputs": 1,
                "drop": "included",
            })
        });
        b.iter(|| {
            black_box(
                HighPrecisionLookupTable::try_new(
                    black_box(poly_length),
                    black_box(ring_modulus),
                    &input_codec,
                    CONFIG,
                    |x, output| workload.digit::<T>(x, output),
                )
                .unwrap(),
            )
        });
    });
}
