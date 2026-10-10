//! Public table contracts run even in compiler-only builds, without keys or transforms.

use primus_encoding::RoundedCodec;
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_poly::PolyLength;
use primus_tfhe_ntru_lut::{
    ChunkFormat, HighPrecisionLookupTable, LookupTableConfig, LookupTableError,
};

#[test]
fn complete_storage_preserves_order_encoding_and_repeated_polynomials() {
    let input = RoundedCodec::new(8u32, PowOf2Modulus::new(256));
    // h=0/1/2/3, d=0 and K=N; output count is independent of input count.
    for (d, outputs) in [(3, 2), (2, 1), (1, 3), (0, 2)] {
        for kind in 0..3 {
            let digit = |x: usize, j: usize| match kind {
                0 => ((x + x / 4 + 3 * (x / 16) + 3 * j) % 4) as u32,
                1 => 2,
                _ => (x % 4) as u32, // Equal prefixes and outputs retain separate storage.
            };
            let config = LookupTableConfig {
                input_chunk_count: 3,
                output_chunk_count: outputs,
                coefficient_chunk_count: d,
            };
            let mut calls = Vec::new();
            let table = HighPrecisionLookupTable::try_new(
                PolyLength::new(64),
                BarrettModulus::new(257),
                &input,
                config,
                |x, j| {
                    calls.push((x, j));
                    digit(x, j)
                },
            )
            .unwrap();
            assert_eq!(
                calls,
                (0..outputs)
                    .flat_map(|j| (0..64).map(move |x| (x, j)))
                    .collect::<Vec<_>>()
            );
            let entries = 4usize.pow(d as u32);
            let prefixes = 64 / entries;
            assert_eq!(table.polynomials_per_output(), prefixes);
            assert_eq!(table.needs_public_lift(), d == 3);
            let start = table.polynomial(0, 0).as_ref().as_ptr();
            for j in 0..outputs {
                for p in 0..prefixes {
                    let polynomial = table.polynomial(j, p);
                    assert_eq!(
                        polynomial.as_ref().as_ptr(),
                        start.wrapping_add((j * prefixes + p) * 64)
                    );
                    for (z, &coefficient) in polynomial.as_ref().iter().enumerate() {
                        let expected = if z < entries {
                            (digit(p * entries + z, j) * 257 + 4) / 8
                        } else {
                            0
                        };
                        assert_eq!(
                            coefficient, expected,
                            "d={d}, output={j}, prefix={p}, coefficient={z}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn invalid_geometry_precedes_callbacks_and_invalid_digit_stops_enumeration() {
    let input = RoundedCodec::new(8u32, PowOf2Modulus::new(256));
    let base = LookupTableConfig {
        input_chunk_count: 3,
        output_chunk_count: 2,
        coefficient_chunk_count: 2,
    };
    let cases = [
        (
            LookupTableConfig {
                input_chunk_count: 0,
                ..base
            },
            LookupTableError::EmptyChunks,
        ),
        (
            LookupTableConfig {
                output_chunk_count: 0,
                ..base
            },
            LookupTableError::EmptyChunks,
        ),
        (
            LookupTableConfig {
                coefficient_chunk_count: 4,
                ..base
            },
            LookupTableError::InvalidCoefficientChunkCount,
        ),
        (
            LookupTableConfig {
                coefficient_chunk_count: 3,
                ..base
            },
            LookupTableError::InsufficientCapacity,
        ),
        (
            LookupTableConfig {
                input_chunk_count: usize::BITS as usize,
                ..base
            },
            LookupTableError::StorageSizeOverflow,
        ),
        // M^c fits usize, but N*P*sizeof(u32) exceeds the allocation byte limit.
        (
            LookupTableConfig {
                input_chunk_count: ((usize::BITS - 7) / 2) as usize,
                coefficient_chunk_count: 0,
                ..base
            },
            LookupTableError::StorageSizeOverflow,
        ),
    ];
    for (config, expected) in cases {
        let result = HighPrecisionLookupTable::try_new(
            PolyLength::new(32),
            BarrettModulus::new(257),
            &input,
            config,
            |_, _| panic!("invalid layout reached callback"),
        );
        assert!(matches!(result, Err(error) if error == expected));
    }
    let mut calls = Vec::new();
    let result = HighPrecisionLookupTable::try_new(
        PolyLength::new(32),
        BarrettModulus::new(257),
        &input,
        base,
        |x, j| {
            calls.push((x, j));
            if (x, j) == (5, 1) { 4 } else { 0 }
        },
    );
    assert!(matches!(
        result,
        Err(LookupTableError::OutputChunkOutOfRange {
            input: 5,
            output: 1
        })
    ));
    assert_eq!(
        calls,
        (0..64)
            .map(|x| (x, 0))
            .chain((0..=5).map(|x| (x, 1)))
            .collect::<Vec<_>>()
    );
}

#[test]
fn chunk_words_preserve_little_endian_digits_and_reject_partial_writes() {
    let format = ChunkFormat::new(4);
    let mut digits = [0u64; 16];
    format.split_to(0xfedc_ba98_7654_3210, &mut digits);
    assert_eq!(digits, core::array::from_fn(|i| i as u64));
    assert_eq!(format.join(&digits), 0xfedc_ba98_7654_3210);
    let mut short = [9u32; 2];
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        format.split_to(256, &mut short)
    }));
    assert!(failed.is_err());
    assert_eq!(short, [9; 2]);
}
