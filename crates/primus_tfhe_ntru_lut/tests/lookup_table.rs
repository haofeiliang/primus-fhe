use primus_lwe::LweParameters;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_reduce::RingContext;
use primus_tfhe_ntru::{DecompositionConfig, TfheParameters};
use primus_tfhe_ntru_lut::{HighPrecisionLookupTable, LookupTableConfig, LookupTableError};

fn parameters<M: RingContext<u64>>(
    modulus: M,
    t: u64,
) -> TfheParameters<u64, M, BarrettModulus<u64>> {
    let ring = NtruParameters::new(64, t, modulus, SecretKeyDistr::SparseTernary, 0.7);
    TfheParameters::try_new(
        LweParameters::new(
            2,
            t,
            BarrettModulus::new(1 << 24),
            SecretKeyDistr::UniformBinary,
            0.7,
        ),
        NlevParameters::with_ntru_params(&ring, 8, None),
        DecompositionConfig {
            log_basis: 8,
            level_count: None,
        },
        0.7,
    )
    .unwrap()
}

fn geometry<M: RingContext<u64>>(modulus: M, q: u128) {
    let parameters = parameters(modulus, 8);
    for coefficient_chunk_count in 0..=3 {
        let config = LookupTableConfig {
            input_chunk_count: 3,
            output_chunk_count: 2,
            coefficient_chunk_count,
        };
        let mut calls = Vec::new();
        let lut = HighPrecisionLookupTable::try_new(&parameters, config, |x, output| {
            calls.push((x, output));
            ((x * 3 + x / 4 + 5) >> (2 * output)) as u64 % 4
        })
        .unwrap();
        assert_eq!(lut.config(), config);
        assert_eq!(lut.chunk_bits(), 2);
        assert_eq!(lut.input_value_count(), 64);
        assert_eq!(
            lut.entries_per_polynomial(),
            4usize.pow(coefficient_chunk_count as u32)
        );
        assert_eq!(
            lut.polynomials_per_output(),
            64 / lut.entries_per_polynomial()
        );
        assert_eq!(
            calls,
            (0..2)
                .flat_map(|o| (0..64).map(move |x| (x, o)))
                .collect::<Vec<_>>()
        );
        for output in 0..2 {
            for prefix in 0..lut.polynomials_per_output() {
                let start = (output * lut.polynomials_per_output() + prefix) * 64;
                for index in 0..64 {
                    let expected = if index < lut.entries_per_polynomial() {
                        let x = prefix * lut.entries_per_polynomial() + index;
                        let digit = ((3 * x + x / 4 + 5) >> (2 * output)) % 4;
                        ((q * digit as u128 + 4) / 8) as u64
                    } else {
                        0
                    };
                    assert_eq!(lut.as_slice()[start + index], expected);
                }
            }
        }
        assert!(lut.is_compatible(&parameters));
    }
}

#[test]
fn table_partition_and_chunk_encoding_match_integer_oracle() {
    geometry(BarrettModulus::new(65_537), 65_537);
    geometry(NativeModulus::new(), 1u128 << 64);
}

#[test]
fn compilation_rejects_invalid_domains_before_callbacks() {
    let parameters = parameters(BarrettModulus::new(65_537), 4);
    for (input_chunk_count, output_chunk_count, coefficient_chunk_count, expected) in [
        (0, 1, 0, LookupTableError::EmptyChunks),
        (1, 0, 0, LookupTableError::EmptyChunks),
        (1, 1, 2, LookupTableError::InvalidCoefficientChunkCount),
        (7, 1, 7, LookupTableError::InsufficientCapacity),
        (
            usize::BITS as usize,
            1,
            0,
            LookupTableError::StorageSizeOverflow,
        ),
        (
            usize::BITS as usize - 2,
            1,
            0,
            LookupTableError::StorageSizeOverflow,
        ),
        (1, usize::MAX, 0, LookupTableError::StorageSizeOverflow),
    ] {
        let result = HighPrecisionLookupTable::try_new(
            &parameters,
            LookupTableConfig {
                input_chunk_count,
                output_chunk_count,
                coefficient_chunk_count,
            },
            |_, _| panic!("invalid geometry must not invoke the callback"),
        );
        assert_eq!(result.err(), Some(expected));
    }
    let config = LookupTableConfig {
        input_chunk_count: 1,
        output_chunk_count: 1,
        coefficient_chunk_count: 0,
    };
    let result = HighPrecisionLookupTable::try_new(&parameters, config, |x, _| x as u64 + 1);
    assert_eq!(
        result.err(),
        Some(LookupTableError::OutputChunkOutOfRange {
            input: 1,
            output: 0
        })
    );
    for t in [2, 6] {
        let parameters = self::parameters(BarrettModulus::new(65_537), t);
        assert_eq!(
            HighPrecisionLookupTable::try_new(&parameters, config, |_, _| panic!()).err(),
            Some(LookupTableError::InvalidPlaintextModulus)
        );
    }
}
