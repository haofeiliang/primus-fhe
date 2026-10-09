//! Operation preparation and integer adaptation use small domains, without transforms or keys.
#![cfg(any(feature = "ntt", feature = "fourier"))]

use primus_tfhe_ntru_lut::{HighPrecLutParameters, HighPrecisionLookupTable, LookupTableError};

#[test]
fn integer_compilation_preserves_digits_and_rejects_truncation() {
    // Fixed u64 coefficients; cleartext can be u8, u64 or u128 independently.
    #[cfg(feature = "ntt")]
    let mut config = primus_tfhe_ntru_lut::experimental::NTT_CLASSIC_LOOKUP_U64;
    #[cfg(not(feature = "ntt"))]
    let mut config = primus_tfhe_ntru_lut::experimental::FOURIER_CLASSIC_LOOKUP_U64;
    config.input_chunk_count = 3;
    config.output_chunk_count = 2;
    let parameters = HighPrecLutParameters::try_from_config(config).unwrap();
    assert_eq!(parameters.layout().coefficient_chunk_count, 3); // d=min(c, floor(log2(N)/tau)).
    let table = parameters
        .compile_fn(|x: u8| (x.wrapping_mul(3) + 1) & 15)
        .unwrap();
    let chunks = parameters.chunk_format();
    let raw = HighPrecisionLookupTable::try_from_parameters(
        parameters.as_ref(),
        parameters.codecs().input_codec(),
        parameters.layout(),
        |x, j| chunks.chunk(((x * 3 + 1) & 15) as u64, j),
    )
    .unwrap();
    for output in 0..2 {
        assert_eq!(
            table.polynomial(output, 0).as_ref(),
            raw.polynomial(output, 0).as_ref()
        );
    }
    assert!(matches!(
        parameters.compile_fn(|_: u8| 16),
        Err(LookupTableError::OutputValueOutOfRange { input: 0 })
    ));

    // Explicit d overrides the default; the same integer results retain their logical polynomials.
    config.coefficient_chunk_count = Some(1);
    config.output_chunk_count = 32;
    let exact = HighPrecLutParameters::try_from_config(config).unwrap();
    assert_eq!(exact.output_bits(), 64);
    let table = exact.compile_fn(|_: u64| u64::MAX).unwrap();
    assert_eq!(table.stats().output_bits, 64);
    assert!(matches!(
        exact.compile_fn(|_: u8| panic!("capacity must precede callbacks")),
        Err(LookupTableError::WordCapacity {
            required: 64,
            available: 8
        })
    ));

    // Wider outputs stay available as chunks and as a sufficiently wide cleartext word.
    config.output_chunk_count = 40;
    let wide = HighPrecLutParameters::try_from_config(config).unwrap();
    assert!(matches!(
        wide.compile_fn(|_: u64| panic!("capacity must precede callbacks")),
        Err(LookupTableError::WordCapacity {
            required: 80,
            available: 64
        })
    ));
    let word = wide.compile_fn(|x: u128| (1u128 << 78) | x).unwrap();
    let digits = wide
        .compile_chunks_fn(|x, output| {
            if output == 39 {
                1
            } else {
                chunks.chunk(x as u64, output)
            }
        })
        .unwrap();
    for output in 0..40 {
        for prefix in 0..word.polynomials_per_output() {
            assert_eq!(
                word.polynomial(output, prefix).as_ref(),
                digits.polynomial(output, prefix).as_ref()
            );
        }
    }
}
