//! Pair chunk geometry with CBS/return domains; use a small public LUT and no keys.

#![cfg(any(feature = "ntt", feature = "fourier"))]

use primus_modulus::PowOf2Modulus;
use primus_reduce::RingContext;
use primus_tfhe_ntru::OneHotLookupTable;
use primus_tfhe_ntru_lut::{HighPrecisionLookupTable, experimental};

/// Keep the recorded layout visible, then exercise independent counts on the same keys/codecs.
fn check_entry<M>(config: primus_tfhe_ntru_lut::HighPrecLutConfig<u64, M, PowOf2Modulus<u64>>)
where
    M: RingContext<u64>
        + TryFrom<primus_tfhe_ntru::ModulusConfig<M>, Error = primus_tfhe_ntru::ModulusConfigError>,
{
    let parameters = config.try_prepare().unwrap();
    let chunks = parameters.chunk_format();
    let mut layout = parameters.layout();
    assert_eq!(layout, config.layout);
    assert_eq!(
        parameters.as_ref().algorithm(),
        config.one_hot.pbs.algorithm
    );
    assert_eq!(
        parameters.key_switching().lwe().dimension(),
        parameters.as_ref().external_lwe().dimension()
    );
    assert_eq!(chunks.bits(), 2);
    assert_eq!(chunks.bit_count(layout.input_chunk_count), 16);
    assert_eq!(chunks.bit_count(layout.output_chunk_count), 16);
    assert_eq!(layout.coefficient_chunk_count, 5);
    assert_eq!(parameters.as_ref().external_lwe().dimension().get(), 800);
    assert_eq!(parameters.as_ref().poly_length().get(), 1024);
    let codecs = parameters.codecs();
    assert_eq!(codecs.output_codec().ciphertext_modulus().value(), 1 << 24);
    assert_eq!(
        codecs
            .lut_output_codec()
            .ciphertext_modulus()
            .explicit_value(),
        parameters
            .as_ref()
            .accumulator_ntru()
            .cipher_modulus_value()
    );
    let one_hot = OneHotLookupTable::try_new(
        parameters.as_ref(),
        parameters.one_hot().gadget(),
        codecs.input_codec(),
    )
    .unwrap();
    assert_eq!(one_hot.guard_radius(), 32);

    // Domain enumeration stays small; changing chunk counts does not remake parameters.
    layout.input_chunk_count = 3;
    layout.coefficient_chunk_count = 2;
    layout.output_chunk_count = 1;
    let table = HighPrecisionLookupTable::try_from_parameters(
        parameters.as_ref(),
        codecs.input_codec(),
        layout,
        |x, output| chunks.chunk(x as u64, output),
    )
    .unwrap();
    assert_eq!(table.stats().input_bits, 6);
    assert_eq!(table.stats().output_bits, 2);
    // Reject incompatible chunk geometry while preparing the operation, before enumeration.
    for (input_chunks, coefficient_chunks, output_chunks) in [(0, 0, 1), (2, 3, 1), (2, 1, 0)] {
        let mut invalid = config;
        invalid.layout.input_chunk_count = input_chunks;
        invalid.layout.coefficient_chunk_count = coefficient_chunks;
        invalid.layout.output_chunk_count = output_chunks;
        assert!(invalid.try_prepare().is_err());
    }
    let mut crowded = config;
    crowded.one_hot.pbs.messages.input_modulus = 1024;
    crowded.layout.coefficient_chunk_count = 1;
    assert!(matches!(
        crowded.try_prepare(),
        Err(primus_tfhe_ntru_lut::HighPrecLutParameterError::Layout(_))
    ));
}

#[test]
fn experimental_lookup_pairs_chunk_format_and_key_material() {
    #[cfg(feature = "ntt")]
    check_entry(experimental::NTT_CLASSIC_LOOKUP_U64);
    #[cfg(feature = "fourier")]
    check_entry(experimental::FOURIER_CLASSIC_LOOKUP_U64);
}
