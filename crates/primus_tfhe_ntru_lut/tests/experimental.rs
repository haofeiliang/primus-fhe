//! Pair chunk geometry with CBS/return domains; use a small public LUT and no keys.

#![cfg(any(feature = "ntt", feature = "fourier"))]

use primus_modulus::PowOf2Modulus;
use primus_reduce::RingContext;
use primus_tfhe_ntru::{CbsParameters, OneHotLookupTable};
use primus_tfhe_ntru_lut::{HighPrecisionLookupTable, experimental};

/// Keep the recorded layout visible, then exercise independent counts on the same keys/codecs.
fn check_entry<M>(config: primus_tfhe_ntru_lut::HighPrecLutConfig<u64, M, PowOf2Modulus<u64>>)
where
    M: RingContext<u64>
        + TryFrom<primus_tfhe_ntru::ModulusConfig<M>, Error = primus_tfhe_ntru::ModulusConfigError>,
{
    let parameters = config.try_prepare().unwrap();
    let chunks = config.try_chunk_format().unwrap();
    let cbs = config.one_hot.gadget;
    let mut config = config.layout;
    assert!(parameters.key_switching_lwe().is_some());
    assert_eq!(chunks.bits(), 2);
    assert_eq!(chunks.bit_count(config.input_chunk_count), 16);
    assert_eq!(chunks.bit_count(config.output_chunk_count), 16);
    assert_eq!(config.coefficient_chunk_count, 5);
    assert_eq!(parameters.external_lwe().dimension().get(), 800);
    assert_eq!(parameters.poly_length().get(), 1024);
    let messages = primus_tfhe::PbsMessageConfig::new(chunks.plaintext_modulus());
    let codecs = parameters.pbs_codecs(messages).unwrap();
    assert_eq!(codecs.output_codec().ciphertext_modulus().value(), 1 << 24);
    assert_eq!(
        codecs
            .lut_output_codec()
            .ciphertext_modulus()
            .explicit_value(),
        parameters.accumulator_ntru().cipher_modulus_value()
    );
    let cbs = CbsParameters::try_from_config(&parameters, cbs).unwrap();
    let one_hot = OneHotLookupTable::try_new(&parameters, &cbs, codecs.input_codec()).unwrap();
    assert_eq!(one_hot.guard_radius(), 32);

    // Domain enumeration stays small; changing chunk counts does not remake parameters.
    config.input_chunk_count = 3;
    config.coefficient_chunk_count = 2;
    config.output_chunk_count = 1;
    let table = HighPrecisionLookupTable::try_from_parameters(
        &parameters,
        codecs.input_codec(),
        config,
        |x, output| chunks.chunk(x as u64, output),
    )
    .unwrap();
    assert_eq!(table.stats().input_bits, 6);
    assert_eq!(table.stats().output_bits, 2);
}

#[test]
fn experimental_lookup_pairs_chunk_format_and_key_material() {
    #[cfg(feature = "ntt")]
    check_entry(experimental::NTT_CLASSIC_LOOKUP_U64);
    #[cfg(feature = "fourier")]
    check_entry(experimental::FOURIER_CLASSIC_LOOKUP_U64);
}
