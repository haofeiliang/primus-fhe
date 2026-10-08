//! Message-domain choices must reach LUT encoding and returned-output decoding together.

use primus_encoding::{CodecError, PlaintextEmbedding::Unsigned};
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_tfhe::{
    FactorizedLookupTable, LookupTableCompiler, LookupTableError, PbsMessageConfig, PolyLength,
};

#[test]
fn padded_bit_width_has_one_extra_codec_bit() {
    // Freeze the distinction between useful input bits and the full output modulus.
    for (bits, modulus) in [(0, 2), (1, 4), (4, 32), (30, 1u32 << 31)] {
        let messages = PbsMessageConfig::<u32>::try_from_input_bits(bits).unwrap();
        assert_eq!(messages.input_modulus, modulus);
        assert_eq!(messages.output_modulus, modulus);
        assert_eq!(messages.with_output_modulus(8).input_modulus, modulus);
    }
    let messages = PbsMessageConfig::<u64>::from_input_bits(62);
    assert_eq!(messages.input_modulus, 1u64 << 63);
    for bits in [31, 32, u32::MAX] {
        assert_eq!(
            PbsMessageConfig::<u32>::try_from_input_bits(bits),
            Err(LookupTableError::InvalidInputEncoding),
        );
    }
    assert_eq!(
        PbsMessageConfig::<u64>::try_from_input_bits(63),
        Err(LookupTableError::InvalidInputEncoding),
    );
}

#[test]
fn configured_domains_drive_rounded_and_factorized_programs() {
    let external = PowOf2Modulus::new(1024u32);
    let accumulator = BarrettModulus::new(97);
    let poly_length = PolyLength::new(32);

    // Cover equal, smaller, larger and odd message domains, without keys or transforms.
    for messages in [
        PbsMessageConfig::new(8u32),
        PbsMessageConfig::new(8).with_output_modulus(4),
        PbsMessageConfig::new(8).with_output_modulus(16),
        PbsMessageConfig::new(5),
    ] {
        let input_t = messages.input_modulus;
        let output_t = messages.output_modulus;
        let domain = input_t.div_ceil(2) as usize;
        let value = output_t - 1;
        let rounded = messages.try_rounded_codecs(external, accumulator).unwrap();
        let compiler = LookupTableCompiler::try_new(
            poly_length,
            rounded.input_codec(),
            accumulator,
            rounded.lut_output_codec(),
        )
        .unwrap();
        let single = compiler.compile_fn(|_| value).unwrap();
        let many = compiler.compile_interleaved_fn(2, |_, _| value).unwrap();
        assert_eq!(single.input_domain_len(), domain);
        assert_eq!(many.input_domain_len(), domain);
        assert_eq!(
            rounded.input_codec().encode_value(1, Unsigned),
            (1024 + input_t / 2) / input_t
        );

        // Independent integer rounding checks Q encoding and the subsequent Q→q return.
        let phase_q = (value * 97 + output_t / 2) / output_t;
        assert_eq!(single.polynomial().as_ref()[0], phase_q);
        assert_eq!(many.polynomial().as_ref()[0], phase_q);
        let returned_phase = (phase_q * 1024 + 97 / 2) / 97;
        assert_eq!(rounded.output_codec().decode_value(returned_phase), value);

        let scaled = messages
            .try_factorized_codecs(external, accumulator)
            .unwrap();
        assert_eq!(
            scaled.input_codec().encode_value(1, Unsigned),
            rounded.input_codec().encode_value(1, Unsigned),
        );
        let mvb = FactorizedLookupTable::try_new(
            domain,
            poly_length,
            2,
            scaled.input_codec(),
            scaled.lut_output_codec(),
            |_, _| value,
        )
        .unwrap();
        assert_eq!(mvb.input_domain_len(), domain);
        assert_eq!(mvb.output_plaintext_modulus(), output_t);
        let delta = (97 + output_t / 2) / output_t;
        assert_eq!(2 * mvb.common_polynomial().as_ref()[0] % 97, delta);
        assert_eq!(
            scaled.lut_output_codec().encode_value(value, Unsigned),
            value * delta
        );
        let returned_phase = (value * delta * 1024 + 97 / 2) / 97;
        assert_eq!(scaled.output_codec().decode_value(returned_phase), value);
    }
}

#[test]
fn codec_preparation_checks_input_and_both_output_domains() {
    use LookupTableError::{InputEncoding, OutputEncoding};

    let external = PowOf2Modulus::new(1024u32);
    let accumulator = BarrettModulus::new(41);
    for (messages, expected) in [
        (
            PbsMessageConfig::new(1),
            InputEncoding(CodecError::InvalidPlaintextModulus),
        ),
        (
            PbsMessageConfig::new(1024),
            InputEncoding(CodecError::CiphertextModulusTooSmall),
        ),
        (
            PbsMessageConfig::new(8).with_output_modulus(1),
            OutputEncoding(CodecError::InvalidPlaintextModulus),
        ),
        (
            PbsMessageConfig::new(64),
            OutputEncoding(CodecError::CiphertextModulusTooSmall),
        ),
    ] {
        assert_eq!(
            messages
                .try_rounded_codecs(external, accumulator)
                .unwrap_err(),
            expected
        );
        assert_eq!(
            messages
                .try_factorized_codecs(external, accumulator)
                .unwrap_err(),
            expected
        );
    }

    // Override before preparing: t_in may exceed Q when the chosen t_out fits.
    let messages = PbsMessageConfig::new(64).with_output_modulus(8);
    assert!(messages.try_rounded_codecs(external, accumulator).is_ok());
    assert!(
        messages
            .try_factorized_codecs(external, accumulator)
            .is_ok()
    );

    // Valid at Q does not imply valid at the return modulus q.
    let messages = PbsMessageConfig::new(8).with_output_modulus(32);
    assert_eq!(
        messages
            .try_rounded_codecs(PowOf2Modulus::new(32), accumulator)
            .unwrap_err(),
        OutputEncoding(CodecError::CiphertextModulusTooSmall),
    );
    assert!(messages.try_rounded_codecs(external, accumulator).is_ok());
    assert_eq!(
        messages
            .try_factorized_codecs(external, accumulator)
            .unwrap_err(),
        OutputEncoding(CodecError::InsufficientScaleRecovery),
    );
    assert_eq!(
        messages
            .try_factorized_codecs(accumulator, BarrettModulus::new(1153))
            .unwrap_err(),
        OutputEncoding(CodecError::InsufficientScaleRecovery),
    );
}
