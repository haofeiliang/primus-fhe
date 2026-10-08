use primus_decompose::DecompositionBaseLog;
use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::RoundedCodec;
use primus_lwe::LweDimension;
use primus_lwe::LweEncryptionParameters;
use primus_modulus::NativeModulus;
use primus_ntru::NlevParameters;
use primus_ntru::{NtruParameters, NtruSecretKey, SecretKeyDistr};
use primus_poly::PolyLength;
use primus_tfhe::PbsMessageConfig;
use primus_tfhe_ntru::{ClientError, ClientKey, GadgetEncryptionConfig, TfheParameters};

const N: usize = 32;
const LWE_DIMENSION: usize = 4;

fn parameters_with_plaintext(t: u32) -> TfheParameters<u32, NativeModulus<u32>> {
    let modulus = NativeModulus::new();

    let accumulator = NtruParameters::new(
        PolyLength::new(N),
        t,
        modulus,
        SecretKeyDistr::gaussian(3.2),
        0.7,
    );
    let blind_rotation_basis = ApproxSignedBasis::new(
        accumulator.cipher_modulus_value(),
        DecompositionBaseLog::new(8),
        None,
    );
    TfheParameters::try_new(
        LweEncryptionParameters::new(
            LweDimension::new(LWE_DIMENSION),
            modulus,
            SecretKeyDistr::UniformBinary,
            0.7,
        ),
        NlevParameters::try_with_basis(&accumulator, blind_rotation_basis).unwrap(),
        GadgetEncryptionConfig {
            decomposition: primus_tfhe_ntru::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: None,
            },
            noise_standard_deviation: 0.7,
        },
    )
    .unwrap()
}

fn imported_key(
    client: [i32; LWE_DIMENSION],
    modulus: impl primus_reduce::Modulus<ValueT = u32>,
) -> ClientKey<u32> {
    // General NTRU secrets and the accumulator retain nonbinary coefficients.
    let mut accumulator = vec![0; N];
    accumulator[..2].copy_from_slice(&[2, 1]);
    let accumulator = NtruSecretKey::new(accumulator, SecretKeyDistr::gaussian(3.2));
    ClientKey::new(
        primus_lwe::LweSecretKey::new(
            client
                .iter()
                .map(|&s| primus_integer::SignedInteger::cast_to_unsigned(s))
                .collect(),
            SecretKeyDistr::UniformBinary,
            modulus,
        ),
        accumulator,
    )
}

#[test]
fn padded_inputs_and_lut_output_codecs_use_independent_domains() {
    use rand::{SeedableRng, rngs::StdRng};
    let mut rng = StdRng::seed_from_u64(0x5041_4444_4544);
    let key = imported_key([1, 0, 1, 1], NativeModulus::new());
    for t in [3u32, 4, 5] {
        let parameters = parameters_with_plaintext(t);
        let codecs = parameters.pbs_codecs(PbsMessageConfig::new(t)).unwrap();
        let input_codec = codecs.input_codec();
        let encryptor = parameters
            .encryptor(key.external_lwe_secret_key(), input_codec)
            .unwrap();
        let decryptor = parameters
            .decryptor(key.external_lwe_secret_key(), input_codec)
            .unwrap();
        let domain_len = t.div_ceil(2);
        let default = parameters
            .lookup_table_compiler(&codecs)
            .unwrap()
            .compile_slice(&vec![t - 1; domain_len as usize])
            .unwrap();
        assert_eq!(
            input_codec.decode_value(default.polynomial().as_ref()[0]),
            t - 1,
        );
        let input = encryptor.encrypt_padded(domain_len - 1, &mut rng).unwrap();
        assert_eq!(decryptor.decrypt(input.as_view()).unwrap(), domain_len - 1);
        assert_eq!(
            encryptor.encrypt_padded(domain_len, &mut rng).unwrap_err(),
            ClientError::MessageOutsidePaddedDomain
        );
        let codecs = parameters
            .pbs_codecs(PbsMessageConfig::new(t).with_output_modulus(8))
            .unwrap();
        let compiler = parameters.lookup_table_compiler(&codecs).unwrap();
        let values: Vec<_> = (0..domain_len).map(|m| 7 - m).collect();
        let single = compiler.compile_slice(&values).unwrap();
        let many = compiler
            .compile_interleaved_fn(1, |m, _| values[m])
            .unwrap();
        assert_eq!(single.input_domain_len(), domain_len as usize);
        assert_eq!(single.polynomial(), many.polynomial());
        assert_eq!(single.polynomial().as_ref()[0], 7u32 << 29);
        if t % 2 == 1 {
            let values: Vec<_> = (0..t).collect();
            let full = compiler.compile_odd_full_domain_slice(&values).unwrap();
            assert_eq!(full.input_domain_len(), t as usize);
        }
    }
}

// q and Q are independent: codec validity at q does not imply validity at Q.
#[test]
fn codec_binding_checks_domains_without_preparing_an_unused_default() {
    use primus_modulus::BarrettModulus;
    use primus_tfhe_ntru::{DecompositionConfig, LookupTableError, TfheClientError, TfheConfig};
    let basis = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(2),
        level_count: None,
    };
    let parameters = TfheParameters::try_from_config(TfheConfig {
        external_lwe: LweEncryptionParameters::new(
            LweDimension::new(LWE_DIMENSION),
            BarrettModulus::new(257),
            SecretKeyDistr::UniformBinary,
            0.7,
        ),
        accumulator_modulus: BarrettModulus::new(41),
        poly_length: PolyLength::new(N),
        accumulator_secret_key_distr: SecretKeyDistr::gaussian(3.2),
        blind_rotation: GadgetEncryptionConfig {
            decomposition: basis,
            noise_standard_deviation: 0.7,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: basis,
            noise_standard_deviation: 0.7,
        },
    })
    .unwrap();
    let key = imported_key([1, 0, 1, 1], parameters.external_lwe().cipher_modulus());
    let foreign = RoundedCodec::new(4, BarrettModulus::new(129));
    assert!(matches!(
        parameters.encryptor(key.external_lwe_secret_key(), &foreign),
        Err(TfheClientError::Client(ClientError::CodecModulusMismatch))
    ));
    assert!(matches!(
        parameters.decryptor(key.external_lwe_secret_key(), &foreign),
        Err(TfheClientError::Client(ClientError::CodecModulusMismatch))
    ));
    let foreign_codecs = PbsMessageConfig::new(4)
        .try_rounded_codecs(
            foreign.ciphertext_modulus(),
            parameters.accumulator_ntru().cipher_modulus(),
        )
        .unwrap();
    assert!(matches!(
        parameters.lookup_table_compiler(&foreign_codecs),
        Err(LookupTableError::InputModulusMismatch)
    ));
    assert!(matches!(
        parameters.pbs_codecs(PbsMessageConfig::new(64)),
        Err(LookupTableError::OutputEncoding(_))
    ));
    // t_in=64 is valid at q=257 but cannot encode an unused default at Q=41.
    // A selected t_out=8 must compile, without shrinking the input to four values.
    for messages in [
        PbsMessageConfig::new(8u32),
        PbsMessageConfig::new(64).with_output_modulus(8),
    ] {
        let domain = messages.input_modulus.div_ceil(2) as usize;
        let codecs = parameters.pbs_codecs(messages).unwrap();
        let compiler = parameters.lookup_table_compiler(&codecs).unwrap();
        let single = compiler.compile_fn(|_| 7).unwrap();
        let many = compiler.compile_interleaved_fn(1, |_, _| 7).unwrap();
        assert_eq!(single.input_domain_len(), domain);
        assert_eq!(many.input_domain_len(), domain);
        assert_eq!(single.polynomial(), many.polynomial());
        assert_eq!(single.polynomial().as_ref()[0], 36); // round(7*41/8), at Q.
        assert_eq!(codecs.output_codec().ciphertext_modulus().value(), 257);
        assert!(matches!(
            compiler.compile_fn(|_| 8),
            Err(LookupTableError::OutputOutOfRange { input: 0 })
        ));
        assert!(matches!(
            compiler.compile_interleaved_fn(1, |_, _| 8),
            Err(LookupTableError::OutputOutOfRange { input: 0 })
        ));

        let codecs = parameters.factorized_pbs_codecs(messages).unwrap();
        let factorized = parameters
            .compile_factorized_lookup_table_fn(&codecs, domain, 3, |_, _| 7)
            .unwrap();
        assert_eq!(factorized.input_domain_len(), domain);
        assert_eq!(factorized.output_plaintext_modulus(), 8);
        assert_eq!(factorized.output_count(), 3);
        assert!(
            factorized
                .common_polynomial()
                .as_ref()
                .iter()
                .all(|&x| x == 23)
        ); // 5/2 mod 41.
        assert!(matches!(
            parameters.compile_factorized_lookup_table_fn(&codecs, domain, 1, |_, _| 8),
            Err(LookupTableError::OutputOutOfRange { input: 0 })
        ));
    }

    // Check both ciphertext roles before evaluating user callbacks.
    for (input_q, output_q, expected) in [
        (129, 41, LookupTableError::InputModulusMismatch),
        (257, 97, LookupTableError::OutputModulusMismatch),
    ] {
        let input_modulus = BarrettModulus::new(input_q);
        let output_modulus = BarrettModulus::new(output_q);
        let rounded = PbsMessageConfig::new(8)
            .try_rounded_codecs(input_modulus, output_modulus)
            .unwrap();
        assert_eq!(
            parameters.lookup_table_compiler(&rounded).unwrap_err(),
            expected
        );
        let factorized = PbsMessageConfig::new(8)
            .try_factorized_codecs(input_modulus, output_modulus)
            .unwrap();
        assert_eq!(
            parameters
                .compile_factorized_lookup_table_fn(&factorized, 4, 1, |_, _| panic!(
                    "mismatched domains must reject before callback"
                ))
                .unwrap_err(),
            expected
        );
    }
}

// CBS candidates stay at Q: they do not pass through the ordinary LWE return.
#[test]
fn cbs_ring_messages_do_not_require_a_return_codec() {
    use primus_encoding::{CodecError, PlaintextEmbedding, ScaledCodec};
    use primus_modulus::BarrettModulus;
    use primus_tfhe_ntru::{DecompositionConfig, LookupTableError, TfheConfig};

    let gadget = GadgetEncryptionConfig {
        decomposition: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(2),
            level_count: None,
        },
        noise_standard_deviation: 0.7,
    };
    let parameters = TfheParameters::try_from_config(TfheConfig {
        external_lwe: LweEncryptionParameters::new(
            LweDimension::new(LWE_DIMENSION),
            BarrettModulus::new(17u32),
            SecretKeyDistr::UniformBinary,
            0.7,
        ),
        accumulator_modulus: BarrettModulus::new(97),
        poly_length: PolyLength::new(N),
        accumulator_secret_key_distr: SecretKeyDistr::UniformBinary,
        blind_rotation: gadget,
        key_switching: gadget,
    })
    .unwrap();

    // At t=12, q=17 satisfies the domain but fails fixed-scale recovery;
    // t=24 exceeds q altogether. Both candidate spaces are valid at Q=97.
    for (ring_t, return_error) in [
        (12, CodecError::InsufficientScaleRecovery),
        (24, CodecError::CiphertextModulusTooSmall),
    ] {
        assert_eq!(
            ScaledCodec::try_new(ring_t, parameters.external_lwe().cipher_modulus()).unwrap_err(),
            return_error
        );
        let (input, ring) = parameters.circuit_bootstrap_codecs(4, ring_t).unwrap();
        assert_eq!(input.ciphertext_modulus().value(), 17);
        assert_eq!(input.plaintext_modulus(), 4);
        assert_eq!(ring.ciphertext_modulus().value(), 97);
        assert_eq!(ring.plaintext_modulus(), ring_t);
        for message in 0..ring_t {
            let encoded = ring.encode_value(message, PlaintextEmbedding::Unsigned);
            assert_eq!(ring.decode_value(encoded), message);
        }
    }

    // Reject errors in either actual codec role, including Q scale recovery.
    assert!(matches!(
        parameters.circuit_bootstrap_codecs(0, 12),
        Err(LookupTableError::InputEncoding(_))
    ));
    for ring_t in [1, 97] {
        assert!(matches!(
            parameters.circuit_bootstrap_codecs(4, ring_t),
            Err(LookupTableError::OutputEncoding(_))
        ));
    }
    assert!(matches!(
        parameters.circuit_bootstrap_codecs(4, 40),
        Err(LookupTableError::OutputEncoding(
            CodecError::InsufficientScaleRecovery
        ))
    ));
}
