use primus_decompose::DecompositionBaseLog;
use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::RoundedCodec;
use primus_lwe::LweDimension;
use primus_lwe::LweEncryptionParameters;
use primus_modulus::NativeModulus;
use primus_ntru::NlevParameters;
use primus_ntru::{NtruParameters, NtruSecretKey, SecretKeyDistr};
use primus_poly::PolyLength;
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
        let input_codec = RoundedCodec::new(t, NativeModulus::new());
        let encryptor = parameters
            .encryptor(key.external_lwe_secret_key(), &input_codec)
            .unwrap();
        let decryptor = parameters
            .decryptor(key.external_lwe_secret_key(), &input_codec)
            .unwrap();
        let domain_len = t.div_ceil(2);
        let default = parameters
            .lookup_table_compiler(&input_codec)
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
        let output_codec = RoundedCodec::new(8, NativeModulus::new());
        let compiler = parameters
            .lookup_table_compiler(&input_codec)
            .unwrap()
            .try_with_output_codec(&output_codec)
            .unwrap();
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
fn codec_binding_checks_input_q_and_default_output_encoding() {
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
        accumulator_noise_standard_deviation: 0.7,
        blind_rotation: basis,
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
    assert!(matches!(
        parameters.lookup_table_compiler(&foreign),
        Err(LookupTableError::InputModulusMismatch)
    ));
    let too_large_for_q_ring = RoundedCodec::new(64, BarrettModulus::new(257));
    assert!(matches!(
        parameters.lookup_table_compiler(&too_large_for_q_ring),
        Err(LookupTableError::OutputEncoding(_))
    ));
}
