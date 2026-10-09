use primus_decompose::DecompositionBaseLog;
use primus_lattice::{GlweDimension, LweDimension};
use primus_modulus::NativeModulus;
use primus_poly::PolyLength;
use primus_tfhe::PbsMessageConfig;

#[test]
fn padded_inputs_and_lut_output_codecs_use_independent_domains() {
    use primus_glwe::{GlweSecretKey, GlweSize, SecretKeyDistr};
    use primus_lwe::LweSecretKey;
    use primus_tfhe_glwe::{
        ClientError, ClientKey, GadgetEncryptionConfig, PbsOrder, PbsParameters,
    };
    use rand::{SeedableRng, rngs::StdRng};

    let mut rng = StdRng::seed_from_u64(0x5041_4444_4544);
    for t in [3u32, 4, 5] {
        let modulus = NativeModulus::new();
        let parameters = PbsParameters::try_from_config(primus_tfhe_glwe::PbsConfig {
            small_lwe: primus_tfhe::LweConfig {
                dimension: LweDimension::new(4),
                cipher_modulus: modulus.into(),
                secret_key_distr: SecretKeyDistr::UniformBinary,
                noise_standard_deviation: 0.7,
            },
            bsk_dimension: GlweDimension::new(1),
            bsk_poly_length: PolyLength::new(32),
            bsk_secret_distr: SecretKeyDistr::UniformBinary,
            bsk_gadget: GadgetEncryptionConfig {
                decomposition: primus_tfhe::DecompositionConfig {
                    log_basis: DecompositionBaseLog::new(8),
                    level_count: None,
                },
                noise_standard_deviation: 0.7,
            },
            key_switching: GadgetEncryptionConfig {
                decomposition: primus_tfhe::DecompositionConfig {
                    log_basis: DecompositionBaseLog::new(8),
                    level_count: None,
                },
                noise_standard_deviation: 0.7,
            },
            method: primus_tfhe::BlindRotationMethod::Classic,
            messages: primus_tfhe::PbsMessageConfig::new(4),
            order: PbsOrder::BootstrapKeyswitch,
        })
        .unwrap();
        let key = ClientKey::new(
            LweSecretKey::new(vec![1, 0, 1, 1], SecretKeyDistr::UniformBinary, modulus),
            GlweSecretKey::new(
                vec![1; 32],
                GlweSize::new(GlweDimension::new(1), PolyLength::new(32)),
                SecretKeyDistr::UniformBinary,
            ),
            PbsOrder::BootstrapKeyswitch,
        );
        let codecs = parameters
            .as_ref()
            .pbs_codecs(PbsMessageConfig::new(t))
            .unwrap();
        let codec = codecs.input_codec();
        let encryptor = parameters
            .as_ref()
            .encryptor_with_codec(key.external_lwe_secret_key(), codec)
            .unwrap();
        let decryptor = parameters
            .as_ref()
            .decryptor_with_codec(key.external_lwe_secret_key(), codec)
            .unwrap();
        let domain_len = t.div_ceil(2);
        let default = parameters
            .as_ref()
            .lookup_table_compiler(&codecs)
            .unwrap()
            .compile_slice(&vec![t - 1; domain_len as usize])
            .unwrap();
        assert_eq!(codec.decode_value(default.polynomial().as_ref()[0]), t - 1,);
        let input = encryptor.encrypt_padded(domain_len - 1, &mut rng).unwrap();
        assert_eq!(decryptor.decrypt(input.as_view()).unwrap(), domain_len - 1);
        assert_eq!(
            encryptor.encrypt_padded(domain_len, &mut rng).unwrap_err(),
            ClientError::MessageOutsidePaddedDomain
        );
        let codecs = parameters
            .as_ref()
            .pbs_codecs(PbsMessageConfig::new(t).with_output_modulus(8))
            .unwrap();
        let compiler = parameters.as_ref().lookup_table_compiler(&codecs).unwrap();
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
