use primus_decompose::DecompositionBaseLog;
use primus_encoding::RoundedCodec;
use primus_lattice::{GlweDimension, LweDimension};
use primus_modulus::NativeModulus;
use primus_poly::PolyLength;

#[test]
fn padded_inputs_and_lut_output_codecs_use_independent_domains() {
    use primus_decompose::primitive::ApproxSignedBasis;
    use primus_glwe::{GlweParameters, GlweSecretKey, GlweSize, SecretKeyDistr};
    use primus_lwe::{LweParameters, LweSecretKey};
    use primus_tfhe_glwe::{
        ClientError, ClientKey, GadgetEncryptionConfig, PbsOrder, TfheParameters,
    };
    use rand::{SeedableRng, rngs::StdRng};

    let mut rng = StdRng::seed_from_u64(0x5041_4444_4544);
    for t in [3u32, 4, 5] {
        let modulus = NativeModulus::new();
        let codec = RoundedCodec::new(t, modulus);
        let lwe = LweParameters::new(
            LweDimension::new(4),
            t,
            modulus,
            SecretKeyDistr::UniformBinary,
            0.7,
        );
        let glwe = GlweParameters::new(
            GlweDimension::new(1),
            PolyLength::new(32),
            t,
            modulus,
            SecretKeyDistr::UniformBinary,
            0.7,
        );
        let bsk = ApproxSignedBasis::new(
            glwe.cipher_modulus_value(),
            DecompositionBaseLog::new(8),
            None,
        );
        let parameters = TfheParameters::try_new(
            lwe.into_encryption_parameters(),
            primus_glwe::GgswParameters::try_with_basis(&glwe, bsk).unwrap(),
            GadgetEncryptionConfig {
                decomposition: ApproxSignedBasis::new(None, DecompositionBaseLog::new(8), None),
                noise_standard_deviation: glwe.noise_distribution().standard_deviation(),
            },
            PbsOrder::BootstrapKeyswitch,
        )
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
        let encryptor = parameters
            .encryptor(key.external_lwe_secret_key(), &codec)
            .unwrap();
        let decryptor = parameters
            .decryptor(key.external_lwe_secret_key(), &codec)
            .unwrap();
        let domain_len = t.div_ceil(2);
        let default = parameters
            .lookup_table_compiler(&codec)
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
        let output_codec = RoundedCodec::new(8, NativeModulus::new());
        let compiler = parameters
            .lookup_table_compiler(&codec)
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
