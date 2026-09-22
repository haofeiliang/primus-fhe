use primus_encoding::RoundedCodec;
use primus_modulus::NativeModulus;

#[test]
fn padded_inputs_and_lut_output_codecs_use_independent_domains() {
    use primus_decompose::primitive::ApproxSignedBasis;
    use primus_glwe::{GlweParameters, GlweSecretKey, GlweSize, SecretKeyDistr};
    use primus_lwe::{LweParameters, LweSecretKey};
    use primus_tfhe_glwe::{ClientError, ClientKey, PbsOrder, TfheParameters};
    use rand::{SeedableRng, rngs::StdRng};

    let mut rng = StdRng::seed_from_u64(0x5041_4444_4544);
    for t in [3u32, 4, 5] {
        let modulus = NativeModulus::new();
        let lwe = LweParameters::new(4, t, modulus, SecretKeyDistr::UniformBinary, 0.7);
        let glwe = GlweParameters::new(1, 8, t, modulus, SecretKeyDistr::UniformBinary, 0.7);
        let bsk = ApproxSignedBasis::new(glwe.cipher_modulus_value(), 8, None);
        let parameters = TfheParameters::try_new(
            lwe,
            glwe,
            bsk,
            ApproxSignedBasis::new(None, 8, None),
            PbsOrder::BootstrapKeyswitch,
        )
        .unwrap();
        let key = ClientKey::new(
            LweSecretKey::new(vec![1, 0, 1, 1], SecretKeyDistr::UniformBinary),
            GlweSecretKey::new(
                vec![1; 8],
                GlweSize::new(1, 8),
                SecretKeyDistr::UniformBinary,
            ),
            PbsOrder::BootstrapKeyswitch,
        );
        let encryptor = parameters.encryptor(&key).unwrap();
        let decryptor = parameters.decryptor(&key).unwrap();
        let domain_len = t.div_ceil(2);
        let default = parameters
            .compile_lookup_table_slice(&vec![t - 1; domain_len as usize])
            .unwrap();
        assert_eq!(
            parameters
                .input_plaintext_codec()
                .decode_value(default.polynomial().as_ref()[0]),
            t - 1,
        );
        let input = encryptor.encrypt_padded(domain_len - 1, &mut rng).unwrap();
        assert_eq!(decryptor.decrypt(&input).unwrap(), domain_len - 1);
        assert_eq!(
            encryptor.encrypt_padded(domain_len, &mut rng).unwrap_err(),
            ClientError::MessageOutsidePaddedDomain
        );
        let output_codec = RoundedCodec::new(8, NativeModulus::new());
        let values: Vec<_> = (0..domain_len).map(|m| 7 - m).collect();
        let single = parameters
            .compile_lookup_table_with_codec_slice(&output_codec, &values)
            .unwrap();
        let many = parameters
            .compile_interleaved_lookup_table_with_codec_fn(&output_codec, 1, |m, _| values[m])
            .unwrap();
        assert_eq!(single.input_domain_len(), domain_len as usize);
        assert_eq!(single.polynomial(), many.polynomial());
        assert_eq!(single.polynomial().as_ref()[0], 7u32 << 29);
        if t % 2 == 1 {
            let values: Vec<_> = (0..t).collect();
            let full = parameters
                .compile_odd_full_domain_lookup_table_with_codec_slice(&output_codec, &values)
                .unwrap();
            assert_eq!(full.input_domain_len(), t as usize);
        }
    }
}
