use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GgswParameters, GlweParameters, GlweSecretKey, GlweSize, SecretKeyDistr};
use primus_lwe::{LweParameters, LwePublicKey, LweSecretKey};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_reduce::RingContext;
use primus_tfhe_glwe::{
    GlweClientError, GlweClientKey, GlweDecryptor, GlweEncryptor, GlweKeyError, GlwePbsOrder,
    GlweTfheParameters,
};
use rand::{Rng, SeedableRng, rngs::StdRng};

fn check<M: RingContext<u32>>(modulus: M) {
    for order in [
        GlwePbsOrder::BootstrapKeyswitch,
        GlwePbsOrder::KeyswitchBootstrap,
    ] {
        // Two different external dimensions and a signed ring secret including -1.
        let small = LweParameters::new(4, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
        let glwe = GlweParameters::new(2, 8, 4, modulus, SecretKeyDistr::UniformTernary, 0.7);
        let bsk = GgswParameters::with_glwe_params(&glwe, 8, None);
        let params = GlweTfheParameters::try_new(
            small.clone(),
            glwe,
            bsk,
            ApproxSignedBasis::new(modulus.explicit_value(), 8, None),
            order,
        )
        .unwrap();
        let client = GlweClientKey::new(
            LweSecretKey::new(vec![1, 0, 1, 1], SecretKeyDistr::UniformBinary),
            GlweSecretKey::new(
                vec![1, -1, 0, 1, 0, -1, 0, 1, 1, 0, -1, 0, 1, 0, 0, -1],
                GlweSize::new(2, 8),
                SecretKeyDistr::UniformTernary,
            ),
            order,
        );
        let mut rng = StdRng::seed_from_u64(0x474c_5745_504b);
        let public = client.try_generate_public_key(&params, &mut rng).unwrap();
        assert_eq!(
            public.dimension(),
            if order == GlwePbsOrder::BootstrapKeyswitch {
                4
            } else {
                16
            }
        );
        let encryptor = GlweEncryptor::try_new(&params, &public).unwrap();
        let decryptor = GlweDecryptor::try_new(&params, &client).unwrap();
        for message in 0..4u32 {
            for ciphertext in [
                encryptor.encrypt(message, &mut rng).unwrap(),
                encryptor.encrypt_centered(message, &mut rng).unwrap(),
            ] {
                assert_eq!(decryptor.decrypt::<u32>(&ciphertext).unwrap(), message);
            }
            if message < 2 {
                let input = encryptor.encrypt_padded(message, &mut rng).unwrap();
                assert_eq!(decryptor.decrypt::<u32>(&input).unwrap(), message);
            }
        }
        let seed = rng.next_u64();
        let mut rng = StdRng::seed_from_u64(seed);
        let mut expected_rng = StdRng::seed_from_u64(seed);
        assert_eq!(
            encryptor.encrypt(u64::MAX, &mut rng).unwrap_err(),
            GlweClientError::MessageConversion
        );
        assert_eq!(
            encryptor.encrypt(4u32, &mut rng).unwrap_err(),
            GlweClientError::MessageOutOfRange
        );
        assert_eq!(
            encryptor.encrypt_centered(4u32, &mut rng).unwrap_err(),
            GlweClientError::MessageOutOfRange
        );
        assert_eq!(
            encryptor.encrypt_padded(2u32, &mut rng).unwrap_err(),
            GlweClientError::MessageOutsidePaddedDomain
        );
        assert_eq!(rng.next_u64(), expected_rng.next_u64());

        // Public-key binding must reject same-word-size foreign moduli, not just dimensions.
        let foreign_params = LweParameters::new(
            public.dimension(),
            4,
            BarrettModulus::new(65_537u32),
            SecretKeyDistr::UniformBinary,
            0.7,
        );
        let foreign_secret = LweSecretKey::generate(&foreign_params, &mut rng);
        let foreign = LwePublicKey::generate(foreign_secret.as_view(), &foreign_params, &mut rng);
        assert_eq!(
            GlweEncryptor::try_new(&params, &foreign).err(),
            Some(GlweClientError::PublicKeyModulusMismatch)
        );
        let short_params = LweParameters::new(3, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
        let short_secret = LweSecretKey::generate(&short_params, &mut rng);
        let short = LwePublicKey::generate(short_secret.as_view(), &short_params, &mut rng);
        assert_eq!(
            GlweEncryptor::try_new(&params, &short).err(),
            Some(GlweClientError::PublicKeyDimensionMismatch {
                expected: public.dimension(),
                actual: 3,
            })
        );
        let wrong_order = if order == GlwePbsOrder::BootstrapKeyswitch {
            GlwePbsOrder::KeyswitchBootstrap
        } else {
            GlwePbsOrder::BootstrapKeyswitch
        };
        let (small_key, ring_key, _) = client.into_parts();
        let wrong_client = GlweClientKey::new(small_key, ring_key, wrong_order);
        let seed = rng.next_u64();
        let mut rng = StdRng::seed_from_u64(seed);
        let mut expected_rng = StdRng::seed_from_u64(seed);
        assert_eq!(
            wrong_client
                .try_generate_public_key(&params, &mut rng)
                .err(),
            Some(GlweKeyError::GlwePbsOrderMismatch {
                expected: order,
                actual: wrong_order,
            })
        );
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }
}

#[test]
fn both_external_domains_support_public_clients_and_reject_incompatible_keys() {
    check(NativeModulus::new());
    check(BarrettModulus::new(132_120_577));
}
