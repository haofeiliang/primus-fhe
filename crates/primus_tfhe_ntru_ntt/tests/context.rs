use primus_decompose::DecompositionBaseLog;
use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::RoundedCodec;
use primus_encoding::ScaledCodec;
use primus_lattice::LweDimension;
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntru::NlevParameters;
use primus_ntru::{NtruParameters, SecretKeyDistr};
use primus_ntt::{NttTable, U32NttTable};
use primus_poly::PolyLength;
use primus_tfhe_ntru_ntt::{TfheContext, TfheEvaluationError, TfheParameters};
use rand::{SeedableRng, rngs::StdRng};
use std::error::Error;

const POLY_LENGTH: usize = 32;
const LWE_DIMENSION: usize = 4;
const PLAIN_MODULUS: u32 = 4;
const CIPHER_MODULUS: u32 = 132_120_577;

fn parameters(
    cipher_modulus: u32,
    bootstrapping_log_basis: u32,
    key_switching_log_basis: u32,
) -> TfheParameters<u32> {
    let modulus = BarrettModulus::new(cipher_modulus);
    let external_lwe = LweParameters::new(
        LweDimension::new(LWE_DIMENSION),
        PLAIN_MODULUS,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let accumulator = NtruParameters::new(
        POLY_LENGTH,
        PLAIN_MODULUS,
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let blind_rotation_basis = ApproxSignedBasis::new(
        accumulator.cipher_modulus_value(),
        DecompositionBaseLog::new(bootstrapping_log_basis),
        None,
    );

    TfheParameters::try_new(
        external_lwe.into_inner(),
        NlevParameters::try_with_basis(&accumulator, blind_rotation_basis).unwrap(),
        primus_tfhe_ntru::DecompositionConfig {
            log_basis: DecompositionBaseLog::new(key_switching_log_basis),
            level_count: None,
        },
        0.7,
    )
    .unwrap()
}

#[test]
fn rejects_server_keys_with_same_layout_but_different_bases_or_modulus() {
    let original = parameters(CIPHER_MODULUS, 9, 9);
    let table = U32NttTable::new(
        PolyLength::new(POLY_LENGTH),
        original.accumulator_ntru().cipher_modulus(),
    )
    .unwrap();
    let context = TfheContext::try_new(original, table).unwrap();
    let input_codec = RoundedCodec::new(4, context.parameters().external_lwe().cipher_modulus());
    let mut rng = StdRng::seed_from_u64(0x4e54_5255_4241_5349);
    let (_, server_key) = context.try_generate_keys(None, &mut rng).unwrap();
    assert!(server_key.circuit_bootstrap_key().is_none());
    assert!(matches!(
        primus_tfhe_ntru_ntt::OneHotCircuitBootstrapEvaluator::try_new(
            &context,
            &server_key,
            &input_codec
        ),
        Err(primus_tfhe_ntru_ntt::OneHotBootstrapError::Evaluation(
            primus_tfhe_ntru_ntt::TfheEvaluationError::MissingCircuitBootstrapKey
        ))
    ));
    assert!(matches!(
        context.circuit_bootstrap_evaluator(&server_key, &input_codec),
        Err(primus_tfhe_ntru_ntt::TfheEvaluationError::MissingCircuitBootstrapKey)
    ));
    assert!(context.evaluator(&server_key).is_ok());

    // Both moduli have 27 bits; bases 2^8 and 2^9 both retain three levels.
    // Shape checks alone therefore accept all of these incompatible keys.
    for (cipher_modulus, bootstrapping_log_basis, key_switching_log_basis) in [
        (CIPHER_MODULUS, 8, 9),
        (CIPHER_MODULUS, 9, 8),
        (104_857_601, 9, 9),
    ] {
        let candidate = parameters(
            cipher_modulus,
            bootstrapping_log_basis,
            key_switching_log_basis,
        );
        assert_eq!(
            candidate.blind_rotation().nlev_len(),
            context.parameters().blind_rotation().nlev_len()
        );
        assert_eq!(
            candidate.key_switching_basis().decompose_length().get(),
            context
                .parameters()
                .key_switching_basis()
                .decompose_length()
                .get()
        );
        let table = U32NttTable::new(
            PolyLength::new(POLY_LENGTH),
            candidate.accumulator_ntru().cipher_modulus(),
        )
        .unwrap();
        let incompatible = TfheContext::try_new(candidate, table).unwrap();
        let input_codec =
            RoundedCodec::new(4, incompatible.parameters().external_lwe().cipher_modulus());
        let expected = if cipher_modulus != CIPHER_MODULUS || key_switching_log_basis != 9 {
            TfheEvaluationError::IncompatibleLweReturnKey
        } else {
            TfheEvaluationError::IncompatibleBlindRotationKey
        };
        assert_eq!(
            incompatible.evaluator(&server_key).err(),
            Some(expected.clone())
        );
        assert_eq!(
            incompatible
                .boolean_evaluator(&server_key, &input_codec)
                .err(),
            Some(expected.clone())
        );
        assert_eq!(
            incompatible.factorized_evaluator(&server_key).err(),
            Some(expected.clone())
        );
    }
}

#[test]
fn construction_errors_preserve_transform_sources() {
    use primus_ntru::{NtruError, NtruSecretKey};
    use primus_tfhe_ntru_ntt::{
        ClientKey, KeyGenerationError, KeyGenerator, TfheClientError, TfheContextError,
    };

    let error = TfheContext::<_, U32NttTable>::try_from_parameters(parameters(19, 2, 2))
        .err()
        .unwrap();
    assert!(matches!(&error, TfheContextError::TransformTable(_)));
    assert!(error.source().unwrap().is::<primus_ntt::NttError<u32>>());

    let context =
        TfheContext::<_, U32NttTable>::try_from_parameters(parameters(CIPHER_MODULUS, 9, 9))
            .unwrap();
    let input_codec = RoundedCodec::new(4, context.parameters().external_lwe().cipher_modulus());
    // Compatible shape/distributions do not imply an invertible secret.
    let client = ClientKey::new(
        primus_lwe::LweSecretKey::new(
            (vec![0; POLY_LENGTH])[..LWE_DIMENSION]
                .iter()
                .map(|&s| {
                    if s < Default::default() {
                        context
                            .parameters()
                            .external_lwe()
                            .cipher_modulus_minus_one()
                    } else {
                        primus_integer::SignedInteger::cast_to_unsigned(s)
                    }
                })
                .collect(),
            SecretKeyDistr::UniformBinary,
            context.parameters().external_lwe().cipher_modulus(),
        ),
        NtruSecretKey::new(vec![0; POLY_LENGTH], SecretKeyDistr::SparseTernary),
    );
    assert_eq!(
        context
            .accumulator_client(
                client.accumulator_ntru_secret_key(),
                ScaledCodec::new(
                    input_codec.plaintext_modulus(),
                    context.parameters().accumulator_ntru().cipher_modulus()
                )
            )
            .err(),
        Some(TfheClientError::Ntru(NtruError::NonInvertibleSecretKey))
    );
    let error = KeyGenerator::new(&context)
        .try_generate_server_key(&client, None, &mut StdRng::seed_from_u64(42))
        .err()
        .unwrap();
    assert_eq!(
        error,
        KeyGenerationError::Ntru(NtruError::NonInvertibleSecretKey)
    );
    assert_eq!(
        error.source().unwrap().downcast_ref::<NtruError>(),
        Some(&NtruError::NonInvertibleSecretKey)
    );
}
