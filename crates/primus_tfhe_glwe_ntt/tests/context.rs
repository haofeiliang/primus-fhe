//! Context/table and decomposition binding, plus independently created
//! client/server keys in both GLWE PBS orders.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_glwe::{
    GlevParameters, GlweEncryptionParameters, GlweParameters, NttGlweGadgetEncryptWorkspace,
    NttGlweKeySwitchingKey, NttGlweSecretKey, SecretKeyDistr,
};
use primus_lattice::{GlweDimension, LweDimension};
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable};
use primus_poly::PolyLength;
use primus_tfhe::{BlindRotationConfig, PbsMessageConfig};
use primus_tfhe_glwe_ntt::{
    ClientKey, GadgetEncryptionConfig, KeyGenerator, PbsOrder, TfheContext, TfheContextError,
    TfheEvaluationError, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

const POLY_LENGTH: usize = 32;
const MODULUS: u32 = 132_120_577;
// Distinct from BR and fresh LWE sigma=0.7 to expose accidental role coupling.
const KS_SIGMA: f64 = 1.25;

fn parameters(order: PbsOrder) -> TfheParameters<u32> {
    parameters_with_bases(order, 8, 4, SecretKeyDistr::UniformBinary)
}

fn parameters_with_bases(
    order: PbsOrder,
    bootstrapping_log_basis: u32,
    key_switching_log_basis: u32,
    distribution: SecretKeyDistr,
) -> TfheParameters<u32> {
    let modulus = BarrettModulus::new(MODULUS);
    let lwe = LweParameters::new(LweDimension::new(4), 4, modulus, distribution, 0.7);
    let glwe = GlweParameters::new(
        GlweDimension::new(1),
        PolyLength::new(POLY_LENGTH),
        4,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let bootstrapping = ApproxSignedBasis::new(
        glwe.cipher_modulus_value(),
        DecompositionBaseLog::new(bootstrapping_log_basis),
        Some(DecompositionLevelCount::new(3)),
    );
    TfheParameters::try_new(
        lwe.into_encryption_parameters(),
        primus_glwe::GgswParameters::try_with_basis(&glwe, bootstrapping).unwrap(),
        GadgetEncryptionConfig {
            decomposition: ApproxSignedBasis::new(
                Some(MODULUS),
                DecompositionBaseLog::new(key_switching_log_basis),
                Some(DecompositionLevelCount::new(4)),
            ),
            noise_standard_deviation: KS_SIGMA,
        },
        order,
    )
    .unwrap()
}

#[test]
fn server_keys_are_bound_to_their_decomposition_bases() {
    let modulus = BarrettModulus::new(MODULUS);
    let source_table = U32NttTable::new(PolyLength::new(POLY_LENGTH), modulus).unwrap();
    let source =
        TfheContext::try_new(parameters(PbsOrder::BootstrapKeyswitch), source_table).unwrap();
    let mut rng = StdRng::seed_from_u64(0x4241_5349_534b_4559);
    let (_, server_key) = source
        .try_generate_keys(BlindRotationConfig::Classic, None, &mut rng)
        .unwrap();
    assert!(server_key.circuit_bootstrap_key().is_none());

    for (br_log, ks_log, distribution, expected) in [
        (
            7,
            4,
            SecretKeyDistr::UniformBinary,
            TfheEvaluationError::IncompatibleBlindRotationKey,
        ),
        (
            8,
            5,
            SecretKeyDistr::UniformBinary,
            TfheEvaluationError::IncompatibleGlweKeySwitchingKey,
        ),
        (
            8,
            4,
            SecretKeyDistr::UniformTernary,
            TfheEvaluationError::IncompatibleBlindRotationKey,
        ),
    ] {
        let parameters =
            parameters_with_bases(PbsOrder::BootstrapKeyswitch, br_log, ks_log, distribution);
        let table = U32NttTable::new(PolyLength::new(POLY_LENGTH), modulus).unwrap();
        let context = TfheContext::try_new(parameters, table).unwrap();
        assert_eq!(context.evaluator(&server_key).err().unwrap(), expected);
    }
}

#[test]
fn rejects_incompatible_ntt_tables() {
    let modulus = BarrettModulus::new(MODULUS);
    let wrong_length = U32NttTable::new(PolyLength::new(POLY_LENGTH * 2), modulus).unwrap();
    let error = TfheContext::try_new(parameters(PbsOrder::BootstrapKeyswitch), wrong_length)
        .err()
        .expect("the length mismatch must be rejected");
    assert!(matches!(error,
        TfheContextError::PolynomialLengthMismatch { expected: POLY_LENGTH, actual }
        if actual == POLY_LENGTH * 2
    ));

    const OTHER_MODULUS: u32 = 998_244_353;
    let wrong_modulus = U32NttTable::new(
        PolyLength::new(POLY_LENGTH),
        BarrettModulus::new(OTHER_MODULUS),
    )
    .unwrap();
    let error = TfheContext::try_new(parameters(PbsOrder::BootstrapKeyswitch), wrong_modulus)
        .err()
        .expect("the modulus mismatch must be rejected");
    assert!(matches!(
        error,
        TfheContextError::ModulusMismatch {
            expected: MODULUS,
            actual: OTHER_MODULUS
        }
    ));
}

#[test]
fn split_keys_support_both_pbs_orders() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let modulus = BarrettModulus::new(MODULUS);
        let table = U32NttTable::new(PolyLength::new(POLY_LENGTH), modulus).unwrap();
        let context = TfheContext::try_new(
            parameters_with_bases(
                order,
                8,
                4,
                SecretKeyDistr::fixed_composition_ternary(4, 1, 1),
            ),
            table,
        )
        .unwrap();
        let input_codec =
            primus_encoding::RoundedCodec::new(4, context.parameters().cipher_modulus());
        let mut rng = StdRng::seed_from_u64(43);
        // Fresh key generation is covered by the PBS and Boolean tests.
        let mut generator = KeyGenerator::new(&context);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        let blind_rotation = generator
            .try_generate_blind_rotation_key(
                &client,
                primus_tfhe_glwe_ntt::BlindRotationConfig::Classic,
                &mut rng,
            )
            .unwrap();
        let mut key_rng = StdRng::seed_from_u64(44);
        let mut reference_rng = StdRng::seed_from_u64(44);
        let key_switching = generator
            .try_generate_glwe_key_switching_key(&client, &mut key_rng)
            .unwrap();
        check_key_switching_noise(&context, &client, &key_switching, &mut reference_rng);
        let server = primus_tfhe_glwe_ntt::ServerKey::new(blind_rotation, key_switching, None);
        let codecs = context
            .parameters()
            .pbs_codecs(PbsMessageConfig::new(input_codec.plaintext_modulus()))
            .unwrap();
        let lookup_table = context
            .parameters()
            .lookup_table_compiler(&codecs)
            .unwrap()
            .compile_slice(&[1u32, 0])
            .unwrap();
        let public = context
            .parameters()
            .try_generate_public_key(client.external_lwe_secret_key(), &mut rng)
            .unwrap();
        let secret_encryptor = context
            .encryptor(client.external_lwe_secret_key(), &input_codec)
            .unwrap();
        let public_encryptor = context.public_encryptor(&public, &input_codec).unwrap();
        let decryptor = context
            .decryptor(client.external_lwe_secret_key(), &input_codec)
            .unwrap();
        let mut evaluator = context.evaluator(&server).unwrap();
        for message in 0..2u32 {
            for input in [
                secret_encryptor.encrypt_padded(message, &mut rng).unwrap(),
                public_encryptor.encrypt_padded(message, &mut rng).unwrap(),
            ] {
                let output = evaluator.apply_lookup_table(input.as_view(), &lookup_table);
                assert_eq!(decryptor.decrypt(output.as_view()).unwrap(), 1 - message);
            }
        }
        let boolean_encryptor = context
            .boolean_public_encryptor(&public, &input_codec)
            .unwrap();
        let boolean_decryptor = context
            .boolean_decryptor(client.external_lwe_secret_key(), &input_codec)
            .unwrap();
        let mut boolean_evaluator = context.boolean_evaluator(&server, &input_codec).unwrap();
        let lhs = boolean_encryptor.encrypt(true, &mut rng).unwrap();
        let rhs = boolean_encryptor.encrypt(false, &mut rng).unwrap();
        assert!(
            boolean_decryptor
                .decrypt(
                    boolean_evaluator
                        .xor(lhs.as_view(), rhs.as_view())
                        .as_view()
                )
                .unwrap()
        );
    }
}

/// Rebuilds KS rows with an independently specified sampler and the same coins.
/// Exact key equality detects using BR/fresh-LWE noise even when PBS still decodes.
fn check_key_switching_noise(
    context: &TfheContext<u32, U32NttTable>,
    client: &ClientKey<u32>,
    actual: &NttGlweKeySwitchingKey<u32>,
    rng: &mut StdRng,
) {
    let output = context.parameters().glwe_key_switching().output();
    let expected_parameters = GlevParameters::try_from_parts(
        output.glwe_size(),
        Arc::new(GlweEncryptionParameters::new(
            context.parameters().cipher_modulus(),
            output.secret_key_distr(),
            KS_SIGMA,
        )),
        output.basis().clone(),
    )
    .unwrap();
    let secret = client.padded_small_glwe_secret_key(context.parameters());
    let secret = NttGlweSecretKey::from_coeff_secret_key(&secret, context.table());
    let mut workspace = NttGlweGadgetEncryptWorkspace::new(expected_parameters.size());
    let expected = NttGlweKeySwitchingKey::generate(
        client.glwe_secret_key(),
        &secret,
        &expected_parameters,
        context.table(),
        rng,
        &mut workspace,
    );
    assert_eq!(actual.as_slice(), expected.as_slice());
}
