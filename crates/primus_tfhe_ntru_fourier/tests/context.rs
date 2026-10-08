use primus_decompose::primitive::ApproxSignedBasis;
use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_encoding::RoundedCodec;
use primus_fft::{FftTable, RustFftTable};
use primus_lattice::LweDimension;
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_ntru::NlevParameters;
use primus_ntru::{NtruParameters, SecretKeyDistr};
use primus_poly::PolyLength;
use primus_tfhe::BlindRotationAlgorithm;
use primus_tfhe_ntru_fourier::{
    GadgetEncryptionConfig, PbsParameters, TfheContext, TfheEvaluationError,
};
use rand::{SeedableRng, rngs::StdRng};

const POLY_LENGTH: usize = 32;
const LWE_DIMENSION: usize = 4;
const PLAIN_MODULUS: u32 = 4;

fn parameters(bootstrapping_log_basis: u32, key_switching_log_basis: u32) -> PbsParameters<u32> {
    let modulus = NativeModulus::new();
    let external_lwe = LweParameters::new(
        LweDimension::new(LWE_DIMENSION),
        PLAIN_MODULUS,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let accumulator = NtruParameters::new(
        PolyLength::new(POLY_LENGTH),
        PLAIN_MODULUS,
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let blind_rotation_basis = ApproxSignedBasis::new(
        accumulator.cipher_modulus_value(),
        DecompositionBaseLog::new(bootstrapping_log_basis),
        Some(DecompositionLevelCount::new(4)),
    );

    PbsParameters::try_new(
        external_lwe.into_encryption_parameters(),
        NlevParameters::try_with_basis(&accumulator, blind_rotation_basis).unwrap(),
        GadgetEncryptionConfig {
            decomposition: primus_tfhe_ntru::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(key_switching_log_basis),
                level_count: Some(DecompositionLevelCount::new(4)),
            },
            noise_standard_deviation: 0.7,
        },
    )
    .unwrap()
}

#[test]
fn rejects_server_keys_with_same_layout_but_different_bases() {
    let table = RustFftTable::new(PolyLength::new(POLY_LENGTH));
    let context = TfheContext::try_new(parameters(8, 8), table).unwrap();
    let input_codec = RoundedCodec::new(4, context.parameters().external_lwe().cipher_modulus());
    let mut rng = StdRng::seed_from_u64(0x464f_5552_4241_5349);
    let (_, server_key) = context
        .try_generate_keys(BlindRotationAlgorithm::Classic, None, &mut rng)
        .unwrap();
    assert!(server_key.circuit_bootstrap_key().is_none());
    assert!(context.evaluator(&server_key).is_ok());

    // Changing either basis preserves all four levels and their storage size.
    for (bootstrapping_log_basis, key_switching_log_basis) in [(7, 8), (8, 7)] {
        let candidate = parameters(bootstrapping_log_basis, key_switching_log_basis);
        assert_eq!(
            candidate.blind_rotation().nlev_len(),
            context.parameters().blind_rotation().nlev_len()
        );
        assert_eq!(
            candidate
                .key_switching_basis()
                .expect("PBS parameters include key switching")
                .decompose_length()
                .get(),
            context
                .parameters()
                .key_switching_basis()
                .expect("PBS parameters include key switching")
                .decompose_length()
                .get()
        );
        let table = RustFftTable::new(PolyLength::new(POLY_LENGTH));
        let incompatible = TfheContext::try_new(candidate, table).unwrap();
        let expected = if key_switching_log_basis != 8 {
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
    }
}
