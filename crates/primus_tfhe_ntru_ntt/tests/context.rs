use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_ntt::{NttTable, U32NttTable};
use primus_tfhe_ntru_ntt::{TfheContext, TfheEvaluationError, TfheParameters};
use rand::{SeedableRng, rngs::StdRng};

const POLY_LENGTH: usize = 16;
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
        LWE_DIMENSION,
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
    let client = NtruParameters::new(
        POLY_LENGTH,
        PLAIN_MODULUS,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    TfheParameters::try_new(
        external_lwe,
        NlevParameters::with_ntru_params(&accumulator, bootstrapping_log_basis, None),
        NlevParameters::with_ntru_params(&client, key_switching_log_basis, None),
    )
    .unwrap()
}

#[test]
fn rejects_server_keys_with_same_layout_but_different_bases_or_modulus() {
    let original = parameters(CIPHER_MODULUS, 9, 9);
    let table = U32NttTable::new(
        POLY_LENGTH.trailing_zeros(),
        original.accumulator_ntru().cipher_modulus(),
    )
    .unwrap();
    let context = TfheContext::try_new(original, table).unwrap();
    let mut rng = StdRng::seed_from_u64(0x4e54_5255_4241_5349);
    let (_, server_key) = context.try_generate_keys(&mut rng).unwrap();
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
        for (candidate, original) in [
            (
                candidate.blind_rotation(),
                context.parameters().blind_rotation(),
            ),
            (
                candidate.ntru_key_switching(),
                context.parameters().ntru_key_switching(),
            ),
        ] {
            assert_eq!(candidate.nlev_len(), original.nlev_len());
        }
        let table = U32NttTable::new(
            POLY_LENGTH.trailing_zeros(),
            candidate.accumulator_ntru().cipher_modulus(),
        )
        .unwrap();
        let incompatible = TfheContext::try_new(candidate, table).unwrap();
        assert_eq!(
            incompatible.evaluator(&server_key).err(),
            Some(TfheEvaluationError::IncompatibleServerKey)
        );
    }
}
