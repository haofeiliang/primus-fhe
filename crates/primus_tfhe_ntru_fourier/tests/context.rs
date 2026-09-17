use primus_fft::{FftTable, RustFftTable};
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_tfhe_ntru_fourier::{TfheContext, TfheEvaluationError, TfheParameters};
use rand::{SeedableRng, rngs::StdRng};

const POLY_LENGTH: usize = 16;
const LWE_DIMENSION: usize = 4;
const PLAIN_MODULUS: u32 = 4;

fn parameters(bootstrapping_log_basis: u32, key_switching_log_basis: u32) -> TfheParameters<u32> {
    let modulus = NativeModulus::new();
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
        NlevParameters::with_ntru_params(&accumulator, bootstrapping_log_basis, Some(4)),
        NlevParameters::with_ntru_params(&client, key_switching_log_basis, Some(4)),
    )
    .unwrap()
}

#[test]
fn rejects_server_keys_with_same_layout_but_different_bases() {
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let context = TfheContext::try_new(parameters(8, 8), table).unwrap();
    let mut rng = StdRng::seed_from_u64(0x464f_5552_4241_5349);
    let (_, server_key) = context.try_generate_keys(&mut rng).unwrap();
    assert!(context.evaluator(&server_key).is_ok());

    // Changing either basis preserves all four levels and their storage size.
    for (bootstrapping_log_basis, key_switching_log_basis) in [(7, 8), (8, 7)] {
        let candidate = parameters(bootstrapping_log_basis, key_switching_log_basis);
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
            assert_eq!(candidate.fourier_nlev_len(), original.fourier_nlev_len());
        }
        let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
        let incompatible = TfheContext::try_new(candidate, table).unwrap();
        assert_eq!(
            incompatible.evaluator(&server_key).err(),
            Some(TfheEvaluationError::IncompatibleServerKey)
        );
    }
}
