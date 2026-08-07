use primus_fft::{FftTable, RustFftTable};
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_ntt::{NttTable, U32NttTable};
use primus_tfhe_ntru_fourier::{NtruTfheParameters, TfheContext};
use rand::{SeedableRng, rngs::StdRng};

const POLY_LENGTH: usize = 256;
const LWE_DIMENSION: usize = 64;
const PLAIN_MODULUS: u32 = 4;

fn parameters() -> NtruTfheParameters<u32, NativeModulus<u32>> {
    let modulus = NativeModulus::new();
    let external_lwe = LweParameters::new(
        LWE_DIMENSION,
        PLAIN_MODULUS,
        modulus,
        SecretKeyDistr::Binary,
        0.7,
    );
    let accumulator = NtruParameters::new(
        POLY_LENGTH,
        PLAIN_MODULUS,
        modulus,
        SecretKeyDistr::Ternary,
        0.7,
    );
    let client = NtruParameters::new(
        POLY_LENGTH,
        PLAIN_MODULUS,
        modulus,
        SecretKeyDistr::Binary,
        0.7,
    );
    NtruTfheParameters::try_new(
        external_lwe,
        NlevParameters::with_ntru_params(&accumulator, 8, Some(4)),
        NlevParameters::with_ntru_params(&client, 8, Some(4)),
    )
    .unwrap()
}

fn ntt_outputs() -> Vec<u32> {
    const Q: u32 = 132_120_577;
    let modulus = primus_modulus::BarrettModulus::new(Q);
    let external_lwe = LweParameters::new(
        LWE_DIMENSION,
        PLAIN_MODULUS,
        modulus,
        SecretKeyDistr::Binary,
        0.7,
    );
    let accumulator = NtruParameters::new(
        POLY_LENGTH,
        PLAIN_MODULUS,
        modulus,
        SecretKeyDistr::Ternary,
        0.7,
    );
    let client = NtruParameters::new(
        POLY_LENGTH,
        PLAIN_MODULUS,
        modulus,
        SecretKeyDistr::Binary,
        0.7,
    );
    let parameters = primus_tfhe_ntru_ntt::NtruTfheParameters::try_new(
        external_lwe,
        NlevParameters::with_ntru_params(&accumulator, 9, None),
        NlevParameters::with_ntru_params(&client, 9, None),
    )
    .unwrap();
    let table = U32NttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let context = primus_tfhe_ntru_ntt::TfheContext::try_new(parameters, table).unwrap();
    let mut rng = StdRng::seed_from_u64(0x4e54_5255_5446_4845);
    let (client_key, server_key) = context.generate_keys(&mut rng).unwrap();
    let encryptor = context.encryptor(&client_key).unwrap();
    let decryptor = context.decryptor(&client_key).unwrap();
    let lut = context.compile_lookup_table_slice(&[1u32, 0]).unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();

    (0..2u32)
        .map(|input| {
            let ciphertext = encryptor.encrypt_padded(input, &mut rng).unwrap();
            let output = evaluator.apply_lookup_table(&ciphertext, &lut);
            decryptor.decrypt::<u32>(&output).unwrap()
        })
        .collect()
}

#[test]
fn matches_the_ntt_backend_on_decrypted_messages() {
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let context = TfheContext::try_new(parameters(), table).unwrap();
    let mut rng = StdRng::seed_from_u64(0x464f_5552_4e54_5255);
    let (client_key, server_key) = context.generate_keys(&mut rng).unwrap();
    let encryptor = context.encryptor(&client_key).unwrap();
    let decryptor = context.decryptor(&client_key).unwrap();
    let lut = context.compile_lookup_table_slice(&[1u32, 0]).unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();

    let fourier_outputs: Vec<u32> = (0..2u32)
        .map(|input| {
            let ciphertext = encryptor.encrypt_padded(input, &mut rng).unwrap();
            let output = evaluator.apply_lookup_table(&ciphertext, &lut);
            decryptor.decrypt::<u32>(&output).unwrap()
        })
        .collect();

    assert_eq!(fourier_outputs, ntt_outputs());
    assert_eq!(fourier_outputs, [1, 0]);
}
