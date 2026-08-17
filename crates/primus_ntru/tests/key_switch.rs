use primus_fft::{FftEngine, FftTable, RustFftTable};
use primus_lattice::ntru::FourierNtruOwned;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{
    FourierNtruDecryptContext, FourierNtruEncryptContext, FourierNtruExternalProductContext,
    FourierNtruGadgetEncryptContext, FourierNtruKeySwitchingKey, FourierNtruSecretKey,
    NlevParameters, NtruParameters, NtruSecretKey, NttNtruExternalProductContext,
    NttNtruGadgetEncryptContext, NttNtruKeySwitchingKey, NttNtruSecretKey, SecretKeyDistr,
};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
use rand::{SeedableRng, rngs::StdRng};

const POLY_LENGTH: usize = 256;
const PLAIN_MODULUS: u32 = 16;
const EXPLICIT_MODULUS: u32 = 132_120_577;

fn message() -> Vec<u32> {
    (0..POLY_LENGTH)
        .map(|index| (3 * index as u32 + 1) % PLAIN_MODULUS)
        .collect()
}

fn ntt_key_pair(
    parameters: &NtruParameters<u32, BarrettModulus<u32>>,
    ntt: &UintNttTable<u32>,
    rng: &mut StdRng,
) -> (NtruSecretKey<u32>, NttNtruSecretKey<u32>) {
    for _ in 0..1024 {
        let coefficient_key = NtruSecretKey::generate(parameters, rng);
        if let Ok(transformed_key) = NttNtruSecretKey::try_from_coeff_secret_key(
            &coefficient_key,
            parameters.cipher_modulus(),
            ntt,
        ) {
            return (coefficient_key, transformed_key);
        }
    }
    panic!("failed to generate an invertible NTT NTRU secret key");
}

#[test]
fn ntt_key_switch_preserves_plaintext() {
    let mut rng = StdRng::seed_from_u64(0x4e54_5452_554b_534b);
    let modulus = BarrettModulus::new(EXPLICIT_MODULUS);
    let ntt = UintNttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let parameters = NtruParameters::new(
        POLY_LENGTH,
        PLAIN_MODULUS,
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let key_switching = NlevParameters::with_ntru_params(&parameters, 9, None);
    let (input_coefficient_key, input_key) = ntt_key_pair(&parameters, &ntt, &mut rng);
    let (output_coefficient_key, output_key) = ntt_key_pair(&parameters, &ntt, &mut rng);
    assert_ne!(
        input_coefficient_key.as_slice(),
        output_coefficient_key.as_slice()
    );

    let mut gadget_context = NttNtruGadgetEncryptContext::new(POLY_LENGTH);
    let switching_key = NttNtruKeySwitchingKey::generate(
        &input_coefficient_key,
        &output_key,
        &key_switching,
        &ntt,
        &mut rng,
        &mut gadget_context,
    );

    let message = message();
    let input = input_key
        .encrypt(
            &Polynomial::new(message.as_slice()),
            &parameters,
            &ntt,
            &mut rng,
        )
        .into_coeff_form(&ntt);
    let mut external_product = NttNtruExternalProductContext::new(POLY_LENGTH);
    let switched = switching_key.key_switch(&input, &key_switching, &ntt, &mut external_product);
    let switched = switched.into_ntt_form(&ntt);

    assert_eq!(
        output_key.decrypt(&switched, &parameters, &ntt).as_ref(),
        message
    );
}

fn fourier_key_pair(
    parameters: &NtruParameters<u32, NativeModulus<u32>>,
    fft: &mut FftEngine<'_, RustFftTable>,
    rng: &mut StdRng,
) -> (NtruSecretKey<u32>, FourierNtruSecretKey) {
    for _ in 0..1024 {
        let coefficient_key = NtruSecretKey::generate(parameters, rng);
        if let Ok(transformed_key) =
            FourierNtruSecretKey::try_from_coeff_secret_key(&coefficient_key, fft)
        {
            return (coefficient_key, transformed_key);
        }
    }
    panic!("failed to generate an invertible Fourier NTRU secret key");
}

#[test]
fn fourier_key_switch_preserves_plaintext() {
    let mut rng = StdRng::seed_from_u64(0x464f_5552_4b53_574b);
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    let parameters = NtruParameters::new(
        POLY_LENGTH,
        PLAIN_MODULUS,
        NativeModulus::new(),
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let key_switching = NlevParameters::with_ntru_params(&parameters, 8, None);
    let (input_coefficient_key, input_key) = fourier_key_pair(&parameters, &mut fft, &mut rng);
    let (output_coefficient_key, output_key) = fourier_key_pair(&parameters, &mut fft, &mut rng);
    assert_ne!(
        input_coefficient_key.as_slice(),
        output_coefficient_key.as_slice()
    );

    let mut gadget_context = FourierNtruGadgetEncryptContext::new(POLY_LENGTH);
    let switching_key = FourierNtruKeySwitchingKey::generate(
        &input_coefficient_key,
        &output_key,
        &key_switching,
        &mut fft,
        &mut rng,
        &mut gadget_context,
    );

    let message = message();
    let mut encrypt_context = FourierNtruEncryptContext::new(POLY_LENGTH);
    let input = input_key.encrypt(
        &Polynomial::new(message.as_slice()),
        &parameters,
        &mut fft,
        &mut rng,
        &mut encrypt_context,
    );
    let mut input_coefficients: primus_ntru::NtruCiphertext<Vec<u32>> =
        primus_ntru::NtruCiphertext::zero(POLY_LENGTH);
    input.write_torus_form(&mut input_coefficients, &mut fft);

    let mut external_product = FourierNtruExternalProductContext::new(POLY_LENGTH);
    let switched = switching_key.key_switch(
        &input_coefficients,
        &key_switching,
        &mut fft,
        &mut external_product,
    );
    let mut transformed = FourierNtruOwned::zero(fft.fourier_length());
    switched.write_fourier_form(&mut transformed, &mut fft);
    let mut decrypt_context = FourierNtruDecryptContext::new(POLY_LENGTH);

    assert_eq!(
        output_key
            .decrypt(&transformed, &parameters, &mut fft, &mut decrypt_context,)
            .as_ref(),
        message
    );
}
