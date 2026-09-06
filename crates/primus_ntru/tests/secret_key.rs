use primus_fft::{FftEngine, FftTable, RustFftTable, TorusFftValue};
use primus_fhe_core::plaintext::PlaintextEmbedding;
use primus_integer::FheUint;
use primus_lattice::ntru::FourierNtruOwned;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{
    FourierNtruDecryptContext, FourierNtruEncryptContext, FourierNtruSecretKey, NtruError,
    NtruParameters, NtruSecretKey, NttNtruSecretKey, SecretCoefficient, SecretKeyDistr,
};
use primus_ntt::{NttTable, PrimitiveRoot, UintNttTable};
use primus_poly::{FourierPolynomialOwned, Polynomial, PolynomialOwned};

const POLY_LENGTH: usize = 256;
const PLAIN_MODULUS: usize = 16;

fn messages<T: FheUint>() -> Vec<T> {
    (0..POLY_LENGTH)
        .map(|index| T::try_from(index % (PLAIN_MODULUS / 2)).unwrap())
        .collect()
}

fn doubled_messages<T: FheUint>(messages: &[T]) -> Vec<T> {
    let t = T::try_from(PLAIN_MODULUS).unwrap();
    messages
        .iter()
        .map(|&message| (message + message) % t)
        .collect()
}

fn negated_messages<T: FheUint>(messages: &[T]) -> Vec<T> {
    let t = T::try_from(PLAIN_MODULUS).unwrap();
    messages
        .iter()
        .map(|&message| {
            if message == T::ZERO {
                T::ZERO
            } else {
                t - message
            }
        })
        .collect()
}

fn monomial_shifted_messages<T: FheUint>(messages: &[T]) -> Vec<T> {
    let t = T::try_from(PLAIN_MODULUS).unwrap();
    let mut shifted = vec![T::ZERO; messages.len()];
    shifted[0] = if messages[messages.len() - 1] == T::ZERO {
        T::ZERO
    } else {
        t - messages[messages.len() - 1]
    };
    shifted[1..].copy_from_slice(&messages[..messages.len() - 1]);
    shifted
}

fn assert_ntt_roundtrip<T>(cipher_modulus: T)
where
    T: FheUint + PrimitiveRoot,
{
    let modulus = BarrettModulus::new(cipher_modulus);
    let ntt = UintNttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let params = NtruParameters::new(
        POLY_LENGTH,
        T::try_from(PLAIN_MODULUS).unwrap(),
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let mut rng = rand::rng();
    let secret_key = NttNtruSecretKey::generate(&params, &ntt, &mut rng).unwrap();
    let messages = messages::<T>();
    let message = Polynomial::new(messages.clone());

    let cipher = secret_key.encrypt(&message, &params, &ntt, &mut rng);
    assert_eq!(
        secret_key.decrypt(&cipher, &params, &ntt).as_ref(),
        messages
    );

    let (decrypted, noise) = secret_key.decrypt_with_noise(&cipher, &params, &ntt);
    assert_eq!(decrypted.as_ref(), messages);
    assert!(noise.as_ref().iter().any(|&value| value != T::ZERO));

    let mut centered_cipher = cipher.clone();
    secret_key.encrypt_centered_to(&message, &mut centered_cipher, &params, &ntt, &mut rng);
    assert_eq!(
        secret_key.decrypt(&centered_cipher, &params, &ntt).as_ref(),
        messages
    );

    let mut encoded = vec![T::ZERO; POLY_LENGTH];
    params.plaintext_codec().add_encode_slice_assign_with_delta(
        &mut encoded,
        &messages,
        PlaintextEmbedding::Unsigned,
    );
    let mut encoded_cipher = cipher.clone();
    secret_key.encrypt_encoded_to(
        &Polynomial::new(encoded),
        &mut encoded_cipher,
        &params,
        &ntt,
        &mut rng,
    );
    assert_eq!(
        secret_key.decrypt(&encoded_cipher, &params, &ntt).as_ref(),
        messages
    );

    let zero_cipher = secret_key.encrypt_zero(&params, &ntt, &mut rng);
    assert_eq!(
        secret_key.decrypt(&zero_cipher, &params, &ntt).as_ref(),
        vec![T::ZERO; POLY_LENGTH]
    );

    let mut sum = cipher.clone();
    sum.add_assign(&cipher, modulus);
    assert_eq!(
        secret_key.decrypt(&sum, &params, &ntt).as_ref(),
        doubled_messages(&messages)
    );

    let mut scalar_product = cipher;
    scalar_product.mul_scalar_assign(T::TWO, modulus);
    assert_eq!(
        secret_key.decrypt(&scalar_product, &params, &ntt).as_ref(),
        doubled_messages(&messages)
    );

    let mut negated = scalar_product;
    negated.neg_assign(modulus);
    assert_eq!(
        secret_key.decrypt(&negated, &params, &ntt).as_ref(),
        negated_messages(&doubled_messages(&messages))
    );

    let mut monomial = PolynomialOwned::zero(POLY_LENGTH);
    monomial.as_mut()[1] = T::ONE;
    let monomial_ntt = ntt.transform_inplace(monomial);
    let mut polynomial_product = secret_key.encrypt(&message, &params, &ntt, &mut rng);
    polynomial_product.mul_ntt_polynomial_assign(&monomial_ntt, modulus);
    assert_eq!(
        secret_key
            .decrypt(&polynomial_product, &params, &ntt)
            .as_ref(),
        monomial_shifted_messages(&messages)
    );
}

#[test]
fn ntt_secret_key_roundtrip_and_linear_operations() {
    assert_ntt_roundtrip(132_120_577u32);
    assert_ntt_roundtrip(1_125_899_906_826_241u64);
}

fn assert_fourier_roundtrip<T>()
where
    T: FheUint + TorusFftValue,
{
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    let params = NtruParameters::new(
        POLY_LENGTH,
        T::try_from(PLAIN_MODULUS).unwrap(),
        NativeModulus::new(),
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let mut rng = rand::rng();
    let secret_key = FourierNtruSecretKey::generate(&params, &mut fft, &mut rng).unwrap();
    let mut encrypt_context = FourierNtruEncryptContext::new(POLY_LENGTH);
    let mut decrypt_context = FourierNtruDecryptContext::new(POLY_LENGTH);
    let messages = messages::<T>();
    let message = Polynomial::new(messages.clone());

    let cipher = secret_key.encrypt(&message, &params, &mut fft, &mut rng, &mut encrypt_context);
    assert_eq!(
        secret_key
            .decrypt(&cipher, &params, &mut fft, &mut decrypt_context,)
            .as_ref(),
        messages
    );

    let mut centered_cipher = cipher.clone();
    secret_key.encrypt_centered_to(
        &message,
        &mut centered_cipher,
        &params,
        &mut fft,
        &mut rng,
        &mut encrypt_context,
    );
    assert_eq!(
        secret_key
            .decrypt(&centered_cipher, &params, &mut fft, &mut decrypt_context,)
            .as_ref(),
        messages
    );

    let mut encoded = vec![T::ZERO; POLY_LENGTH];
    params.plaintext_codec().add_encode_slice_assign_with_delta(
        &mut encoded,
        &messages,
        PlaintextEmbedding::Unsigned,
    );
    let mut encoded_cipher = cipher.clone();
    secret_key.encrypt_encoded_to(
        &Polynomial::new(encoded),
        &mut encoded_cipher,
        &params,
        &mut fft,
        &mut rng,
        &mut encrypt_context,
    );
    assert_eq!(
        secret_key
            .decrypt(&encoded_cipher, &params, &mut fft, &mut decrypt_context,)
            .as_ref(),
        messages
    );

    let zero_cipher = secret_key.encrypt_zero(&params, &mut fft, &mut rng, &mut encrypt_context);
    assert_eq!(
        secret_key
            .decrypt(&zero_cipher, &params, &mut fft, &mut decrypt_context,)
            .as_ref(),
        vec![T::ZERO; POLY_LENGTH]
    );

    let mut sum = cipher.clone();
    sum.add_assign(&cipher);
    assert_eq!(
        secret_key
            .decrypt(&sum, &params, &mut fft, &mut decrypt_context)
            .as_ref(),
        doubled_messages(&messages)
    );

    let mut scalar_product: FourierNtruOwned = cipher;
    scalar_product.mul_scalar_assign(2.0);
    assert_eq!(
        secret_key
            .decrypt(&scalar_product, &params, &mut fft, &mut decrypt_context,)
            .as_ref(),
        doubled_messages(&messages)
    );

    let mut monomial = vec![T::ZERO; POLY_LENGTH];
    monomial[1] = T::ONE;
    let mut monomial_fourier = FourierPolynomialOwned::zero(fft.fourier_length());
    fft.forward_as_integer(&monomial, monomial_fourier.as_mut());
    let mut polynomial_product =
        secret_key.encrypt(&message, &params, &mut fft, &mut rng, &mut encrypt_context);
    polynomial_product.mul_fourier_polynomial_assign(&monomial_fourier);
    assert_eq!(
        secret_key
            .decrypt(&polynomial_product, &params, &mut fft, &mut decrypt_context,)
            .as_ref(),
        monomial_shifted_messages(&messages)
    );
}

#[test]
fn fourier_secret_key_roundtrip_and_linear_operations() {
    assert_fourier_roundtrip::<u32>();
    assert_fourier_roundtrip::<u64>();
}

#[test]
fn transform_backends_reject_the_zero_key() {
    let zero_key = NtruSecretKey::<u32>::new(
        vec![SecretCoefficient::<u32>::default(); POLY_LENGTH],
        SecretKeyDistr::SparseTernary,
    );

    let modulus = BarrettModulus::new(132_120_577u32);
    let ntt = UintNttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    assert!(matches!(
        NttNtruSecretKey::try_from_coeff_secret_key(&zero_key, modulus, &ntt),
        Err(NtruError::NonInvertibleSecretKey)
    ));

    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    assert!(matches!(
        FourierNtruSecretKey::try_from_coeff_secret_key(&zero_key, &mut fft),
        Err(NtruError::NonInvertibleSecretKey)
    ));
}

#[test]
fn key_generation_supports_small_coefficient_distributions() {
    let mut rng = rand::rng();
    let modulus = BarrettModulus::new(132_120_577u32);
    let ntt = UintNttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let fft_table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&fft_table);

    for distribution in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::SparseTernary,
        SecretKeyDistr::Gaussian(3.2),
    ] {
        let ntt_params = NtruParameters::new(
            POLY_LENGTH,
            PLAIN_MODULUS as u32,
            modulus,
            distribution,
            0.7,
        );
        NttNtruSecretKey::generate(&ntt_params, &ntt, &mut rng).unwrap();

        let fourier_params = NtruParameters::new(
            POLY_LENGTH,
            PLAIN_MODULUS as u32,
            NativeModulus::new(),
            distribution,
            0.7,
        );
        FourierNtruSecretKey::generate(&fourier_params, &mut fft, &mut rng).unwrap();
    }
}
