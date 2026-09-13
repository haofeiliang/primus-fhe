use primus_encoding::PlaintextEmbedding;
use primus_fft::{FftEngine, FftTable, RustFftTable, TorusFftValue};
use primus_glwe::{
    FourierGlweDecryptContext, FourierGlweEncryptContext, FourierGlweSecretKey, GlweParameters,
    SecretKeyDistr,
};
use primus_integer::FheUint;
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;
use rand::{SeedableRng, rngs::StdRng};

const DIMENSION: usize = 2;
const POLY_LENGTH: usize = 256;
const PLAIN_MODULUS: usize = 16;

fn assert_roundtrip<T>()
where
    T: FheUint + TorusFftValue,
{
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    let mut rng = StdRng::seed_from_u64(42);
    let messages: Vec<T> = (0..POLY_LENGTH)
        .map(|index| T::try_from(index % PLAIN_MODULUS).unwrap())
        .collect();
    let message = Polynomial::new(messages.clone());

    for secret_key_distr in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::SparseTernary,
        SecretKeyDistr::gaussian(3.2),
        // A weight greater than N must be sampled over all k*N coefficients.
        SecretKeyDistr::fixed_hamming_weight_ternary(DIMENSION * POLY_LENGTH, POLY_LENGTH + 7),
    ] {
        let params = GlweParameters::new(
            DIMENSION,
            POLY_LENGTH,
            T::try_from(PLAIN_MODULUS).unwrap(),
            NativeModulus::new(),
            secret_key_distr,
            0.7,
        );
        let (_, secret_key) = FourierGlweSecretKey::generate_pair(&params, &mut fft, &mut rng);
        let mut encrypt_context = FourierGlweEncryptContext::new(POLY_LENGTH);
        let mut decrypt_context = FourierGlweDecryptContext::new(POLY_LENGTH);

        let mut cipher =
            secret_key.encrypt(&message, &params, &mut fft, &mut rng, &mut encrypt_context);
        assert_eq!(
            secret_key
                .decrypt(&cipher, &params, &mut fft, &mut decrypt_context)
                .as_ref(),
            messages
        );

        secret_key.encrypt_centered_to(
            &message,
            &mut cipher,
            &params,
            &mut fft,
            &mut rng,
            &mut encrypt_context,
        );
        assert_eq!(
            secret_key
                .decrypt(&cipher, &params, &mut fft, &mut decrypt_context)
                .as_ref(),
            messages
        );

        secret_key.encrypt_zeros_to(
            &mut cipher,
            &params,
            &mut fft,
            &mut rng,
            &mut encrypt_context,
        );
        assert_eq!(
            secret_key
                .decrypt(&cipher, &params, &mut fft, &mut decrypt_context)
                .as_ref(),
            vec![T::ZERO; POLY_LENGTH]
        );

        let mut encoded = vec![T::ZERO; POLY_LENGTH];
        params.plaintext_codec().add_encode_slice_assign(
            &mut encoded,
            &messages,
            PlaintextEmbedding::Unsigned,
        );
        secret_key.encrypt_encoded_to(
            &Polynomial::new(encoded),
            &mut cipher,
            &params,
            &mut fft,
            &mut rng,
            &mut encrypt_context,
        );
        assert_eq!(
            secret_key
                .decrypt(&cipher, &params, &mut fft, &mut decrypt_context)
                .as_ref(),
            messages
        );
    }
}

#[test]
fn fourier_glwe_secret_key_roundtrip_u32() {
    assert_roundtrip::<u32>();
}

#[test]
fn fourier_glwe_secret_key_roundtrip_u64() {
    assert_roundtrip::<u64>();
}
