use primus_fhe_core::lwe::{LweParameters, LweSecretKey, SecretKeyDistr};
use primus_integer::FheUint;
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus};
use primus_reduce::RingContext;

const DIMENSION: usize = 670;
const NOISE_ALPHA: f64 = 2.980_232_238_769_531_2e-8; // 2^-25
const PLAIN_MODULI: [usize; 2] = [256, 257];
const SECRET_KEY_TYPES: [SecretKeyDistr; 3] = [
    SecretKeyDistr::Binary,
    SecretKeyDistr::Ternary,
    SecretKeyDistr::Gaussian(3.2),
];

fn noise_standard_deviation_from_q(q: f64) -> f64 {
    (q * NOISE_ALPHA).max(0.7)
}

fn from_usize<T: FheUint>(value: usize) -> T {
    T::try_from(value).unwrap()
}

fn noise_standard_deviation<T, M>(cipher_modulus: M) -> f64
where
    T: FheUint,
    M: RingContext<T>,
{
    let q = cipher_modulus
        .explicit_value()
        .map_or(2.0_f64.powi(T::BITS as i32), |q| q.as_into());
    noise_standard_deviation_from_q(q)
}

fn assert_lwe_secret_key_enc_dec<T, M>(cipher_modulus: M)
where
    T: FheUint,
    M: RingContext<T>,
{
    let mut rng = rand::rng();
    let noise_standard_deviation = noise_standard_deviation(cipher_modulus);

    for secret_key_distr in SECRET_KEY_TYPES {
        for plain_modulus_usize in PLAIN_MODULI {
            let plain_modulus = from_usize(plain_modulus_usize);
            let params = LweParameters::new(
                DIMENSION,
                plain_modulus,
                cipher_modulus,
                secret_key_distr,
                noise_standard_deviation,
            );
            let secret_key = LweSecretKey::generate(&params, &mut rng);

            for message in (0..plain_modulus_usize).map(from_usize::<T>) {
                let ciphertext = secret_key.encrypt(message, &params, &mut rng);

                let decrypted: T = secret_key.decrypt(&ciphertext, &params);
                assert_eq!(decrypted, message);

                let (decrypted_with_noise, _noise): (T, T) =
                    secret_key.decrypt_with_noise(&ciphertext, &params);
                assert_eq!(decrypted_with_noise, message);

                let ciphertext = secret_key.encrypt_centered(message, &params, &mut rng);

                let decrypted: T = secret_key.decrypt(&ciphertext, &params);
                assert_eq!(decrypted, message);

                let (decrypted_with_noise, _noise): (T, T) =
                    secret_key.decrypt_centered_with_noise(&ciphertext, &params);
                assert_eq!(decrypted_with_noise, message);
            }

            let messages: Vec<T> = (0..DIMENSION)
                .map(|index| from_usize(index % plain_modulus_usize))
                .collect();
            let ciphertext = secret_key.encrypt_multi_messages(&messages, &params, &mut rng);

            let decrypted: Vec<T> = secret_key.decrypt_multi_messages(&ciphertext, &params);
            assert_eq!(decrypted, messages);

            let ciphertext =
                secret_key.encrypt_multi_messages_centered(&messages, &params, &mut rng);

            let decrypted: Vec<T> = secret_key.decrypt_multi_messages(&ciphertext, &params);
            assert_eq!(decrypted, messages);

            let ciphertext = secret_key.encrypt_multi_zeros(DIMENSION, &params, &mut rng);
            let decrypted: Vec<T> = secret_key.decrypt_multi_messages(&ciphertext, &params);
            assert_eq!(decrypted, vec![T::ZERO; DIMENSION]);
        }
    }
}

#[test]
fn test_lwe_secret_key_enc_dec_native_modulus() {
    assert_lwe_secret_key_enc_dec::<u64, _>(NativeModulus::<u64>::new());
    assert_lwe_secret_key_enc_dec::<u32, _>(NativeModulus::<u32>::new());
}

#[test]
fn test_lwe_secret_key_enc_dec_power_of_two_modulus() {
    assert_lwe_secret_key_enc_dec::<u64, _>(PowOf2Modulus::new(1u64 << 50));
    assert_lwe_secret_key_enc_dec::<u32, _>(PowOf2Modulus::new(1u32 << 30));
}

#[test]
fn test_lwe_secret_key_enc_dec_prime_modulus() {
    assert_lwe_secret_key_enc_dec::<u64, _>(BarrettModulus::new(1_125_899_906_826_241u64));
    assert_lwe_secret_key_enc_dec::<u32, _>(BarrettModulus::new(536_813_569u32));
}
