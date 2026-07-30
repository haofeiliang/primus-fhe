use primus_fhe_core::{
    NttRlweCiphertext, NttRlweSecretKey, PlaintextEmbedding, RingSecretKeyType, RlweParameters,
    RlweSecretKey,
};
use primus_integer::FheUint;
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
use primus_reduce::FieldContext;

const POLY_LENGTH: usize = 1024;
const NOISE_ALPHA: f64 = 2.980_232_238_769_531_2e-8; // 2^-25
const SECRET_KEY_GAUSSIAN_STANDARD_DEVIATION: f64 = 3.2;
const PLAIN_MODULI: [usize; 2] = [256, 257];
const SECRET_KEY_TYPES: [RingSecretKeyType; 3] = [
    RingSecretKeyType::Binary,
    RingSecretKeyType::Ternary,
    RingSecretKeyType::Gaussian(SECRET_KEY_GAUSSIAN_STANDARD_DEVIATION),
];

fn from_usize<T: FheUint>(value: usize) -> T {
    T::try_from(value).unwrap()
}

fn noise_standard_deviation<T, M>(cipher_modulus: M) -> f64
where
    T: FheUint,
    M: FieldContext<T>,
{
    let q: f64 = cipher_modulus.value().as_into();
    (q * NOISE_ALPHA).max(0.7)
}

fn message_polynomial<T: FheUint>(plain_modulus: usize) -> Polynomial<Vec<T>> {
    Polynomial::new(
        (0..POLY_LENGTH)
            .map(|index| from_usize(index % plain_modulus))
            .collect(),
    )
}

fn noiseless_delta_ciphertext<T, M, Table>(
    message: &Polynomial<Vec<T>>,
    params: &RlweParameters<T, M>,
    table: &Table,
    embedding: PlaintextEmbedding,
) -> NttRlweCiphertext<Vec<T>>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    let mut ciphertext = NttRlweCiphertext::zero(params.poly_length() * 2);
    let (_, b) = ciphertext.a_b_mut_slices();

    params
        .plaintext_codec()
        .add_encode_slice_assign_with_delta(b, message.as_ref(), embedding);
    table.transform_slice(b);

    ciphertext
}

fn assert_rlwe_secret_key_enc_dec<T, M>(cipher_modulus: M)
where
    T: FheUint,
    M: FieldContext<T>,
{
    let mut rng = rand::rng();
    let table = UintNttTable::new(POLY_LENGTH.trailing_zeros(), cipher_modulus).unwrap();
    let noise_standard_deviation = noise_standard_deviation(cipher_modulus);

    for secret_key_type in SECRET_KEY_TYPES {
        for plain_modulus_usize in PLAIN_MODULI {
            let params = RlweParameters::new(
                POLY_LENGTH,
                from_usize(plain_modulus_usize),
                cipher_modulus,
                secret_key_type,
                noise_standard_deviation,
            );
            let secret_key = RlweSecretKey::generate(&params, &mut rng);
            let secret_key = NttRlweSecretKey::from_coeff_secret_key(&secret_key, &table);

            let message = message_polynomial(plain_modulus_usize);
            let mut ciphertext: NttRlweCiphertext<Vec<T>> =
                NttRlweCiphertext::zero(POLY_LENGTH * 2);
            secret_key.encrypt_inplace(&message, &mut ciphertext, &params, &table, &mut rng);

            let decrypted = secret_key.decrypt(&ciphertext, &params, &table);
            assert_eq!(decrypted.as_ref(), message.as_ref());

            let (decrypted_with_noise, _noise) =
                secret_key.decrypt_with_noise(&ciphertext, &params, &table);
            assert_eq!(decrypted_with_noise.as_ref(), message.as_ref());

            let ciphertext =
                noiseless_delta_ciphertext(&message, &params, &table, PlaintextEmbedding::Unsigned);
            let decrypted = secret_key.decrypt(&ciphertext, &params, &table);
            assert_eq!(decrypted.as_ref(), message.as_ref());

            let (decrypted_with_noise, noise) =
                secret_key.decrypt_with_noise(&ciphertext, &params, &table);
            assert_eq!(decrypted_with_noise.as_ref(), message.as_ref());
            assert_eq!(noise.as_ref(), vec![T::ZERO; POLY_LENGTH]);

            let mut ciphertext: NttRlweCiphertext<Vec<T>> =
                NttRlweCiphertext::zero(POLY_LENGTH * 2);
            secret_key.encrypt_centered_inplace(
                &message,
                &mut ciphertext,
                &params,
                &table,
                &mut rng,
            );

            let decrypted = secret_key.decrypt(&ciphertext, &params, &table);
            assert_eq!(decrypted.as_ref(), message.as_ref());

            let (decrypted_with_noise, _noise) =
                secret_key.decrypt_centered_with_noise(&ciphertext, &params, &table);
            assert_eq!(decrypted_with_noise.as_ref(), message.as_ref());

            let ciphertext =
                noiseless_delta_ciphertext(&message, &params, &table, PlaintextEmbedding::Centered);
            let decrypted = secret_key.decrypt(&ciphertext, &params, &table);
            assert_eq!(decrypted.as_ref(), message.as_ref());

            let (decrypted_with_noise, noise) =
                secret_key.decrypt_centered_with_noise(&ciphertext, &params, &table);
            assert_eq!(decrypted_with_noise.as_ref(), message.as_ref());
            assert_eq!(noise.as_ref(), vec![T::ZERO; POLY_LENGTH]);

            let ciphertext = secret_key.encrypt_zeros(&params, &table, &mut rng);
            let decrypted = secret_key.decrypt(&ciphertext, &params, &table);
            assert_eq!(decrypted.as_ref(), vec![T::ZERO; POLY_LENGTH]);

            let ciphertext = secret_key.encrypt_multi_zeros(POLY_LENGTH, &params, &table, &mut rng);
            let decrypted: Vec<T> = secret_key.decrypt_multi_messages(&ciphertext, &params, &table);
            assert_eq!(decrypted, vec![T::ZERO; POLY_LENGTH]);
        }
    }
}

#[test]
fn test_rlwe_secret_key_enc_dec_prime_modulus() {
    assert_rlwe_secret_key_enc_dec::<u64, _>(BarrettModulus::new(1_125_899_906_826_241u64));
    assert_rlwe_secret_key_enc_dec::<u32, _>(BarrettModulus::new(132_120_577u32));
}
