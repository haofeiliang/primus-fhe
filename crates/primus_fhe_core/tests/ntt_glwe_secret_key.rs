use primus_fhe_core::{
    GlweParameters, GlweSecretKey, NttGlweSecretKey, PlaintextEmbedding, RingSecretKeyType,
};
use primus_integer::FheUint;
use primus_lattice::glwe::NttGlwe;
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, PrimitiveRoot, UintNttTable};
use primus_poly::{Polynomial, PolynomialOwned};

const DIMENSION: usize = 2;
const POLY_LENGTH: usize = 256;
const PLAIN_MODULUS: usize = 16;

fn assert_roundtrip<T>(cipher_modulus: T)
where
    T: FheUint + PrimitiveRoot,
{
    let modulus = BarrettModulus::new(cipher_modulus);
    let ntt = UintNttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let mut rng = rand::rng();
    let messages: Vec<T> = (0..POLY_LENGTH)
        .map(|index| T::try_from(index % PLAIN_MODULUS).unwrap())
        .collect();
    let message = Polynomial::new(messages.clone());

    for secret_key_type in [RingSecretKeyType::Binary, RingSecretKeyType::Ternary] {
        let params = GlweParameters::new(
            DIMENSION,
            POLY_LENGTH,
            T::try_from(PLAIN_MODULUS).unwrap(),
            modulus,
            secret_key_type,
            0.7,
        );
        let coeff_secret_key = GlweSecretKey::generate(&params, &mut rng);
        assert_eq!(coeff_secret_key.as_slice().len(), DIMENSION * POLY_LENGTH);
        assert_eq!(coeff_secret_key.iter().len(), DIMENSION);
        assert!(
            coeff_secret_key
                .iter()
                .all(|polynomial| polynomial.as_ref().len() == POLY_LENGTH)
        );

        let secret_key = NttGlweSecretKey::from_coeff_secret_key(&coeff_secret_key, &ntt);
        let mut cipher: NttGlwe<Vec<T>> = NttGlwe::zero((DIMENSION + 1) * POLY_LENGTH);

        secret_key.encrypt_to(&message, &mut cipher, &params, &ntt, &mut rng);
        assert_eq!(
            secret_key.decrypt(&cipher, &params, &ntt).as_ref(),
            messages
        );

        secret_key.encrypt_centered_to(&message, &mut cipher, &params, &ntt, &mut rng);
        assert_eq!(
            secret_key.decrypt(&cipher, &params, &ntt).as_ref(),
            messages
        );

        secret_key.encrypt_zeros_to(&mut cipher, &params, &ntt, &mut rng);
        assert_eq!(
            secret_key.decrypt(&cipher, &params, &ntt).as_ref(),
            vec![T::ZERO; POLY_LENGTH]
        );

        let mut encoded = vec![T::ZERO; POLY_LENGTH];
        params.plaintext_codec().add_encode_slice_assign_with_delta(
            &mut encoded,
            &messages,
            PlaintextEmbedding::Unsigned,
        );
        secret_key.encrypt_encoded_to(
            &Polynomial::new(encoded),
            &mut cipher,
            &params,
            &ntt,
            &mut rng,
        );

        let mut reused_output = PolynomialOwned::new(vec![T::MAX; POLY_LENGTH]);
        secret_key.decrypt_to(&cipher, &mut reused_output, &params, &ntt);
        assert_eq!(reused_output.as_ref(), messages);
    }
}

#[test]
fn ntt_glwe_secret_key_roundtrip_u32() {
    assert_roundtrip(132_120_577u32);
}

#[test]
fn ntt_glwe_secret_key_roundtrip_u64() {
    assert_roundtrip(1_125_899_906_826_241u64);
}
