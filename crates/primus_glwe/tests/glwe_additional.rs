use primus_fhe_core::plaintext::PlaintextEmbedding;
use primus_glwe::{
    GlweParameters, GlweSecretKey, NttGlweCiphertext, NttGlwePublicKey, NttGlweSecretKey,
    SecretKeyDistr,
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;

const DIMENSION: usize = 2;
const POLY_LENGTH: usize = 256;
const PLAIN_MODULUS: u64 = 256;
const CIPHER_MODULUS: u64 = 1_125_899_906_826_241;

#[test]
fn additional_glwe_workflows() {
    let modulus = BarrettModulus::new(CIPHER_MODULUS);
    let params = GlweParameters::new(
        DIMENSION,
        POLY_LENGTH,
        PLAIN_MODULUS,
        modulus,
        SecretKeyDistr::Binary,
        0.7,
    );
    let table = UintNttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let mut rng = rand::rng();
    let coeff_secret_key = GlweSecretKey::generate(&params, &mut rng);
    let secret_key = NttGlweSecretKey::from_coeff_secret_key(&coeff_secret_key, &table);
    let public_key = NttGlwePublicKey::new(&secret_key, &params, &table, &mut rng);
    let message = Polynomial::new(
        (0..POLY_LENGTH)
            .map(|index| index as u64 % PLAIN_MODULUS)
            .collect::<Vec<_>>(),
    );

    let ciphertext = public_key.encrypt(&message, &params, &table, &mut rng);
    assert_eq!(
        secret_key.decrypt(&ciphertext, &params, &table).as_ref(),
        message.as_ref()
    );

    let mut noiseless: NttGlweCiphertext<Vec<u64>> = NttGlweCiphertext::zero(params.glwe_len());
    let (_, body) = noiseless.a_b_mut_slices(POLY_LENGTH);
    params.plaintext_codec().add_encode_slice_assign_with_delta(
        body,
        message.as_ref(),
        PlaintextEmbedding::Unsigned,
    );
    table.transform_slice(body);
    let (decoded, noise) = secret_key.decrypt_with_noise(&noiseless, &params, &table);
    assert_eq!(decoded.as_ref(), message.as_ref());
    assert_eq!(noise.as_ref(), vec![0; POLY_LENGTH]);

    let truncated = secret_key.encrypt_multi_zeros(32, &params, &table, &mut rng);
    let decoded: Vec<u64> = secret_key.decrypt_multi_messages(&truncated, &params, &table);
    assert_eq!(decoded, vec![0; 32]);
}
