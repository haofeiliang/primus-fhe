use primus_encoding::PlaintextEmbedding;
use primus_glwe::{
    GlweParameters, NttGlweCiphertext, NttGlwePublicEncryptContext, NttGlwePublicKey,
    NttGlweSecretKey, SecretKeyDistr,
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
use rand::{Rng, SeedableRng, rngs::StdRng};

const DIMENSION: usize = 2;
const POLY_LENGTH: usize = 256;
const PLAIN_MODULUS: u64 = 256;
const CIPHER_MODULUS: u64 = 1_125_899_906_826_241;

#[test]
fn public_key_encoding_modes_reuse_workspace() {
    let modulus = BarrettModulus::new(CIPHER_MODULUS);
    let params = GlweParameters::new(
        DIMENSION,
        POLY_LENGTH,
        PLAIN_MODULUS,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let table = UintNttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let (_, secret_key) = NttGlweSecretKey::generate_pair(&params, &table, &mut rng);
    let public_key = NttGlwePublicKey::generate(&secret_key, &params, &table, &mut rng);
    let message = Polynomial::new(
        (0..POLY_LENGTH)
            .map(|index| index as u64 % PLAIN_MODULUS)
            .collect::<Vec<_>>(),
    );

    let mut context = NttGlwePublicEncryptContext::new(POLY_LENGTH);
    // The same coins must yield the same ciphertext for explicit encoding and
    // the corresponding plaintext embedding, even after reusing the workspace.
    for embedding in [PlaintextEmbedding::Unsigned, PlaintextEmbedding::Centered] {
        let seed = rng.next_u64();
        let mut actual_rng = StdRng::seed_from_u64(seed);
        let mut expected_rng = StdRng::seed_from_u64(seed);
        let mut fresh_context = NttGlwePublicEncryptContext::new(POLY_LENGTH);
        let expected = match embedding {
            PlaintextEmbedding::Unsigned => public_key.encrypt(
                &message,
                &params,
                &table,
                &mut expected_rng,
                &mut fresh_context,
            ),
            PlaintextEmbedding::Centered => {
                let mut output = NttGlweCiphertext::<Vec<u64>>::zero(params.glwe_len());
                public_key.encrypt_centered_to(
                    &message,
                    &mut output,
                    &params,
                    &table,
                    &mut expected_rng,
                    &mut fresh_context,
                );
                output
            }
        };
        let mut encoded = Polynomial::new(vec![0; POLY_LENGTH]);
        params.plaintext_codec().add_encode_slice_assign(
            encoded.as_mut(),
            message.as_ref(),
            embedding,
        );
        let mut ciphertext: NttGlweCiphertext<Vec<u64>> =
            NttGlweCiphertext::zero(params.glwe_len());
        public_key.encrypt_encoded_to(
            &encoded,
            &mut ciphertext,
            &params,
            &table,
            &mut actual_rng,
            &mut context,
        );
        assert_eq!(ciphertext.as_ref(), expected.as_ref());
        assert_eq!(actual_rng.next_u64(), expected_rng.next_u64());
        assert_eq!(
            secret_key.decrypt(&ciphertext, &params, &table).as_ref(),
            message.as_ref()
        );
    }

    let encrypted_zero = public_key.encrypt_zeros(&params, &table, &mut rng, &mut context);
    assert_eq!(
        secret_key
            .decrypt(&encrypted_zero, &params, &table)
            .as_ref(),
        vec![0; POLY_LENGTH]
    );
}
