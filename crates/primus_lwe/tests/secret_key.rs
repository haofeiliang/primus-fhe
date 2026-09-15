use primus_encoding::PlaintextEmbedding;
use primus_lattice::lwe::Lwe;
use primus_lwe::{LweParameters, LweSecretKey, SecretKeyDistr};
use primus_modulus::BarrettModulus;
use rand::{SeedableRng, rngs::StdRng};

#[test]
fn message_encryption_reuses_storage_for_both_embeddings() {
    let params = LweParameters::new(
        7,
        4,
        BarrettModulus::new(97u32),
        SecretKeyDistr::UniformTernary,
        0.7,
    );
    let mut rng = StdRng::seed_from_u64(0x1_ee06);
    let key = LweSecretKey::generate(&params, &mut rng);
    let mut storage = [u32::MAX; 8];
    for message in 0..4u32 {
        for centered in [false, true] {
            let mut rng = StdRng::seed_from_u64(0x1_ee06);
            let mut expected_rng = StdRng::seed_from_u64(0x1_ee06);
            let mut output = Lwe::new(&mut storage[..]);
            let expected = if centered {
                key.encrypt_with_embedding_to(
                    message,
                    &mut output,
                    &params,
                    &mut rng,
                    PlaintextEmbedding::Centered,
                );
                key.encrypt_with_embedding(
                    message,
                    &params,
                    &mut expected_rng,
                    PlaintextEmbedding::Centered,
                )
            } else {
                key.encrypt_to(message, &mut output, &params, &mut rng);
                key.encrypt(message, &params, &mut expected_rng)
            };
            assert_eq!(output.0, expected.0.as_slice());
            let input = Lwe::new(&storage[..]);
            assert_eq!(key.decrypt(&input, &params), message);
        }
    }
}

#[test]
fn noise_is_distance_to_the_decoded_message_embedding() {
    let params = LweParameters::new(
        1,
        4u32,
        BarrettModulus::new(97),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let key = LweSecretKey::new(vec![1u32], SecretKeyDistr::UniformBinary);

    // For m=2, q=97, t=4, ties away from zero give unsigned E(m)=49
    // and centered E(m)=-49 mod 97=48. Use an independent, known phase.
    for (embedding, encoded) in [
        (PlaintextEmbedding::Unsigned, 49i32),
        (PlaintextEmbedding::Centered, 48),
    ] {
        for noise in [-2i32, 0, 2] {
            let body = (11 + encoded + noise).rem_euclid(97) as u32;
            let storage = [11u32, body];
            let ciphertext = Lwe::new(&storage[..]);
            let result: (u32, u32) = key.decrypt_with_noise(&ciphertext, &params, embedding);
            assert_eq!(result, (2, noise.unsigned_abs()));
        }
    }
}
