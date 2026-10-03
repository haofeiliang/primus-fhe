use primus_encoding::PlaintextEmbedding;
use primus_lattice::LweDimension;
use primus_lattice::lwe::Lwe;
use primus_lwe::{LweParameters, LweSecretKey, SecretKeyDistr};
use primus_modulus::BarrettModulus;
use rand::{SeedableRng, rngs::StdRng};

#[test]
fn message_encryption_reuses_storage_for_both_embeddings() {
    let params = LweParameters::new(
        LweDimension::new(7),
        4,
        BarrettModulus::new(97u32),
        SecretKeyDistr::UniformTernary,
        0.7,
    );
    let mut rng = StdRng::seed_from_u64(0x1_ee06);
    let key = LweSecretKey::generate(params.inner(), &mut rng);
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
        LweDimension::new(1),
        4u32,
        BarrettModulus::new(97),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let key = LweSecretKey::new(
        vec![1u32],
        SecretKeyDistr::UniformBinary,
        params.cipher_modulus(),
    );

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

#[test]
fn owning_domain_is_preserved_and_rejected_before_sampling_or_writing() {
    use primus_integer::FheUint;
    use primus_modulus::{NativeModulus, PowOf2Modulus};
    use primus_reduce::{Modulus, RingContext};
    use rand::Rng;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    fn check<T: FheUint, M: RingContext<T>, Other: Modulus<ValueT = T>>(modulus: M, other: Other) {
        let params = LweParameters::new(
            LweDimension::new(4),
            T::TWO,
            modulus,
            SecretKeyDistr::UniformBinary,
            0.7,
        );
        let mut rng = StdRng::seed_from_u64(0x4c57_4544);
        let generated = LweSecretKey::generate(params.inner(), &mut rng);
        assert_eq!(generated.cipher_modulus_minus_one(), modulus.minus_one());

        // Both imports contain the same valid binary secret, so residue scans
        // cannot distinguish their domains. No secret copying is needed to bind.
        let matching = LweSecretKey::new(vec![T::ONE; 4], SecretKeyDistr::UniformBinary, modulus);
        let foreign = LweSecretKey::new(vec![T::ONE; 4], SecretKeyDistr::UniformBinary, other);
        assert_eq!(foreign.cipher_modulus_minus_one(), other.minus_one());
        let mut output = matching.encrypt(T::ONE, &params, &mut rng);
        assert_eq!(matching.decrypt(&output, &params), T::ONE);
        let original = output.clone();
        let seed = rng.next_u64();
        let mut rng = StdRng::seed_from_u64(seed);
        let mut untouched = StdRng::seed_from_u64(seed);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                foreign.encrypt_to(T::ONE, &mut output, &params, &mut rng);
            }))
            .is_err()
        );
        assert_eq!(output, original);
        assert_eq!(rng.next_u64(), untouched.next_u64());
        assert!(catch_unwind(AssertUnwindSafe(|| foreign.decrypt(&output, &params))).is_err());

        // Batch checks precede the first entry, including empty batches.
        let mut batch = vec![T::ONE; 10];
        let seed = rng.next_u64();
        let mut rng = StdRng::seed_from_u64(seed);
        let mut untouched = StdRng::seed_from_u64(seed);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                foreign.encrypt_batch_to(&[T::ZERO, T::ONE], &mut batch, &params, &mut rng);
            }))
            .is_err()
        );
        assert_eq!(batch, vec![T::ONE; 10]);
        assert_eq!(rng.next_u64(), untouched.next_u64());
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                foreign.decrypt_phase_batch_to(&[], &mut [], modulus);
            }))
            .is_err()
        );
    }

    check(NativeModulus::<u32>::new(), PowOf2Modulus::new(1 << 31));
    check(PowOf2Modulus::<u32>::new(1 << 31), NativeModulus::new());
    check(BarrettModulus::<u32>::new(97), BarrettModulus::new(101));
    check(NativeModulus::<u64>::new(), PowOf2Modulus::new(1 << 63));
    check(BarrettModulus::<u64>::new(97), BarrettModulus::new(101));
}
