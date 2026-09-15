use primus_encoding::PlaintextEmbedding;
use primus_integer::FheUint;
use primus_lattice::lwe::MultiMsgLwe;
use primus_lwe::{LweParameters, LweSecretKey, MultiMsgLweCiphertext, SecretKeyDistr};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_reduce::RingContext;
use rand::{SeedableRng, rngs::StdRng};

#[test]
fn packed_capacity_is_enforced() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let params = LweParameters::new(
        4,
        4u32,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let mut rng = StdRng::seed_from_u64(0x1_ee03);
    let key = LweSecretKey::generate(&params, &mut rng);

    // The first disallowed body reuses a mask up to sign.
    let count = params.dimension() + 1;
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            key.encrypt_multi_messages(&vec![0u32; count], &params, &mut rng)
        }))
        .is_err()
    );
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            key.encrypt_multi_zeros(count, &params, &mut rng)
        }))
        .is_err()
    );
    let malformed = MultiMsgLweCiphertext::new(vec![0u32; params.dimension() + count]);
    assert!(catch_unwind(|| key.decrypt_multi_messages(&malformed, &params)).is_err());
}

#[test]
fn packed_samples_decrypt_independently() {
    check_packed_samples(NativeModulus::<u32>::new());
    check_packed_samples(NativeModulus::<u64>::new());
    check_packed_samples(BarrettModulus::new(132_120_577u32));
    check_packed_samples(BarrettModulus::new(1_125_899_906_826_241u64));
}

fn check_packed_samples<T: FheUint, M: RingContext<T>>(modulus: M) {
    // Moving rotation splits exercise vector blocks and tails in both word widths.
    let dimension = 513;
    let params = LweParameters::new(
        dimension,
        T::as_from(4u32),
        modulus,
        SecretKeyDistr::UniformTernary,
        0.7,
    );
    let pattern = [T::ONE, modulus.reduce_neg(T::ONE), T::ZERO, T::ONE];
    let key = LweSecretKey::new(
        (0..dimension).map(|i| pattern[i % pattern.len()]).collect(),
        SecretKeyDistr::UniformTernary,
    );
    let mut rng = StdRng::seed_from_u64(0x1_ee04);
    let messages: Vec<T> = (0..dimension).map(|i| T::as_from(i % 4)).collect();
    let check = |ciphertext: MultiMsgLweCiphertext<T>, messages: &[T]| {
        assert_eq!(ciphertext.0.len(), dimension + messages.len());
        let borrowed = MultiMsgLwe::new(ciphertext.0.as_slice());
        assert_eq!(key.decrypt_multi_messages(&borrowed, &params), messages);
        // The lattice extractor is independent of the packed phase helper,
        // exposing a rotation/sign error shared by encryption and decryption.
        for (index, &message) in messages.iter().enumerate() {
            let sample = ciphertext.extract_lwe_at(index, dimension, modulus);
            assert_eq!(key.decrypt(&sample, &params), message);
        }
    };
    for count in [0, 3, dimension] {
        for embedding in [PlaintextEmbedding::Unsigned, PlaintextEmbedding::Centered] {
            check(
                key.encrypt_multi_messages_with_embedding(
                    &messages[..count],
                    &params,
                    &mut rng,
                    embedding,
                ),
                &messages[..count],
            );
        }
    }
    for count in [0, 3] {
        check(
            key.encrypt_multi_zeros(count, &params, &mut rng),
            &[T::ZERO; 3][..count],
        );
    }
}
