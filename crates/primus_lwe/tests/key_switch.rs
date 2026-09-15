use primus_decompose::primitive::ApproxSignedBasis;
use primus_lwe::{
    LweKeySwitchingKey, LweParameters, LweSecretKey, LweSecretKeyRef, SecretKeyDistr,
};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_reduce::RingContext;
use rand::{Rng, SeedableRng, rngs::StdRng};

#[test]
fn signed_input_generation_matches_encoded() {
    check_signed_generation(NativeModulus::new());
    check_signed_generation(BarrettModulus::new(132_120_577));
}

fn check_signed_generation<M: RingContext<u32>>(modulus: M) {
    let q = modulus.explicit_value().map_or(1i64 << 32, i64::from);
    let input_parameters =
        LweParameters::new(8, 4u32, modulus, SecretKeyDistr::UniformTernary, 0.7);
    let output_parameters =
        LweParameters::new(5, 4u32, modulus, SecretKeyDistr::UniformTernary, 0.7);
    // Base sixteen also exercises general digits in the end-to-end check;
    // the exact entry-sum test below covers both base four and base sixteen.
    let basis = ApproxSignedBasis::new(modulus.explicit_value(), 4, None);
    let mut rng = StdRng::seed_from_u64(0x1_ee06);
    let signed_key = [-1, 0, 1, -1, 1, 0, -1, 1];
    let input_secret_key = LweSecretKey::new(
        signed_key
            .iter()
            .map(|&value: &i32| i64::from(value).rem_euclid(q) as u32)
            .collect(),
        SecretKeyDistr::UniformTernary,
    );
    let signed_output_key = [1, -1, 0, 1, -1];
    let output_secret_key = LweSecretKey::new(
        signed_output_key
            .iter()
            .map(|&value: &i32| i64::from(value).rem_euclid(q) as u32)
            .collect(),
        SecretKeyDistr::UniformTernary,
    );
    let mut encoded_rng = StdRng::seed_from_u64(0x1_ee08);
    let key_switching_key = LweKeySwitchingKey::generate(
        input_secret_key.as_view(),
        &output_secret_key,
        &output_parameters,
        basis.clone(),
        &mut encoded_rng,
    );
    let expected_next_random = encoded_rng.next_u64();
    let mut signed_rng = StdRng::seed_from_u64(0x1_ee08);
    let signed_key_switching_key = LweKeySwitchingKey::generate(
        LweSecretKeyRef::Signed(&signed_key),
        &output_secret_key,
        &output_parameters,
        basis,
        &mut signed_rng,
    );
    // Input representation preserves entry layout and RNG consumption.
    assert_eq!(
        key_switching_key.as_slice(),
        signed_key_switching_key.as_slice()
    );
    assert_eq!(signed_rng.next_u64(), expected_next_random);

    let mut output = primus_lwe::LweCiphertext::new(vec![17u32; output_parameters.dimension() + 1]);
    *output.b_mut() = (q / 2) as u32;
    for message in 0u32..4 {
        let input = input_secret_key.encrypt(message, &input_parameters, &mut rng);
        key_switching_key.key_switch_to(&input, &mut output, modulus);
        assert_eq!(
            output_secret_key.decrypt(&output, &output_parameters),
            message
        );
    }
}

#[test]
fn key_switch_validates_before_writing() {
    use primus_lwe::LweCiphertext;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let modulus = BarrettModulus::new(97u32);
    let output_parameters = LweParameters::new(2, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let basis = ApproxSignedBasis::new(Some(97), 2, None);
    let output_key = LweSecretKey::new(vec![1, 0], SecretKeyDistr::UniformBinary);
    let mut rng = StdRng::seed_from_u64(0x1_ee09);
    let key = LweKeySwitchingKey::generate(
        LweSecretKeyRef::Encoded(&[1, 0, 1]),
        &output_key,
        &output_parameters,
        basis,
        &mut rng,
    );
    // Missing bodies, wrong dimensions and wrong modulus must all leave output intact.
    for (input_len, output_len, q) in [(0, 3, 97), (4, 0, 97), (3, 3, 97), (4, 2, 97), (4, 3, 101)]
    {
        let input = LweCiphertext::new(vec![7u32; input_len]);
        let mut storage = vec![11u32; output_len];
        let expected = storage.clone();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                key.key_switch_to(
                    &input,
                    &mut primus_lattice::lwe::Lwe::new(storage.as_mut_slice()),
                    BarrettModulus::new(q),
                );
            }))
            .is_err()
        );
        assert_eq!(storage, expected);
    }
    for (input_len, output_len, q) in [
        (5, 3, 97),
        (8, 5, 97),
        (8, 7, 97),
        (8, 6, 101),
        (0, 3, 97),
        (0, 0, 101),
    ] {
        let input = vec![7u32; input_len];
        let mut output = vec![11u32; output_len];
        let expected = output.clone();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                key.key_switch_batch_to(&input, &mut output, BarrettModulus::new(q));
            }))
            .is_err()
        );
        assert_eq!(output, expected);
    }
}

#[test]
fn generation_validates_before_sampling() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let parameters = LweParameters::new(
        2,
        4u32,
        BarrettModulus::new(97),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    for (input_key, output_dimension, basis_modulus) in [
        (LweSecretKeyRef::Encoded(&[]), 2, 97),
        (LweSecretKeyRef::Signed(&[]), 2, 97),
        (LweSecretKeyRef::Encoded(&[1]), 0, 97),
        (LweSecretKeyRef::Encoded(&[1]), 3, 97),
        (LweSecretKeyRef::Encoded(&[1]), 2, 101),
    ] {
        let output_key =
            LweSecretKey::new(vec![1; output_dimension], SecretKeyDistr::UniformBinary);
        let basis = ApproxSignedBasis::new(Some(basis_modulus), 2, None);
        let mut rng = StdRng::seed_from_u64(0x1_ee0a);
        let mut expected_rng = StdRng::seed_from_u64(0x1_ee0a);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                LweKeySwitchingKey::generate(input_key, &output_key, &parameters, basis, &mut rng)
            }))
            .is_err()
        );
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }
}

#[test]
fn batch_matches_scalar_key_entry_sum() {
    check_batch_sum(NativeModulus::<u32>::new());
    check_batch_sum(BarrettModulus::new(132_120_577u32));
    check_batch_sum(NativeModulus::<u64>::new());
    check_batch_sum(BarrettModulus::new(1u64 << 40));
}

fn check_batch_sum<T: primus_integer::FheUint, M: RingContext<T>>(modulus: M) {
    use primus_lattice::lwe::{Lwe, LweIter};
    use rand::distr::Distribution;

    let mut rng = StdRng::seed_from_u64(0x1_ee10);
    let params = LweParameters::new(65, T::TWO, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let output_key = LweSecretKey::generate(&params, &mut rng);
    for log_basis in [2, 4] {
        let basis = ApproxSignedBasis::new(modulus.explicit_value(), log_basis, None);
        let key = LweKeySwitchingKey::generate(
            LweSecretKeyRef::Encoded(&[T::ONE; 7]),
            &output_key,
            &params,
            basis,
            &mut rng,
        );
        for count in [0, 1, 7, 8, 17] {
            let mut input: Vec<T> = params
                .cipher_modulus_uniform_distr()
                .sample_iter(&mut rng)
                .take(count * 8)
                .collect();
            // Include zero and negative residues to exercise rounding and carry chains.
            for sample in input.as_chunks_mut::<8>().0 {
                sample[0] = T::ZERO;
                sample[1] = modulus.reduce_neg(T::ONE);
                sample[2] = modulus.reduce_neg(T::TWO);
            }
            let mut expected = vec![T::ZERO; count * 66];
            for (input, output) in
                LweIter::new(&input, 8).zip(expected.as_chunks_mut::<66>().0.iter_mut())
            {
                output[65] = input.b();
                for (&coefficient, block) in input.a().iter().zip(
                    key.as_slice()
                        .chunks_exact(66 * key.basis().decompose_length()),
                ) {
                    let (adjusted, mut carry) = key.basis().init_value_carry(coefficient);
                    for (decomposer, entry) in
                        key.basis().decomposer_iter().zip(block.as_chunks::<66>().0)
                    {
                        let (digit, next) = decomposer.decompose(adjusted, carry);
                        carry = next;
                        for (acc, &value) in output.iter_mut().zip(entry) {
                            *acc = modulus.reduce_sub(*acc, modulus.reduce_mul(digit, value));
                        }
                    }
                }
                let mut single = Lwe::new(vec![T::ONE; 66]);
                key.key_switch_to(&input, &mut single, modulus);
                assert_eq!(single.0.as_slice(), output.as_slice());
            }
            let mut actual = vec![T::ONE; count * 66];
            key.key_switch_batch_to(&input, &mut actual, modulus);
            assert_eq!(actual, expected);
        }
    }
}
