//! Independent coefficient phases, rounding and key-entry noise for NTRU -> LWE.

use std::panic::{AssertUnwindSafe, catch_unwind};

use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::{AsInto, FheUint};
use primus_lwe::{LweCiphertext, LweParameters, LweSecretKey};
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus, UintModulus};
use primus_ntru::{
    NtruCiphertext, NtruLweKeySwitchingKey, NtruLweKeySwitchingWorkspace, NtruSecretKey,
    SecretKeyDistr,
};
use primus_reduce::{Modulus, RingContext};
use primus_test_allocations::{CountingAllocator, measure};
use rand::{Rng, SeedableRng, rngs::StdRng};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

const F: [i128; 8] = [1, -1, 0, 1, 0, 0, -1, 1];
// Even signed sum: this target cannot be padded into an invertible native NTRU key.
const S: [i128; 5] = [1, -1, 0, 1, -1];

fn modulus_value<T: FheUint, M: Modulus<ValueT = T>>(modulus: M) -> u128 {
    modulus
        .explicit_value()
        .map_or(1u128 << T::BITS, |q| q.as_into())
}

fn center(value: i128, q: i128) -> i128 {
    (value + q / 2).rem_euclid(q) - q / 2
}

// u128 covers the exact biased product even for Q=q=2^64 and c=2^64-1.
fn rounded(value: u128, source: u128, target: u128) -> u128 {
    ((value * target + source / 2) / source) % target
}

fn ring_phase(input: &[u128], index: usize, q: u128) -> i128 {
    let n = input.len();
    F.iter()
        .enumerate()
        .map(|(i, &f)| {
            let j = (index + n - i) % n;
            let v = input[j] as i128 * f;
            if i <= index { v } else { -v }
        })
        .sum::<i128>()
        .rem_euclid(q as i128)
}

fn lwe_phase(input: &[u128], q: u128) -> i128 {
    (input[S.len()] as i128
        - input[..S.len()]
            .iter()
            .zip(S)
            .map(|(&a, s)| a as i128 * s)
            .sum::<i128>())
    .rem_euclid(q as i128)
}

fn check<T: FheUint, Q: Modulus<ValueT = T>, M: RingContext<T>>(source: Q, target: M) {
    let source_q = modulus_value::<T, _>(source);
    let q = modulus_value::<T, _>(target);
    let secret = NtruSecretKey::new(
        F.iter().map(|&v| v.as_into()).collect(),
        SecretKeyDistr::UniformTernary,
    );
    let output_secret = LweSecretKey::new(
        S.iter()
            .map(|&v| T::as_from(v.rem_euclid(q as i128)))
            .collect(),
        SecretKeyDistr::UniformTernary,
    );
    let parameters =
        LweParameters::new(S.len(), T::TWO, target, SecretKeyDistr::UniformTernary, 0.7);
    let mut workspace = NtruLweKeySwitchingWorkspace::new(F.len());
    let mut output = LweCiphertext::<T>::new(vec![T::ONE; S.len() + 1]);
    for level_count in [None, Some(2)] {
        let basis = ApproxSignedBasis::new(target.explicit_value(), 4, level_count);
        let mut rng = StdRng::seed_from_u64(0x4e5452554c5745);
        let key = NtruLweKeySwitchingKey::generate(
            &secret,
            source,
            &output_secret,
            &parameters,
            basis,
            &mut rng,
        );
        assert_eq!(key.input_modulus(), source.explicit_value());
        assert_eq!(key.poly_length(), F.len());
        assert_eq!(key.output_dimension(), S.len());
        let basis = key.basis();
        let levels = basis.decompose_length();
        let scalars: Vec<u128> = basis.scalar_iter().map(|v| v.as_into()).collect();
        let entries: Vec<Vec<u128>> = key
            .as_slice()
            .as_chunks::<{ S.len() + 1 }>()
            .0
            .iter()
            .map(|row| row.iter().map(|&v| v.as_into()).collect())
            .collect();
        let row_noise: Vec<i128> = entries
            .iter()
            .enumerate()
            .map(|(j, row)| {
                center(
                    lwe_phase(row, q) - scalars[j % levels] as i128 * F[j / levels],
                    q as i128,
                )
            })
            .collect();
        let edges = [
            0,
            1,
            source_q - 1,
            source_q / 2,
            source_q / 2 - 1,
            (source_q / q.min(source_q)) / 2,
            source_q - 2,
            source_q / 3,
        ];
        for round in 0..4 {
            let raw: Vec<_> = (0..F.len())
                .map(|i| {
                    if round == 3 {
                        0
                    } else {
                        edges[(i + round) % edges.len()]
                    }
                })
                .collect();
            let input = NtruCiphertext::new(raw.iter().map(|&v| T::as_from(v)).collect::<Vec<_>>());
            let switched: Vec<_> = raw.iter().map(|&v| rounded(v, source_q, q)).collect();
            for index in (0..F.len()).rev() {
                let input_phase = ring_phase(&switched, index, q);
                let scaled_phase =
                    rounded(ring_phase(&raw, index, source_q) as u128, source_q, q) as i128;
                // Each coefficient rounds within 1/2; rounding the phase adds at most 1/2.
                assert!(
                    2 * center(input_phase - scaled_phase, q as i128).abs()
                        <= F.iter().map(|v| v.abs()).sum::<i128>() + 1
                );
                let mask: Vec<_> = (0..F.len())
                    .map(|i| {
                        let v = switched[(index + F.len() - i) % F.len()];
                        if i <= index { (q - v) % q } else { v }
                    })
                    .collect();
                // Build the output from independent integer sums of the stored LWE rows.
                let mut expected = vec![0u128; S.len() + 1];
                let mut phase_error = 0i128;
                let mut bound = 0i128;
                for (i, &a) in mask.iter().enumerate() {
                    let (adjusted, mut carry) = basis.init_value_carry(T::as_from(a));
                    let mut reconstructed = 0u128;
                    for (level, decomposer) in basis.decomposer_iter().enumerate() {
                        let (digit, next) = decomposer.decompose(adjusted, carry);
                        carry = next;
                        let d: u128 = digit.as_into();
                        let row = i * levels + level;
                        for (out, &v) in expected.iter_mut().zip(&entries[row]) {
                            *out = (*out + q - (d * v) % q) % q;
                        }
                        reconstructed = (reconstructed + (d * scalars[level]) % q) % q;
                        let term = center(d as i128, q as i128) * row_noise[row];
                        phase_error -= term;
                        bound += term.abs();
                    }
                    let residual = center(a as i128 - reconstructed as i128, q as i128);
                    phase_error += residual * F[i];
                    bound += (residual * F[i]).abs();
                }
                let (_, allocations) = measure(|| {
                    if index == 0 {
                        key.key_switch_to(&input, &mut output, target, &mut workspace);
                    } else {
                        key.key_switch_at_to(&input, index, &mut output, target, &mut workspace);
                    }
                });
                assert_eq!(allocations.count, 0);
                let actual: Vec<u128> = output.as_ref().iter().map(|&v| v.as_into()).collect();
                assert_eq!(actual, expected);
                assert!(actual.iter().all(|&v| v < q));
                assert_eq!(
                    lwe_phase(&actual, q),
                    (input_phase + phase_error).rem_euclid(q as i128)
                );
                assert!(center(lwe_phase(&actual, q) - input_phase, q as i128).abs() <= bound);
                // This fixed fixture's observed-entry bound is nonvacuous, not a tail estimate.
                assert!(bound < q as i128 / 8);
            }
        }
    }
}

fn check_moduli<T: FheUint>() {
    let native = NativeModulus::<T>::new();
    let odd = BarrettModulus::new(T::as_from(65537u32));
    let source = BarrettModulus::new(T::as_from(132120577u32));
    let power = PowOf2Modulus::new(T::ONE << (T::BITS - 4));
    check(native, native);
    check(native, odd);
    check(native, power);
    check(source, odd);
    check(source, source);
    check(source, native);
    check(BarrettModulus::new(T::as_from(131074u32)), odd); // half ties, including endpoint
    check(
        PowOf2Modulus::new(T::ONE << (T::BITS - 2)),
        PowOf2Modulus::new(T::as_from(65536u32)),
    );
    check(UintModulus::new(T::MAX), odd); // full-width explicit source; no narrowing
    check(UintModulus::new(T::MAX), native);
}

#[test]
fn coefficient_rounding_extraction_and_independent_lwe_key_switch() {
    check_moduli::<u32>();
    check_moduli::<u64>();
}

#[test]
fn validation_precedes_output_writes_and_key_sampling() {
    let modulus = BarrettModulus::new(65537u32);
    let params = LweParameters::new(3, 2, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let secret = NtruSecretKey::new(vec![1i32, -1, 0, 1], SecretKeyDistr::UniformTernary);
    let target = LweSecretKey::new(vec![1u32, 0, 1], SecretKeyDistr::UniformBinary);
    let basis = ApproxSignedBasis::new(Some(65537), 4, None);
    let mut rng = StdRng::seed_from_u64(10);
    let key = NtruLweKeySwitchingKey::generate(
        &secret,
        NativeModulus::new(),
        &target,
        &params,
        basis,
        &mut rng,
    );
    for (input_len, index, output_len, scratch_len, q) in [
        (0, 0, 4, 4, 65537),
        (3, 0, 4, 4, 65537),
        (5, 0, 4, 4, 65537),
        (4, 4, 4, 4, 65537),
        (4, usize::MAX, 4, 4, 65537),
        (4, 0, 0, 4, 65537),
        (4, 0, 3, 4, 65537),
        (4, 0, 5, 4, 65537),
        (4, 0, 4, 3, 65537),
        (4, 0, 4, 4, 65539),
    ] {
        let input = NtruCiphertext::new(vec![9u32; input_len]);
        let mut output = LweCiphertext::new(vec![17u32; output_len]);
        let before = output.as_ref().to_vec();
        let mut workspace = NtruLweKeySwitchingWorkspace::new(scratch_len);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                key.key_switch_at_to(
                    &input,
                    index,
                    &mut output,
                    BarrettModulus::new(q),
                    &mut workspace,
                );
            }))
            .is_err()
        );
        assert_eq!(output.as_ref(), before);
    }
    for (f, dimension, basis_q, source_q) in [
        (65537, 3, 65537, 97),
        (-65537, 3, 65537, 97),
        (i32::MIN, 3, 65537, 97),
        (1, 2, 65537, 97),
        (1, 3, 65539, 97),
        (1, 3, 65537, 1),
    ] {
        let mut rng = StdRng::seed_from_u64(11);
        let mut untouched = StdRng::seed_from_u64(11);
        let secret = NtruSecretKey::new(vec![f; 4], SecretKeyDistr::UniformTernary);
        let output_key = LweSecretKey::new(vec![1; dimension], SecretKeyDistr::UniformBinary);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                NtruLweKeySwitchingKey::generate(
                    &secret,
                    UintModulus(source_q),
                    &output_key,
                    &params,
                    ApproxSignedBasis::new(Some(basis_q), 4, None),
                    &mut rng,
                );
            }))
            .is_err()
        );
        assert_eq!(rng.next_u64(), untouched.next_u64());
    }
    assert!(catch_unwind(|| NtruLweKeySwitchingWorkspace::<u32>::new(0)).is_err());
    assert!(catch_unwind(|| NtruLweKeySwitchingWorkspace::<u32>::new(usize::MAX)).is_err());
}

fn check_encrypted_return<T: FheUint, Q: Modulus<ValueT = T>>(
    input: &NtruCiphertext<Vec<T>>,
    secret: &NtruSecretKey<T>,
    source: Q,
) {
    let target = BarrettModulus::new(T::as_from(65537u32));
    let params = LweParameters::new(
        7,
        T::as_from(16u32),
        target,
        SecretKeyDistr::fixed_hamming_weight_binary(7, 2),
        0.7,
    );
    let mut rng = StdRng::seed_from_u64(0x4e54524c57);
    let output_secret = LweSecretKey::generate(&params, &mut rng);
    let key = NtruLweKeySwitchingKey::generate(
        secret,
        source,
        &output_secret,
        &params,
        ApproxSignedBasis::new(target.explicit_value(), 4, None),
        &mut rng,
    );
    let mut workspace = NtruLweKeySwitchingWorkspace::new(secret.poly_length());
    let mut output = LweCiphertext::zero(params.dimension());
    for index in [0, 31, 3, 16, 0] {
        let (_, allocations) =
            measure(|| key.key_switch_at_to(input, index, &mut output, target, &mut workspace));
        assert_eq!(allocations.count, 0);
        assert_eq!(
            output_secret.decrypt(&output, &params),
            T::as_from((3 * index + 1) % 8)
        );
    }
}

fn check_ntt_encryption<T: FheUint, Table: primus_ntt::MonomialNttTable<ValueT = T>>(q: T) {
    use primus_ntru::{NtruParameters, NttNtruSecretKey};
    use primus_poly::Polynomial;
    let modulus = BarrettModulus::new(q);
    let ntt = Table::new(5, modulus).unwrap();
    let params = NtruParameters::new(
        32,
        T::as_from(16u32),
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let mut rng = StdRng::seed_from_u64(0x4e54524e54);
    let (secret, transformed) = NttNtruSecretKey::generate_pair(&params, &ntt, &mut rng).unwrap();
    let message = Polynomial::new(
        (0..32usize)
            .map(|i| T::as_from((3 * i + 1) % 8))
            .collect::<Vec<_>>(),
    );
    let input = transformed
        .encrypt(&message, &params, &ntt, &mut rng)
        .into_coeff_form(&ntt);
    check_encrypted_return(&input, &secret, modulus);
}

fn check_fourier_encryption<T: primus_fft::TorusFftValue, Table: primus_fft::FftTable>() {
    use primus_fft::FftEngine;
    use primus_ntru::{FourierNtruEncryptWorkspace, FourierNtruSecretKey, NtruParameters};
    use primus_poly::Polynomial;
    let table = Table::new(5).unwrap();
    let mut fft = FftEngine::new(&table);
    let modulus = NativeModulus::<T>::new();
    let params = NtruParameters::new(
        32,
        T::as_from(16u32),
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let mut rng = StdRng::seed_from_u64(0x4e54524654);
    let (secret, transformed) =
        FourierNtruSecretKey::generate_pair(&params, &mut fft, &mut rng).unwrap();
    let message = Polynomial::new(
        (0..32usize)
            .map(|i| T::as_from((3 * i + 1) % 8))
            .collect::<Vec<_>>(),
    );
    let mut input = NtruCiphertext::zero(32);
    transformed
        .encrypt(
            &message,
            &params,
            &mut fft,
            &mut rng,
            &mut FourierNtruEncryptWorkspace::new(32),
        )
        .write_torus_form(&mut input, &mut fft);
    check_encrypted_return(&input, &secret, modulus);
}

#[test]
fn encrypted_ntt_and_fourier_return_to_independent_noninvertible_lwe_secret() {
    use primus_fft::{RustFftTable, TfheFftTable};
    check_ntt_encryption::<u32, primus_ntt::U32NttTable>(132_120_577);
    check_ntt_encryption::<u64, primus_ntt::U64NttTable>(1_125_899_906_826_241);
    check_fourier_encryption::<u32, RustFftTable>();
    check_fourier_encryption::<u32, TfheFftTable>();
    check_fourier_encryption::<u64, RustFftTable>();
    check_fourier_encryption::<u64, TfheFftTable>();
}
