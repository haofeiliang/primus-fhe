//! Independent coefficient phases, rounding and key-entry noise for NTRU -> LWE.

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_lattice::LweDimension;
use primus_poly::PolyLength;
use std::panic::{AssertUnwindSafe, catch_unwind};

use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::{AsInto, FheUint};
use primus_lattice::lwe::LweIter;
use primus_lwe::{LweCiphertext, LweParameters, LweSecretKey};
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus, UintModulus};
use primus_ntru::{
    NtruCiphertext, NtruLweKeySwitchingBatchWorkspace, NtruLweKeySwitchingKey,
    NtruLweKeySwitchingWorkspace, NtruSecretKey, SecretKeyDistr,
};
use primus_reduce::{Modulus, RingContext};
use primus_test_allocations::{CountingAllocator, measure};
use rand::{Rng, SeedableRng, rngs::StdRng};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

const N: usize = 32;
const F: [i128; N] = {
    let mut secret = [0; N];
    secret[0] = 1;
    secret[1] = -1;
    secret[3] = 1;
    secret[6] = -1;
    secret[7] = 1;
    secret
};
// Even signed sum: this target cannot be padded into an invertible native NTRU key.
const S: [i128; 5] = [1, -1, 0, 1, -1];

// Represent native and explicit moduli uniformly, including 2^64.
fn modulus_value<T: FheUint, M: Modulus<ValueT = T>>(modulus: M) -> u128 {
    modulus
        .explicit_value()
        .map_or(1u128 << T::BITS, |q| q.as_into())
}

// Choose a signed representative for circular phase-error comparisons.
fn center(value: i128, q: i128) -> i128 {
    (value + q / 2).rem_euclid(q) - q / 2
}

// u128 covers the exact biased product even for Q=q=2^64 and c=2^64-1.
fn rounded(value: u128, source: u128, target: u128) -> u128 {
    ((value * target + source / 2) / source) % target
}

// Independent negacyclic coefficient of f*c under the fixed signed secret F.
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

// Independent b-<a,S> phase under the target secret.
fn lwe_phase(input: &[u128], q: u128) -> i128 {
    (input[S.len()] as i128
        - input[..S.len()]
            .iter()
            .zip(S)
            .map(|(&a, s)| a as i128 * s)
            .sum::<i128>())
    .rem_euclid(q as i128)
}

// Cache one key's rows and observed row noise for independent integer accumulation.
// Gadget decomposition is shared with the basis API; products, modular sums and
// negacyclic phase checks are computed with u128/i128 instead of the return kernel.
struct ReturnOracle<'a, T: FheUint> {
    basis: &'a ApproxSignedBasis<T>,
    q: u128,
    scalars: Vec<u128>,
    entries: Vec<Vec<u128>>,
    row_noise: Vec<i128>,
}

impl<'a, T: FheUint> ReturnOracle<'a, T> {
    // Decode the stored key rows once, reusing them for every input and coefficient.
    fn new(key: &'a NtruLweKeySwitchingKey<T>, q: u128) -> Self {
        let basis = key.basis();
        let levels = basis.decompose_length().get();
        let scalars: Vec<u128> = basis.scalar_iter().map(|v| v.as_into()).collect();
        let entries: Vec<Vec<u128>> = LweIter::new(key.as_slice(), S.len() + 1)
            .map(|row| row.as_ref().iter().map(|&v| v.as_into()).collect())
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
        Self {
            basis,
            q,
            scalars,
            entries,
            row_noise,
        }
    }

    // Check exact ciphertext coefficients and the phase error from rounding,
    // decomposition residuals and the actual sampled key-entry noise.
    fn assert_output(
        &self,
        raw: &[u128],
        switched: &[u128],
        source_q: u128,
        index: usize,
        output: &LweCiphertext<T>,
    ) {
        let q = self.q;
        let levels = self.basis.decompose_length().get();
        let input_phase = ring_phase(switched, index, q);
        let scaled_phase = rounded(ring_phase(raw, index, source_q) as u128, source_q, q) as i128;
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
            let (adjusted, mut carry) = self.basis.init_value_carry(T::as_from(a));
            let mut reconstructed = 0u128;
            for (level, decomposer) in self.basis.decomposer_iter().enumerate() {
                let (digit, next) = decomposer.decompose(adjusted, carry);
                carry = next;
                let d: u128 = digit.as_into();
                let row = i * levels + level;
                for (out, &v) in expected.iter_mut().zip(&self.entries[row]) {
                    *out = (*out + q - (d * v) % q) % q;
                }
                reconstructed = (reconstructed + (d * self.scalars[level]) % q) % q;
                let term = center(d as i128, q as i128) * self.row_noise[row];
                phase_error -= term;
                bound += term.abs();
            }
            let residual = center(a as i128 - reconstructed as i128, q as i128);
            phase_error += residual * F[i];
            bound += (residual * F[i]).abs();
        }
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

// Exercise wrap, half ties, negacyclic signs and a final zero input after dirty reuse.
fn coefficient_inputs<T: FheUint>(source_q: u128, q: u128) -> Vec<NtruCiphertext<Vec<T>>> {
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
    (0..4)
        .map(|round| {
            NtruCiphertext::new(
                (0..F.len())
                    .map(|i| {
                        T::as_from(if round == 3 {
                            0
                        } else {
                            edges[(i + round) % edges.len()]
                        })
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .collect()
}

// Establish an integer-checked result for each source/index pair. Later batch
// comparisons reuse these ciphertexts, so their oracle is not another batch path.
fn check_scalar_returns<T: FheUint, M: RingContext<T>>(
    key: &NtruLweKeySwitchingKey<T>,
    inputs: &[NtruCiphertext<Vec<T>>],
    source_q: u128,
    target: M,
) -> Vec<Vec<LweCiphertext<T>>> {
    let q = modulus_value::<T, _>(target);
    let oracle = ReturnOracle::new(key, q);
    let mut workspace = NtruLweKeySwitchingWorkspace::new(PolyLength::new(F.len()));
    let mut output = LweCiphertext::<T>::new(vec![T::ONE; S.len() + 1]);
    let mut expected_inputs = Vec::new();
    for input in inputs {
        let raw: Vec<u128> = input.as_ref().iter().map(|&v| v.as_into()).collect();
        let switched: Vec<_> = raw.iter().map(|&v| rounded(v, source_q, q)).collect();
        let mut expected = vec![output.clone(); F.len()];
        for index in (0..F.len()).rev() {
            let (_, allocations) = measure(|| {
                if index == 0 {
                    key.key_switch_to(input, &mut output, target, &mut workspace);
                } else {
                    key.key_switch_at_to(input, index, &mut output, target, &mut workspace);
                }
            });
            assert_eq!(allocations.count, 0);
            oracle.assert_output(&raw, &switched, source_q, index, &output);
            expected[index].as_mut().copy_from_slice(output.as_ref());
        }
        expected_inputs.push(expected);
    }
    expected_inputs
}

// Shared-input returns preserve repeated/nonmonotonic indices across two tiles
// and a tail. Singleton and empty requests reuse the same dirty buffers.
fn check_shared_input_returns<T: FheUint, M: RingContext<T>>(
    key: &NtruLweKeySwitchingKey<T>,
    inputs: &[NtruCiphertext<Vec<T>>],
    expected_inputs: &[Vec<LweCiphertext<T>>],
    target: M,
    workspace: &mut NtruLweKeySwitchingBatchWorkspace<T>,
    outputs: &mut [LweCiphertext<T>],
) {
    for (input, expected) in inputs.iter().zip(expected_inputs) {
        for count in [17, 1, 0] {
            let indices = (0..count).map(|i| (3 * i + 1) % F.len());
            let (_, allocations) = measure(|| {
                key.key_switch_many_at_to(
                    input,
                    indices.clone(),
                    &mut outputs[..count],
                    target,
                    workspace,
                );
            });
            assert_eq!(allocations.count, 0);
            for (output, index) in outputs[..count].iter().zip(indices) {
                assert_eq!(output, &expected[index]);
            }
        }
    }
}

// Streamed returns retain extracted LWEs while the single source buffer is
// overwritten before KS. A short final tile must ignore older slots past its end.
fn check_streamed_returns<T: FheUint, M: RingContext<T>>(
    key: &NtruLweKeySwitchingKey<T>,
    inputs: &[NtruCiphertext<Vec<T>>],
    expected_inputs: &[Vec<LweCiphertext<T>>],
    target: M,
    workspace: &mut NtruLweKeySwitchingBatchWorkspace<T>,
    outputs: &mut [LweCiphertext<T>],
) {
    let mut current = NtruCiphertext::<Vec<T>>::zero(F.len());
    let capacity = workspace.batch_capacity();
    for slot in 0..capacity {
        workspace.extracted_slot_mut(slot).as_mut().fill(T::ONE);
    }
    for count in [17, 1, 0] {
        let (_, allocations) = measure(|| {
            for (tile, outputs) in outputs[..count].chunks_mut(capacity).enumerate() {
                for slot in 0..outputs.len() {
                    let i = tile * capacity + slot;
                    current
                        .as_mut()
                        .copy_from_slice(inputs[i % inputs.len()].as_ref());
                    key.modulus_switch_extract_at_to(
                        current.as_view(),
                        (3 * i + 1) % F.len(),
                        workspace.extracted_slot_mut(slot),
                        target,
                    );
                    current.as_mut().fill(T::ZERO);
                }
                key.key_switch_extracted_batch_to(outputs, target, workspace);
            }
            if count == 0 {
                key.key_switch_extracted_batch_to(&mut outputs[..0], target, workspace);
            }
        });
        assert_eq!(allocations.count, 0);
        for (i, output) in outputs[..count].iter().enumerate() {
            assert_eq!(
                output,
                &expected_inputs[i % inputs.len()][(3 * i + 1) % F.len()]
            );
        }
    }
}

// Generate each modulus/basis fixture once for all three return paths.
fn check_modulus_pair<T: FheUint, Q: Modulus<ValueT = T>, M: RingContext<T>>(source: Q, target: M) {
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
        target,
    );
    let parameters = LweParameters::new(
        LweDimension::new(S.len()),
        T::TWO,
        target,
        SecretKeyDistr::UniformTernary,
        0.7,
    );
    let inputs = coefficient_inputs(source_q, q);
    let mut workspace = NtruLweKeySwitchingBatchWorkspace::new(
        PolyLength::new(F.len()),
        LweDimension::new(S.len()),
    );
    let mut outputs = vec![LweCiphertext::new(vec![T::ONE; S.len() + 1]); 17];
    for level_count in [None, Some(2)] {
        let basis = ApproxSignedBasis::new(
            target.explicit_value(),
            DecompositionBaseLog::new(4),
            level_count.map(DecompositionLevelCount::new),
        );
        let mut rng = StdRng::seed_from_u64(0x4e5452554c5745);
        let key = NtruLweKeySwitchingKey::generate(
            &secret,
            source,
            &output_secret,
            parameters.encryption_parameters(),
            basis,
            &mut rng,
        );
        assert_eq!(key.input_modulus(), source.explicit_value());
        assert_eq!(key.poly_length(), F.len());
        assert_eq!(key.output_dimension(), LweDimension::new(S.len()));
        let expected = check_scalar_returns(&key, &inputs, source_q, target);
        check_shared_input_returns(
            &key,
            &inputs,
            &expected,
            target,
            &mut workspace,
            &mut outputs,
        );
        check_streamed_returns(
            &key,
            &inputs,
            &expected,
            target,
            &mut workspace,
            &mut outputs,
        );
    }
}

// Keep both word widths on the same source/target modulus and rounding matrix.
fn check_moduli<T: FheUint>() {
    let native = NativeModulus::<T>::new();
    let odd = BarrettModulus::new(T::as_from(65537u32));
    let source = BarrettModulus::new(T::as_from(132120577u32));
    let power = PowOf2Modulus::new(T::ONE << (T::BITS - 4));
    check_modulus_pair(native, native);
    check_modulus_pair(native, odd);
    check_modulus_pair(native, power);
    check_modulus_pair(source, odd);
    check_modulus_pair(source, source);
    check_modulus_pair(source, native);
    check_modulus_pair(BarrettModulus::new(T::as_from(131074u32)), odd); // half ties, including endpoint
    check_modulus_pair(
        PowOf2Modulus::new(T::ONE << (T::BITS - 2)),
        PowOf2Modulus::new(T::as_from(65536u32)),
    );
    check_modulus_pair(UintModulus::new(T::MAX), odd); // full-width explicit source; no narrowing
    check_modulus_pair(UintModulus::new(T::MAX), native);
}

// Scalar integer oracles also anchor the two batch paths at both word widths.
#[test]
fn coefficient_rounding_extraction_and_independent_lwe_key_switch() {
    check_moduli::<u32>();
    check_moduli::<u64>();
}

// Invalid scalar inputs leave the caller's output unchanged.
fn check_scalar_errors(key: &NtruLweKeySwitchingKey<u32>) {
    for (input_len, index, output_len, scratch_len, q) in [
        (0, 0, 4, N, 65537),
        (N - 1, 0, 4, N, 65537),
        (N + 1, 0, 4, N, 65537),
        (N, N, 4, N, 65537),
        (N, usize::MAX, 4, N, 65537),
        (N, 0, 0, N, 65537),
        (N, 0, 3, N, 65537),
        (N, 0, 5, N, 65537),
        (N, 0, 4, 2 * N, 65537),
        (N, 0, 4, N, 65539),
    ] {
        let input = NtruCiphertext::new(vec![9u32; input_len]);
        let mut output = LweCiphertext::new(vec![17u32; output_len]);
        let before = output.as_ref().to_vec();
        let mut workspace = NtruLweKeySwitchingWorkspace::new(PolyLength::new(scratch_len));
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
}

// Validate all indices and output shapes before any shared-input batch write.
fn check_shared_input_errors(key: &NtruLweKeySwitchingKey<u32>) {
    // Reject the complete batch before touching its first output, even when
    // the invalid index or ciphertext is last. Other rows isolate each binding.
    for (input_len, indices, output_lens, scratch_n, scratch_dimension, q) in [
        (N, [0, N], vec![4, 4], N, 3, 65537),
        (N, [0, 1], vec![4], N, 3, 65537),
        (N, [0, 1], vec![4, 4, 4], N, 3, 65537),
        (N, [0, 1], vec![4, 3], N, 3, 65537),
        (N - 1, [0, 1], vec![4, 4], N, 3, 65537),
        (N, [0, 1], vec![4, 4], 2 * N, 3, 65537),
        (N, [0, 1], vec![4, 4], N, 2, 65537),
        (N, [0, 1], vec![4, 4], N, 3, 65539),
    ] {
        let input = NtruCiphertext::new(vec![9u32; input_len]);
        let mut outputs: Vec<_> = output_lens
            .into_iter()
            .map(|len| LweCiphertext::new(vec![17u32; len]))
            .collect();
        let before = outputs.clone();
        let mut workspace = NtruLweKeySwitchingBatchWorkspace::new(
            PolyLength::new(scratch_n),
            LweDimension::new(scratch_dimension),
        );
        assert!(
            catch_unwind(AssertUnwindSafe(|| key.key_switch_many_at_to(
                &input,
                indices.into_iter(),
                &mut outputs,
                BarrettModulus::new(q),
                &mut workspace,
            )))
            .is_err()
        );
        assert_eq!(outputs, before);
    }
}

// Check extraction, filled-prefix bounds and slot access as separate boundaries.
fn check_streamed_errors(key: &NtruLweKeySwitchingKey<u32>) {
    for (input_len, index, output_len, q) in [
        (N - 1, 0, N + 1, 65537),
        (N, N, N + 1, 65537),
        (N, 0, N, 65537),
        (N, 0, N + 1, 65539),
    ] {
        let input = NtruCiphertext::new(vec![9u32; input_len]);
        let mut extracted = LweCiphertext::new(vec![17u32; output_len]);
        let before = extracted.clone();
        assert!(
            catch_unwind(AssertUnwindSafe(|| key.modulus_switch_extract_at_to(
                input.as_view(),
                index,
                extracted.as_mut_view(),
                BarrettModulus::new(q),
            )))
            .is_err()
        );
        assert_eq!(extracted, before);
    }
    for (count, last_len, scratch_n, scratch_dimension, q) in [
        (9, 4, N, 3, 65537),
        (2, 3, N, 3, 65537),
        (2, 4, 2 * N, 3, 65537),
        (2, 4, N, 2, 65537),
        (2, 4, N, 3, 65539),
    ] {
        let mut outputs = vec![LweCiphertext::new(vec![17u32; 4]); count];
        *outputs.last_mut().unwrap() = LweCiphertext::new(vec![17; last_len]);
        let before = outputs.clone();
        let mut workspace = NtruLweKeySwitchingBatchWorkspace::new(
            PolyLength::new(scratch_n),
            LweDimension::new(scratch_dimension),
        );
        assert!(
            catch_unwind(AssertUnwindSafe(|| key.key_switch_extracted_batch_to(
                &mut outputs,
                BarrettModulus::new(q),
                &mut workspace,
            )))
            .is_err()
        );
        assert_eq!(outputs, before);
    }
    let mut workspace =
        NtruLweKeySwitchingBatchWorkspace::<u32>::new(PolyLength::new(32), LweDimension::new(3));
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _ = workspace.extracted_slot_mut(workspace.batch_capacity());
        }))
        .is_err()
    );
}

// Invalid key bindings must fail before consuming randomness.
fn check_generation_errors(params: &LweParameters<u32, BarrettModulus<u32>>) {
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
        let secret = NtruSecretKey::new(vec![f; N], SecretKeyDistr::UniformTernary);
        let output_key = LweSecretKey::new(
            vec![1; dimension],
            SecretKeyDistr::UniformBinary,
            params.cipher_modulus(),
        );
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                NtruLweKeySwitchingKey::generate(
                    &secret,
                    UintModulus(source_q),
                    &output_key,
                    params.encryption_parameters(),
                    ApproxSignedBasis::new(Some(basis_q), DecompositionBaseLog::new(4), None),
                    &mut rng,
                );
            }))
            .is_err()
        );
        assert_eq!(rng.next_u64(), untouched.next_u64());
    }
}

// A valid dimension can still overflow the batch tile length.
fn check_workspace_errors() {
    assert!(
        catch_unwind(|| NtruLweKeySwitchingBatchWorkspace::<u32>::new(
            PolyLength::new(32),
            LweDimension::new(usize::MAX / 8)
        ))
        .is_err()
    );
}

// One small key serves every evaluation boundary; invalid generation preserves RNG state.
#[test]
fn validation_precedes_output_writes_and_key_sampling() {
    let modulus = BarrettModulus::new(65537u32);
    let params = LweParameters::new(
        LweDimension::new(3),
        2,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let secret = NtruSecretKey::new(
        F.iter().map(|&value| value as i32).collect(),
        SecretKeyDistr::UniformTernary,
    );
    let target = LweSecretKey::new(
        vec![1u32, 0, 1],
        SecretKeyDistr::UniformBinary,
        params.cipher_modulus(),
    );
    let basis = ApproxSignedBasis::new(Some(65537), DecompositionBaseLog::new(4), None);
    let mut rng = StdRng::seed_from_u64(10);
    let key = NtruLweKeySwitchingKey::generate(
        &secret,
        NativeModulus::new(),
        &target,
        params.encryption_parameters(),
        basis,
        &mut rng,
    );
    check_scalar_errors(&key);
    check_shared_input_errors(&key);
    check_streamed_errors(&key);
    check_generation_errors(&params);
    check_workspace_errors();
}

// Return actual encrypted coefficients to an independent, noninvertible LWE secret.
fn check_encrypted_return<T: FheUint, Q: Modulus<ValueT = T>>(
    input: &NtruCiphertext<Vec<T>>,
    secret: &NtruSecretKey<T>,
    source: Q,
) {
    let target = BarrettModulus::new(T::as_from(65537u32));
    let params = LweParameters::new(
        LweDimension::new(7),
        T::as_from(16u32),
        target,
        SecretKeyDistr::fixed_hamming_weight_binary(7, 2),
        0.7,
    );
    let mut rng = StdRng::seed_from_u64(0x4e54524c57);
    let output_secret = LweSecretKey::generate(params.encryption_parameters(), &mut rng);
    let key = NtruLweKeySwitchingKey::generate(
        secret,
        source,
        &output_secret,
        params.encryption_parameters(),
        ApproxSignedBasis::new(target.explicit_value(), DecompositionBaseLog::new(4), None),
        &mut rng,
    );
    let mut workspace = NtruLweKeySwitchingWorkspace::new(PolyLength::new(secret.poly_length()));
    let mut output = LweCiphertext::zero(params.dimension().get());
    for index in [0, 31, 3, 16, 0] {
        let (_, allocations) =
            measure(|| key.key_switch_at_to(input, index, &mut output, target, &mut workspace));
        assert_eq!(allocations.count, 0);
        assert_eq!(
            output_secret.decrypt_message(&output, &params),
            T::as_from((3 * index + 1) % 8)
        );
    }
}

// Recover an NTT ciphertext to coefficients before exercising the common return API.
fn check_ntt_encryption<T: FheUint, Table: primus_ntt::MonomialNttTable<ValueT = T>>(q: T) {
    use primus_ntru::{NtruParameters, NttNtruSecretKey};
    use primus_poly::Polynomial;
    let modulus = BarrettModulus::new(q);
    let ntt = Table::new(PolyLength::new(32), modulus).unwrap();
    let params = NtruParameters::new(
        PolyLength::new(32),
        T::as_from(16u32),
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let mut rng = StdRng::seed_from_u64(0x4e54524e54);
    let (secret, transformed) =
        NttNtruSecretKey::generate_pair(params.encryption_parameters(), &ntt, &mut rng).unwrap();
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

// Include each FFT backend's torus recovery error in the encrypted return check.
fn check_fourier_encryption<T: primus_fft::TorusFftValue, Table: primus_fft::FftTable>() {
    use primus_fft::FftEngine;
    use primus_ntru::{FourierNtruEncryptWorkspace, FourierNtruSecretKey, NtruParameters};
    use primus_poly::Polynomial;
    let table = Table::new(PolyLength::new(32));
    let mut fft = FftEngine::new(&table);
    let modulus = NativeModulus::<T>::new();
    let params = NtruParameters::new(
        PolyLength::new(32),
        T::as_from(16u32),
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let mut rng = StdRng::seed_from_u64(0x4e54524654);
    let (secret, transformed) =
        FourierNtruSecretKey::generate_pair(params.encryption_parameters(), &mut fft, &mut rng)
            .unwrap();
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
            &mut FourierNtruEncryptWorkspace::new(PolyLength::new(32)),
        )
        .write_torus_form(&mut input, &mut fft);
    check_encrypted_return(&input, &secret, modulus);
}

// Cover backend conversion and key independence beyond synthetic coefficient fixtures.
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
