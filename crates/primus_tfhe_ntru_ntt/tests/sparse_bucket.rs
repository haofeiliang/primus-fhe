//! B8.1 prototype: NTRU initialization and one bucket, before a sparse server-key API.

use num_traits::{ConstOne, ConstZero};
use primus_integer::{AsInto, FheUint};
use primus_modulus::BarrettModulus;
use primus_ntru::{
    NgswCiphertext, NlevParameters, NtruCiphertext, NtruParameters, NttNlevCiphertext,
    NttNtruExternalProductContext, NttNtruGadgetEncryptContext, NttNtruSecretKey, SecretKeyDistr,
};
use primus_ntt::{NttTable, U32NttTable, U64NttTable};
use primus_poly::Polynomial;
use primus_test_allocations::{CountingAllocator, measure};
use primus_tfhe::sparse::BucketMap;
use rand::{SeedableRng, rngs::StdRng};
use zeroize::Zeroizing;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

// Schoolbook multiplication by the signed secret, independent of NTT arithmetic.
fn phase<T: FheUint>(cipher: &[T], secret: &[T::SignedInteger], q: i128) -> Vec<i128> {
    let n = cipher.len();
    let mut result = vec![0; n];
    for (i, &coefficient) in cipher.iter().enumerate() {
        let coefficient: i128 = coefficient.as_into();
        for (j, &secret) in secret.iter().enumerate() {
            let secret: i128 = secret.as_into();
            let product = coefficient * secret;
            if i + j < n {
                result[i + j] += product;
            } else {
                result[i + j - n] -= product;
            }
        }
    }
    result
        .iter_mut()
        .for_each(|value| *value = value.rem_euclid(q));
    result
}

fn rotate(input: &[i128], exponent: usize, q: i128) -> Vec<i128> {
    let n = input.len();
    let mut result = vec![0; n];
    for (i, &value) in input.iter().enumerate() {
        let index = (i + exponent) % (2 * n);
        result[index % n] = if index < n { value } else { -value }.rem_euclid(q);
    }
    result
}

fn max_error(actual: &[i128], expected: &[i128], q: i128) -> i128 {
    actual
        .iter()
        .zip(expected)
        .map(|(&actual, &expected)| {
            let delta = (actual - expected).rem_euclid(q);
            delta.min(q - delta)
        })
        .max()
        .unwrap()
}

fn check_bucket<T: FheUint, Table: NttTable<ValueT = T>>(q: T) {
    const N: usize = 32;
    const DIM: usize = 16;
    const WEIGHT: usize = 4;
    let q_wide: i128 = q.as_into();
    let modulus = BarrettModulus::new(q);
    let ntt = Table::new(N.trailing_zeros(), modulus).unwrap();
    let client_params = NtruParameters::new(
        N,
        T::as_from(16usize),
        modulus,
        SecretKeyDistr::fixed_hamming_weight_binary(DIM, WEIGHT),
        0.7,
    );
    let mut rng = StdRng::seed_from_u64(0xB801);
    // An even weight is valid for this odd-q NTT ring. Rejection never edits a bit.
    let (client, _) =
        NttNtruSecretKey::generate_padded_pair(&client_params, DIM, &ntt, &mut rng).unwrap();
    let client_before = Zeroizing::new(client.as_slice().to_vec());
    let nonzero_indices = Zeroizing::new(
        client.as_slice()[..DIM]
            .iter()
            .enumerate()
            .filter_map(|(i, &bit)| (bit == T::SignedInteger::ONE).then_some(i))
            .collect::<Vec<_>>(),
    );
    assert_eq!(nonzero_indices.len(), WEIGHT);
    assert!(
        client.as_slice()[DIM..]
            .iter()
            .all(|&v| v == T::SignedInteger::ZERO)
    );

    let params = NtruParameters::new(
        N,
        T::as_from(16usize),
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let gadget = NlevParameters::with_ntru_params(&params, 8, None);
    let basis = gadget.basis();
    let scalars: Vec<i128> = basis.scalar_iter().map(|v| v.as_into()).collect();
    let digit_bound: i128 = basis.basis_value().as_into();
    let digit_bound = digit_bound / 2;
    let residual: i128 = basis.approximate_error_bound().as_into();
    let (secret, key) = NttNtruSecretKey::generate_pair(&params, &ntt, &mut rng).unwrap();
    let secret_coefficients: Vec<i128> = secret.as_slice().iter().map(|&v| v.as_into()).collect();
    let secret_norm: i128 = secret_coefficients.iter().map(|v| v.abs()).sum();

    // NLev[1] has phase g_l + e_l, unlike NGSW[1]'s g_l*f + e_l.
    let mut initializer = NttNlevCiphertext::<Vec<T>>::zero(gadget.nlev_len());
    key.encrypt_nlev_constant_to(
        T::ONE,
        &mut initializer,
        &gadget,
        &ntt,
        &mut rng,
        &mut NttNtruGadgetEncryptContext::new(N),
    );
    let mut init_error_sum = 0;
    for (level, &scalar) in initializer.as_ref().as_chunks::<N>().0.iter().zip(&scalars) {
        let mut coefficients = level.to_vec();
        ntt.inverse_transform_slice(&mut coefficients);
        let mut expected = vec![0; N];
        expected[0] = scalar;
        init_error_sum += max_error(
            &phase(&coefficients, secret.as_slice(), q_wide),
            &expected,
            q_wide,
        );
    }
    let lut: Vec<i128> = (0..N).map(|i| q_wide / 16 * (i % 8) as i128).collect();
    let rotated_lut = rotate(&lut, N + 1, q_wide);
    let encoded = Polynomial::new(
        rotated_lut
            .iter()
            .map(|&v| T::as_from(v))
            .collect::<Vec<_>>(),
    );
    let mut input = NtruCiphertext::<Vec<T>>::zero(N);
    let mut product = NtruCiphertext::<Vec<T>>::zero(N);
    let mut scratch = NttNtruExternalProductContext::new(N);
    let (_, allocations) = measure(|| {
        initializer.external_product_to(&encoded, &mut input, basis, modulus, &ntt, &mut scratch);
    });
    assert_eq!(allocations.count, 0);
    let input_phase = phase(input.as_ref(), secret.as_slice(), q_wide);
    let init_bound = residual + N as i128 * digit_bound * init_error_sum;
    assert!(max_error(&input_phase, &rotated_lut, q_wide) <= init_bound);

    // c=1,b>n guarantees publicly empty buckets as well as occupied/nonempty ones.
    for (copies, buckets) in [(3, 8), (1, DIM + 1)] {
        let (map, selected) =
            BucketMap::try_generate(DIM, copies, buckets, &nonzero_indices, &mut rng).unwrap();
        assert_eq!(client.as_slice(), client_before.as_slice());
        let mut recovered: Vec<_> = selected
            .iter()
            .copied()
            .filter(|&i| i != BucketMap::UNASSIGNED)
            .collect();
        recovered.sort_unstable();
        assert_eq!(recovered, *nonzero_indices);

        // Final coefficient layout: [bucket][entry...,dummy][level][coefficient].
        // Every slot gets fresh noise, including zero selectors and zero dummies.
        let mut bits = Zeroizing::new(Vec::new());
        for (bucket, &chosen) in selected.iter().enumerate() {
            let start = map.bucket_offsets()[bucket];
            let end = map.bucket_offsets()[bucket + 1];
            bits.extend(map.input_indices()[start..end].iter().map(|&i| {
                if i == chosen {
                    T::SignedInteger::ONE
                } else {
                    T::SignedInteger::ZERO
                }
            }));
            bits.push(if chosen == BucketMap::UNASSIGNED {
                T::SignedInteger::ONE
            } else {
                T::SignedInteger::ZERO
            });
        }
        let mut data = vec![T::ZERO; bits.len() * gadget.nlev_len()];
        key.encrypt_ngsw_signed_constant_batch_to(&bits, &mut data, &gadget, &ntt, &mut rng);
        for polynomial in data.as_chunks_mut::<N>().0.iter_mut() {
            ntt.inverse_transform_slice(polynomial);
        }
        // Independently recover every row phase, including encrypted zeros.
        let row_phases: Vec<_> = data
            .as_chunks::<N>()
            .0
            .iter()
            .map(|row| phase(row, secret.as_slice(), q_wide))
            .collect();
        let mut aggregate = vec![q - T::ONE; gadget.nlev_len()];
        let mut public_empty = 0;
        for (bucket, &chosen) in selected.iter().enumerate() {
            let start = map.bucket_offsets()[bucket];
            let end = map.bucket_offsets()[bucket + 1];
            let indices = &map.input_indices()[start..end];
            public_empty += usize::from(indices.is_empty());
            let first = start + bucket;
            let dummy = end + bucket;
            assert_eq!(
                bits[first..=dummy]
                    .iter()
                    .filter(|&&v| v == T::SignedInteger::ONE)
                    .count(),
                1
            );
            let controls = &data[first * gadget.nlev_len()..dummy * gadget.nlev_len()];
            let dummy_control = &data[dummy * gadget.nlev_len()..(dummy + 1) * gadget.nlev_len()];
            // Include identity, sign change, and both sides of negacyclic wrap.
            for shift in [None, Some(N - 1), Some(N), Some(2 * N - 1)] {
                let exponents: Vec<_> = (0..DIM)
                    .map(|i| shift.map_or(0, |s| (s + 7 * i) % (2 * N)))
                    .collect();
                let exponent = if chosen == BucketMap::UNASSIGNED {
                    0
                } else {
                    exponents[chosen]
                };
                let (_, allocations) = measure(|| {
                    aggregate.copy_from_slice(dummy_control);
                    for (&i, control) in
                        indices.iter().zip(controls.chunks_exact(gadget.nlev_len()))
                    {
                        for (output, row) in aggregate
                            .as_chunks_mut::<N>()
                            .0
                            .iter_mut()
                            .zip(control.as_chunks::<N>().0.iter())
                        {
                            Polynomial(output).add_mul_monomial_assign(
                                &Polynomial(row),
                                exponents[i],
                                modulus,
                            );
                        }
                    }
                    NgswCiphertext::new(aggregate.as_mut_slice())
                        .into_ntt_form(&ntt)
                        .external_product_to(
                            &input,
                            &mut product,
                            basis,
                            modulus,
                            &ntt,
                            &mut scratch,
                        );
                });
                assert_eq!(allocations.count, 0);
                // Exact row-phase linearity proves all encrypted-zero/dummy noise was included.
                let mut bucket_error_sum = 0;
                for (level, (&scalar, row)) in scalars
                    .iter()
                    .zip(aggregate.as_chunks::<N>().0.iter())
                    .enumerate()
                {
                    let mut expected = row_phases[dummy * scalars.len() + level].clone();
                    for (slot, &i) in indices.iter().enumerate() {
                        let rotated = rotate(
                            &row_phases[(first + slot) * scalars.len() + level],
                            exponents[i],
                            q_wide,
                        );
                        for (acc, value) in expected.iter_mut().zip(rotated) {
                            *acc = (*acc + value).rem_euclid(q_wide);
                        }
                    }
                    let mut coefficients = row.to_vec();
                    ntt.inverse_transform_slice(&mut coefficients);
                    assert_eq!(phase(&coefficients, secret.as_slice(), q_wide), expected);
                    let target: Vec<_> = rotate(&secret_coefficients, exponent, q_wide)
                        .iter()
                        .map(|&v| (v * scalar).rem_euclid(q_wide))
                        .collect();
                    bucket_error_sum += max_error(&expected, &target, q_wide);
                }
                let bucket_bound =
                    secret_norm * residual + N as i128 * digit_bound * bucket_error_sum;
                // Nonvacuous, fixture-specific bounds; not a Gaussian cutoff or failure rate.
                assert!(init_bound + bucket_bound < q_wide / 32);
                let actual = phase(product.as_ref(), secret.as_slice(), q_wide);
                assert!(
                    max_error(&actual, &rotate(&input_phase, exponent, q_wide), q_wide)
                        <= bucket_bound
                );
                assert!(
                    max_error(&actual, &rotate(&rotated_lut, exponent, q_wide), q_wide)
                        <= init_bound + bucket_bound
                );
            }
        }
        if copies == 1 {
            assert!(public_empty > 0);
        }
    }
}

#[test]
fn sparse_ngsw_bucket_preserves_rotation_and_budgets_encrypted_initialization() {
    check_bucket::<u32, U32NttTable>(132_120_577);
    check_bucket::<u64, U64NttTable>(1_125_899_906_826_241);
}
