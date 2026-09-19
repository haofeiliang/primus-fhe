//! Independent coefficient phases and FFT error in NTRU bucket aggregation.

use num_traits::{ConstOne, ConstZero};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_integer::SignedInteger;
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_ntru::{
    FourierNgswCiphertext, FourierNlevCiphertext, FourierNtruExternalProductContext,
    FourierNtruGadgetEncryptContext, FourierNtruSecretKey, NgswCiphertext, NlevCiphertext,
    NlevParameters, NtruCiphertext, NtruParameters, SecretKeyDistr,
};
use primus_poly::Polynomial;
use primus_test_allocations::{CountingAllocator, measure};
use primus_tfhe_ntru_fourier::{ClientKey, KeyGenerator, TfheContext, TfheParameters};
use rand::{SeedableRng, rngs::StdRng};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

const N: usize = 32;
const DIM: usize = 16;
const WEIGHT: usize = 5;

// Independent exact negacyclic convolution modulo 2^w.
fn product<T: TorusFftValue>(a: &[T], b: &[T]) -> Vec<T> {
    let mut output = vec![T::ZERO; a.len()];
    for (i, &a) in a.iter().enumerate() {
        for (j, &b) in b.iter().enumerate() {
            let k = (i + j) % output.len();
            let ab = a.wrapping_mul(b);
            output[k] = if i + j < output.len() {
                output[k].wrapping_add(ab)
            } else {
                output[k].wrapping_sub(ab)
            };
        }
    }
    output
}

fn rotate<T: TorusFftValue>(input: &[T], exponent: usize) -> Vec<T> {
    let n = input.len();
    let mut output = vec![T::ZERO; n];
    for (i, &v) in input.iter().enumerate() {
        let k = (i + exponent) % (2 * n);
        output[k % n] = if k < n { v } else { v.wrapping_neg() };
    }
    output
}

fn error<T: TorusFftValue>(a: &[T], b: &[T]) -> u128 {
    a.iter()
        .zip(b)
        .map(|(&a, &b)| {
            let distance: u128 = a.wrapping_sub(b).min(b.wrapping_sub(a)).as_into();
            distance
        })
        .max()
        .unwrap()
}

// Gadget digits use the basis contract; products and accumulation are integer schoolbook.
fn exact_external<T: TorusFftValue>(
    input: &[T],
    rows: &[T],
    basis: &ApproxSignedBasis<T>,
) -> Vec<T> {
    let mut carries = vec![false; input.len()];
    basis.init_carry_slice(input, &mut carries);
    let mut digits = vec![T::ZERO; input.len()];
    let mut output = vec![T::ZERO; input.len()];
    for (decomposer, row) in basis.decomposer_iter().zip(rows.chunks_exact(input.len())) {
        decomposer.decompose_slice_to(input, &mut digits, &mut carries);
        for (a, b) in output.iter_mut().zip(product(&digits, row)) {
            *a = a.wrapping_add(b);
        }
    }
    output
}

fn check<T: TorusFftValue, Table: FftTable>() {
    let table = Table::new(N.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    let modulus = NativeModulus::<T>::new();
    let client_params = NtruParameters::new(
        N,
        T::as_from(16usize),
        modulus,
        SecretKeyDistr::fixed_hamming_weight_binary(DIM, WEIGHT),
        0.7,
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
    let mut rng = StdRng::seed_from_u64(0xB803);
    let (client, _) =
        FourierNtruSecretKey::generate_padded_pair(&client_params, DIM, &mut fft, &mut rng)
            .unwrap();
    let support: Vec<_> = client.as_slice()[..DIM]
        .iter()
        .enumerate()
        .filter_map(|(i, &v)| (v == T::SignedInteger::ONE).then_some(i))
        .collect();
    assert_eq!(support.len(), WEIGHT);
    let (secret, key) = FourierNtruSecretKey::generate_pair(&params, &mut fft, &mut rng).unwrap();
    drop(fft);
    let context = TfheContext::try_new(
        TfheParameters::try_new(
            LweParameters::new(
                DIM,
                T::as_from(16usize),
                modulus,
                client_params.secret_key_distr(),
                0.7,
            ),
            gadget.clone(),
            NlevParameters::with_ntru_params(&client_params, 8, None),
        )
        .unwrap(),
        table,
    )
    .unwrap();
    let mut fft = context.new_fft_engine();
    let imported = ClientKey::new(client, secret.clone(), DIM);
    let native_secret: Vec<T> = secret
        .as_slice()
        .iter()
        .map(|&s| s.cast_to_unsigned())
        .collect();
    let norm = secret
        .as_slice()
        .iter()
        .filter(|&&s| s != T::SignedInteger::ZERO)
        .count() as u128;
    let mut encrypt = FourierNtruGadgetEncryptContext::new(N);
    let mut initializer = FourierNlevCiphertext::<Vec<Complex64>>::zero(gadget.fourier_nlev_len());
    key.encrypt_nlev_constant_to(
        T::ONE,
        &mut initializer,
        &gadget,
        &mut fft,
        &mut rng,
        &mut encrypt,
    );
    let mut initializer_coeff = NlevCiphertext::<Vec<T>>::zero(gadget.nlev_len());
    initializer.write_torus_form(&mut initializer_coeff, &mut fft);
    let lut: Vec<_> = (0..N).map(|i| T::as_from(i % 8) << (T::BITS - 4)).collect();
    let mut current = NtruCiphertext::<Vec<T>>::zero(N);
    let mut scratch = NtruCiphertext::<Vec<T>>::zero(N);
    let mut ep = FourierNtruExternalProductContext::new(N);
    let (_, allocation) = measure(|| {
        initializer.external_product_to(
            &Polynomial(lut.as_slice()),
            &mut current,
            basis,
            &mut fft,
            &mut ep,
        )
    });
    assert_eq!(allocation.count, 0);
    let init_error = error(&product(current.as_ref(), &native_secret), &lut);
    let init_numeric = error(
        current.as_ref(),
        &exact_external(&lut, initializer_coeff.as_ref(), basis),
    );
    let q = 1u128 << T::BITS;
    assert!(init_error < q / 64);
    let residual: u128 = basis.approximate_error_bound().as_into();
    let digit_bound: u128 = basis.basis_value().as_into();
    let init_row_error: u128 = initializer_coeff
        .as_ref()
        .as_chunks::<N>()
        .0
        .iter()
        .zip(basis.scalar_iter())
        .map(|(row, scalar)| {
            let mut target = vec![T::ZERO; N];
            target[0] = scalar;
            error(&product(row, &native_secret), &target)
        })
        .sum();
    let init_budget =
        residual + N as u128 * (digit_bound / 2) * init_row_error + norm * init_numeric;
    assert!(init_budget < q / 32 && init_error <= init_budget);
    for (copies, buckets) in [(3, 10), (1, 17)] {
        let server = KeyGenerator::new(&context)
            .try_generate_sparse_server_key(&imported, copies, buckets, &mut rng)
            .unwrap();
        let sparse = server.sparse_bootstrapping_key().unwrap();
        let mut selected_counts = [0; DIM];
        for j in 0..sparse.bucket_count() {
            let (indices, controls) = sparse.bucket(j);
            let data: Vec<_> = controls.flat_map(|row| row.0.iter().copied()).collect();
            let rows: Vec<_> = data
                .as_chunks::<N>()
                .0
                .iter()
                .map(|row| product(row, &native_secret))
                .collect();
            // Decode a control only for this independent secret-side test.
            let top = basis.scalar_iter().last().unwrap();
            let target: Vec<_> = native_secret.iter().map(|&v| v.wrapping_mul(top)).collect();
            let zero = vec![T::ZERO; N];
            let bits: Vec<_> = rows
                .chunks_exact(gadget.decompose_length())
                .map(|control| {
                    let row = control.last().unwrap();
                    let e0 = error(row, &zero);
                    let e1 = error(row, &target);
                    assert!(e0.min(e1) < q / 1024);
                    usize::from(e1 < e0)
                })
                .collect();
            assert_eq!(bits.iter().sum::<usize>(), 1);
            let mut chosen = None;
            for (&index, &bit) in indices.iter().zip(&bits) {
                selected_counts[index] += bit;
                if bit == 1 {
                    chosen = Some(index);
                }
            }
            for shift in [0, N - 1, N + 1] {
                let exponents: Vec<_> = (0..DIM)
                    .map(|i| {
                        if shift == 0 {
                            0
                        } else {
                            (shift + 7 * i) % (2 * N)
                        }
                    })
                    .collect();
                let exponent = chosen.map_or(0, |i| exponents[i]);
                let mut aggregate = NgswCiphertext::<Vec<T>>::zero(gadget.nlev_len());
                let mut transformed =
                    FourierNgswCiphertext::<Vec<Complex64>>::zero(gadget.fourier_nlev_len());
                let before = product(current.as_ref(), &native_secret);
                let (_, allocation) = measure(|| {
                    let (controls, dummy) =
                        data.as_slice().split_at(indices.len() * gadget.nlev_len());
                    aggregate.as_mut().copy_from_slice(dummy);
                    for (&i, control) in
                        indices.iter().zip(controls.chunks_exact(gadget.nlev_len()))
                    {
                        for (acc, row) in aggregate
                            .as_mut()
                            .as_chunks_mut::<N>()
                            .0
                            .iter_mut()
                            .zip(control.as_chunks::<N>().0.iter())
                        {
                            Polynomial(acc).add_mul_monomial_assign(
                                &Polynomial(row),
                                exponents[i],
                                modulus,
                            );
                        }
                    }
                    aggregate.write_fourier_form(&mut transformed, &mut fft);
                    transformed.external_product_to(
                        &current,
                        &mut scratch,
                        basis,
                        &mut fft,
                        &mut ep,
                    );
                });
                assert_eq!(allocation.count, 0);
                let expected_control = rotate(&native_secret, exponent);
                let mut row_error_sum = 0;
                let mut recovered = NgswCiphertext::<Vec<T>>::zero(gadget.nlev_len());
                transformed.write_torus_form(&mut recovered, &mut fft);
                assert!(error(aggregate.as_ref(), recovered.as_ref()) <= q / (1u128 << 40) + 1);
                for (level, (row, scalar)) in aggregate
                    .as_ref()
                    .as_chunks::<N>()
                    .0
                    .iter()
                    .zip(basis.scalar_iter())
                    .enumerate()
                {
                    let phase = product(row, &native_secret);
                    let mut linear =
                        rows[indices.len() * gadget.decompose_length() + level].clone();
                    for (slot, &i) in indices.iter().enumerate() {
                        for (a, b) in linear.iter_mut().zip(rotate(
                            &rows[slot * gadget.decompose_length() + level],
                            exponents[i],
                        )) {
                            *a = a.wrapping_add(b);
                        }
                    }
                    assert_eq!(phase, linear);
                    let target: Vec<_> = expected_control
                        .iter()
                        .map(|&v| v.wrapping_mul(scalar))
                        .collect();
                    row_error_sum += error(&phase, &target);
                }
                let exact = exact_external(current.as_ref(), aggregate.as_ref(), basis);
                let numerical = error(scratch.as_ref(), &exact);
                let added = error(
                    &product(scratch.as_ref(), &native_secret),
                    &rotate(&before, exponent),
                );
                let budget = norm * residual
                    + N as u128 * (digit_bound / 2) * row_error_sum
                    + norm * numerical;
                assert!(budget < q / 32);
                assert!(added <= budget);
                // A fixed regression allowance, not a general FFT error theorem.
                assert!(numerical <= q / (1u128 << 40) + 1);
                std::mem::swap(&mut current, &mut scratch);
            }
        }
        for (i, count) in selected_counts.into_iter().enumerate() {
            assert_eq!(count, usize::from(support.contains(&i)));
        }
    }
}

#[test]
fn sparse_bucket_fourier_phase_and_numerical_budgets() {
    check::<u32, RustFftTable>();
    check::<u32, TfheFftTable>();
    check::<u64, RustFftTable>();
    check::<u64, TfheFftTable>();
}
