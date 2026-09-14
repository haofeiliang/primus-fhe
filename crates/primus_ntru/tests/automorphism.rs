use std::panic::{AssertUnwindSafe, catch_unwind};

use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable, TfheFftTable};
use primus_modulus::BarrettModulus;
use primus_modulus::NativeModulus;
use primus_ntru::{
    FourierNtruAutomorphismContext, FourierNtruAutomorphismKey, FourierNtruCiphertext,
    FourierNtruDecryptContext, FourierNtruEncryptContext, FourierNtruGadgetEncryptContext,
    FourierNtruSecretKey, NlevParameters, NtruCiphertext, NtruParameters,
    NttNtruAutomorphismContext, NttNtruAutomorphismKey, NttNtruCiphertext,
    NttNtruGadgetEncryptContext, NttNtruSecretKey, SecretKeyDistr,
};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
use rand::{Rng, SeedableRng, rngs::StdRng};

const N: usize = 256;
const Q: u32 = 132_120_577;
const P: u32 = 16;

fn substitute(input: &[u32], degree: usize) -> Vec<u32> {
    let mut output = vec![0; input.len()];
    for (i, &value) in input.iter().enumerate() {
        let power = i * degree;
        output[power % input.len()] = if (power / input.len()).is_multiple_of(2) {
            value
        } else {
            (P - value) % P
        };
    }
    output
}

fn fourier_automorphism<Table: FftTable>() {
    let table = Table::new(N.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    let parameters = NtruParameters::new(
        N,
        P,
        NativeModulus::new(),
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let mut rng = StdRng::seed_from_u64(0x6175_746f_464f_5552);
    let (secret, key) =
        FourierNtruSecretKey::generate_pair(&parameters, &mut fft, &mut rng).unwrap();
    assert!(secret.as_slice().contains(&-1));
    let message: Vec<u32> = (0..N).map(|i| (3 * i as u32 + 1) % P).collect();
    let input = key.encrypt(
        &Polynomial(message.as_slice()),
        &parameters,
        &mut fft,
        &mut rng,
        &mut FourierNtruEncryptContext::new(N),
    );
    let mut coefficients = NtruCiphertext::<Vec<u32>>::zero(N);
    input.write_torus_form(&mut coefficients, &mut fft);
    let mut generation = FourierNtruGadgetEncryptContext::new(N);
    let mut context = FourierNtruAutomorphismContext::new(N);
    let mut decrypt = FourierNtruDecryptContext::new(N);
    let mut output = NtruCiphertext::new(vec![7u32; N]);
    let mut transformed_output = FourierNtruCiphertext::<Vec<Complex64>>::zero(N / 2);
    let mut transformed_coeff_output = FourierNtruCiphertext::<Vec<Complex64>>::zero(N / 2);
    for log_basis in [3, 10] {
        let gadget = NlevParameters::with_ntru_params(&parameters, log_basis, None);
        for degree in [1, 3, N + 1, 2 * N - 1] {
            let auto = FourierNtruAutomorphismKey::generate(
                degree,
                &secret,
                &key,
                &gadget,
                &mut fft,
                &mut rng,
                &mut generation,
            );
            assert_eq!(auto.degree(), degree);
            assert_eq!(auto.poly_length(), N);
            assert_eq!(auto.basis(), gadget.basis());
            auto.apply_to(&coefficients, &mut output, &mut fft, &mut context);
            auto.apply_fourier_to(&input, &mut transformed_output, &mut fft, &mut context);
            output.write_fourier_form(&mut transformed_coeff_output, &mut fft);
            // Different representative/rounding paths need not be bit-identical.
            // Both must decrypt the independently substituted target message.
            for output in [&transformed_output, &transformed_coeff_output] {
                assert_eq!(
                    key.decrypt(output, &parameters, &mut fft, &mut decrypt)
                        .as_ref(),
                    substitute(&message, degree),
                    "degree={degree}, log_basis={log_basis}",
                );
            }
        }
    }
}

#[test]
fn fourier_automorphism_preserves_the_original_nonbinary_secret() {
    fourier_automorphism::<RustFftTable>();
    fourier_automorphism::<TfheFftTable>();
}

#[test]
fn fourier_automorphism_rejects_incompatible_resources_before_writes() {
    // Boundary checks run before any backend work; both FFT layouts are covered above.
    let table = RustFftTable::new(N.trailing_zeros()).unwrap();
    let short_table = RustFftTable::new((N / 2).trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    let parameters = NtruParameters::new(
        N,
        P,
        NativeModulus::new(),
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let gadget = NlevParameters::with_ntru_params(&parameters, 3, None);
    let mut rng = StdRng::seed_from_u64(0x6175_746f_4642_4e44);
    let (secret, key) =
        FourierNtruSecretKey::generate_pair(&parameters, &mut fft, &mut rng).unwrap();
    let mut generation = FourierNtruGadgetEncryptContext::new(N);
    let auto = FourierNtruAutomorphismKey::generate(
        3,
        &secret,
        &key,
        &gadget,
        &mut fft,
        &mut rng,
        &mut generation,
    );
    for (input_len, output_len, scratch_len, table) in [
        (N / 2, N, N, &table),
        (N, N / 2, N, &table),
        (N, N, N / 2, &table),
        (N, N, N, &short_table),
    ] {
        let mut fft = FftEngine::new(table);
        let input = NtruCiphertext::<Vec<u32>>::zero(input_len);
        let mut output = NtruCiphertext::new(vec![7; output_len]);
        let mut context = FourierNtruAutomorphismContext::new(scratch_len);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                auto.apply_to(&input, &mut output, &mut fft, &mut context);
            }))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&value| value == 7));
        let input = FourierNtruCiphertext::<Vec<Complex64>>::zero(input_len / 2);
        let mut output = FourierNtruCiphertext::new(vec![Complex64::new(7.0, 0.0); output_len / 2]);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                auto.apply_fourier_to(&input, &mut output, &mut fft, &mut context);
            }))
            .is_err()
        );
        assert!(
            output
                .as_ref()
                .iter()
                .all(|&value| value == Complex64::new(7.0, 0.0))
        );
    }
    for (degree, table) in [
        (0, &table),
        (2, &table),
        (2 * N + 1, &table),
        (3, &short_table),
    ] {
        let mut fft = FftEngine::new(table);
        let mut rng = StdRng::seed_from_u64(37);
        let mut expected_rng = StdRng::seed_from_u64(37);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _ = FourierNtruAutomorphismKey::generate(
                    degree,
                    &secret,
                    &key,
                    &gadget,
                    &mut fft,
                    &mut rng,
                    &mut generation,
                );
            }))
            .is_err()
        );
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }
}

#[test]
fn ntt_automorphism_preserves_the_original_nonbinary_secret() {
    let modulus = BarrettModulus::new(Q);
    let table = UintNttTable::new(N.trailing_zeros(), modulus).unwrap();
    let parameters = NtruParameters::new(N, P, modulus, SecretKeyDistr::SparseTernary, 0.7);
    let mut rng = StdRng::seed_from_u64(0x6175_746f_4e54_5452);
    let (secret, key) = NttNtruSecretKey::generate_pair(&parameters, &table, &mut rng).unwrap();
    assert!(secret.as_slice().contains(&-1));
    let message: Vec<u32> = (0..N).map(|i| (3 * i as u32 + 1) % P).collect();
    let input = key.encrypt(
        &Polynomial(message.as_slice()),
        &parameters,
        &table,
        &mut rng,
    );
    let mut coefficients = NtruCiphertext::<Vec<u32>>::zero(N);
    input.write_coeff_form(&mut coefficients, &table);
    let mut generation = NttNtruGadgetEncryptContext::new(N);
    let mut context = NttNtruAutomorphismContext::new(N);
    let mut output = NtruCiphertext::new(vec![7u32; N]);
    let mut transformed_output = NttNtruCiphertext::<Vec<u32>>::zero(N);
    let mut transformed_coeff_output = NttNtruCiphertext::<Vec<u32>>::zero(N);
    for log_basis in [3, 10] {
        let gadget = NlevParameters::with_ntru_params(&parameters, log_basis, None);
        for degree in [1, 3, N + 1, 2 * N - 1] {
            let auto = NttNtruAutomorphismKey::generate(
                degree,
                &secret,
                &key,
                &gadget,
                &table,
                &mut rng,
                &mut generation,
            );
            assert_eq!(auto.degree(), degree);
            assert_eq!(auto.poly_length(), N);
            assert_eq!(auto.basis(), gadget.basis());
            auto.apply_to(&coefficients, &mut output, modulus, &table, &mut context);
            auto.apply_ntt_to(
                &input,
                &mut transformed_output,
                modulus,
                &table,
                &mut context,
            );
            output.write_ntt_form(&mut transformed_coeff_output, &table);
            assert_eq!(
                transformed_output.as_ref(),
                transformed_coeff_output.as_ref()
            );
            assert_eq!(
                key.decrypt(&transformed_output, &parameters, &table)
                    .as_ref(),
                substitute(&message, degree),
                "degree={degree}, log_basis={log_basis}",
            );
        }
    }
}

#[test]
fn ntt_automorphism_rejects_incompatible_resources_before_writes() {
    let modulus = BarrettModulus::new(Q);
    let other_modulus = BarrettModulus::new(998_244_353);
    let table = UintNttTable::new(N.trailing_zeros(), modulus).unwrap();
    let short_table = UintNttTable::new((N / 2).trailing_zeros(), modulus).unwrap();
    let other_table = UintNttTable::new(N.trailing_zeros(), other_modulus).unwrap();
    let parameters = NtruParameters::new(N, P, modulus, SecretKeyDistr::SparseTernary, 0.7);
    let gadget = NlevParameters::with_ntru_params(&parameters, 3, None);
    let mut rng = StdRng::seed_from_u64(0x6175_746f_626f_756e);
    let (secret, key) = NttNtruSecretKey::generate_pair(&parameters, &table, &mut rng).unwrap();
    let mut generation = NttNtruGadgetEncryptContext::new(N);
    let auto = NttNtruAutomorphismKey::generate(
        3,
        &secret,
        &key,
        &gadget,
        &table,
        &mut rng,
        &mut generation,
    );
    for (input_len, output_len, scratch_len, modulus, table) in [
        (N / 2, N, N, modulus, &table),
        (N, N / 2, N, modulus, &table),
        (N, N, N / 2, modulus, &table),
        (N, N, N, modulus, &short_table),
        (N, N, N, other_modulus, &table),
        (N, N, N, modulus, &other_table),
    ] {
        let input = NtruCiphertext::<Vec<u32>>::zero(input_len);
        let mut output = NtruCiphertext::new(vec![7; output_len]);
        let mut context = NttNtruAutomorphismContext::new(scratch_len);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                auto.apply_to(&input, &mut output, modulus, table, &mut context);
            }))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&value| value == 7));
        let input = NttNtruCiphertext::new(input.as_ref());
        let mut output = NttNtruCiphertext::new(output.as_mut());
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                auto.apply_ntt_to(&input, &mut output, modulus, table, &mut context);
            }))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&value| value == 7));
    }
    // Construction must reject a bad degree or domain before consuming randomness.
    for (degree, table) in [
        (0, &table),
        (2, &table),
        (2 * N + 1, &table),
        (3, &short_table),
        (3, &other_table),
    ] {
        let mut rng = StdRng::seed_from_u64(37);
        let mut expected_rng = StdRng::seed_from_u64(37);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _ = NttNtruAutomorphismKey::generate(
                    degree,
                    &secret,
                    &key,
                    &gadget,
                    table,
                    &mut rng,
                    &mut generation,
                );
            }))
            .is_err()
        );
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }
}
