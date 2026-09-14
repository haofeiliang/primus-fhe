use std::panic::{AssertUnwindSafe, catch_unwind};

use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable, TfheFftTable};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{
    FourierNgswCiphertext, FourierNlevCiphertext, FourierNtruEncryptContext,
    FourierNtruExternalProductContext, FourierNtruGadgetEncryptContext, FourierNtruSchemeSwitchKey,
    FourierNtruSecretKey, NlevCiphertext, NlevParameters, NtruCiphertext, NtruParameters,
    NtruSecretKey, NttNgswCiphertext, NttNlevCiphertext, NttNtruExternalProductContext,
    NttNtruGadgetEncryptContext, NttNtruSchemeSwitchKey, NttNtruSecretKey, SecretKeyDistr,
};
use primus_ntt::{NttTable, U64NttTable};
use primus_poly::Polynomial;
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 32;
const Q: u64 = 1_125_899_906_826_241;

fn secret() -> NtruSecretKey<u64> {
    let mut coefficients = vec![0; N];
    coefficients[0] = 1;
    coefficients[1] = 1;
    coefficients[3] = -1;
    NtruSecretKey::new(coefficients, SecretKeyDistr::SparseTernary)
}

// Independent negacyclic convolution by the fixed nonbinary secret 1+X-X³.
fn assert_phase(cipher: &[u64], expected: &[u64], q: u128, tolerance: u128) {
    let mut actual = [0u128; N];
    for (i, &value) in cipher.iter().enumerate() {
        for (shift, sign) in [(0, false), (1, false), (3, true)] {
            let negative = (i + shift >= N) ^ sign;
            let term = if negative {
                (q - u128::from(value)) % q
            } else {
                value.into()
            };
            actual[(i + shift) % N] = (actual[(i + shift) % N] + term) % q;
        }
    }
    for (i, (actual, &expected)) in actual.into_iter().zip(expected).enumerate() {
        let difference = (actual + q - u128::from(expected)) % q;
        assert!(
            difference.min(q - difference) < tolerance,
            "phase mismatch at {i}: {actual} vs {expected}"
        );
    }
}

fn expected_level(scalar: u64, bit: u64, q: u128) -> [u64; N] {
    let mut expected = [0; N];
    let value = u128::from(scalar) * u128::from(bit) % q;
    expected[0] = value as u64;
    expected[1] = value as u64;
    expected[3] = ((q - value) % q) as u64;
    expected
}

fn messages(q: u128) -> [Polynomial<Vec<u64>>; 2] {
    [1, 5].map(|offset| {
        Polynomial::new(
            (0..N)
                .map(|i| (((i + offset) % 8) as u128 * (q / 16)) as u64)
                .collect(),
        )
    })
}

#[test]
fn ntt_scheme_switch_has_independent_bases_and_produces_cmux_controls() {
    let modulus = BarrettModulus::new(Q);
    let table = U64NttTable::new(N.trailing_zeros(), modulus).unwrap();
    let parameters = NtruParameters::new(N, 16, modulus, SecretKeyDistr::SparseTernary, 0.7);
    let secret = secret();
    let key = NttNtruSecretKey::try_from_coeff_secret_key(&secret, modulus, &table).unwrap();
    let mut rng = StdRng::seed_from_u64(117);
    let mut generation = NttNtruGadgetEncryptContext::new(N);
    let mut scratch = NttNtruExternalProductContext::new(N);
    let messages = messages(Q.into());
    let operands = messages.each_ref().map(|message| {
        let mut transformed = primus_ntru::NttNtruCiphertext::<Vec<u64>>::zero(N);
        key.encrypt_encoded_to(message, &mut transformed, &parameters, &table, &mut rng);
        let mut output = NtruCiphertext::<Vec<u64>>::zero(N);
        transformed.write_coeff_form(&mut output, &table);
        output
    });
    for log_key_basis in [3, 10] {
        let key_parameters = NlevParameters::with_ntru_params(&parameters, log_key_basis, None);
        // L_output below and above L_key=5 for B_key=2^10.
        for output_levels in [2, 6] {
            let output_parameters =
                NlevParameters::with_ntru_params(&parameters, 8, Some(output_levels));
            let ss = NttNtruSchemeSwitchKey::generate(
                &secret,
                &key,
                output_parameters.basis(),
                &key_parameters,
                &table,
                &mut rng,
                &mut generation,
            );
            assert_eq!(ss.key_basis(), key_parameters.basis());
            assert_eq!(ss.output_basis(), output_parameters.basis());
            let mut encrypted = NttNlevCiphertext::<Vec<u64>>::zero(output_parameters.nlev_len());
            let mut input = NlevCiphertext::<Vec<u64>>::zero(output_parameters.nlev_len());
            let mut output = NttNgswCiphertext::<Vec<u64>>::zero(output_parameters.nlev_len());
            let mut row = NtruCiphertext::<Vec<u64>>::zero(N);
            for bit in [0, 1] {
                key.encrypt_nlev_constant_to(
                    bit,
                    &mut encrypted,
                    &output_parameters,
                    &table,
                    &mut rng,
                    &mut generation,
                );
                for (transformed, mut input) in
                    encrypted.iter_ntt_ntru(N).zip(input.iter_ntru_mut(N))
                {
                    transformed.write_coeff_form(&mut input, &table);
                }
                ss.apply_to(&input, &mut output, modulus, &table, &mut scratch);
                for (scalar, level) in output_parameters
                    .basis()
                    .scalar_iter()
                    .zip(output.iter_ntt_ntru(N))
                {
                    level.write_coeff_form(&mut row, &table);
                    // Functional tolerance includes f/f² amplification; it is
                    // independent of the much larger high-layer gadget scales.
                    assert_phase(
                        row.as_ref(),
                        &expected_level(scalar, bit, Q.into()),
                        Q.into(),
                        1 << 24,
                    );
                }
                output.cmux_to(
                    &operands[0],
                    &operands[1],
                    &mut row,
                    output_parameters.basis(),
                    modulus,
                    &table,
                    &mut scratch,
                );
                // Even the deliberately short output basis retains 16 bits.
                assert_phase(
                    row.as_ref(),
                    messages[bit as usize].as_ref(),
                    Q.into(),
                    u128::from(Q) / 2048,
                );
            }
            output.as_mut().fill(7);
            let mut wrong = NttNtruExternalProductContext::new(2 * N);
            assert!(
                catch_unwind(AssertUnwindSafe(|| ss.apply_to(
                    &input,
                    &mut output,
                    modulus,
                    &table,
                    &mut wrong
                )))
                .is_err()
            );
            assert!(output.as_ref().iter().all(|&value| value == 7));
            let short = NlevCiphertext::new(&input.as_ref()[..input.as_ref().len() - 1]);
            assert!(
                catch_unwind(AssertUnwindSafe(|| ss.apply_to(
                    &short,
                    &mut output,
                    modulus,
                    &table,
                    &mut scratch
                )))
                .is_err()
            );
            assert!(output.as_ref().iter().all(|&value| value == 7));
        }
    }
    let foreign = primus_decompose::primitive::ApproxSignedBasis::new(None, 8, Some(2));
    let key_parameters = NlevParameters::with_ntru_params(&parameters, 10, None);
    let mut untouched = StdRng::seed_from_u64(19);
    let mut invalid = StdRng::seed_from_u64(19);
    assert!(
        catch_unwind(AssertUnwindSafe(|| NttNtruSchemeSwitchKey::generate(
            &secret,
            &key,
            &foreign,
            &key_parameters,
            &table,
            &mut invalid,
            &mut generation
        )))
        .is_err()
    );
    assert_eq!(
        rand::Rng::next_u64(&mut invalid),
        rand::Rng::next_u64(&mut untouched)
    );
}

fn fourier<Table: FftTable>() {
    let q = 1u128 << 64;
    let table = Table::new(N.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    let parameters = NtruParameters::new(
        N,
        16u64,
        NativeModulus::new(),
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let secret = secret();
    let key = FourierNtruSecretKey::try_from_coeff_secret_key(&secret, &mut fft).unwrap();
    let mut rng = StdRng::seed_from_u64(119);
    let mut generation = FourierNtruGadgetEncryptContext::new(N);
    let mut encrypt = FourierNtruEncryptContext::new(N);
    let mut scratch = FourierNtruExternalProductContext::new(N);
    let messages = messages(q);
    let operands = messages.each_ref().map(|message| {
        let mut transformed = primus_ntru::FourierNtruCiphertext::<Vec<Complex64>>::zero(N / 2);
        key.encrypt_encoded_to(
            message,
            &mut transformed,
            &parameters,
            &mut fft,
            &mut rng,
            &mut encrypt,
        );
        let mut output = NtruCiphertext::<Vec<u64>>::zero(N);
        transformed.write_torus_form(&mut output, &mut fft);
        output
    });
    for log_key_basis in [3, 10] {
        let key_parameters = NlevParameters::with_ntru_params(&parameters, log_key_basis, None);
        for output_levels in [2, 7] {
            let output_parameters =
                NlevParameters::with_ntru_params(&parameters, 8, Some(output_levels));
            let ss = FourierNtruSchemeSwitchKey::generate(
                &secret,
                &key,
                output_parameters.basis(),
                &key_parameters,
                &mut fft,
                &mut rng,
                &mut generation,
            );
            assert_eq!(ss.key_basis(), key_parameters.basis());
            assert_eq!(ss.output_basis(), output_parameters.basis());
            let mut encrypted =
                FourierNlevCiphertext::<Vec<Complex64>>::zero(output_parameters.fourier_nlev_len());
            let mut input = NlevCiphertext::<Vec<u64>>::zero(output_parameters.nlev_len());
            let mut output =
                FourierNgswCiphertext::<Vec<Complex64>>::zero(output_parameters.fourier_nlev_len());
            let mut row = NtruCiphertext::<Vec<u64>>::zero(N);
            for bit in [0, 1] {
                key.encrypt_nlev_constant_to(
                    bit,
                    &mut encrypted,
                    &output_parameters,
                    &mut fft,
                    &mut rng,
                    &mut generation,
                );
                for (transformed, mut input) in
                    encrypted.iter_ntru(N / 2).zip(input.iter_ntru_mut(N))
                {
                    transformed.write_torus_form(&mut input, &mut fft);
                }
                ss.apply_to(&input, &mut output, &mut fft, &mut scratch);
                for (scalar, level) in output_parameters
                    .basis()
                    .scalar_iter()
                    .zip(output.iter_ntru(N / 2))
                {
                    level.write_torus_form(&mut row, &mut fft);
                    assert_phase(row.as_ref(), &expected_level(scalar, bit, q), q, 1 << 26);
                }
                output.cmux_to(
                    &operands[0],
                    &operands[1],
                    &mut row,
                    output_parameters.basis(),
                    &mut fft,
                    &mut scratch,
                );
                assert_phase(row.as_ref(), messages[bit as usize].as_ref(), q, q / 2048);
            }
            output.as_mut().fill(Complex64::new(7.0, 0.0));
            let mut wrong = FourierNtruExternalProductContext::new(2 * N);
            assert!(
                catch_unwind(AssertUnwindSafe(|| ss.apply_to(
                    &input,
                    &mut output,
                    &mut fft,
                    &mut wrong
                )))
                .is_err()
            );
            assert!(
                output
                    .as_ref()
                    .iter()
                    .all(|&value| value == Complex64::new(7.0, 0.0))
            );
            let short = NlevCiphertext::new(&input.as_ref()[..input.as_ref().len() - 1]);
            assert!(
                catch_unwind(AssertUnwindSafe(|| ss.apply_to(
                    &short,
                    &mut output,
                    &mut fft,
                    &mut scratch
                )))
                .is_err()
            );
            assert!(
                output
                    .as_ref()
                    .iter()
                    .all(|&value| value == Complex64::new(7.0, 0.0))
            );
        }
    }
}

#[test]
fn fourier_scheme_switch_has_independent_bases_and_produces_cmux_controls() {
    fourier::<RustFftTable>();
    fourier::<TfheFftTable>();
}
