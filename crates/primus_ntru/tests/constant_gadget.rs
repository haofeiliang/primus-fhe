use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable, TfheFftTable};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{
    FourierNgswCiphertext, FourierNlevCiphertext, FourierNtruGadgetEncryptContext,
    FourierNtruSecretKey, NlevParameters, NtruParameters, NttNgswCiphertext, NttNlevCiphertext,
    NttNtruGadgetEncryptContext, NttNtruSecretKey, SecretKeyDistr,
};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

const POLY_LENGTH: usize = 256;
const EXPLICIT_MODULUS: u32 = 132_120_577;

#[test]
fn constant_nlev_matches_polynomial_encryption() {
    let modulus = BarrettModulus::new(EXPLICIT_MODULUS);
    let ntt = UintNttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let params = NtruParameters::new(
        POLY_LENGTH,
        16u32,
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let gadget = NlevParameters::with_ntru_params(&params, 9, None);
    let mut rng = StdRng::seed_from_u64(75);
    let key = NttNtruSecretKey::generate(&params, &ntt, &mut rng).unwrap();
    let mut context = NttNtruGadgetEncryptContext::new(POLY_LENGTH);
    let mut expected = NttNlevCiphertext::<Vec<u32>>::zero(gadget.nlev_len());
    let mut actual = expected.clone();
    for constant in [0, 1, EXPLICIT_MODULUS - 1] {
        let mut message = Polynomial::new(vec![0; POLY_LENGTH]);
        message.as_mut()[0] = constant;
        let mut reference_rng = StdRng::seed_from_u64(83);
        let mut actual_rng = StdRng::seed_from_u64(83);
        key.encrypt_nlev_to(
            &message,
            &mut expected,
            &gadget,
            &ntt,
            &mut reference_rng,
            &mut context,
        );
        // Old polynomial data must not survive in the constant's zero tail.
        message.as_mut().fill(1);
        key.encrypt_nlev_to(&message, &mut actual, &gadget, &ntt, &mut rng, &mut context);
        key.encrypt_nlev_constant_to(
            constant,
            &mut actual,
            &gadget,
            &ntt,
            &mut actual_rng,
            &mut context,
        );
        assert_eq!(actual.as_ref(), expected.as_ref());
        assert_eq!(actual_rng.next_u64(), reference_rng.next_u64());
    }
    let mut rng = StdRng::seed_from_u64(89);
    let mut expected_rng = StdRng::seed_from_u64(89);
    actual.as_mut().fill(17);
    assert!(
        catch_unwind(AssertUnwindSafe(|| key.encrypt_nlev_constant_to(
            EXPLICIT_MODULUS,
            &mut actual,
            &gadget,
            &ntt,
            &mut rng,
            &mut context
        )))
        .is_err()
    );
    assert!(actual.as_ref().iter().all(|&value| value == 17));
    assert_eq!(rng.next_u64(), expected_rng.next_u64());
    check_fourier_constant_nlev::<RustFftTable>();
    check_fourier_constant_nlev::<TfheFftTable>();
}

fn check_fourier_constant_nlev<Table: FftTable>() {
    let table = Table::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    let params = NtruParameters::new(
        POLY_LENGTH,
        16u32,
        NativeModulus::new(),
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let gadget = NlevParameters::with_ntru_params(&params, 8, None);
    let mut rng = StdRng::seed_from_u64(75);
    let key = FourierNtruSecretKey::generate(&params, &mut fft, &mut rng).unwrap();
    let mut context = FourierNtruGadgetEncryptContext::new(POLY_LENGTH);
    let mut expected = FourierNlevCiphertext::<Vec<Complex64>>::zero(gadget.fourier_nlev_len());
    let mut actual = expected.clone();
    for constant in [0, 1, u32::MAX] {
        let mut message = Polynomial::new(vec![0; POLY_LENGTH]);
        message.as_mut()[0] = constant;
        let mut reference_rng = StdRng::seed_from_u64(83);
        let mut actual_rng = StdRng::seed_from_u64(83);
        key.encrypt_nlev_to(
            &message,
            &mut expected,
            &gadget,
            &mut fft,
            &mut reference_rng,
            &mut context,
        );
        // Old polynomial data must not survive in the constant's zero tail.
        message.as_mut().fill(1);
        key.encrypt_nlev_to(
            &message,
            &mut actual,
            &gadget,
            &mut fft,
            &mut rng,
            &mut context,
        );
        key.encrypt_nlev_constant_to(
            constant,
            &mut actual,
            &gadget,
            &mut fft,
            &mut actual_rng,
            &mut context,
        );
        assert_eq!(actual.as_ref(), expected.as_ref());
        assert_eq!(actual_rng.next_u64(), reference_rng.next_u64());
    }
}

#[test]
fn signed_ngsw_batches_match_polynomial_encryption() {
    let modulus = BarrettModulus::new(EXPLICIT_MODULUS);
    let ntt = UintNttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let params = NtruParameters::new(
        POLY_LENGTH,
        16u32,
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let gadget = NlevParameters::with_ntru_params(&params, 9, None);
    let mut rng = StdRng::seed_from_u64(79);
    let key = NttNtruSecretKey::generate(&params, &ntt, &mut rng).unwrap();
    let mut context = NttNtruGadgetEncryptContext::new(POLY_LENGTH);
    for input in [&[][..], &[1][..], &[0, 1, -1, 2][..]] {
        let mut expected = vec![0; input.len() * gadget.nlev_len()];
        let mut actual = vec![17; expected.len()];
        let mut reference_rng = StdRng::seed_from_u64(87);
        let mut actual_rng = StdRng::seed_from_u64(87);
        for (&constant, block) in input
            .iter()
            .zip(expected.chunks_exact_mut(gadget.nlev_len()))
        {
            let mut message = Polynomial::new(vec![0; POLY_LENGTH]);
            message.as_mut()[0] = if constant < 0 {
                EXPLICIT_MODULUS - (-constant) as u32
            } else {
                constant as u32
            };
            key.encrypt_ngsw_to(
                &message,
                &mut NttNgswCiphertext::new(block),
                &gadget,
                &ntt,
                &mut reference_rng,
                &mut context,
            );
        }
        key.encrypt_ngsw_signed_constant_batch_to(
            input,
            &mut actual,
            &gadget,
            &ntt,
            &mut actual_rng,
        );
        assert_eq!(actual, expected);
        assert_eq!(actual_rng.next_u64(), reference_rng.next_u64());
    }
    // Reject an invalid later constant before writing the first block.
    for (input, length) in [
        (&[1, i32::MIN][..], 2 * gadget.nlev_len()),
        (&[1][..], gadget.nlev_len() + 1),
    ] {
        let mut output = vec![17; length];
        let mut rng = StdRng::seed_from_u64(89);
        let mut expected_rng = StdRng::seed_from_u64(89);
        assert!(
            catch_unwind(AssertUnwindSafe(|| key
                .encrypt_ngsw_signed_constant_batch_to(
                    input,
                    &mut output,
                    &gadget,
                    &ntt,
                    &mut rng
                )))
            .is_err()
        );
        assert!(output.iter().all(|&value| value == 17));
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }
    check_fourier_ngsw_batch::<RustFftTable>();
    check_fourier_ngsw_batch::<TfheFftTable>();
}

fn check_fourier_ngsw_batch<Table: FftTable>() {
    let table = Table::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    let params = NtruParameters::new(
        POLY_LENGTH,
        16u32,
        NativeModulus::new(),
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let gadget = NlevParameters::with_ntru_params(&params, 8, None);
    let mut rng = StdRng::seed_from_u64(79);
    let key = FourierNtruSecretKey::generate(&params, &mut fft, &mut rng).unwrap();
    let mut context = FourierNtruGadgetEncryptContext::new(POLY_LENGTH);
    for input in [&[][..], &[1][..], &[0, 1, -1, 2][..]] {
        let mut expected = vec![Complex64::default(); input.len() * gadget.fourier_nlev_len()];
        let mut actual = vec![Complex64::new(17.0, 17.0); expected.len()];
        let mut reference_rng = StdRng::seed_from_u64(87);
        let mut actual_rng = StdRng::seed_from_u64(87);
        for (&constant, block) in input
            .iter()
            .zip(expected.chunks_exact_mut(gadget.fourier_nlev_len()))
        {
            let mut message = Polynomial::new(vec![0; POLY_LENGTH]);
            message.as_mut()[0] = constant as u32;
            key.encrypt_ngsw_to(
                &message,
                &mut FourierNgswCiphertext::new(block),
                &gadget,
                &mut fft,
                &mut reference_rng,
                &mut context,
            );
        }
        if let Some(block) = actual.chunks_exact_mut(gadget.fourier_nlev_len()).next() {
            key.encrypt_ngsw_to(
                &Polynomial::new(vec![1u32; POLY_LENGTH]),
                &mut FourierNgswCiphertext::new(block),
                &gadget,
                &mut fft,
                &mut rng,
                &mut context,
            );
        }
        key.encrypt_ngsw_signed_constant_batch_to(
            input,
            &mut actual,
            &gadget,
            &mut fft,
            &mut actual_rng,
            &mut context,
        );
        assert_eq!(actual, expected);
        assert_eq!(actual_rng.next_u64(), reference_rng.next_u64());
    }
    // An empty batch still validates shared workspace; wrong output length
    // must also fail before consuming randomness or modifying output.
    for (input, length, workspace_length) in [
        (&[][..], 0, POLY_LENGTH / 2),
        (&[1][..], gadget.fourier_nlev_len() + 1, POLY_LENGTH),
    ] {
        let mut output = vec![Complex64::new(17.0, 17.0); length];
        let mut context = FourierNtruGadgetEncryptContext::new(workspace_length);
        let mut rng = StdRng::seed_from_u64(89);
        let mut expected_rng = StdRng::seed_from_u64(89);
        assert!(
            catch_unwind(AssertUnwindSafe(|| key
                .encrypt_ngsw_signed_constant_batch_to(
                    input,
                    &mut output,
                    &gadget,
                    &mut fft,
                    &mut rng,
                    &mut context
                )))
            .is_err()
        );
        assert!(
            output
                .iter()
                .all(|&value| value == Complex64::new(17.0, 17.0))
        );
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }
}
