use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable};
use primus_lattice::ntru::{FourierNtruOwned, Ntru, NttNtru};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{
    FourierNgswCiphertext, FourierNlevCiphertext, FourierNtruDecryptContext,
    FourierNtruEncryptContext, FourierNtruExternalProductContext, FourierNtruGadgetEncryptContext,
    FourierNtruSecretKey, NtruParameters, NttNgswCiphertext, NttNlevCiphertext,
    NttNtruExternalProductContext, NttNtruGadgetEncryptContext, NttNtruSecretKey, SecretKeyDistr,
};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::{Polynomial, PolynomialOwned};

const POLY_LENGTH: usize = 256;
const PLAINTEXT_MODULUS: u32 = 16;
const EXPLICIT_MODULUS: u32 = 132_120_577;

fn plaintext(offset: u32) -> Vec<u32> {
    (0..POLY_LENGTH)
        .map(|index| (index as u32 + offset) % (PLAINTEXT_MODULUS / 2))
        .collect()
}

fn shifted_plaintext(input: &[u32]) -> Vec<u32> {
    let mut output = vec![0; input.len()];
    output[0] = (PLAINTEXT_MODULUS - input[input.len() - 1]) % PLAINTEXT_MODULUS;
    output[1..].copy_from_slice(&input[..input.len() - 1]);
    output
}

fn explicit_distance(lhs: u32, rhs: u32) -> u32 {
    let distance = lhs.abs_diff(rhs);
    distance.min(EXPLICIT_MODULUS - distance)
}

fn native_distance(lhs: u32, rhs: u32) -> u32 {
    lhs.wrapping_sub(rhs).min(rhs.wrapping_sub(lhs))
}

fn decrypt_ntt_output(
    secret_key: &NttNtruSecretKey<u32>,
    cipher: &Ntru<Vec<u32>>,
    params: &NtruParameters<u32, BarrettModulus<u32>>,
    ntt: &UintNttTable<u32>,
) -> Vec<u32> {
    let mut transformed: NttNtru<Vec<u32>> = NttNtru::zero(POLY_LENGTH);
    cipher.write_ntt_form(&mut transformed, ntt);
    secret_key
        .decrypt(&transformed, params, ntt)
        .as_ref()
        .to_vec()
}

fn decrypt_fourier_output(
    secret_key: &FourierNtruSecretKey,
    cipher: &Ntru<Vec<u32>>,
    params: &NtruParameters<u32, NativeModulus<u32>>,
    fft: &mut FftEngine<'_, RustFftTable>,
    context: &mut FourierNtruDecryptContext,
) -> Vec<u32> {
    let mut transformed = FourierNtruOwned::zero(fft.fourier_length());
    cipher.write_fourier_form(&mut transformed, fft);
    secret_key
        .decrypt(&transformed, params, fft, context)
        .as_ref()
        .to_vec()
}

#[test]
fn ntt_nlev_generation_and_ngsw_cmux() {
    let modulus = BarrettModulus::new(EXPLICIT_MODULUS);
    let ntt = UintNttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let params = NtruParameters::new(
        POLY_LENGTH,
        PLAINTEXT_MODULUS,
        modulus,
        SecretKeyDistr::Ternary,
        0.7,
    );
    let basis = ApproxSignedBasis::new(Some(EXPLICIT_MODULUS), 9, None);
    let mut rng = rand::rng();
    let secret_key = NttNtruSecretKey::generate(&params, &ntt, &mut rng).unwrap();
    let mut gadget_context = NttNtruGadgetEncryptContext::new(POLY_LENGTH);

    let mut one = vec![0; POLY_LENGTH];
    one[0] = 1;
    let one = Polynomial::new(one);
    let mut nlev: NttNlevCiphertext<Vec<u32>> =
        NttNlevCiphertext::zero(basis.decompose_length() * POLY_LENGTH);
    secret_key.encrypt_nlev_to(
        &one,
        &mut nlev,
        &params,
        &basis,
        &ntt,
        &mut rng,
        &mut gadget_context,
    );

    for (scalar, level) in basis.scalar_iter().zip(nlev.iter_ntt_ntru(POLY_LENGTH)) {
        let mut phase = PolynomialOwned::zero(POLY_LENGTH);
        secret_key.phase_to(&level, &mut phase, &params, &ntt);
        assert!(explicit_distance(phase.as_ref()[0], scalar) <= 8);
        assert!(
            phase.as_ref()[1..]
                .iter()
                .all(|&value| explicit_distance(value, 0) <= 8)
        );
    }

    let mut control_message = vec![0; POLY_LENGTH];
    control_message[0] = 1;
    let mut control: NttNgswCiphertext<Vec<u32>> =
        NttNgswCiphertext::zero(basis.decompose_length() * POLY_LENGTH);
    secret_key.encrypt_ngsw_to(
        &Polynomial::new(control_message),
        &mut control,
        &params,
        &basis,
        &ntt,
        &mut rng,
        &mut gadget_context,
    );

    let messages = [plaintext(0), plaintext(2), plaintext(5)];
    let candidates: Vec<Ntru<Vec<u32>>> = messages
        .iter()
        .map(|message| {
            secret_key
                .encrypt(
                    &Polynomial::new(message.as_slice()),
                    &params,
                    &ntt,
                    &mut rng,
                )
                .into_coeff_form(&ntt)
        })
        .collect();
    let mut output: Ntru<Vec<u32>> = Ntru::zero(POLY_LENGTH);
    let mut external_product_context = NttNtruExternalProductContext::new(POLY_LENGTH);

    control.cmux_to(
        &candidates[0],
        &candidates[1],
        &mut output,
        &basis,
        modulus,
        &ntt,
        &mut external_product_context,
    );
    assert_eq!(
        decrypt_ntt_output(&secret_key, &output, &params, &ntt),
        messages[1]
    );

    control.cmux_monomial_to(
        &candidates[0],
        1,
        &mut output,
        &basis,
        modulus,
        &ntt,
        &mut external_product_context,
    );
    assert_eq!(
        decrypt_ntt_output(&secret_key, &output, &params, &ntt),
        shifted_plaintext(&messages[0])
    );

    let mut controls: [NttNgswCiphertext<Vec<u32>>; 2] =
        core::array::from_fn(|_| NttNgswCiphertext::zero(basis.decompose_length() * POLY_LENGTH));
    for (selected, expected) in messages.iter().enumerate() {
        for (index, control) in controls.iter_mut().enumerate() {
            let mut message = vec![0; POLY_LENGTH];
            message[0] = u32::from(selected == index + 1);
            secret_key.encrypt_ngsw_to(
                &Polynomial::new(message),
                control,
                &params,
                &basis,
                &ntt,
                &mut rng,
                &mut gadget_context,
            );
        }

        NttNgswCiphertext::cmux_k_to(
            &controls,
            &candidates[0],
            &candidates[1..],
            &mut output,
            &basis,
            modulus,
            &ntt,
            &mut external_product_context,
        );
        assert_eq!(
            decrypt_ntt_output(&secret_key, &output, &params, &ntt),
            *expected
        );
    }
}

#[test]
fn fourier_nlev_generation_and_ngsw_cmux() {
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    let params = NtruParameters::new(
        POLY_LENGTH,
        PLAINTEXT_MODULUS,
        NativeModulus::new(),
        SecretKeyDistr::Ternary,
        0.7,
    );
    let basis = ApproxSignedBasis::new(None, 8, None);
    let mut rng = rand::rng();
    let secret_key = FourierNtruSecretKey::generate(&params, &mut fft, &mut rng).unwrap();
    let mut gadget_context = FourierNtruGadgetEncryptContext::new(POLY_LENGTH);
    let mut decrypt_context = FourierNtruDecryptContext::new(POLY_LENGTH);

    let mut one = vec![0; POLY_LENGTH];
    one[0] = 1;
    let one = Polynomial::new(one);
    let mut nlev: FourierNlevCiphertext<Vec<Complex64>> =
        FourierNlevCiphertext::zero(basis.decompose_length() * fft.fourier_length());
    secret_key.encrypt_nlev_to(
        &one,
        &mut nlev,
        &params,
        &basis,
        &mut fft,
        &mut rng,
        &mut gadget_context,
    );

    for (scalar, level) in basis
        .scalar_iter()
        .zip(nlev.iter_ntru(fft.fourier_length()))
    {
        let mut phase = PolynomialOwned::zero(POLY_LENGTH);
        secret_key.phase_to(&level, &mut phase, &params, &mut fft, &mut decrypt_context);
        assert!(native_distance(phase.as_ref()[0], scalar) <= 8);
        assert!(
            phase.as_ref()[1..]
                .iter()
                .all(|&value| native_distance(value, 0) <= 8)
        );
    }

    let mut control_message = vec![0; POLY_LENGTH];
    control_message[0] = 1;
    let mut control: FourierNgswCiphertext<Vec<Complex64>> =
        FourierNgswCiphertext::zero(basis.decompose_length() * fft.fourier_length());
    secret_key.encrypt_ngsw_to(
        &Polynomial::new(control_message),
        &mut control,
        &params,
        &basis,
        &mut fft,
        &mut rng,
        &mut gadget_context,
    );

    let messages = [plaintext(0), plaintext(2), plaintext(5)];
    let mut encrypt_context = FourierNtruEncryptContext::new(POLY_LENGTH);
    let mut candidates = Vec::with_capacity(messages.len());
    for message in &messages {
        let input_fourier = secret_key.encrypt(
            &Polynomial::new(message.as_slice()),
            &params,
            &mut fft,
            &mut rng,
            &mut encrypt_context,
        );
        let mut input: Ntru<Vec<u32>> = Ntru::zero(POLY_LENGTH);
        input_fourier.write_torus_form(&mut input, &mut fft);
        candidates.push(input);
    }
    let mut output: Ntru<Vec<u32>> = Ntru::zero(POLY_LENGTH);
    let mut external_product_context = FourierNtruExternalProductContext::new(POLY_LENGTH);

    control.cmux_to(
        &candidates[0],
        &candidates[1],
        &mut output,
        &basis,
        &mut fft,
        &mut external_product_context,
    );
    assert_eq!(
        decrypt_fourier_output(
            &secret_key,
            &output,
            &params,
            &mut fft,
            &mut decrypt_context,
        ),
        messages[1]
    );

    control.cmux_monomial_to(
        &candidates[0],
        1,
        &mut output,
        &basis,
        &mut fft,
        &mut external_product_context,
    );
    assert_eq!(
        decrypt_fourier_output(
            &secret_key,
            &output,
            &params,
            &mut fft,
            &mut decrypt_context,
        ),
        shifted_plaintext(&messages[0])
    );

    let mut controls: [FourierNgswCiphertext<Vec<Complex64>>; 2] = core::array::from_fn(|_| {
        FourierNgswCiphertext::zero(basis.decompose_length() * fft.fourier_length())
    });
    for (selected, expected) in messages.iter().enumerate() {
        for (index, control) in controls.iter_mut().enumerate() {
            let mut message = vec![0; POLY_LENGTH];
            message[0] = u32::from(selected == index + 1);
            secret_key.encrypt_ngsw_to(
                &Polynomial::new(message),
                control,
                &params,
                &basis,
                &mut fft,
                &mut rng,
                &mut gadget_context,
            );
        }

        FourierNgswCiphertext::cmux_k_to(
            &controls,
            &candidates[0],
            &candidates[1..],
            &mut output,
            &basis,
            &mut fft,
            &mut external_product_context,
        );
        assert_eq!(
            decrypt_fourier_output(
                &secret_key,
                &output,
                &params,
                &mut fft,
                &mut decrypt_context,
            ),
            *expected
        );
    }
}
