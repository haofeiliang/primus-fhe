use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable};
use primus_lattice::ntru::Ntru;
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

fn plaintext() -> Vec<u32> {
    (0..POLY_LENGTH)
        .map(|index| (index as u32) % (PLAINTEXT_MODULUS / 2))
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

#[test]
fn ntt_nlev_generation_and_ngsw_external_product() {
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

    let mut monomial = vec![0; POLY_LENGTH];
    monomial[1] = 1;
    let mut ngsw: NttNgswCiphertext<Vec<u32>> =
        NttNgswCiphertext::zero(basis.decompose_length() * POLY_LENGTH);
    secret_key.encrypt_ngsw_to(
        &Polynomial::new(monomial),
        &mut ngsw,
        &params,
        &basis,
        &ntt,
        &mut rng,
        &mut gadget_context,
    );

    let message = plaintext();
    let input = secret_key
        .encrypt(
            &Polynomial::new(message.as_slice()),
            &params,
            &ntt,
            &mut rng,
        )
        .into_coeff_form(&ntt);
    let mut output: Ntru<Vec<u32>> = Ntru::zero(POLY_LENGTH);
    let mut external_product_context = NttNtruExternalProductContext::new(POLY_LENGTH);
    ngsw.external_product_to(
        &input,
        &mut output,
        &basis,
        modulus,
        &ntt,
        &mut external_product_context,
    );

    assert_eq!(
        secret_key
            .decrypt(&output.into_ntt_form(&ntt), &params, &ntt)
            .as_ref(),
        shifted_plaintext(&message)
    );
}

#[test]
fn fourier_nlev_generation_and_ngsw_external_product() {
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

    let mut monomial = vec![0; POLY_LENGTH];
    monomial[1] = 1;
    let mut ngsw: FourierNgswCiphertext<Vec<Complex64>> =
        FourierNgswCiphertext::zero(basis.decompose_length() * fft.fourier_length());
    secret_key.encrypt_ngsw_to(
        &Polynomial::new(monomial),
        &mut ngsw,
        &params,
        &basis,
        &mut fft,
        &mut rng,
        &mut gadget_context,
    );

    let message = plaintext();
    let mut encrypt_context = FourierNtruEncryptContext::new(POLY_LENGTH);
    let input_fourier = secret_key.encrypt(
        &Polynomial::new(message.as_slice()),
        &params,
        &mut fft,
        &mut rng,
        &mut encrypt_context,
    );
    let mut input: Ntru<Vec<u32>> = Ntru::zero(POLY_LENGTH);
    input_fourier.write_torus_form(&mut input, &mut fft);
    let mut output: Ntru<Vec<u32>> = Ntru::zero(POLY_LENGTH);
    let mut external_product_context = FourierNtruExternalProductContext::new(POLY_LENGTH);
    ngsw.external_product_to(
        &input,
        &mut output,
        &basis,
        &mut fft,
        &mut external_product_context,
    );

    let mut output_fourier = primus_lattice::ntru::FourierNtruOwned::zero(fft.fourier_length());
    output.write_fourier_form(&mut output_fourier, &mut fft);
    assert_eq!(
        secret_key
            .decrypt(&output_fourier, &params, &mut fft, &mut decrypt_context,)
            .as_ref(),
        shifted_plaintext(&message)
    );
}
