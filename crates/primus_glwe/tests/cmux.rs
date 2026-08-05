use primus_fft::{FftEngine, FftTable, RustFftTable};
use primus_glwe::{
    FourierGadgetEncryptContext, FourierGlweDecryptContext, FourierGlweEncryptContext,
    FourierGlweSecretKey, GlevParameters, GlweParameters, GlweSecretKey, NttGadgetDomain,
    NttGadgetEncryptContext, NttGlweSecretKey, SecretKeyDistr,
};
use primus_lattice::{
    context::{FourierExternalProductContext, NttExternalProductContext},
    ggsw::{FourierGgswOwned, NttGgsw},
    glwe::{FourierGlweOwned, Glwe, NttGlwe, TorusGlwe},
};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;

const DIMENSION: usize = 1;
const POLY_LENGTH: usize = 256;
const PLAINTEXT_MODULUS: u32 = 16;

fn plaintext(offset: u32) -> Vec<u32> {
    (0..POLY_LENGTH)
        .map(|index| (index as u32 + offset) % PLAINTEXT_MODULUS)
        .collect()
}

#[test]
fn fourier_cmux_selects_requested_glwe() {
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    let mut rng = rand::rng();
    let glwe_params = GlweParameters::new(
        DIMENSION,
        POLY_LENGTH,
        PLAINTEXT_MODULUS,
        NativeModulus::new(),
        SecretKeyDistr::Binary,
        0.7,
    );
    let params = GlevParameters::with_glwe_params(&glwe_params, 8, None);
    let secret_key = FourierGlweSecretKey::generate(&glwe_params, &mut fft, &mut rng);
    let mut encrypt_context = FourierGlweEncryptContext::new(POLY_LENGTH);
    let mut decrypt_context = FourierGlweDecryptContext::new(POLY_LENGTH);
    let mut gadget_context = FourierGadgetEncryptContext::new(params.size());
    let mut cmux_context = FourierExternalProductContext::new(params.size());

    let messages = [plaintext(1), plaintext(7)];
    let mut ciphertexts: [TorusGlwe<Vec<u32>>; 2] = [
        TorusGlwe::zero(params.glwe_len()),
        TorusGlwe::zero(params.glwe_len()),
    ];
    for (message, ciphertext) in messages.iter().zip(&mut ciphertexts) {
        let mut fourier = FourierGlweOwned::zero(params.fourier_glwe_len());
        secret_key.encrypt_to(
            &Polynomial::new(message.as_slice()),
            &mut fourier,
            &glwe_params,
            &mut fft,
            &mut rng,
            &mut encrypt_context,
        );
        fourier.write_torus_form(ciphertext, &mut fft);
    }

    let mut control = FourierGgswOwned::zero(params.fourier_ggsw_len());
    let mut output: TorusGlwe<Vec<u32>> = TorusGlwe::zero(params.glwe_len());
    for (bit, expected) in messages.iter().enumerate() {
        let mut control_message = vec![0u32; POLY_LENGTH];
        control_message[0] = bit as u32;
        secret_key.encrypt_ggsw_to(
            &Polynomial::new(control_message),
            &mut control,
            &params,
            &mut fft,
            &mut rng,
            &mut gadget_context,
        );

        control.cmux_to(
            &ciphertexts[0],
            &ciphertexts[1],
            &mut output,
            params.basis(),
            &mut fft,
            &mut cmux_context,
        );

        let mut output_fourier = FourierGlweOwned::zero(params.fourier_glwe_len());
        output.write_fourier_form(&mut output_fourier, &mut fft);
        assert_eq!(
            secret_key
                .decrypt(
                    &output_fourier,
                    &glwe_params,
                    &mut fft,
                    &mut decrypt_context,
                )
                .as_ref(),
            expected.as_slice()
        );
    }
}

#[test]
fn ntt_cmux_selects_requested_glwe() {
    const MODULUS: u32 = 132_120_577;

    let modulus = BarrettModulus::new(MODULUS);
    let ntt = UintNttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let mut rng = rand::rng();
    let glwe_params = GlweParameters::new(
        DIMENSION,
        POLY_LENGTH,
        PLAINTEXT_MODULUS,
        modulus,
        SecretKeyDistr::Ternary,
        0.7,
    );
    let params = GlevParameters::with_glwe_params(&glwe_params, 8, None);
    let domain = NttGadgetDomain::try_new(&params, &ntt).unwrap();
    let coeff_secret_key = GlweSecretKey::generate(&glwe_params, &mut rng);
    let secret_key = NttGlweSecretKey::from_coeff_secret_key(&coeff_secret_key, &ntt);
    let mut gadget_context = NttGadgetEncryptContext::new(domain.size());
    let mut cmux_context = NttExternalProductContext::new(domain.size());

    let messages = [plaintext(2), plaintext(11)];
    let mut ciphertexts: [Glwe<Vec<u32>>; 2] =
        [Glwe::zero(params.glwe_len()), Glwe::zero(params.glwe_len())];
    for (message, ciphertext) in messages.iter().zip(&mut ciphertexts) {
        let mut ntt_ciphertext: NttGlwe<Vec<u32>> = NttGlwe::zero(params.glwe_len());
        secret_key.encrypt_to(
            &Polynomial::new(message.as_slice()),
            &mut ntt_ciphertext,
            &glwe_params,
            &ntt,
            &mut rng,
        );
        ntt_ciphertext.write_coeff_form(ciphertext, &ntt);
    }

    let mut control: NttGgsw<Vec<u32>> = NttGgsw::zero(params.ggsw_len());
    let mut output: Glwe<Vec<u32>> = Glwe::zero(params.glwe_len());
    for (bit, expected) in messages.iter().enumerate() {
        let mut control_message = vec![0u32; POLY_LENGTH];
        control_message[0] = bit as u32;
        secret_key.encrypt_ggsw_to(
            &Polynomial::new(control_message),
            &mut control,
            &domain,
            &mut rng,
            &mut gadget_context,
        );

        control.cmux_to(
            &ciphertexts[0],
            &ciphertexts[1],
            &mut output,
            params.basis(),
            modulus,
            &ntt,
            &mut cmux_context,
        );

        let mut output_ntt: NttGlwe<Vec<u32>> = NttGlwe::zero(params.glwe_len());
        output.write_ntt_form(&mut output_ntt, &ntt);
        assert_eq!(
            secret_key.decrypt(&output_ntt, &glwe_params, &ntt).as_ref(),
            expected.as_slice()
        );
    }
}
