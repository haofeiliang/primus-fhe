use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable};
use primus_glwe::{
    FourierGadgetEncryptContext, FourierGlweDecryptContext, FourierGlweEncryptContext,
    FourierGlweSecretKey, GlevParameters, GlweParameters, NttGadgetEncryptContext,
    NttGlweSecretKey, SecretKeyDistr,
};
use primus_lattice::{
    context::{FourierGlweExternalProductContext, NttGlweExternalProductContext},
    ggsw::{FourierGgsw, NttGgsw, NttGgswIter},
    glwe::{FourierGlweOwned, Glwe, NttGlwe, TorusGlwe},
};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
use rand::{SeedableRng, rngs::StdRng};

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
    let mut rng = StdRng::seed_from_u64(42);
    let glwe_params = GlweParameters::new(
        DIMENSION,
        POLY_LENGTH,
        PLAINTEXT_MODULUS,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let params = GlevParameters::with_glwe_params(&glwe_params, 8, None);
    let (_, secret_key) = FourierGlweSecretKey::generate_pair(&glwe_params, &mut fft, &mut rng);
    let mut encrypt_context = FourierGlweEncryptContext::new(POLY_LENGTH);
    let mut decrypt_context = FourierGlweDecryptContext::new(POLY_LENGTH);
    let mut gadget_context = FourierGadgetEncryptContext::new(params.size());
    let mut cmux_context = FourierGlweExternalProductContext::new(params.size());

    let messages = [plaintext(1), plaintext(7), plaintext(12)];
    let mut ciphertexts: [TorusGlwe<Vec<u32>>; 3] =
        core::array::from_fn(|_| TorusGlwe::zero(params.glwe_len()));
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

    let mut output: TorusGlwe<Vec<u32>> = TorusGlwe::zero(params.glwe_len());
    let ggsw_len = params.fourier_ggsw_len();
    let mut controls = vec![Complex64::default(); 2 * ggsw_len];
    // Exercise both CMUX kernels and every valid selector, reusing output/context.
    for (control_count, selected) in [(1, 0), (1, 1), (2, 0), (2, 1), (2, 2)] {
        let selectors = [u32::from(selected == 1), u32::from(selected == 2)];
        secret_key.encrypt_ggsw_constant_batch_to(
            &selectors[..control_count],
            &mut controls[..control_count * ggsw_len],
            &params,
            &mut fft,
            &mut rng,
            &mut gadget_context,
        );

        if control_count == 1 {
            FourierGgsw::new(&controls[..ggsw_len]).cmux_to(
                &ciphertexts[0],
                &ciphertexts[1],
                &mut output,
                params.basis(),
                &mut fft,
                &mut cmux_context,
            );
        } else {
            FourierGgsw::cmux_k_to(
                controls.chunks_exact(ggsw_len).map(FourierGgsw::new),
                &ciphertexts[0],
                &ciphertexts[1..],
                &mut output,
                params.basis(),
                &mut fft,
                &mut cmux_context,
            );
        }

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
            messages[selected].as_slice()
        );
    }
}

#[test]
fn ntt_cmux_selects_requested_glwe() {
    const MODULUS: u32 = 132_120_577;

    let modulus = BarrettModulus::new(MODULUS);
    let ntt = UintNttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let glwe_params = GlweParameters::new(
        DIMENSION,
        POLY_LENGTH,
        PLAINTEXT_MODULUS,
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let params = GlevParameters::with_glwe_params(&glwe_params, 8, None);
    let (_, secret_key) = NttGlweSecretKey::generate_pair(&glwe_params, &ntt, &mut rng);
    let mut gadget_context = NttGadgetEncryptContext::new(params.size());
    let mut cmux_context = NttGlweExternalProductContext::new(params.size());

    let messages = [plaintext(2), plaintext(7), plaintext(11)];
    let mut ciphertexts: [Glwe<Vec<u32>>; 3] =
        core::array::from_fn(|_| Glwe::zero(params.glwe_len()));
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

    let mut output: Glwe<Vec<u32>> = Glwe::zero(params.glwe_len());
    let ggsw_len = params.ggsw_len();
    let mut controls = vec![0u32; 2 * ggsw_len];
    for (control_count, selected) in [(1, 0), (1, 1), (2, 0), (2, 1), (2, 2)] {
        let selectors = [u32::from(selected == 1), u32::from(selected == 2)];
        secret_key.encrypt_ggsw_constant_batch_to(
            &selectors[..control_count],
            &mut controls[..control_count * ggsw_len],
            &params,
            &ntt,
            &mut rng,
            &mut gadget_context,
        );

        if control_count == 1 {
            NttGgsw::new(&controls[..ggsw_len]).cmux_to(
                &ciphertexts[0],
                &ciphertexts[1],
                &mut output,
                params.basis(),
                modulus,
                &ntt,
                &mut cmux_context,
            );
        } else {
            NttGgsw::cmux_k_to(
                NttGgswIter::new(&controls, ggsw_len),
                &ciphertexts[0],
                &ciphertexts[1..],
                &mut output,
                params.basis(),
                modulus,
                &ntt,
                &mut cmux_context,
            );
        }

        let mut output_ntt: NttGlwe<Vec<u32>> = NttGlwe::zero(params.glwe_len());
        output.write_ntt_form(&mut output_ntt, &ntt);
        assert_eq!(
            secret_key.decrypt(&output_ntt, &glwe_params, &ntt).as_ref(),
            messages[selected].as_slice()
        );
    }
}
