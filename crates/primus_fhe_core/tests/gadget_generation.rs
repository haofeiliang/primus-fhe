use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftEngine, FftTable, RustFftTable};
use primus_fhe_core::{
    FourierGadgetEncryptContext, FourierGlweDecryptContext, FourierGlweEncryptContext,
    FourierGlweSecretKey, GlevCommonSize, GlevParameters, GlweCommonSize, GlweParameters,
    GlweSecretKey, NttGadgetEncryptContext, NttGlweSecretKey, RingSecretKeyType,
};
use primus_lattice::{
    context::tfhe::{TfheFftContext, TfheNttContext},
    ggsw::{FourierGgswOwned, NttGgsw},
    glev::{FourierGlevOwned, NttGlev},
    glwe::{FourierGlweOwned, Glwe, NttGlwe, TorusGlwe},
    tfhe::external_product::{fourier_external_product_to, ntt_external_product_to},
};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::{Polynomial, PolynomialOwned};
use primus_reduce::{ReduceMul, ReduceNeg};

const DIMENSION: usize = 2;
const POLY_LENGTH: usize = 256;

#[test]
fn single_modulus_common_sizes_match_layout() {
    let glwe = GlweCommonSize::new(DIMENSION, POLY_LENGTH);
    assert_eq!(glwe.dimension(), DIMENSION);
    assert_eq!(glwe.poly_length(), POLY_LENGTH);
    assert_eq!(glwe.glwe_mid(), DIMENSION * POLY_LENGTH);
    assert_eq!(glwe.secret_key_len(), DIMENSION * POLY_LENGTH);
    assert_eq!(glwe.glwe_len(), (DIMENSION + 1) * POLY_LENGTH);
    assert_eq!(glwe.fourier_glwe_mid(), DIMENSION * POLY_LENGTH / 2);
    assert_eq!(glwe.fourier_glwe_len(), (DIMENSION + 1) * POLY_LENGTH / 2);

    let glev = GlevCommonSize::new(glwe, 4);
    assert_eq!(glev.glwe_common_size(), glwe);
    assert_eq!(glev.decompose_length(), 4);
    assert_eq!(glev.glev_len(), 4 * glwe.glwe_len());
    assert_eq!(glev.ggsw_len(), (DIMENSION + 1) * glev.glev_len());
    assert_eq!(glev.fourier_glev_len(), 4 * glwe.fourier_glwe_len());
    assert_eq!(
        glev.fourier_ggsw_len(),
        (DIMENSION + 1) * glev.fourier_glev_len()
    );
}

fn native_distance(lhs: u32, rhs: u32) -> u32 {
    lhs.wrapping_sub(rhs).min(rhs.wrapping_sub(lhs))
}

fn explicit_distance(lhs: u32, rhs: u32, modulus: u32) -> u32 {
    let distance = lhs.abs_diff(rhs);
    distance.min(modulus - distance)
}

#[test]
fn fourier_glev_generation_and_ggsw_external_product() {
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    let mut rng = rand::rng();
    let glwe_params = GlweParameters::new(
        DIMENSION,
        POLY_LENGTH,
        16u32,
        NativeModulus::new(),
        RingSecretKeyType::Binary,
        0.7,
    );
    let basis = ApproxSignedBasis::new(None, 8, None);
    let params = GlevParameters::with_glwe_params(&glwe_params, basis);
    let secret_key = FourierGlweSecretKey::generate(&glwe_params, &mut fft, &mut rng);
    let mut gadget_context =
        FourierGadgetEncryptContext::new(POLY_LENGTH, params.basis().decompose_length());
    let mut decrypt_context = FourierGlweDecryptContext::new(POLY_LENGTH);

    let mut raw_message = vec![0u32; POLY_LENGTH];
    raw_message[0] = 1;
    let raw_message = Polynomial::new(raw_message);
    let mut glev = FourierGlevOwned::zero(params.fourier_glev_len());
    secret_key.encrypt_glev_to(
        &raw_message,
        &mut glev,
        &params,
        &mut fft,
        &mut rng,
        &mut gadget_context,
    );

    for (scalar, glwe) in params
        .basis()
        .scalar_iter()
        .zip(glev.iter_glwe(params.fourier_glwe_len()))
    {
        let mut phase = PolynomialOwned::zero(POLY_LENGTH);
        secret_key.phase_to(&glwe, &mut phase, &mut fft, &mut decrypt_context);
        assert!(native_distance(phase.as_ref()[0], scalar) <= 8);
        assert!(
            phase.as_ref()[1..]
                .iter()
                .all(|&value| native_distance(value, 0) <= 8)
        );
    }

    let mut ggsw = FourierGgswOwned::zero(params.fourier_ggsw_len());
    secret_key.encrypt_ggsw_to(
        &raw_message,
        &mut ggsw,
        &params,
        &mut fft,
        &mut rng,
        &mut gadget_context,
    );

    let plaintext_values: Vec<u32> = (0..POLY_LENGTH).map(|index| (index % 16) as u32).collect();
    let plaintext = Polynomial::new(plaintext_values.clone());

    let mut monomial_message = vec![0u32; POLY_LENGTH];
    monomial_message[1] = 1;
    secret_key.encrypt_ggsw_to(
        &Polynomial::new(monomial_message),
        &mut ggsw,
        &params,
        &mut fft,
        &mut rng,
        &mut gadget_context,
    );

    let mut input_fourier = FourierGlweOwned::zero(params.fourier_glwe_len());
    let mut glwe_context = FourierGlweEncryptContext::new(POLY_LENGTH);
    secret_key.encrypt_to(
        &plaintext,
        &mut input_fourier,
        &glwe_params,
        &mut fft,
        &mut rng,
        &mut glwe_context,
    );
    let mut input: TorusGlwe<Vec<u32>> = TorusGlwe::zero(params.glwe_len());
    input_fourier.write_torus_form(&mut input, &mut fft);

    let mut output: TorusGlwe<Vec<u32>> = TorusGlwe::zero(params.glwe_len());
    let mut external_product_context = TfheFftContext::new(DIMENSION, POLY_LENGTH);
    fourier_external_product_to(
        &input,
        &ggsw,
        &mut output,
        params.basis(),
        &mut fft,
        &mut external_product_context,
    );

    let mut output_fourier = FourierGlweOwned::zero(params.fourier_glwe_len());
    output.write_fourier_form(&mut output_fourier, &mut fft);
    let mut expected = vec![0u32; POLY_LENGTH];
    expected[0] = (16 - plaintext_values[POLY_LENGTH - 1]) % 16;
    expected[1..].copy_from_slice(&plaintext_values[..POLY_LENGTH - 1]);
    assert_eq!(
        secret_key
            .decrypt(
                &output_fourier,
                &glwe_params,
                &mut fft,
                &mut decrypt_context,
            )
            .as_ref(),
        expected
    );
}

#[test]
fn ntt_glev_and_ggsw_generation() {
    const MODULUS: u32 = 132_120_577;

    let modulus = BarrettModulus::new(MODULUS);
    let ntt = UintNttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let mut rng = rand::rng();
    let glwe_params = GlweParameters::new(
        DIMENSION,
        POLY_LENGTH,
        16u32,
        modulus,
        RingSecretKeyType::Ternary,
        0.7,
    );
    let basis = ApproxSignedBasis::new(Some(MODULUS), 8, None);
    let params = GlevParameters::with_glwe_params(&glwe_params, basis);
    let coeff_secret_key = GlweSecretKey::generate(&glwe_params, &mut rng);
    let secret_key = NttGlweSecretKey::from_coeff_secret_key(&coeff_secret_key, &ntt);
    let mut context = NttGadgetEncryptContext::new(POLY_LENGTH, params.basis().decompose_length());

    let mut raw_message = vec![0u32; POLY_LENGTH];
    raw_message[0] = 1;
    let raw_message = Polynomial::new(raw_message);
    let mut glev: NttGlev<Vec<u32>> = NttGlev::zero(params.glev_len());
    secret_key.encrypt_glev_to(
        &raw_message,
        &mut glev,
        &params,
        &ntt,
        &mut rng,
        &mut context,
    );

    for (scalar, glwe) in params
        .basis()
        .scalar_iter()
        .zip(glev.iter_ntt_glwe(params.glwe_len()))
    {
        let mut phase = PolynomialOwned::zero(POLY_LENGTH);
        secret_key.phase_to(&glwe, &mut phase, &ntt, modulus);
        assert!(explicit_distance(phase.as_ref()[0], scalar, MODULUS) <= 8);
        assert!(
            phase.as_ref()[1..]
                .iter()
                .all(|&value| explicit_distance(value, 0, MODULUS) <= 8)
        );
    }

    let mut ggsw: NttGgsw<Vec<u32>> = NttGgsw::zero(params.ggsw_len());
    secret_key.encrypt_ggsw_to(
        &raw_message,
        &mut ggsw,
        &params,
        &ntt,
        &mut rng,
        &mut context,
    );

    for (row, glev) in ggsw.iter_ntt_glev(params.glev_len()).enumerate() {
        for (scalar, glwe) in params
            .basis()
            .scalar_iter()
            .zip(glev.iter_ntt_glwe(params.glwe_len()))
        {
            let mut phase = PolynomialOwned::zero(POLY_LENGTH);
            secret_key.phase_to(&glwe, &mut phase, &ntt, modulus);
            let expected: Vec<u32> = if row == DIMENSION {
                let mut values = vec![0; POLY_LENGTH];
                values[0] = scalar;
                values
            } else {
                coeff_secret_key
                    .iter()
                    .nth(row)
                    .unwrap()
                    .iter()
                    .map(|&coefficient| {
                        let coefficient = if coefficient < 0 {
                            modulus.reduce_neg(coefficient.unsigned_abs())
                        } else {
                            coefficient as u32
                        };
                        modulus.reduce_neg(modulus.reduce_mul(coefficient, scalar))
                    })
                    .collect()
            };
            assert!(
                phase
                    .as_ref()
                    .iter()
                    .zip(expected)
                    .all(|(&actual, expected)| explicit_distance(actual, expected, MODULUS) <= 8)
            );
        }
    }

    let plaintext_values: Vec<u32> = (0..POLY_LENGTH).map(|index| (index % 16) as u32).collect();
    let plaintext = Polynomial::new(plaintext_values.clone());

    let mut monomial_message = vec![0u32; POLY_LENGTH];
    monomial_message[1] = 1;
    secret_key.encrypt_ggsw_to(
        &Polynomial::new(monomial_message),
        &mut ggsw,
        &params,
        &ntt,
        &mut rng,
        &mut context,
    );

    let mut input_ntt: NttGlwe<Vec<u32>> = NttGlwe::zero(params.glwe_len());
    secret_key.encrypt_to(&plaintext, &mut input_ntt, &glwe_params, &ntt, &mut rng);
    let input = input_ntt.into_coeff_form(&ntt);
    let mut output: Glwe<Vec<u32>> = Glwe::zero(params.glwe_len());
    let mut external_product_context = TfheNttContext::new(DIMENSION, POLY_LENGTH);
    ntt_external_product_to(
        &input,
        &ggsw,
        &mut output,
        params.basis(),
        modulus,
        &ntt,
        &mut external_product_context,
    );
    let output_ntt = output.into_ntt_form(&ntt);
    let mut expected = vec![0u32; POLY_LENGTH];
    expected[0] = (16 - plaintext_values[POLY_LENGTH - 1]) % 16;
    expected[1..].copy_from_slice(&plaintext_values[..POLY_LENGTH - 1]);
    assert_eq!(
        secret_key.decrypt(&output_ntt, &glwe_params, &ntt).as_ref(),
        expected
    );
}
