use primus_fft::{FftEngine, FftTable, RustFftTable};
use primus_glwe::{
    FourierGadgetEncryptContext, FourierGlweDecryptContext, FourierGlweEncryptContext,
    FourierGlweSecretKey, GlevParameters, GlweParameters, NttGadgetEncryptContext,
    NttGlweSecretKey, SecretKeyDistr,
};
use primus_lattice::{
    context::{FourierGlweExternalProductContext, NttGlweExternalProductContext},
    ggsw::{FourierGgswOwned, NttGgsw},
    glev::{FourierGlevOwned, NttGlev},
    glwe::{FourierGlweOwned, Glwe, NttGlwe, TorusGlwe},
};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::{Polynomial, PolynomialOwned};
use rand::{SeedableRng, rngs::StdRng};

const DIMENSION: usize = 2;
const POLY_LENGTH: usize = 256;

// Independent integer oracle for g_l * m (body row) or -g_l * m * s_r
// (mask row) in Z_q[X]/(X^N + 1). Test sizes and coefficients fit in i128.
fn expected_ggsw_phase(message: &[u32], secret: Option<&[i32]>, scalar: u32, q: u64) -> Vec<u32> {
    let mut phase: Vec<i128> = message.iter().map(|&value| i128::from(value)).collect();
    if let Some(secret) = secret {
        phase.fill(0);
        for (i, &m) in message.iter().enumerate() {
            for (j, &s) in secret.iter().enumerate() {
                let product = i128::from(m) * i128::from(s);
                if i + j < message.len() {
                    phase[i + j] -= product;
                } else {
                    phase[i + j - message.len()] += product;
                }
            }
        }
    }
    phase
        .into_iter()
        .map(|value| (value * i128::from(scalar)).rem_euclid(i128::from(q)) as u32)
        .collect()
}

fn native_distance(lhs: u32, rhs: u32) -> u32 {
    lhs.wrapping_sub(rhs).min(rhs.wrapping_sub(lhs))
}

fn explicit_distance(lhs: u32, rhs: u32, modulus: u32) -> u32 {
    let distance = lhs.abs_diff(rhs);
    distance.min(modulus - distance)
}

#[test]
fn fourier_gadget_phases_and_external_product() {
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    let mut rng = StdRng::seed_from_u64(42);
    let glwe_params = GlweParameters::new(
        DIMENSION,
        POLY_LENGTH,
        16u32,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let params = GlevParameters::with_glwe_params(&glwe_params, 8, None);
    let (coeff_secret_key, secret_key) =
        FourierGlweSecretKey::generate_pair(&glwe_params, &mut fft, &mut rng);
    let mut gadget_context = FourierGadgetEncryptContext::new(params.size());
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
    let ring_message = Polynomial::new(
        (0..POLY_LENGTH)
            .map(|i| (i as u32).wrapping_mul(0x9e37_79b9))
            .collect::<Vec<_>>(),
    );
    secret_key.encrypt_ggsw_to(
        &ring_message,
        &mut ggsw,
        &params,
        &mut fft,
        &mut rng,
        &mut gadget_context,
    );
    for (row, glev) in ggsw.iter_glev(params.fourier_glev_len()).enumerate() {
        for (scalar, glwe) in params
            .basis()
            .scalar_iter()
            .zip(glev.iter_glwe(params.fourier_glwe_len()))
        {
            let mut phase = PolynomialOwned::zero(POLY_LENGTH);
            secret_key.phase_to(&glwe, &mut phase, &mut fft, &mut decrypt_context);
            let expected = expected_ggsw_phase(
                ring_message.as_ref(),
                coeff_secret_key.iter().nth(row),
                scalar,
                1u64 << 32,
            );
            assert!(
                phase
                    .iter()
                    .zip(expected)
                    .all(|(&actual, expected)| native_distance(actual, expected) <= 8),
                "GGSW row {row}, scalar {scalar}"
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
    let mut external_product_context = FourierGlweExternalProductContext::new(params.size());
    ggsw.external_product_to(
        &input,
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
fn ntt_gadget_phases_and_external_product() {
    const MODULUS: u32 = 132_120_577;

    let modulus = BarrettModulus::new(MODULUS);
    let ntt = UintNttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let glwe_params = GlweParameters::new(
        DIMENSION,
        POLY_LENGTH,
        16u32,
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let params = GlevParameters::with_glwe_params(&glwe_params, 8, None);
    let (coeff_secret_key, secret_key) =
        NttGlweSecretKey::generate_pair(&glwe_params, &ntt, &mut rng);
    let mut context = NttGadgetEncryptContext::new(params.size());

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
        secret_key.phase_to(&glwe, &mut phase, modulus, &ntt);
        assert!(explicit_distance(phase.as_ref()[0], scalar, MODULUS) <= 8);
        assert!(
            phase.as_ref()[1..]
                .iter()
                .all(|&value| explicit_distance(value, 0, MODULUS) <= 8)
        );
    }

    let mut ggsw: NttGgsw<Vec<u32>> = NttGgsw::zero(params.ggsw_len());
    let ring_message = Polynomial::new(
        (0..POLY_LENGTH)
            .map(|i| (i as u32).wrapping_mul(0x9e37_79b9) % MODULUS)
            .collect::<Vec<_>>(),
    );
    secret_key.encrypt_ggsw_to(
        &ring_message,
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
            secret_key.phase_to(&glwe, &mut phase, modulus, &ntt);
            let expected = expected_ggsw_phase(
                ring_message.as_ref(),
                coeff_secret_key.iter().nth(row),
                scalar,
                u64::from(MODULUS),
            );
            assert!(
                phase
                    .as_ref()
                    .iter()
                    .zip(expected)
                    .all(|(&actual, expected)| explicit_distance(actual, expected, MODULUS) <= 8),
                "GGSW row {row}, scalar {scalar}"
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
    let mut external_product_context = NttGlweExternalProductContext::new(params.size());
    ggsw.external_product_to(
        &input,
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

#[test]
fn ntt_constant_ggsw_batch_matches_individual_encryptions() {
    use rand::Rng;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let n = 16usize;
    let modulus = BarrettModulus::new(257u32);
    let glwe = GlweParameters::new(2, n, 16, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let params = GlevParameters::with_glwe_params(&glwe, 4, None);
    let table = UintNttTable::new(n.trailing_zeros(), modulus).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let (_, key) = NttGlweSecretKey::generate_pair(&glwe, &table, &mut rng);
    let mut context = NttGadgetEncryptContext::new(params.size());
    let mut single_context = NttGadgetEncryptContext::new(params.size());
    // Include empty input, binary BSK inputs and general canonical constants.
    for constants in [&[][..], &[0, 1, 256, 17][..]] {
        let mut batch = vec![7; constants.len() * params.ggsw_len()];
        let mut singles = batch.clone();
        let mut rng = StdRng::seed_from_u64(43);
        let mut single_rng = StdRng::seed_from_u64(43);
        key.encrypt_ggsw_constant_batch_to(
            constants,
            &mut batch,
            &params,
            &table,
            &mut rng,
            &mut context,
        );
        let mut message = PolynomialOwned::zero(n);
        for (&constant, chunk) in constants
            .iter()
            .zip(singles.chunks_exact_mut(params.ggsw_len()))
        {
            message.as_mut()[0] = constant;
            key.encrypt_ggsw_to(
                &message,
                &mut NttGgsw::new(chunk),
                &params,
                &table,
                &mut single_rng,
                &mut single_context,
            );
        }
        assert_eq!(batch, singles);
        assert_eq!(rng.next_u64(), single_rng.next_u64());
    }
    // An invalid total length must fail before writing or consuming randomness.
    for len in [params.ggsw_len(), 2 * params.ggsw_len() + 1] {
        let mut output = vec![7; len];
        let mut rng = StdRng::seed_from_u64(43);
        let mut expected_rng = StdRng::seed_from_u64(43);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                key.encrypt_ggsw_constant_batch_to(
                    &[0, 1],
                    &mut output,
                    &params,
                    &table,
                    &mut rng,
                    &mut context,
                );
            }))
            .is_err()
        );
        assert_eq!(output, vec![7; len]);
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }
}
