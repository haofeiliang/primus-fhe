use primus_glwe::{
    GlevParameters, GlweParameters, GlweSecretKey, NttGadgetEncryptContext,
    NttGlweSchemeSwitchContext, NttGlweSchemeSwitchKey, NttGlweSecretKey, SecretKeyDistr,
};
use primus_lattice::{
    context::NttGlweExternalProductContext,
    ggsw::NttGgsw,
    glev::NttGlev,
    glwe::{Glwe, NttGlwe},
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U64NttTable};
use primus_poly::Polynomial;
use rand::{SeedableRng, rngs::StdRng};

mod common;

const POLY_LENGTH: usize = 256;
const DIMENSION: usize = 2;
const PLAINTEXT_MODULUS: u64 = 16;
const MODULUS: u64 = 1_125_899_906_826_241;

#[test]
fn ntt_scheme_switch_produces_an_external_product_control() {
    let modulus = BarrettModulus::new(MODULUS);
    let ntt = U64NttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let glwe_parameters = GlweParameters::new(
        DIMENSION,
        POLY_LENGTH,
        PLAINTEXT_MODULUS,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let output_parameters = GlevParameters::with_glwe_params(&glwe_parameters, 10, Some(2));
    let scheme_parameters = GlevParameters::with_glwe_params(&glwe_parameters, 10, Some(3));
    let mut rng = StdRng::seed_from_u64(0x0043_4253_5052_494d);
    let coefficient_secret = GlweSecretKey::generate(
        glwe_parameters.size(),
        glwe_parameters.secret_key_sampler(),
        &mut rng,
    );
    let secret = NttGlweSecretKey::from_coeff_secret_key(&coefficient_secret, &ntt);
    let mut gadget = NttGadgetEncryptContext::new(scheme_parameters.size());

    let scheme_key = NttGlweSchemeSwitchKey::generate(
        &coefficient_secret,
        &secret,
        output_parameters.size(),
        &scheme_parameters,
        &ntt,
        &mut rng,
        &mut gadget,
    );
    gadget.resize(output_parameters.size());
    let mut control_message = vec![0; POLY_LENGTH];
    control_message[0] = 1;
    let mut input_glev: NttGlev<Vec<u64>> = NttGlev::zero(output_parameters.glev_len());
    secret.encrypt_glev_to(
        &Polynomial::new(control_message),
        &mut input_glev,
        &output_parameters,
        &ntt,
        &mut rng,
        &mut gadget,
    );
    let input_glev = input_glev.into_coeff_form(&ntt);
    let mut control: NttGgsw<Vec<u64>> = NttGgsw::zero(output_parameters.ggsw_len());
    let mut scheme_context = NttGlweSchemeSwitchContext::new(scheme_parameters.size());
    scheme_key.apply_to(
        &input_glev,
        &mut control,
        modulus,
        &ntt,
        &mut scheme_context,
    );

    let selected_message = vec![5; POLY_LENGTH];
    let mut selected: NttGlwe<Vec<u64>> = NttGlwe::zero(glwe_parameters.glwe_len());
    secret.encrypt_to(
        &Polynomial::new(selected_message.as_slice()),
        &mut selected,
        &glwe_parameters,
        &ntt,
        &mut rng,
    );
    let selected = selected.into_coeff_form(&ntt);
    let mut product: Glwe<Vec<u64>> = Glwe::zero(glwe_parameters.glwe_len());
    let mut external_product = NttGlweExternalProductContext::new(output_parameters.size());
    control.external_product_to(
        &selected,
        &mut product,
        output_parameters.basis(),
        modulus,
        &ntt,
        &mut external_product,
    );
    let product = product.into_ntt_form(&ntt);
    assert_eq!(
        secret.decrypt(&product, &glwe_parameters, &ntt).as_ref(),
        selected_message
    );

    // Reject mismatched modulus/table pairs before copying any row.
    let wrong_modulus = BarrettModulus::new(132_120_577u64);
    let wrong_table = U64NttTable::new(POLY_LENGTH.trailing_zeros(), wrong_modulus).unwrap();
    let wrong_length_table = U64NttTable::new((POLY_LENGTH * 2).trailing_zeros(), modulus).unwrap();
    for (modulus, table) in [
        (modulus, &wrong_table),
        (wrong_modulus, &wrong_table),
        (modulus, &wrong_length_table),
    ] {
        let mut output = NttGgsw::new(vec![7u64; output_parameters.ggsw_len()]);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                scheme_key.apply_to(
                    &input_glev,
                    &mut output,
                    modulus,
                    table,
                    &mut scheme_context,
                );
            }))
            .is_err()
        );
        assert_eq!(output.as_ref(), vec![7u64; output_parameters.ggsw_len()]);
    }
}

fn fourier_scheme_switch<Table: primus_fft::FftTable>() {
    use common::{K, N, assert_phase, encrypt, message, secret};
    use primus_fft::FftEngine;
    use primus_glwe::{
        FourierGadgetEncryptContext, FourierGlweSchemeSwitchContext, FourierGlweSchemeSwitchKey,
        FourierGlweSecretKey, GlweSize,
    };
    use primus_lattice::{
        context::FourierGlweExternalProductContext,
        ggsw::{FourierGgsw, Ggsw},
        glev::Glev,
    };
    use primus_modulus::NativeModulus;

    let table = Table::new(N.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    let params = GlweParameters::new(
        K,
        N,
        64u64,
        NativeModulus::new(),
        SecretKeyDistr::UniformTernary,
        0.7,
    );
    // The output's gadget basis is independent of the scheme-switch key's basis.
    let output_params = GlevParameters::with_glwe_params(&params, 8, Some(3));
    let key_params = GlevParameters::with_glwe_params(&params, 10, Some(4));
    let coeff = GlweSecretKey::<u64>::new(secret(), params.size(), SecretKeyDistr::UniformTernary);
    let sk = FourierGlweSecretKey::from_coeff_secret_key(&coeff, &mut fft);
    let mut rng = StdRng::seed_from_u64(0x534348454d45);
    let key = FourierGlweSchemeSwitchKey::generate(
        &coeff,
        &sk,
        output_params.size(),
        &key_params,
        &mut fft,
        &mut rng,
        &mut FourierGadgetEncryptContext::new(key_params.size()),
    );
    // Build GLev(X^(N-1)) with an independent coefficient-domain encryption oracle.
    let mut input = Glev::new(vec![0; output_params.glev_len()]);
    for (scalar, block) in output_params
        .basis()
        .scalar_iter()
        .zip(input.as_mut().chunks_exact_mut(params.glwe_len()))
    {
        let mut m = vec![0; N];
        m[N - 1] = scalar;
        block.copy_from_slice(encrypt(&m, &secret(), 1u128 << 64, &mut rng).as_ref());
    }
    let mut output = FourierGgsw::<Vec<_>>::zero(output_params.fourier_ggsw_len());
    let mut context = FourierGlweSchemeSwitchContext::new(key_params.size());
    key.apply_to(&input, &mut output, &mut fft, &mut context);

    // Check every row and level, including the directly transformed body row.
    let mut coefficient_output = Ggsw::new(vec![0u64; output_params.ggsw_len()]);
    output.write_torus_form(&mut coefficient_output, &mut fft);
    for (row, levels) in coefficient_output
        .as_ref()
        .chunks_exact(output_params.glev_len())
        .enumerate()
    {
        for (scalar, ciphertext) in output_params
            .basis()
            .scalar_iter()
            .zip(levels.chunks_exact(params.glwe_len()))
        {
            let mut expected = vec![0u64; N];
            if row == K {
                expected[N - 1] = scalar;
            } else {
                for (i, &s) in secret()[row * N..(row + 1) * N].iter().enumerate() {
                    // -s(X) * X^(N-1), reduced modulo X^N+1.
                    let value = (s as u64).wrapping_mul(scalar);
                    expected[(i + N - 1) % N] = if i == 0 { value.wrapping_neg() } else { value };
                }
            }
            assert_phase(ciphertext, &expected, &secret(), 1u128 << 64);
        }
    }
    let m = message(1u128 << 64);
    let selected = encrypt(&m, &secret(), 1u128 << 64, &mut rng);
    let mut product = Glwe::new(vec![0; params.glwe_len()]);
    output.external_product_to(
        &selected,
        &mut product,
        output_params.basis(),
        &mut fft,
        &mut FourierGlweExternalProductContext::new(output_params.size()),
    );
    let mut expected = vec![0; N];
    expected[N - 1] = m[0];
    for i in 1..N {
        expected[i - 1] = m[i].wrapping_neg();
    }
    assert_phase(product.as_ref(), &expected, &secret(), 1u128 << 64);

    let wrong_table = Table::new((N * 2).trailing_zeros()).unwrap();
    let mut wrong_fft = FftEngine::new(&wrong_table);
    let wrong_size = primus_lattice::GadgetSize::new(
        GlweSize::new(K + 1, N),
        key_params.size().decompose_length(),
    );
    for (input_len, output_len, wrong_fft_length, size) in [
        (
            input.as_ref().len() - 1,
            output.as_ref().len(),
            false,
            key_params.size(),
        ),
        (
            input.as_ref().len(),
            output.as_ref().len() - 1,
            false,
            key_params.size(),
        ),
        (
            input.as_ref().len(),
            output.as_ref().len(),
            true,
            key_params.size(),
        ),
        (
            input.as_ref().len(),
            output.as_ref().len(),
            false,
            wrong_size,
        ),
    ] {
        let mut output = FourierGgsw::new(vec![primus_fft::Complex64::new(7.0, 0.0); output_len]);
        let engine = if wrong_fft_length {
            &mut wrong_fft
        } else {
            &mut fft
        };
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                key.apply_to(
                    &Glev::new(&input.as_ref()[..input_len]),
                    &mut output,
                    engine,
                    &mut FourierGlweSchemeSwitchContext::new(size),
                );
            }))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|x| x.re == 7.0 && x.im == 0.0));
    }
}

#[test]
fn fourier_scheme_switch_preserves_gadget_rows_and_external_product_semantics() {
    fourier_scheme_switch::<primus_fft::RustFftTable>();
    fourier_scheme_switch::<primus_fft::TfheFftTable>();
}
