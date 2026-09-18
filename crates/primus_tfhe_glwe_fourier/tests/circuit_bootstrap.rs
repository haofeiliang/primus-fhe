use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, RustFftTable, TfheFftTable};
use primus_glwe::{
    FourierGlweEncryptContext, FourierGlweSchemeSwitchContext, FourierGlweSecretKey,
    FourierGlweTraceContext, GlevParameters, GlweParameters, SecretKeyDistr,
};
use primus_lattice::{
    ggsw::{FourierGgsw, Ggsw},
    glev::Glev,
    glwe::{FourierGlwe, Glwe},
};
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;
use primus_tfhe_glwe_fourier::{
    CircuitBootstrapKeyError, CircuitBootstrapParameterError, CircuitBootstrapParameters,
    ClientKey, KeyGenerator, PbsOrder, TfheContext, TfheParameters,
};
use rand::{RngExt, SeedableRng, rngs::StdRng};

const POLY_LENGTH: usize = 32;
const DIMENSION: usize = 2;

fn parameters(dimension: usize, poly_length: usize, plaintext_modulus: u64) -> TfheParameters<u64> {
    TfheParameters::try_new(
        LweParameters::new(
            4,
            plaintext_modulus,
            NativeModulus::new(),
            SecretKeyDistr::UniformBinary,
            0.7,
        ),
        GlweParameters::new(
            dimension,
            poly_length,
            plaintext_modulus,
            NativeModulus::new(),
            SecretKeyDistr::UniformTernary,
            0.7,
        ),
        ApproxSignedBasis::new(None, 8, Some(3)),
        ApproxSignedBasis::new(None, 8, Some(4)),
        PbsOrder::BootstrapKeyswitch,
    )
    .unwrap()
}

fn circuit_parameters(tfhe: &TfheParameters<u64>) -> CircuitBootstrapParameters<u64> {
    CircuitBootstrapParameters::try_new(
        tfhe,
        ApproxSignedBasis::new(None, 8, Some(3)),
        GlevParameters::with_glwe_params(tfhe.accumulator_glwe(), 8, Some(7)),
        GlevParameters::with_glwe_params(tfhe.accumulator_glwe(), 10, Some(5)),
    )
    .unwrap()
}

// Exact native-ring phase, independent of FFT and sample extraction.
fn phase(ciphertext: &[u64], secret: &[i64]) -> Vec<u64> {
    let (mask, body) = ciphertext.split_at(DIMENSION * POLY_LENGTH);
    let mut phase = body.to_vec();
    for (mask, secret) in mask
        .as_chunks::<POLY_LENGTH>()
        .0
        .iter()
        .zip(secret.as_chunks::<POLY_LENGTH>().0)
    {
        for (i, &a) in mask.iter().enumerate() {
            for (j, &s) in secret.iter().enumerate() {
                let product = a.wrapping_mul(s as u64);
                let coefficient = &mut phase[(i + j) % POLY_LENGTH];
                *coefficient = if i + j < POLY_LENGTH {
                    coefficient.wrapping_sub(product)
                } else {
                    coefficient.wrapping_add(product)
                };
            }
        }
    }
    phase
}

fn generated_keys_project_and_scheme_switch<Table: FftTable>() {
    let context = TfheContext::try_new(
        parameters(DIMENSION, POLY_LENGTH, 4),
        Table::new(POLY_LENGTH.trailing_zeros()).unwrap(),
    )
    .unwrap();
    let parameters = circuit_parameters(context.parameters());
    let mut rng = StdRng::seed_from_u64(0x4342_534b_4559);
    let client = ClientKey::generate(context.parameters(), &mut rng);
    let mut generator = KeyGenerator::new(&context);
    let key = generator
        .try_generate_circuit_bootstrap_key(&client, &parameters, &mut rng)
        .unwrap();
    // CBS leaves a different gadget layout in the reusable generator.
    generator
        .try_generate_server_key(&client, &mut rng)
        .unwrap();

    assert_eq!(parameters.lookup_table_padded_output_count(), 4);
    assert_eq!(key.trace_key().basis(), parameters.trace().basis());
    assert_eq!(
        key.trace_key().automorphism_count(),
        POLY_LENGTH.trailing_zeros() as usize
    );
    assert_eq!(
        key.scheme_switch_key().key_basis(),
        parameters.scheme_switch().basis()
    );
    assert_eq!(
        key.scheme_switch_key().key_size(),
        parameters.scheme_switch().size()
    );
    assert_eq!(
        key.scheme_switch_key().output_size(),
        parameters.output_size()
    );

    let mut fft = context.new_fft_engine();
    let secret = FourierGlweSecretKey::from_coeff_secret_key(client.glwe_secret_key(), &mut fft);
    let glwe = context.parameters().accumulator_glwe();
    // A nonzero tail requires full projection, not prefix-only expansion.
    let mut message = vec![1u64 << 56; POLY_LENGTH];
    for (coefficient, scalar) in message
        .iter_mut()
        .zip(parameters.output_basis().scalar_iter())
    {
        *coefficient = scalar;
    }
    let mut encrypted = FourierGlwe::<Vec<_>>::zero(glwe.size().fourier_glwe_len());
    secret.encrypt_encoded_to(
        &Polynomial::new(message),
        &mut encrypted,
        glwe,
        &mut fft,
        &mut rng,
        &mut FourierGlweEncryptContext::new(POLY_LENGTH),
    );
    let mut input = Glwe::new(vec![0u64; glwe.glwe_len()]);
    encrypted.write_torus_form(&mut input, &mut fft);
    let mut projected = Glev::new(vec![0u64; parameters.output_size().glev_len()]);
    key.trace_key().project_coefficients_to(
        &input,
        &[0, 1, 2],
        projected.as_mut(),
        &mut fft,
        &mut FourierGlweTraceContext::new(glwe.size()),
    );
    let mut output = FourierGgsw::<Vec<_>>::zero(parameters.output_size().fourier_ggsw_len());
    key.scheme_switch_key().apply_to(
        &projected,
        &mut output,
        &mut fft,
        &mut FourierGlweSchemeSwitchContext::new(parameters.scheme_switch().size()),
    );
    let mut coefficients = Ggsw::new(vec![0u64; parameters.output_size().ggsw_len()]);
    output.write_torus_form(&mut coefficients, &mut fft);
    // Leave at least a factor-four margin to the smallest programmed gadget scale.
    let tolerance = parameters.output_basis().scalar_iter().min().unwrap() / 4;
    for (row, levels) in coefficients
        .as_ref()
        .chunks_exact(parameters.output_size().glev_len())
        .enumerate()
    {
        for (scalar, ciphertext) in parameters
            .output_basis()
            .scalar_iter()
            .zip(levels.chunks_exact(glwe.glwe_len()))
        {
            for (index, actual) in phase(ciphertext, client.glwe_secret_key().as_slice())
                .into_iter()
                .enumerate()
            {
                let expected = if row == DIMENSION {
                    if index == 0 { scalar } else { 0 }
                } else {
                    (client.glwe_secret_key().as_slice()[row * POLY_LENGTH + index] as u64)
                        .wrapping_mul(scalar)
                        .wrapping_neg()
                };
                let error = actual.wrapping_sub(expected);
                assert!(
                    error.min(error.wrapping_neg()) < tolerance,
                    "row={row}, scale={scalar}, coefficient={index}"
                );
            }
        }
    }
}

#[test]
fn additional_keys_feed_trace_and_scheme_switch_with_both_ffts() {
    generated_keys_project_and_scheme_switch::<RustFftTable>();
    generated_keys_project_and_scheme_switch::<TfheFftTable>();
}

#[test]
fn circuit_parameters_check_native_basis_layout_and_padded_capacity() {
    use CircuitBootstrapParameterError as Error;
    let tfhe = parameters(DIMENSION, POLY_LENGTH, POLY_LENGTH as u64);
    let trace = tfhe.blind_rotation_ggsw();
    let make =
        |basis| CircuitBootstrapParameters::try_new(&tfhe, basis, trace.clone(), trace.clone());
    assert!(make(ApproxSignedBasis::new(None, 8, Some(2))).is_ok());
    assert_eq!(
        make(ApproxSignedBasis::new(None, 8, Some(3))).err(),
        Some(Error::OutputDecompositionTooLarge)
    );
    assert_eq!(
        make(ApproxSignedBasis::new(Some(1 << 63), 8, Some(2))).err(),
        Some(Error::OutputBasisModulusMismatch)
    );
    for (dimension, poly_length) in [(DIMENSION + 1, POLY_LENGTH), (DIMENSION, POLY_LENGTH * 2)] {
        let foreign = parameters(dimension, poly_length, 4);
        for (role, trace, scheme_switch) in [
            (
                "trace",
                foreign.blind_rotation_ggsw().clone(),
                trace.clone(),
            ),
            (
                "scheme-switch",
                trace.clone(),
                foreign.blind_rotation_ggsw().clone(),
            ),
        ] {
            assert_eq!(
                CircuitBootstrapParameters::try_new(
                    &tfhe,
                    ApproxSignedBasis::new(None, 8, Some(2)),
                    trace,
                    scheme_switch
                )
                .err(),
                Some(Error::GlweLayoutMismatch { role })
            );
        }
    }
}

#[test]
fn incompatible_parameters_and_client_keys_are_rejected_before_sampling() {
    let context = TfheContext::try_new(
        parameters(DIMENSION, POLY_LENGTH, 4),
        RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap(),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let client = ClientKey::generate(context.parameters(), &mut rng);
    for (dimension, poly_length, plaintext_modulus) in [
        (DIMENSION + 1, POLY_LENGTH, 4),
        (DIMENSION, POLY_LENGTH * 2, 4),
        (DIMENSION, POLY_LENGTH, 8),
    ] {
        let foreign = circuit_parameters(&parameters(dimension, poly_length, plaintext_modulus));
        let mut rng = StdRng::seed_from_u64(43);
        let mut untouched_rng = StdRng::seed_from_u64(43);
        assert!(matches!(
            context.generate_circuit_bootstrap_key(&client, &foreign, &mut rng),
            Err(CircuitBootstrapKeyError::IncompatibleParameters)
        ));
        assert_eq!(rng.random::<u64>(), untouched_rng.random::<u64>());
    }
    let foreign_client = ClientKey::generate(&parameters(DIMENSION + 1, POLY_LENGTH, 4), &mut rng);
    let mut rng = StdRng::seed_from_u64(43);
    let mut untouched_rng = StdRng::seed_from_u64(43);
    assert!(matches!(
        context.generate_circuit_bootstrap_key(
            &foreign_client,
            &circuit_parameters(context.parameters()),
            &mut rng
        ),
        Err(CircuitBootstrapKeyError::ClientKey(_))
    ));
    assert_eq!(rng.random::<u64>(), untouched_rng.random::<u64>());
}
