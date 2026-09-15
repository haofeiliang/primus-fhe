#[path = "../../primus_tfhe_ntru/tests/support/allocations.rs"]
mod allocations;

use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GgswParameters, GlweParameters, NttGlweSecretKey, SecretKeyDistr};
use primus_lattice::{
    context::NttGlweExternalProductContext,
    ggsw::NttGgsw,
    glwe::{Glwe, NttGlwe},
};
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U64NttTable};
use primus_poly::Polynomial;
use primus_tfhe_glwe_ntt::{
    CircuitBootstrapEvaluationError, CircuitBootstrapParameters, PbsOrder, TfheContext,
    TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

const POLY_LENGTH: usize = 256;
const MODULUS: u64 = 1_125_899_906_826_241;

fn parameters(order: PbsOrder, plain_modulus: u64) -> TfheParameters<u64> {
    let modulus = BarrettModulus::new(MODULUS);
    let lwe = LweParameters::new(
        4,
        plain_modulus,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let glwe = GlweParameters::new(
        1,
        POLY_LENGTH,
        plain_modulus,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    // Full decomposition keeps the phase error below the third output level.
    let bootstrapping = ApproxSignedBasis::new(glwe.cipher_modulus_value(), 10, None);
    TfheParameters::try_new(
        lwe,
        glwe,
        bootstrapping,
        ApproxSignedBasis::new(Some(MODULUS), 10, Some(4)),
        order,
    )
    .unwrap()
}

#[test]
fn circuit_bootstrap_preserves_gadget_scales_and_controls_cmux() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let tfhe = parameters(order, 4);
        let modulus = BarrettModulus::new(MODULUS);
        let table = U64NttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
        let context = TfheContext::try_new(tfhe, table).unwrap();
        let mut rng = StdRng::seed_from_u64(0x0050_4154_4348_4544 ^ order as u64);
        let (client_key, server_key) = context.generate_keys(&mut rng).unwrap();
        let main_secret =
            NttGlweSecretKey::from_coeff_secret_key(client_key.glwe_secret_key(), context.table());
        let glwe = context.parameters().glwe();
        let mut choices: [Glwe<Vec<u64>>; 2] =
            core::array::from_fn(|_| Glwe::zero(glwe.glwe_len()));
        for (value, choice) in [1u64, 3].into_iter().zip(&mut choices) {
            let mut encrypted: NttGlwe<Vec<u64>> = NttGlwe::zero(glwe.glwe_len());
            main_secret.encrypt_to(
                &Polynomial::new(vec![value; POLY_LENGTH]),
                &mut encrypted,
                glwe,
                context.table(),
                &mut rng,
            );
            encrypted.write_coeff_form(choice, context.table());
        }

        let encryptor = context.encryptor(&client_key).unwrap();
        for levels in [2, 3] {
            let circuit_parameters = CircuitBootstrapParameters::try_new(
                context.parameters(),
                ApproxSignedBasis::new(Some(MODULUS), 8, Some(levels)),
                GgswParameters::with_glwe_params(glwe, 10, None),
                GgswParameters::with_glwe_params(glwe, 10, None),
            )
            .unwrap();
            let circuit_key = context
                .generate_circuit_bootstrap_key(&client_key, &circuit_parameters, &mut rng)
                .unwrap();
            let incompatible_trace =
                GgswParameters::with_glwe_params(context.parameters().glwe(), 9, None);
            let incompatible_parameters = CircuitBootstrapParameters::try_new(
                context.parameters(),
                circuit_parameters.output_basis().clone(),
                incompatible_trace,
                circuit_parameters.scheme_switch().clone(),
            )
            .unwrap();
            assert!(matches!(
                context.circuit_bootstrap_evaluator(
                    &server_key,
                    &incompatible_parameters,
                    &circuit_key,
                ),
                Err(CircuitBootstrapEvaluationError::IncompatibleCircuitBootstrapKey)
            ));
            // GLWE scheme switching binds output layout, so another output basis
            // with the same level count can reuse this circuit key.
            let circuit_parameters = CircuitBootstrapParameters::try_new(
                context.parameters(),
                ApproxSignedBasis::new(Some(MODULUS), 9, Some(levels)),
                circuit_parameters.trace().clone(),
                circuit_parameters.scheme_switch().clone(),
            )
            .unwrap();
            let mut evaluator = context
                .circuit_bootstrap_evaluator(&server_key, &circuit_parameters, &circuit_key)
                .unwrap();
            assert_eq!(
                circuit_parameters.many_lut_output_count(),
                levels.next_power_of_two()
            );
            let mut control =
                NttGgsw::<Vec<u64>>::zero(circuit_parameters.output_size().ggsw_len());
            for bit in 0..=1u64 {
                let input = encryptor.encrypt_padded(bit, &mut rng).unwrap();
                if bit == 1 {
                    for (dimension, length) in [
                        (input.dimension() - 1, control.as_ref().len()),
                        (input.dimension(), control.as_ref().len() - 1),
                    ] {
                        let bad_input = LweCiphertext::zero(dimension);
                        let mut bad_output = NttGgsw::new(vec![7; length]);
                        assert!(
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                evaluator.circuit_bootstrap_to(&bad_input, &mut bad_output);
                            }))
                            .is_err()
                        );
                        assert!(bad_output.as_ref().iter().all(|&value| value == 7));
                    }
                }
                let (_, allocation) = allocations::measure(|| {
                    evaluator.circuit_bootstrap_to(&input, &mut control);
                });
                assert_eq!(allocation.count, 0, "CBS must reuse its workspace");
                let output_size = circuit_parameters.output_size();
                let mut phase = Polynomial::new(vec![0u64; POLY_LENGTH]);
                for (row, glev) in control.iter_ntt_glev(output_size.glev_len()).enumerate() {
                    let secret = client_key.glwe_secret_key().iter().nth(row);
                    for (scalar, level) in circuit_parameters
                        .output_basis()
                        .scalar_iter()
                        .zip(glev.iter_ntt_glwe(glwe.glwe_len()))
                    {
                        main_secret.phase_to(&level, &mut phase, modulus, context.table());
                        for (index, &actual) in phase.as_ref().iter().enumerate() {
                            // Mask rows encrypt -g_l * bit * s_r; the body row
                            // encrypts the constant g_l * bit, with a zero tail.
                            let coefficient =
                                secret.map_or(i128::from(index == 0), |s| -i128::from(s[index]));
                            let expected = (coefficient * i128::from(scalar) * i128::from(bit))
                                .rem_euclid(i128::from(MODULUS))
                                as u64;
                            let distance = actual.abs_diff(expected);
                            let distance = distance.min(MODULUS - distance);
                            // Functional fixture bound, below the smallest gadget step.
                            assert!(
                                distance < (1 << 22),
                                "order {order:?}, levels {levels}, bit {bit}, row {row}, index {index}: distance {distance}"
                            );
                        }
                    }
                }
                let mut selected: Glwe<Vec<u64>> = Glwe::zero(glwe.glwe_len());
                let mut external_product =
                    NttGlweExternalProductContext::new(circuit_parameters.output_size());
                control.cmux_to(
                    &choices[0],
                    &choices[1],
                    &mut selected,
                    circuit_parameters.output_basis(),
                    modulus,
                    context.table(),
                    &mut external_product,
                );
                let selected = selected.into_ntt_form(context.table());
                assert_eq!(
                    main_secret
                        .decrypt(&selected, glwe, context.table())
                        .as_ref(),
                    vec![if bit == 0 { 1 } else { 3 }; POLY_LENGTH],
                    "PBS order {order:?}, control bit {bit}"
                );
            }
        }
    }
}

#[test]
fn circuit_parameters_check_capacity_layout_and_basis_domain() {
    use primus_tfhe_glwe_ntt::CircuitBootstrapParameterError as Error;
    let tfhe = parameters(PbsOrder::BootstrapKeyswitch, POLY_LENGTH as u64);
    let trace = tfhe.bootstrapping();
    let output = |levels| ApproxSignedBasis::new(Some(MODULUS), 8, Some(levels));
    let valid = CircuitBootstrapParameters::try_new(&tfhe, output(2), trace.clone(), trace.clone())
        .unwrap();
    assert_eq!(valid.output_size().glwe_size(), tfhe.glwe().size());
    assert!(matches!(
        CircuitBootstrapParameters::try_new(&tfhe, output(3), trace.clone(), trace.clone()),
        Err(Error::OutputDecompositionTooLarge)
    ));
    for modulus in [None, Some(132_120_577)] {
        assert!(matches!(
            CircuitBootstrapParameters::try_new(
                &tfhe,
                ApproxSignedBasis::new(modulus, 8, Some(2)),
                trace.clone(),
                trace.clone(),
            ),
            Err(Error::OutputBasisModulusMismatch)
        ));
    }
    for (dimension, poly_length, modulus, expected) in [
        (
            2,
            POLY_LENGTH,
            MODULUS,
            Error::GlweLayoutMismatch { role: "trace" },
        ),
        (
            1,
            POLY_LENGTH * 2,
            MODULUS,
            Error::GlweLayoutMismatch { role: "trace" },
        ),
        (
            1,
            POLY_LENGTH,
            132_120_577,
            Error::CipherModulusMismatch { role: "trace" },
        ),
    ] {
        let foreign = GlweParameters::new(
            dimension,
            poly_length,
            4,
            BarrettModulus::new(modulus),
            SecretKeyDistr::UniformBinary,
            0.7,
        );
        let result = CircuitBootstrapParameters::try_new(
            &tfhe,
            output(2),
            GgswParameters::with_glwe_params(&foreign, 8, Some(2)),
            trace.clone(),
        );
        assert_eq!(result.err(), Some(expected));
    }
}
