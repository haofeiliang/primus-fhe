#[path = "../../primus_tfhe/tests/support/allocations.rs"]
mod allocations;

use primus_decompose::primitive::ApproxSignedBasis;
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntru::{
    NlevParameters, NtruCiphertext, NtruParameters, NttNgswCiphertext, NttNtruCiphertext,
    NttNtruExternalProductContext, NttNtruSecretKey, SecretKeyDistr,
};
use primus_ntt::{NttTable, U64NttTable};
use primus_poly::Polynomial;
use primus_tfhe_ntru_ntt::{
    CircuitBootstrapEvaluationError, CircuitBootstrapParameters, NtruTfheParameters, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 256;
const Q: u64 = 1_125_899_906_826_241;

#[test]
fn circuit_bootstrap_preserves_gadget_scales_and_controls_cmux() {
    let modulus = BarrettModulus::new(Q);
    let lwe = LweParameters::new(16, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let accumulator = NtruParameters::new(N, 4, modulus, SecretKeyDistr::SparseTernary, 0.7);
    let client = NtruParameters::new(N, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let tfhe = NtruTfheParameters::try_new(
        lwe,
        NlevParameters::with_ntru_params(&accumulator, 10, None),
        NlevParameters::with_ntru_params(&client, 10, None),
    )
    .unwrap();
    let context =
        TfheContext::try_new(tfhe, U64NttTable::new(N.trailing_zeros(), modulus).unwrap()).unwrap();
    let mut rng = StdRng::seed_from_u64(0x004e_5454_5f43_4253);
    let (client, server) = context.generate_keys(&mut rng).unwrap();
    let key = NttNtruSecretKey::try_from_coeff_secret_key(
        client.accumulator_ntru_secret_key(),
        modulus,
        context.table(),
    )
    .unwrap();
    let encryptor = context.encryptor(&client).unwrap();
    let choices = [1, 3].map(|message| {
        let transformed = key.encrypt(
            &Polynomial::new(vec![message; N]),
            &accumulator,
            context.table(),
            &mut rng,
        );
        let mut output = NtruCiphertext::<Vec<u64>>::zero(N);
        transformed.write_coeff_form(&mut output, context.table());
        output
    });
    for levels in [2, 3] {
        // An odd level count exercises padding of the internal ManyLUT.
        let output_basis = ApproxSignedBasis::new(Some(Q), 8, Some(levels));
        let parameters = CircuitBootstrapParameters::try_new(
            context.parameters(),
            output_basis,
            NlevParameters::with_ntru_params(&accumulator, 10, None),
            NlevParameters::with_ntru_params(&accumulator, 10, None),
        )
        .unwrap();
        let circuit_key = context
            .generate_circuit_bootstrap_key(&client, &parameters, &mut rng)
            .unwrap();
        let mut evaluator = context
            .circuit_bootstrap_evaluator(&server, &parameters, &circuit_key)
            .unwrap();
        let mut control = NttNgswCiphertext::<Vec<u64>>::zero(parameters.output_nlev_len());
        let mut selected = NtruCiphertext::<Vec<u64>>::zero(N);
        let mut transformed = NttNtruCiphertext::<Vec<u64>>::zero(N);
        let mut scratch = NttNtruExternalProductContext::new(N);
        for bit in [0u64, 1, 0] {
            let input = encryptor.encrypt_padded(bit, &mut rng).unwrap();
            let (_, allocation) =
                allocations::measure(|| evaluator.circuit_bootstrap_to(&input, &mut control));
            assert_eq!(
                allocation.count, 0,
                "CBS must reuse scratch from its first call"
            );
            let mut phase = Polynomial::new(vec![0u64; N]);
            for (scalar, level) in parameters
                .output_basis()
                .scalar_iter()
                .zip(control.iter_ntt_ntru(N))
            {
                key.phase_to(&level, &mut phase, modulus, context.table());
                for (&actual, &f) in phase
                    .as_ref()
                    .iter()
                    .zip(client.accumulator_ntru_secret_key().as_slice())
                {
                    let value =
                        (u128::from(scalar) * u128::from(f.unsigned_abs()) * u128::from(bit))
                            % u128::from(Q);
                    let expected = if f < 0 {
                        (u128::from(Q) - value) % u128::from(Q)
                    } else {
                        value
                    };
                    let distance = (u128::from(actual) + u128::from(Q) - expected) % u128::from(Q);
                    // Functional bound, below even the third-layer gadget step.
                    assert!(distance.min(u128::from(Q) - distance) < (1 << 24));
                }
            }
            control.cmux_to(
                &choices[0],
                &choices[1],
                &mut selected,
                parameters.output_basis(),
                modulus,
                context.table(),
                &mut scratch,
            );
            selected.write_ntt_form(&mut transformed, context.table());
            assert_eq!(
                key.decrypt(&transformed, &accumulator, context.table())
                    .as_ref(),
                &[if bit == 0 { 1 } else { 3 }; N]
            );
        }
        control.as_mut().fill(7);
        let invalid = primus_tfhe::LweCiphertext::zero(15);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || evaluator.circuit_bootstrap_to(&invalid, &mut control)
            ))
            .is_err()
        );
        assert!(control.as_ref().iter().all(|&value| value == 7));
        let input = encryptor.encrypt_padded(1u64, &mut rng).unwrap();
        let short_len = control.as_ref().len() - 1;
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| evaluator
                .circuit_bootstrap_to(
                    &input,
                    &mut NttNgswCiphertext::new(&mut control.as_mut()[..short_len])
                )))
            .is_err()
        );
        assert!(control.as_ref().iter().all(|&value| value == 7));
        for role in 0..3 {
            let output_basis = if role == 0 {
                ApproxSignedBasis::new(Some(Q), 9, Some(levels))
            } else {
                parameters.output_basis().clone()
            };
            let mut parts = [
                parameters.trace().clone(),
                parameters.scheme_switch().clone(),
            ];
            if role > 0 {
                parts[role - 1] = NlevParameters::with_ntru_params(
                    &accumulator,
                    9,
                    Some(parts[role - 1].decompose_length()),
                );
            }
            let [trace, scheme_switch] = parts;
            let foreign = CircuitBootstrapParameters::try_new(
                context.parameters(),
                output_basis,
                trace,
                scheme_switch,
            )
            .unwrap();
            assert!(matches!(
                context.circuit_bootstrap_evaluator(&server, &foreign, &circuit_key),
                Err(CircuitBootstrapEvaluationError::IncompatibleCircuitBootstrapKey)
            ));
        }
    }
}

#[test]
fn circuit_parameters_check_capacity_ring_and_basis_domain() {
    use primus_tfhe_ntru_ntt::CircuitBootstrapParameterError as Error;
    let modulus = BarrettModulus::new(Q);
    let make = |plain| {
        let acc = NtruParameters::new(N, plain, modulus, SecretKeyDistr::SparseTernary, 0.7);
        let client = NtruParameters::new(N, plain, modulus, SecretKeyDistr::UniformBinary, 0.7);
        NtruTfheParameters::try_new(
            LweParameters::new(16, plain, modulus, SecretKeyDistr::UniformBinary, 0.7),
            NlevParameters::with_ntru_params(&acc, 10, None),
            NlevParameters::with_ntru_params(&client, 10, None),
        )
        .unwrap()
    };
    let tfhe = make(N as u64); // Only two interleaved outputs fit this domain.
    let trace = tfhe.bootstrapping().clone();
    let output = |levels| ApproxSignedBasis::new(Some(Q), 8, Some(levels));
    assert!(
        CircuitBootstrapParameters::try_new(&tfhe, output(2), trace.clone(), trace.clone()).is_ok()
    );
    assert!(matches!(
        CircuitBootstrapParameters::try_new(&tfhe, output(3), trace.clone(), trace.clone()),
        Err(Error::OutputDecompositionTooLarge)
    ));
    let foreign_ring = NtruParameters::new(N * 2, 4, modulus, SecretKeyDistr::SparseTernary, 0.7);
    let foreign_modulus = NtruParameters::new(
        N,
        4,
        BarrettModulus::new(132_120_577u64),
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    for foreign in [&foreign_ring, &foreign_modulus] {
        assert!(matches!(
            CircuitBootstrapParameters::try_new(
                &tfhe,
                output(2),
                NlevParameters::with_ntru_params(foreign, 8, Some(2)),
                trace.clone()
            ),
            Err(Error::PolynomialLengthMismatch { role: "trace" }
                | Error::CipherModulusMismatch { role: "trace" })
        ));
    }
    assert!(matches!(
        CircuitBootstrapParameters::try_new(
            &tfhe,
            ApproxSignedBasis::new(None, 8, Some(2)),
            trace.clone(),
            trace,
        ),
        Err(Error::OutputBasisModulusMismatch)
    ));
}
