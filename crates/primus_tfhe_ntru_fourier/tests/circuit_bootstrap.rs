#[path = "../../primus_tfhe/tests/support/allocations.rs"]
mod allocations;

use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftTable, RustFftTable, TfheFftTable};
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_ntru::{
    FourierNgswCiphertext, FourierNtruCiphertext, FourierNtruExternalProductContext,
    FourierNtruSecretKey, NlevParameters, NtruCiphertext, NtruParameters, SecretKeyDistr,
};
use primus_poly::Polynomial;
use primus_tfhe_ntru_fourier::{
    CircuitBootstrapEvaluationError, CircuitBootstrapParameters, NtruTfheParameters, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 256;

fn circuit_bootstrap<Table: FftTable>() {
    let modulus = NativeModulus::<u64>::new();
    let lwe = LweParameters::new(16, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let accumulator = NtruParameters::new(N, 4, modulus, SecretKeyDistr::SparseTernary, 0.7);
    let client = NtruParameters::new(N, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let tfhe = NtruTfheParameters::try_new(
        lwe,
        NlevParameters::with_ntru_params(&accumulator, 10, None),
        NlevParameters::with_ntru_params(&client, 10, None),
    )
    .unwrap();
    let context = TfheContext::try_new(tfhe, Table::new(N.trailing_zeros()).unwrap()).unwrap();
    let mut rng = StdRng::seed_from_u64(0x004e_5454_5f43_4253);
    let (client, server) = context.generate_keys(&mut rng).unwrap();
    let mut fft = context.new_fft_engine();
    let key = FourierNtruSecretKey::try_from_coeff_secret_key(
        client.accumulator_ntru_secret_key(),
        &mut fft,
    )
    .unwrap();
    let mut encrypt = primus_ntru::FourierNtruEncryptContext::new(N);
    let mut decrypt = primus_ntru::FourierNtruDecryptContext::new(N);
    let encryptor = context.encryptor(&client).unwrap();
    let choices = [1, 3].map(|message| {
        let transformed = key.encrypt(
            &Polynomial::new(vec![message; N]),
            &accumulator,
            &mut fft,
            &mut rng,
            &mut encrypt,
        );
        let mut output = NtruCiphertext::<Vec<u64>>::zero(N);
        transformed.write_torus_form(&mut output, &mut fft);
        output
    });
    // Three gadget levels exercise multiple scales and an internal padding slot.
    let levels = 3;
    let output_basis = ApproxSignedBasis::new(None, 8, Some(levels));
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
    let mut control =
        FourierNgswCiphertext::<Vec<Complex64>>::zero(parameters.output_fourier_nlev_len());
    let mut selected = NtruCiphertext::<Vec<u64>>::zero(N);
    let mut transformed = FourierNtruCiphertext::<Vec<Complex64>>::zero(N / 2);
    let mut scratch = FourierNtruExternalProductContext::new(N);
    // A zero result must overwrite the previous nonzero control.
    for bit in [1u64, 0] {
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
            .zip(control.iter_ntru(N / 2))
        {
            key.phase_to(&level, &mut phase, &mut fft, &mut decrypt);
            for (&actual, &f) in phase
                .as_ref()
                .iter()
                .zip(client.accumulator_ntru_secret_key().as_slice())
            {
                let q = 1u128 << 64;
                let value =
                    (u128::from(scalar) * u128::from(f.unsigned_abs()) * u128::from(bit)) % q;
                let expected = if f < 0 { (q - value) % q } else { value };
                let distance = (u128::from(actual) + q - expected) % q;
                // Separate native/FFT fixture bound, not an NTT noise model.
                assert!(distance.min(q - distance) < (1 << 32));
            }
        }
        control.cmux_to(
            &choices[0],
            &choices[1],
            &mut selected,
            parameters.output_basis(),
            &mut fft,
            &mut scratch,
        );
        selected.write_fourier_form(&mut transformed, &mut fft);
        assert_eq!(
            key.decrypt(&transformed, &accumulator, &mut fft, &mut decrypt)
                .as_ref(),
            &[if bit == 0 { 1 } else { 3 }; N]
        );
    }
    control.as_mut().fill(Complex64::new(7.0, 0.0));
    let invalid = primus_tfhe::LweCiphertext::zero(15);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || evaluator.circuit_bootstrap_to(&invalid, &mut control)
        ))
        .is_err()
    );
    assert!(
        control
            .as_ref()
            .iter()
            .all(|&value| value == Complex64::new(7.0, 0.0))
    );
    let input = encryptor.encrypt_padded(1u64, &mut rng).unwrap();
    let short_len = control.as_ref().len() - 1;
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| evaluator
            .circuit_bootstrap_to(
                &input,
                &mut FourierNgswCiphertext::new(&mut control.as_mut()[..short_len])
            )))
        .is_err()
    );
    assert!(
        control
            .as_ref()
            .iter()
            .all(|&value| value == Complex64::new(7.0, 0.0))
    );
    for role in 0..3 {
        let output_basis = if role == 0 {
            ApproxSignedBasis::new(None, 9, Some(levels))
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

#[test]
fn circuit_bootstrap_preserves_gadget_scales_and_controls_cmux() {
    circuit_bootstrap::<RustFftTable>();
    circuit_bootstrap::<TfheFftTable>();
}

#[test]
fn circuit_parameters_check_capacity_ring_and_basis_domain() {
    use primus_tfhe_ntru_fourier::CircuitBootstrapParameterError as Error;
    let modulus = NativeModulus::<u64>::new();
    let acc = NtruParameters::new(N, N as u64, modulus, SecretKeyDistr::SparseTernary, 0.7);
    let client = NtruParameters::new(N, N as u64, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let tfhe = NtruTfheParameters::try_new(
        LweParameters::new(16, N as u64, modulus, SecretKeyDistr::UniformBinary, 0.7),
        NlevParameters::with_ntru_params(&acc, 10, None),
        NlevParameters::with_ntru_params(&client, 10, None),
    )
    .unwrap();
    let trace = tfhe.bootstrapping().clone();
    let output = |levels| ApproxSignedBasis::new(None, 8, Some(levels));
    assert!(
        CircuitBootstrapParameters::try_new(&tfhe, output(2), trace.clone(), trace.clone()).is_ok()
    );
    assert!(matches!(
        CircuitBootstrapParameters::try_new(&tfhe, output(3), trace.clone(), trace.clone()),
        Err(Error::OutputDecompositionTooLarge)
    ));
    let foreign = NtruParameters::new(N * 2, 4, modulus, SecretKeyDistr::SparseTernary, 0.7);
    assert!(matches!(
        CircuitBootstrapParameters::try_new(
            &tfhe,
            output(2),
            NlevParameters::with_ntru_params(&foreign, 10, None),
            trace.clone()
        ),
        Err(Error::PolynomialLengthMismatch { role: "trace" })
    ));
    assert!(matches!(
        CircuitBootstrapParameters::try_new(
            &tfhe,
            ApproxSignedBasis::new(Some(132_120_577), 8, Some(2)),
            trace.clone(),
            trace,
        ),
        Err(Error::OutputBasisModulusMismatch)
    ));
}
