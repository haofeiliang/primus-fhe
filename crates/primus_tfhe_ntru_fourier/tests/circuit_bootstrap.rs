//! Gadget-scale phases and actual CMux/external-product consumption;
//! parameter-constructor boundaries belong to the common family crate.

use primus_fft::{Complex64, FftTable, RustFftTable, TfheFftTable};
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_ntru::{
    FourierNgswCiphertext, FourierNtruSecretKey, NlevParameters, NtruParameters, SecretKeyDistr,
};
use primus_poly::Polynomial;
use primus_test_allocations as allocations;
use primus_tfhe::ProgrammableBootstrap as _;
use primus_tfhe_ntru_fourier::{
    CircuitBootstrapConfig, CircuitBootstrapEvaluator, DecompositionConfig, TfheContext,
    TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

const N: usize = 64;

// Reuse one evaluator across controls, then consume its gadget ciphertexts.
fn circuit_bootstrap<Table: FftTable>(distr: SecretKeyDistr) {
    let modulus = NativeModulus::<u64>::new();
    let lwe = LweParameters::new(
        16,
        4,
        primus_modulus::PowOf2Modulus::new(1u64 << 24),
        distr,
        0.7,
    );
    let accumulator = NtruParameters::new(N, 4, modulus, SecretKeyDistr::SparseTernary, 0.7);

    let tfhe = TfheParameters::try_new(
        lwe,
        NlevParameters::with_ntru_params(&accumulator, 10, None),
        primus_tfhe_ntru::DecompositionConfig {
            log_basis: 10,
            level_count: None,
        },
        0.7,
    )
    .unwrap();
    let context = TfheContext::<_, Table, _>::try_from_parameters(tfhe).unwrap();
    let mut rng = StdRng::seed_from_u64(0x004e_5454_5f43_4253);
    // Three gadget levels exercise multiple scales and an internal padding slot.
    let levels = 3;
    let cbs_config = CircuitBootstrapConfig {
        output: DecompositionConfig {
            log_basis: 8,
            level_count: Some(levels),
        },
        trace: DecompositionConfig {
            log_basis: 10,
            level_count: None,
        },
        trace_noise_standard_deviation: 0.7,
        scheme_switch: DecompositionConfig {
            log_basis: 10,
            level_count: None,
        },
        scheme_switch_noise_standard_deviation: 0.7,
    };
    let (client, server) = context
        .try_generate_keys(Some(cbs_config), &mut rng)
        .unwrap();
    let circuit_key = server.circuit_bootstrap_key().unwrap();
    let parameters = circuit_key.parameters();
    let mut fft = context.new_fft_engine();
    let key = FourierNtruSecretKey::try_from_coeff_secret_key(
        client.accumulator_ntru_secret_key(),
        &mut fft,
    )
    .unwrap();
    let mut decrypt = primus_ntru::FourierNtruDecryptWorkspace::new(N);
    let encryptor = context.encryptor(&client).unwrap();
    // The same CBS-enabled server key also supports ordinary PBS.
    let identity = context
        .parameters()
        .compile_lookup_table_fn(|message| message as u64)
        .unwrap();
    let input = encryptor.encrypt_padded(1u64, &mut rng).unwrap();
    let mut output = context
        .evaluator(&server)
        .unwrap()
        .apply_lookup_table(&input, &identity);
    assert_eq!(
        context
            .decryptor(&client)
            .unwrap()
            .decrypt(&output)
            .unwrap(),
        1
    );

    let mut accumulator_client = context.accumulator_client(&client).unwrap();
    let choices = [1u64, 3].map(|message| {
        let mut output = context.allocate_accumulator_ciphertext();
        let (_, allocation) = allocations::measure(|| {
            accumulator_client.encrypt_to(&[message; N], &mut output, &mut rng)
        });
        assert_eq!(
            allocation.count, 0,
            "accumulator encryption must reuse its workspace"
        );
        output
    });

    let mut evaluator =
        CircuitBootstrapEvaluator::try_from_bootstrapper(context.evaluator(&server).unwrap())
            .unwrap();
    let mut control = evaluator.allocate_output();
    let mut selected = context.allocate_accumulator_ciphertext();
    let mut product = context.allocate_accumulator_ciphertext();
    let mut decoded = vec![0; N];
    let mut decoded_product = vec![0; N];
    // A zero result must overwrite the previous nonzero control.
    for bit in [1u64, 0] {
        let input = encryptor.encrypt_padded(bit, &mut rng).unwrap();
        let (_, allocation) = allocations::measure(|| {
            evaluator.circuit_bootstrap_to(&input, &mut control);
            evaluator.cmux_to(&control, &choices[0], &choices[1], &mut selected);
            evaluator.external_product_to(&control, &choices[1], &mut product);
            evaluator
                .bootstrapper_mut()
                .apply_lookup_table_to(&input, &identity, &mut output);
            accumulator_client.decrypt_to(&selected, &mut decoded);
            accumulator_client.decrypt_to(&product, &mut decoded_product);
        });
        assert_eq!(
            context
                .decryptor(&client)
                .unwrap()
                .decrypt(&output)
                .unwrap(),
            bit
        );
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
        assert_eq!(decoded, vec![if bit == 0 { 1 } else { 3 }; N]);
        assert_eq!(decoded_product, vec![3 * bit; N]);
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

    let (_, recovery) = allocations::measure(|| evaluator.into_bootstrapper());
    assert_eq!(
        recovery.count, 0,
        "converted CBS retains ordinary workspace"
    );
}

#[test]
fn circuit_bootstrap_preserves_gadget_scales_and_controls_cmux() {
    for distr in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::fixed_composition_ternary(16, 3, 4),
    ] {
        circuit_bootstrap::<RustFftTable>(distr);
        circuit_bootstrap::<TfheFftTable>(distr);
    }
}
