//! Gadget-scale phases and actual CMux/external-product consumption;
//! parameter-constructor boundaries belong to the common family crate.

use primus_lwe::LweParameters;
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_ntru::{
    NlevParameters, NtruParameters, NttNgswCiphertext, NttNtruSecretKey, SecretKeyDistr,
};
use primus_ntt::U64NttTable;
use primus_poly::Polynomial;
use primus_test_allocations as allocations;
use primus_tfhe::ProgrammableBootstrap as _;
use primus_tfhe_ntru_ntt::{
    CircuitBootstrapConfig, CircuitBootstrapEvaluator, DecompositionConfig, TfheContext,
    TfheParameters,
};
use rand::{RngExt, SeedableRng, rngs::StdRng};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

const N: usize = 64;
const Q: u64 = 1_125_899_906_826_241;

// Reuse one evaluator across controls, then consume its gadget ciphertexts.
fn circuit_bootstrap(distr: SecretKeyDistr) {
    let modulus = BarrettModulus::new(Q);
    let lwe = LweParameters::new(16, 4, PowOf2Modulus::new(1u64 << 24), distr, 0.7);
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
    let context = TfheContext::<_, U64NttTable, _>::try_from_parameters(tfhe).unwrap();
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
    let key = NttNtruSecretKey::try_from_coeff_secret_key(
        client.accumulator_ntru_secret_key(),
        modulus,
        context.table(),
    )
    .unwrap();
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
    // Client shape failures precede sampling or writes, even with reused storage.
    selected.as_mut().fill(7);
    let mut rejected_rng = StdRng::seed_from_u64(43);
    let mut untouched_rng = StdRng::seed_from_u64(43);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            accumulator_client.encrypt_to(&[0; N - 1], &mut selected, &mut rejected_rng);
        }))
        .is_err()
    );
    assert_eq!(rejected_rng.random::<u64>(), untouched_rng.random::<u64>());
    assert!(selected.as_ref().iter().all(|&value| value == 7));
    decoded.fill(7);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            accumulator_client.decrypt_to(&selected, &mut decoded[..N - 1]);
        }))
        .is_err()
    );
    assert!(decoded.iter().all(|&value| value == 7));
    let short_input = primus_ntru::NtruCiphertext::new(&choices[0].as_ref()[..N - 1]);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evaluator.external_product_to(&control, &short_input, &mut selected);
        }))
        .is_err()
    );
    assert!(selected.as_ref().iter().all(|&value| value == 7));
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
            .zip(control.iter_ntt_ntru(N))
        {
            key.phase_to(&level, &mut phase, modulus, context.table());
            for (&actual, &f) in phase
                .as_ref()
                .iter()
                .zip(client.accumulator_ntru_secret_key().as_slice())
            {
                let value = (u128::from(scalar) * u128::from(f.unsigned_abs()) * u128::from(bit))
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
        assert_eq!(decoded, vec![if bit == 0 { 1 } else { 3 }; N]);
        assert_eq!(decoded_product, vec![3 * bit; N]);
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
        circuit_bootstrap(distr);
    }
}
