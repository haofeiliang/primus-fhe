use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_fft::{FftTable, RustFftTable, TfheFftTable};
use primus_glwe::{GlweParameters, SecretKeyDistr};
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::NativeModulus;
use primus_test_allocations as allocations;
use primus_tfhe::{ProgrammableBootstrap, ProgrammableBootstrapInterleaved};
use primus_tfhe_glwe_fourier::{
    CircuitBootstrapConfig, CircuitBootstrapEvaluator, CircuitBootstrapParameters, ClientKey,
    DecompositionConfig, KeyGenerator, PbsOrder, TfheContext, TfheEvaluationError, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

const N: usize = 256;

fn context<Table: FftTable>(
    order: PbsOrder,
    weight: usize,
    log_basis: u32,
) -> TfheContext<u64, Table> {
    let modulus = NativeModulus::new();
    let parameters = TfheParameters::try_new(
        LweParameters::new(
            16,
            15,
            modulus,
            SecretKeyDistr::fixed_hamming_weight_binary(16, weight),
            0.7,
        ),
        GlweParameters::new(1, N, 15, modulus, SecretKeyDistr::UniformTernary, 0.7),
        ApproxSignedBasis::new(None, log_basis, Some(6)),
        ApproxSignedBasis::new(None, 8, Some(6)),
        order,
    )
    .unwrap();
    TfheContext::try_from_parameters(parameters).unwrap()
}

fn check_pbs<Table: FftTable>() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let context = context::<Table>(order, 4, 8);
        let mut generator = KeyGenerator::new(&context);
        let mut rng = StdRng::seed_from_u64(0x4234_3250);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        let sparse_key = generator
            .try_generate_sparse_server_key(&client, 3, 8, &mut rng)
            .unwrap();
        let classic_key = generator
            .try_generate_server_key(&client, None, &mut rng)
            .unwrap();
        let mut sparse = context.evaluator(&sparse_key).unwrap();
        let mut classic = context.evaluator(&classic_key).unwrap();
        let dimension = context.parameters().external_lwe_dimension();
        assert_eq!(
            dimension,
            if order == PbsOrder::BootstrapKeyswitch {
                16
            } else {
                N
            }
        );
        let encryptor = context.encryptor(&client).unwrap();
        let decryptor = context.decryptor(&client).unwrap();
        // Non-power-of-two input centers and a different output scale exercise
        // the exact prepared quantizer through both complete PBS orders.
        let codec = RoundedCodec::new(16, NativeModulus::new());
        let function = |m: usize| (3 * m as u64 + 1) % 16;
        let functions = |m: usize, i: usize| (m + 2 * i) as u64;
        let single = context
            .parameters()
            .compile_lookup_table_fn(&codec, function)
            .unwrap();
        let many = context
            .parameters()
            .compile_interleaved_lookup_table_fn(&codec, 3, functions)
            .unwrap();
        assert_eq!(many.padded_output_count(), 4);
        let mut outputs = vec![LweCiphertext::zero(dimension); 3];
        let check = |output: &LweCiphertext<u64>, message| {
            let phase = decryptor.decrypt_phase(output).unwrap();
            let expected = codec.encode_value(message, PlaintextEmbedding::Unsigned);
            let error = phase.wrapping_sub(expected);
            assert!(
                error.min(error.wrapping_neg()) < 1 << 59,
                "phase escaped decoding radius"
            );
            assert_eq!(codec.decode_value(phase), message);
        };
        for message in [0, 3, 7] {
            let mut input = encryptor.encrypt_padded(message, &mut rng).unwrap();
            // A controlled +/- q/1024 phase offset remains within the LUT margin.
            *input.b_mut() = if message == 0 {
                input.b().wrapping_sub(1 << 54)
            } else {
                input.b().wrapping_add(1 << 54)
            };
            for evaluator in [&mut sparse, &mut classic] {
                // Include the first call, and switch step 1 -> 4 -> 1 without resets.
                let (_, allocation) = allocations::measure(|| {
                    ProgrammableBootstrap::apply_lookup_table_to(
                        evaluator,
                        &input,
                        &single,
                        &mut outputs[0],
                    );
                });
                assert_eq!(allocation.count, 0);
                check(&outputs[0], function(message as usize));
                let (_, allocation) = allocations::measure(|| {
                    ProgrammableBootstrapInterleaved::apply_interleaved_lookup_table_to(
                        evaluator,
                        &input,
                        &many,
                        &mut outputs,
                    );
                });
                assert_eq!(allocation.count, 0);
                for (i, output) in outputs.iter().enumerate() {
                    check(output, functions(message as usize, i));
                }
                let (_, allocation) = allocations::measure(|| {
                    evaluator.apply_lookup_table_to(&input, &single, &mut outputs[0]);
                });
                assert_eq!(allocation.count, 0);
                check(&outputs[0], function(message as usize));
            }
        }
    }
}

#[test]
fn sparse_pbs_preserves_external_secret_and_interleaved_outputs_in_both_orders() {
    check_pbs::<RustFftTable>();
    check_pbs::<TfheFftTable>();
}

#[test]
fn sparse_keys_bind_parameters_and_cannot_enter_circuit_bootstrapping() {
    let order = PbsOrder::BootstrapKeyswitch;
    let context = context::<RustFftTable>(order, 4, 8);
    let mut rng = StdRng::seed_from_u64(0x4234_3243);
    let client = ClientKey::generate(context.parameters(), &mut rng);
    let mut generator = KeyGenerator::new(&context);
    let server = generator
        .try_generate_sparse_server_key(&client, 3, 8, &mut rng)
        .unwrap();
    for incompatible in [
        self::context::<RustFftTable>(order, 5, 8),
        self::context::<RustFftTable>(order, 4, 7),
    ] {
        assert!(matches!(
            incompatible.evaluator(&server),
            Err(TfheEvaluationError::IncompatibleServerKey)
        ));
    }
    assert!(matches!(
        context.circuit_bootstrap_evaluator(&server),
        Err(TfheEvaluationError::UnsupportedSparseBootstrapping)
    ));
    // Supplying otherwise compatible standalone CBS material must not bypass
    // the sparse CBS restriction through the advanced construction entry.
    let decomposition = DecompositionConfig {
        log_basis: 8,
        level_count: Some(6),
    };
    let parameters = CircuitBootstrapParameters::try_from_config(
        context.parameters(),
        CircuitBootstrapConfig {
            output: DecompositionConfig {
                log_basis: 8,
                level_count: Some(3),
            },
            trace: decomposition,
            trace_noise_standard_deviation: 0.7,
            scheme_switch: decomposition,
            scheme_switch_noise_standard_deviation: 0.7,
        },
    )
    .unwrap();
    let key = generator
        .try_generate_circuit_bootstrap_key(&client, parameters, &mut rng)
        .unwrap();
    assert!(matches!(
        CircuitBootstrapEvaluator::try_from_parts(&context, &server, key.parameters(), &key),
        Err(TfheEvaluationError::UnsupportedSparseBootstrapping)
    ));
}
