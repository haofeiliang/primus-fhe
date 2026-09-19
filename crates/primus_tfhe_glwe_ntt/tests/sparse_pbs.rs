use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_glwe::{GlweParameters, SecretKeyDistr};
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable};
use primus_test_allocations as allocations;
use primus_tfhe::{BivariateLookupTable, ProgrammableBootstrap, ProgrammableBootstrapInterleaved};
use primus_tfhe_glwe_ntt::{
    ClientKey, KeyGenerator, PbsOrder, TfheContext, TfheEvaluationError, TfheParameters,
};
use primus_tfhe_test_support::boolean;
use rand::{SeedableRng, rngs::StdRng};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

const Q: u32 = 132_120_577;
const N: usize = 256;

fn context(
    order: PbsOrder,
    plaintext_modulus: u32,
    weight: usize,
    log_basis: u32,
) -> TfheContext<u32, U32NttTable> {
    let modulus = BarrettModulus::new(Q);
    let parameters = TfheParameters::try_new(
        LweParameters::new(
            16,
            plaintext_modulus,
            modulus,
            SecretKeyDistr::fixed_hamming_weight_binary(16, weight),
            0.7,
        ),
        GlweParameters::new(
            1,
            N,
            plaintext_modulus,
            modulus,
            SecretKeyDistr::UniformBinary,
            0.7,
        ),
        ApproxSignedBasis::new(Some(Q), log_basis, Some(3)),
        ApproxSignedBasis::new(Some(Q), 9, None),
        order,
    )
    .unwrap();
    TfheContext::try_new(
        parameters,
        U32NttTable::new(N.trailing_zeros(), modulus).unwrap(),
    )
    .unwrap()
}

#[test]
fn sparse_pbs_preserves_external_secret_and_interleaved_outputs_in_both_orders() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let context = context(order, 8, 4, 7);
        let mut generator = KeyGenerator::new(&context);
        let mut rng = StdRng::seed_from_u64(0x5035_5042);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        let sparse_key = generator
            .try_generate_sparse_server_key(&client, 3, 8, None, &mut rng)
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
        // A distinct output scale exercises P2.1 through both dispatch branches.
        let codec = RoundedCodec::new(16, BarrettModulus::new(Q));
        let function = |m: usize| (3 * m as u32 + 1) % 16;
        let functions = |m: usize, i: usize| (m + 2 * i) as u32;
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
        let check = |output: &LweCiphertext<u32>, message: u32| {
            let phase = decryptor.decrypt_phase(output).unwrap();
            let expected = codec.encode_value(message, PlaintextEmbedding::Unsigned);
            let distance = phase.abs_diff(expected);
            assert!(distance.min(Q - distance) < Q / 32 - 1);
            assert_eq!(codec.decode_value(phase), message);
        };
        for message in 0..4 {
            let input = encryptor.encrypt_padded(message, &mut rng).unwrap();
            for evaluator in [&mut sparse, &mut classic] {
                // Reuse one evaluator across step 1 -> 4 -> 1 and across inputs.
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
                evaluator.apply_lookup_table_to(&input, &single, &mut outputs[0]);
                check(&outputs[0], function(message as usize));
            }
        }
        // The common public boundary rejects output mistakes before dispatch/writes.
        let input = encryptor.encrypt_padded(1, &mut rng).unwrap();
        let before = outputs.clone();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sparse.apply_interleaved_lookup_table_to(&input, &many, &mut outputs[..2]);
            }))
            .is_err()
        );
        assert_eq!(outputs, before);
        sparse.apply_lookup_table_to(&input, &single, &mut outputs[0]);
        check(&outputs[0], function(1));
        // A matching layout alone does not bind the sparse weight or gadget basis.
        for incompatible in [self::context(order, 8, 5, 7), self::context(order, 8, 4, 8)] {
            assert!(matches!(
                incompatible.evaluator(&sparse_key),
                Err(TfheEvaluationError::IncompatibleServerKey)
            ));
        }
    }
}

fn add_phase_error(ciphertext: &mut LweCiphertext<u32>, error: i64) {
    let body = ciphertext.b_mut();
    *body = (i64::from(*body) + error).rem_euclid(i64::from(Q)) as u32;
}

fn centered_error(phase: u32, expected: u32) -> i64 {
    let difference = (i64::from(phase) - i64::from(expected)).rem_euclid(i64::from(Q));
    if difference > i64::from(Q / 2) {
        difference - i64::from(Q)
    } else {
        difference
    }
}

#[test]
fn sparse_boolean_gates_chain_in_both_orders_without_allocating() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let context = context(order, 4, 4, 7);
        let mut rng = StdRng::seed_from_u64(0xB303_0004);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        let server = KeyGenerator::new(&context)
            .try_generate_sparse_server_key(&client, 3, 8, None, &mut rng)
            .unwrap();
        let encryptor = context.boolean_encryptor(&client).unwrap();
        let decryptor = context.boolean_decryptor(&client).unwrap();
        let phase_decryptor = context.decryptor(&client).unwrap();
        let mut evaluator = context.boolean_evaluator(&server).unwrap();
        let mut inputs = [
            encryptor.encrypt(false, &mut rng).unwrap(),
            encryptor.encrypt(true, &mut rng).unwrap(),
        ];
        // Controlled input errors also pass through affine gate preprocessing.
        add_phase_error(&mut inputs[0], i64::from(Q / 128));
        add_phase_error(&mut inputs[1], -i64::from(Q / 128));
        let dimension = context.parameters().external_lwe_dimension();
        let mut output = LweCiphertext::zero(dimension);
        let mut current = LweCiphertext::zero(dimension);
        let codec = context.parameters().input_plaintext_codec();
        let (_, allocation) = allocations::measure(|| {
            boolean::check_truth_tables_and_chain(
                &mut evaluator,
                &inputs,
                &mut output,
                &mut current,
                |ciphertext| {
                    let value = decryptor.decrypt(ciphertext).unwrap();
                    let phase = phase_decryptor.decrypt_phase(ciphertext).unwrap();
                    let center = codec.encode_value(u32::from(value), PlaintextEmbedding::Unsigned);
                    assert!(centered_error(phase, center).abs() < i64::from(Q / 8 - 1));
                    value
                },
            );
        });
        assert_eq!(
            allocation.count, 0,
            "gates and their chain must reuse storage"
        );
    }
}

#[test]
fn sparse_bivariate_and_odd_full_domain_respect_input_margins_in_both_orders() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let context = context(order, 15, 4, 7);
        let mut rng = StdRng::seed_from_u64(0xB303_000F);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        let server = KeyGenerator::new(&context)
            .try_generate_sparse_server_key(&client, 3, 8, None, &mut rng)
            .unwrap();
        let encryptor = context.encryptor(&client).unwrap();
        let decryptor = context.decryptor(&client).unwrap();
        let mut evaluator = context.evaluator(&server).unwrap();
        let input_codec = context.parameters().input_plaintext_codec();
        let output_codec = RoundedCodec::new(8, BarrettModulus::new(Q));
        let encode_input =
            |message| input_codec.encode_value(message, PlaintextEmbedding::Unsigned);
        let phase = |ciphertext: &LweCiphertext<u32>| decryptor.decrypt_phase(ciphertext).unwrap();
        let check_output = |output: &LweCiphertext<u32>, expected| {
            let center = output_codec.encode_value(expected, PlaintextEmbedding::Unsigned);
            let phase = phase(output);
            assert!(centered_error(phase, center).abs() < i64::from(Q / 16 - 1));
            assert_eq!(output_codec.decode_value(phase), expected);
        };
        let bivariate =
            BivariateLookupTable::try_new(3, 2, N, input_codec, &output_codec, |x, y| {
                (x * x + y) as u32
            })
            .unwrap();
        let full_value = |m: usize| ((m * m + 3) % 8) as u32;
        let full = context
            .parameters()
            .compile_odd_full_domain_lookup_table_fn(&output_codec, full_value)
            .unwrap();
        let dimension = context.parameters().external_lwe_dimension();
        let mut packed = LweCiphertext::zero(dimension);
        let mut output = LweCiphertext::zero(dimension);

        // B=3 amplifies rhs noise. Equal-sign offsets use about half the ordinary
        // input half-width q/(2*t); opposite signs exercise cancellation and rho.
        let error_unit = i64::from(Q / (15 * 16));
        for (x, y, lhs_sign, rhs_sign) in [(0, 0, -1, -1), (2, 1, 1, -1), (1, 1, 1, 1)] {
            let mut lhs = encryptor.encrypt_padded(x, &mut rng).unwrap();
            let mut rhs = encryptor.encrypt_padded(y, &mut rng).unwrap();
            add_phase_error(&mut lhs, lhs_sign * error_unit);
            add_phase_error(&mut rhs, rhs_sign * error_unit);
            let lhs_error = centered_error(phase(&lhs), encode_input(x));
            let rhs_error = centered_error(phase(&rhs), encode_input(y));
            let packed_center = encode_input(x + 3 * y);
            let rounding_error = i64::from(encode_input(x)) + 3 * i64::from(encode_input(y))
                - i64::from(packed_center);
            let (_, allocation) = allocations::measure(|| {
                bivariate.pack_to(&lhs, &rhs, &mut packed);
                evaluator.apply_lookup_table_to(&packed, bivariate.lookup_table(), &mut output);
            });
            assert_eq!(allocation.count, 0, "packing and PBS must reuse storage");
            assert_eq!(
                centered_error(phase(&packed), packed_center),
                lhs_error + 3 * rhs_error + rounding_error
            );
            check_output(&output, x * x + y);
        }

        // Odd full-domain folding halves the input margin to about q/(4*t).
        // Check both folds, zero wraparound, and the last message, at half margin.
        for (message, sign) in [(0, -1), (7, 1), (8, -1), (14, 1), (1, 0)] {
            encryptor
                .encrypt_to(message, &mut packed, &mut rng)
                .unwrap();
            add_phase_error(&mut packed, sign * i64::from(Q / (8 * 15)));
            let (_, allocation) = allocations::measure(|| {
                evaluator.apply_lookup_table_to(&packed, &full, &mut output);
            });
            assert_eq!(allocation.count, 0, "full-domain PBS must reuse storage");
            check_output(&output, full_value(message as usize));
        }
    }
}
