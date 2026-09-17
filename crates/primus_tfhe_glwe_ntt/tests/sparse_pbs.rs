#[path = "../../primus_tfhe/tests/support/allocations.rs"]
mod allocations;

use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_glwe::{GlweParameters, SecretKeyDistr};
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable};
use primus_tfhe::{ProgrammableBootstrap, ProgrammableBootstrapInterleaved};
use primus_tfhe_glwe_ntt::{
    KeyGenerator, PbsOrder, TfheContext, TfheEvaluationError, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

const Q: u32 = 132_120_577;
const N: usize = 256;

fn context(order: PbsOrder, weight: usize, log_basis: u32) -> TfheContext<u32, U32NttTable> {
    let modulus = BarrettModulus::new(Q);
    let parameters = TfheParameters::try_new(
        LweParameters::new(
            16,
            8,
            modulus,
            SecretKeyDistr::fixed_hamming_weight_binary(16, weight),
            0.7,
        ),
        GlweParameters::new(1, N, 8, modulus, SecretKeyDistr::UniformBinary, 0.7),
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
        let context = context(order, 4, 7);
        let mut generator = KeyGenerator::new(&context);
        let mut rng = StdRng::seed_from_u64(0x5035_5042);
        let client = generator.generate_client_key(&mut rng);
        let sparse_key = generator
            .try_generate_sparse_server_key(&client, 3, 8, &mut rng)
            .unwrap();
        let classic_key = generator
            .try_generate_server_key(&client, &mut rng)
            .unwrap();
        let mut sparse = context.evaluator(&sparse_key).unwrap();
        let mut classic = context.evaluator(&classic_key).unwrap();
        let dimension = context.parameters().ciphertext_lwe_dimension();
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
        let single = context.compile_lookup_table_fn(&codec, function).unwrap();
        let many = context
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
        for incompatible in [self::context(order, 5, 7), self::context(order, 4, 8)] {
            assert!(matches!(
                incompatible.evaluator(&sparse_key),
                Err(TfheEvaluationError::IncompatibleServerKey)
            ));
        }
    }
}
