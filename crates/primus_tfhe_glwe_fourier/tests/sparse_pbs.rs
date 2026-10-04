//! Classic/sparse differential PBS and ManyLUT on reused workspaces;
//! bucket layouts and quantization margins are part of the fixture.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_fft::{FftTable, RustFftTable, TfheFftTable};
use primus_glwe::{GlweParameters, SecretKeyDistr};
use primus_lattice::{GlweDimension, LweDimension};
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::NativeModulus;
use primus_poly::PolyLength;
use primus_test_allocations as allocations;
use primus_tfhe::{ProgrammableBootstrap, ProgrammableBootstrapInterleaved};
use primus_tfhe_glwe_fourier::{
    BlindRotationConfig, ClientKey, KeyGenerator, PbsOrder, TfheContext, TfheEvaluationError,
    TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

const N: usize = 128;

fn context<Table: FftTable>(
    order: PbsOrder,
    weight: usize,
    log_basis: u32,
) -> TfheContext<u64, Table> {
    let modulus = NativeModulus::new();
    let parameters = TfheParameters::try_new(
        (LweParameters::new(
            LweDimension::new(16),
            15,
            modulus,
            SecretKeyDistr::fixed_hamming_weight_binary(16, weight),
            0.7,
        ))
        .into_encryption_parameters(),
        primus_glwe::GgswParameters::try_with_basis(
            &(GlweParameters::new(
                GlweDimension::new(1),
                PolyLength::new(N),
                15,
                modulus,
                SecretKeyDistr::UniformTernary,
                0.7,
            )),
            ApproxSignedBasis::new(
                None,
                DecompositionBaseLog::new(log_basis),
                Some(DecompositionLevelCount::new(6)),
            ),
        )
        .unwrap(),
        ApproxSignedBasis::new(
            None,
            DecompositionBaseLog::new(8),
            Some(DecompositionLevelCount::new(6)),
        ),
        order,
    )
    .unwrap();
    TfheContext::from_parameters(parameters)
}

fn check_pbs<Table: FftTable>() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let context = context::<Table>(order, 4, 8);
        let input_codec =
            primus_encoding::RoundedCodec::new(15, context.parameters().cipher_modulus());
        let mut generator = KeyGenerator::new(&context);
        let mut rng = StdRng::seed_from_u64(0x4234_3250);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        let sparse_key = generator
            .try_generate_server_key(
                &client,
                BlindRotationConfig::Sparse {
                    copy_count: 3,
                    bucket_count: 8,
                },
                None,
                &mut rng,
            )
            .unwrap();
        let classic_key = generator
            .try_generate_server_key(&client, BlindRotationConfig::Classic, None, &mut rng)
            .unwrap();
        let mut sparse = context.evaluator(&sparse_key).unwrap();
        let mut classic = context.evaluator(&classic_key).unwrap();
        let dimension = context.parameters().external_lwe_dimension().get();
        assert_eq!(
            dimension,
            (LweDimension::new(if order == PbsOrder::BootstrapKeyswitch {
                16
            } else {
                N
            }))
            .get()
        );
        let encryptor = context
            .encryptor(client.external_lwe_secret_key(), &input_codec)
            .unwrap();
        let decryptor = context
            .decryptor(client.external_lwe_secret_key(), &input_codec)
            .unwrap();
        // Non-power-of-two input centers and a different output scale exercise
        // the exact prepared rotation modulus switch through both complete PBS orders.
        let codec = RoundedCodec::new(16, NativeModulus::new());
        let compiler = context
            .parameters()
            .lookup_table_compiler(&input_codec)
            .unwrap()
            .try_with_output_codec(&codec)
            .unwrap();
        let function = |m: usize| (3 * m as u64 + 1) % 16;
        let functions = |m: usize, i: usize| (m + 2 * i) as u64;
        let single = compiler.compile_fn(function).unwrap();
        let many = compiler.compile_interleaved_fn(3, functions).unwrap();
        assert_eq!(many.padded_output_count(), 4);
        let mut outputs = vec![LweCiphertext::zero(dimension); 3];
        let check = |output: &LweCiphertext<u64>, message| {
            let phase = decryptor.decrypt_phase(output.as_view()).unwrap();
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
                        input.as_view(),
                        &single,
                        outputs[0].as_mut_view(),
                    );
                });
                assert_eq!(allocation.count, 0);
                check(&outputs[0], function(message as usize));
                let (_, allocation) = allocations::measure(|| {
                    ProgrammableBootstrapInterleaved::apply_interleaved_lookup_table_to(
                        evaluator,
                        input.as_view(),
                        &many,
                        &mut outputs,
                    );
                });
                assert_eq!(allocation.count, 0);
                for (i, output) in outputs.iter().enumerate() {
                    check(output, functions(message as usize, i));
                }
                let (_, allocation) = allocations::measure(|| {
                    evaluator.apply_lookup_table_to(
                        input.as_view(),
                        &single,
                        outputs[0].as_mut_view(),
                    );
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
fn sparse_keys_bind_parameters() {
    let order = PbsOrder::BootstrapKeyswitch;
    let context = context::<RustFftTable>(order, 4, 8);
    let mut rng = StdRng::seed_from_u64(0x4234_3243);
    let client = ClientKey::generate(context.parameters(), &mut rng);
    let mut generator = KeyGenerator::new(&context);
    let server = generator
        .try_generate_server_key(
            &client,
            BlindRotationConfig::Sparse {
                copy_count: 3,
                bucket_count: 8,
            },
            None,
            &mut rng,
        )
        .unwrap();
    for incompatible in [
        self::context::<RustFftTable>(order, 5, 8),
        self::context::<RustFftTable>(order, 4, 7),
    ] {
        assert!(matches!(
            incompatible.evaluator(&server),
            Err(TfheEvaluationError::IncompatibleBlindRotationKey)
        ));
    }
}
