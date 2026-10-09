//! Classic/sparse differential PBS and ManyLUT on reused workspaces;
//! bucket layouts and quantization margins are part of the fixture.

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_fft::{FftTable, RustFftTable, TfheFftTable};
use primus_glwe::SecretKeyDistr;
use primus_lattice::{GlweDimension, LweDimension};
use primus_lwe::LweCiphertext;
use primus_modulus::NativeModulus;
use primus_poly::PolyLength;
use primus_tfhe::{PbsMessageConfig, ProgrammableBootstrap, ProgrammableBootstrapInterleaved};
use primus_tfhe_glwe_fourier::{
    BlindRotationMethod, ClientKey, GadgetEncryptionConfig, KeyGenerator, PbsOrder, PbsParameters,
    TfheContext, TfheEvaluationError,
};
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 128;

fn context<Table: FftTable>(
    order: PbsOrder,
    weight: usize,
    log_basis: u32,
) -> (
    primus_tfhe_glwe_fourier::PbsParameters<u64>,
    TfheContext<u64, Table>,
) {
    let modulus = NativeModulus::new();
    let parameters = PbsParameters::try_from_config(primus_tfhe_glwe::PbsConfig {
        small_lwe: primus_tfhe::LweConfig {
            dimension: LweDimension::new(16),
            cipher_modulus: modulus.into(),
            secret_key_distr: SecretKeyDistr::fixed_hamming_weight_binary(16, weight),
            noise_standard_deviation: 0.7,
        },
        bsk_dimension: GlweDimension::new(1),
        bsk_poly_length: PolyLength::new(N),
        bsk_secret_distr: SecretKeyDistr::UniformTernary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: primus_tfhe::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(log_basis),
                level_count: Some(DecompositionLevelCount::new(6)),
            },
            noise_standard_deviation: 0.7,
        },
        // Independent KS noise also reaches complete sparse server-key generation.
        key_switching: GadgetEncryptionConfig {
            decomposition: primus_tfhe::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: Some(DecompositionLevelCount::new(6)),
            },
            noise_standard_deviation: 1.25,
        },
        method: BlindRotationMethod::Classic,
        messages: PbsMessageConfig::new(4),
        order,
    })
    .unwrap();
    let context = TfheContext::from_parameters(parameters.clone());
    (parameters, context)
}

fn check_pbs<Table: FftTable>() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let (context_parameters, context) = self::context::<Table>(order, 4, 8);
        let input_codec =
            primus_encoding::RoundedCodec::new(15, context.parameters().cipher_modulus());
        let mut generator = KeyGenerator::new(&context);
        let mut rng = StdRng::seed_from_u64(0x4234_3250);
        let (client, sparse_key) = generator
            .try_generate_with_parameters(
                context_parameters.glwe_key_switching(),
                BlindRotationMethod::Sparse {
                    copy_count: 3,
                    bucket_count: 8,
                },
                &mut rng,
            )
            .unwrap();
        let classic_key = generator
            .try_generate_server_key_with_parameters(
                context_parameters.glwe_key_switching(),
                &client,
                BlindRotationMethod::Classic,
                &mut rng,
            )
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
        let codecs = context
            .parameters()
            .pbs_codecs(
                PbsMessageConfig::new(input_codec.plaintext_modulus())
                    .with_output_modulus(codec.plaintext_modulus()),
            )
            .unwrap();
        let compiler = context.parameters().lookup_table_compiler(&codecs).unwrap();
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
                ProgrammableBootstrap::apply_lookup_table_to(
                    evaluator,
                    input.as_view(),
                    &single,
                    outputs[0].as_mut_view(),
                );
                check(&outputs[0], function(message as usize));
                ProgrammableBootstrapInterleaved::apply_interleaved_lookup_table_to(
                    evaluator,
                    input.as_view(),
                    &many,
                    &mut outputs,
                );
                for (i, output) in outputs.iter().enumerate() {
                    check(output, functions(message as usize, i));
                }
                evaluator.apply_lookup_table_to(input.as_view(), &single, outputs[0].as_mut_view());
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
    let (context_parameters, context) = self::context::<RustFftTable>(order, 4, 8);
    let mut rng = StdRng::seed_from_u64(0x4234_3243);
    let client = ClientKey::generate(context.parameters(), &mut rng);
    let mut generator = KeyGenerator::new(&context);
    let server = generator
        .try_generate_server_key_with_parameters(
            context_parameters.glwe_key_switching(),
            &client,
            BlindRotationMethod::Sparse {
                copy_count: 3,
                bucket_count: 8,
            },
            &mut rng,
        )
        .unwrap();
    for (_, incompatible) in [
        self::context::<RustFftTable>(order, 5, 8),
        self::context::<RustFftTable>(order, 4, 7),
    ] {
        assert!(matches!(
            incompatible.evaluator(&server),
            Err(TfheEvaluationError::IncompatibleBlindRotationKey)
        ));
    }
}
