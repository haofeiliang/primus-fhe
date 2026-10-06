use primus_decompose::DecompositionBaseLog;
use primus_encoding::{PlaintextEmbedding, RoundedCodec, ScaledCodec};
use primus_lattice::LweDimension;
use primus_lwe::LweEncryptionParameters;
use primus_modulus::BarrettModulus;
use primus_ntru::SecretKeyDistr;
use primus_ntt::U32NttTable;
use primus_poly::PolyLength;
use primus_test_allocations as allocations;
use primus_tfhe_ntru_ntt::{
    DecompositionConfig, FactorizedLookupTable, GadgetEncryptionConfig, InterleavedLookupTable,
    LookupTable, LookupTableError, LweCiphertext, NttFactorizedLookupTable, TfheConfig,
    TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

const N: usize = 128;
const Q: u32 = 132_120_577;
const DOMAIN: usize = 8;

fn context(distr: SecretKeyDistr) -> TfheContext<u32, U32NttTable> {
    let parameters = TfheParameters::try_from_config(TfheConfig {
        accumulator_modulus: BarrettModulus::new(Q),
        external_lwe: LweEncryptionParameters::new(
            LweDimension::new(3),
            BarrettModulus::new(Q),
            distr,
            0.7,
        ),
        poly_length: PolyLength::new(N),
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        blind_rotation: GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: None,
            },
            noise_standard_deviation: 0.7,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: None,
            },
            noise_standard_deviation: 0.7,
        },
    })
    .unwrap();
    TfheContext::try_from_parameters(parameters).unwrap()
}

fn value(message: usize, output: usize) -> u32 {
    match output % 3 {
        0 => (7 - message) as u32,
        1 => (message % 2) as u32,
        _ => u32::from(message >= 3),
    }
}

fn check_complete(distr: SecretKeyDistr) {
    let context = context(distr);
    let input_codec = RoundedCodec::new(15, context.parameters().external_lwe().cipher_modulus());
    let modulus = context.parameters().accumulator_ntru().cipher_modulus();
    let codec = ScaledCodec::new(8, modulus);
    let mut rng = StdRng::seed_from_u64(0xB301);
    let (client, server) = context.try_generate_keys(None, &mut rng).unwrap();
    let encryptor = context
        .encryptor(client.external_lwe_secret_key(), &input_codec)
        .unwrap();
    let decryptor = context
        .decryptor(client.external_lwe_secret_key(), &input_codec)
        .unwrap();
    let mut pbs = context.evaluator(&server).unwrap();
    let mut evaluator = primus_tfhe_ntru_ntt::FactorizedEvaluator::new(&pbs);
    let dimension = context.parameters().external_lwe_dimension().get();
    // The reference uses the same Scaled centers, not Rounded outputs.
    let singles: [_; 3] = std::array::from_fn(|i| {
        LookupTable::try_new(DOMAIN, PolyLength::new(N), 15, modulus, modulus, |m| {
            Ok(codec.encode_value(value(m, i), PlaintextEmbedding::Unsigned))
        })
        .unwrap()
    });
    let mut reference = LweCiphertext::zero(dimension);
    let check = |outputs: &[LweCiphertext<u32>], message: usize| {
        for (i, output) in outputs.iter().enumerate() {
            assert_eq!(output.dimension(), dimension);
            assert_eq!(
                codec.decode_value(decryptor.decrypt_phase(output.as_view()).unwrap()),
                value(message, i),
                "message={message}, output={i}"
            );
        }
    };

    for count in [1, 3, 17] {
        let (lut, allocation) = allocations::measure(|| {
            context
                .compile_factorized_lookup_table_fn(&input_codec, &codec, DOMAIN, count, value)
                .unwrap()
        });
        assert_eq!(
            allocation.count, 2,
            "preparation must reuse the factor buffer"
        );
        assert_eq!(
            (
                lut.input_domain_len(),
                lut.output_count(),
                lut.output_plaintext_modulus()
            ),
            (DOMAIN, count, 8)
        );
        let mut outputs = vec![LweCiphertext::new(vec![Q - 1; dimension + 1]); count];
        for message in [0, 3, 7, 0] {
            let input = encryptor.encrypt_padded(message as u32, &mut rng).unwrap();
            let (_, allocation) = allocations::measure(|| {
                evaluator.apply_lookup_table_to(input.as_view(), &lut, &mut outputs, &mut pbs);
            });
            assert_eq!(allocation.count, 0, "MVB must reuse its workspace");
            check(&outputs, message);
            if count == 3 {
                for (single, output) in singles.iter().zip(&outputs) {
                    pbs.apply_lookup_table_to(input.as_view(), single, reference.as_mut_view());
                    assert_eq!(
                        codec.decode_value(decryptor.decrypt_phase(reference.as_view()).unwrap()),
                        codec.decode_value(decryptor.decrypt_phase(output.as_view()).unwrap())
                    );
                }
            }
        }
    }
    // Interleaving 17 outputs leaves only N/32=4 coefficients per output.
    assert!(matches!(
        InterleavedLookupTable::try_new(
            DOMAIN,
            PolyLength::new(N),
            17,
            15,
            modulus,
            modulus,
            |_, _| Ok(0)
        ),
        Err(LookupTableError::PlaintextDomainTooLarge { .. })
    ));

    // For t_out=2, Delta is odd: the initializer must handle modular Delta/2,
    // whose canonical value is large, before any noisy public multiplication.
    let binary_codec = ScaledCodec::new(2, modulus);
    let binary = context
        .compile_factorized_lookup_table_fn(&input_codec, &binary_codec, DOMAIN, 1, |m, _| {
            u32::from(m >= 3)
        })
        .unwrap();
    for message in [0, 7] {
        let input = encryptor.encrypt_padded(message, &mut rng).unwrap();
        let output = evaluator.apply_lookup_table(input.as_view(), &binary, &mut pbs);
        assert_eq!(
            binary_codec.decode_value(decryptor.decrypt_phase(output[0].as_view()).unwrap()),
            u32::from(message >= 3)
        );
    }

    let lut = context
        .compile_factorized_lookup_table_fn(&input_codec, &codec, DOMAIN, 3, value)
        .unwrap();
    // Identical parameters do not establish NTT context identity.
    let other_context = self::context(distr);
    let foreign = other_context
        .compile_factorized_lookup_table_fn(&input_codec, &codec, DOMAIN, 3, value)
        .unwrap();
    let input = encryptor.encrypt_padded(3, &mut rng).unwrap();
    let wrong = LweCiphertext::zero(dimension - 1);
    for case in 0..4 {
        let mut outputs = vec![input.clone(); if case == 0 { 2 } else { 3 }];
        if case == 1 {
            outputs[2] = wrong.clone();
        }
        let before = outputs.clone();
        assert!(
            catch_unwind(AssertUnwindSafe(|| evaluator.apply_lookup_table_to(
                if case == 2 {
                    wrong.as_view()
                } else {
                    input.as_view()
                },
                if case == 3 { &foreign } else { &lut },
                &mut outputs,
                &mut pbs
            )))
            .is_err()
        );
        assert_eq!(outputs, before);
    }
    check(
        &evaluator.apply_lookup_table(input.as_view(), &lut, &mut pbs),
        3,
    );

    for (n, t, input_q, output_q) in [(N / 2, 15, Q, Q), (N, 15, 97, Q), (N, 15, Q, 97)] {
        let raw = FactorizedLookupTable::try_new(
            2,
            PolyLength::new(n),
            1,
            &RoundedCodec::new(t, BarrettModulus::new(input_q)),
            &ScaledCodec::new(8, BarrettModulus::new(output_q)),
            |_, _| 0,
        )
        .unwrap();
        assert!(
            catch_unwind(AssertUnwindSafe(|| NttFactorizedLookupTable::new(
                &context, raw
            )))
            .is_err()
        );
    }
    assert!(matches!(
        context.compile_factorized_lookup_table_fn(
            &input_codec,
            &ScaledCodec::new(8, BarrettModulus::new(97)),
            DOMAIN,
            3,
            value
        ),
        Err(LookupTableError::OutputModulusMismatch)
    ));
}

#[test]
fn factorized_pbs_preserves_scaled_outputs_and_reuses_workspace() {
    for distr in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::fixed_composition_ternary(3, 1, 2),
    ] {
        check_complete(distr);
    }
}
