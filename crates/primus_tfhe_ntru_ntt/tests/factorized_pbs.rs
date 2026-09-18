use primus_encoding::{PlaintextEmbedding, RoundedCodec, ScaledCodec};
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntru::SecretKeyDistr;
use primus_ntt::U32NttTable;
use primus_test_allocations as allocations;
use primus_tfhe_ntru_ntt::{
    DecompositionConfig, FactorizedLookupTable, InterleavedLookupTable, LookupTable,
    LookupTableError, LweCiphertext, NttFactorizedLookupTable, TfheConfig, TfheContext,
    TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

const N: usize = 128;
const Q: u32 = 132_120_577;
const DOMAIN: usize = 8;

fn context() -> TfheContext<u32, U32NttTable> {
    let parameters = TfheParameters::try_from_config(TfheConfig {
        external_lwe: LweParameters::new(
            3,
            15,
            BarrettModulus::new(Q),
            SecretKeyDistr::UniformBinary,
            0.7,
        ),
        poly_length: N,
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 0.7,
        blind_rotation: DecompositionConfig {
            log_basis: 8,
            level_count: None,
        },
        key_switching: DecompositionConfig {
            log_basis: 8,
            level_count: None,
        },
        key_switching_noise_standard_deviation: 0.7,
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

#[test]
fn factorized_pbs_preserves_scaled_outputs_and_reuses_workspace() {
    let context = context();
    let modulus = context.parameters().accumulator_ntru().cipher_modulus();
    let codec = ScaledCodec::new(8, modulus);
    let mut rng = StdRng::seed_from_u64(0xB301);
    let (client, server) = context.try_generate_keys(None, &mut rng).unwrap();
    let encryptor = context.encryptor(&client).unwrap();
    let decryptor = context.decryptor(&client).unwrap();
    let mut evaluator = context.factorized_evaluator(&server).unwrap();
    let dimension = context.parameters().external_lwe_dimension();
    // The reference uses the same Scaled centers, not Rounded outputs.
    let singles: [_; 3] = std::array::from_fn(|i| {
        LookupTable::try_new(DOMAIN, N, 15, modulus, modulus, |m| {
            Ok(codec.encode_value(value(m, i), PlaintextEmbedding::Unsigned))
        })
        .unwrap()
    });
    let mut ordinary = context.evaluator(&server).unwrap();
    let mut reference = LweCiphertext::zero(dimension);
    let check = |outputs: &[LweCiphertext<u32>], message: usize| {
        for (i, output) in outputs.iter().enumerate() {
            assert_eq!(output.dimension(), dimension);
            assert_eq!(
                codec.decode_value(decryptor.decrypt_phase(output).unwrap()),
                value(message, i),
                "message={message}, output={i}"
            );
        }
    };

    for count in [1, 3, 17] {
        let (lut, allocation) = allocations::measure(|| {
            context
                .compile_factorized_lookup_table_fn(&codec, DOMAIN, count, value)
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
                evaluator.apply_lookup_table_to(&input, &lut, &mut outputs);
            });
            assert_eq!(allocation.count, 0, "MVB must reuse its workspace");
            check(&outputs, message);
            if count == 3 {
                for (single, output) in singles.iter().zip(&outputs) {
                    ordinary.apply_lookup_table_to(&input, single, &mut reference);
                    assert_eq!(
                        codec.decode_value(decryptor.decrypt_phase(&reference).unwrap()),
                        codec.decode_value(decryptor.decrypt_phase(output).unwrap())
                    );
                }
            }
        }
    }
    // Interleaving 17 outputs leaves only N/32=4 coefficients per output.
    assert!(matches!(
        InterleavedLookupTable::try_new(DOMAIN, N, 17, 15, modulus, modulus, |_, _| Ok(0)),
        Err(LookupTableError::PlaintextDomainTooLarge { .. })
    ));

    // For t_out=2, Delta is odd: the initializer must handle modular Delta/2,
    // whose canonical value is large, before any noisy public multiplication.
    let binary_codec = ScaledCodec::new(2, modulus);
    let binary = context
        .compile_factorized_lookup_table_fn(&binary_codec, DOMAIN, 1, |m, _| u32::from(m >= 3))
        .unwrap();
    for message in [0, 7] {
        let input = encryptor.encrypt_padded(message, &mut rng).unwrap();
        let output = evaluator.apply_lookup_table(&input, &binary);
        assert_eq!(
            binary_codec.decode_value(decryptor.decrypt_phase(&output[0]).unwrap()),
            u32::from(message >= 3)
        );
    }

    let lut = context
        .compile_factorized_lookup_table_fn(&codec, DOMAIN, 3, value)
        .unwrap();
    // Identical parameters do not establish NTT context identity.
    let other_context = self::context();
    let foreign = other_context
        .compile_factorized_lookup_table_fn(&codec, DOMAIN, 3, value)
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
                if case == 2 { &wrong } else { &input },
                if case == 3 { &foreign } else { &lut },
                &mut outputs,
            )))
            .is_err()
        );
        assert_eq!(outputs, before);
    }
    check(&evaluator.apply_lookup_table(&input, &lut), 3);

    for (n, t, input_q, output_q) in [
        (N / 2, 15, Q, Q),
        (N, 8, Q, Q),
        (N, 15, 97, Q),
        (N, 15, Q, 97),
    ] {
        let raw = FactorizedLookupTable::try_new(
            2,
            n,
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
            &ScaledCodec::new(8, BarrettModulus::new(97)),
            DOMAIN,
            3,
            value
        ),
        Err(LookupTableError::OutputModulusMismatch)
    ));
}
