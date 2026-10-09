use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_lattice::{GlweDimension, LweDimension};
use primus_poly::PolyLength;
use primus_tfhe::PbsMessageConfig;
use std::panic::{AssertUnwindSafe, catch_unwind};

use primus_encoding::{PlaintextEmbedding::Unsigned, RoundedCodec, ScaledCodec};
use primus_fft::{FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_glwe::SecretKeyDistr;
use primus_lwe::LweCiphertext;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_tfhe_glwe_fourier::{
    BlindRotationMethod, FactorizedLookupTable, FourierFactorizedLookupTable,
    GadgetEncryptionConfig, KeyGenerator, LookupTable, LookupTableError, PbsOrder, PbsParameters,
    TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 128;
const DIM: usize = 8;
const DOMAIN: usize = 8;

fn context<T: TorusFftValue, Table: FftTable>(
    order: PbsOrder,
    ternary: bool,
) -> (
    primus_tfhe_glwe_fourier::PbsParameters<T>,
    TfheContext<T, Table>,
) {
    let modulus = NativeModulus::new();
    let distribution = if ternary {
        SecretKeyDistr::fixed_composition_ternary(DIM, 2, 2)
    } else {
        SecretKeyDistr::fixed_hamming_weight_binary(DIM, 4)
    };
    let parameters = PbsParameters::try_from_config(primus_tfhe_glwe::PbsConfig {
        small_lwe: primus_tfhe::LweConfig {
            dimension: LweDimension::new(DIM),
            cipher_modulus: modulus.into(),
            secret_key_distr: distribution,
            noise_standard_deviation: 0.7,
        },
        bsk_dimension: GlweDimension::new(2),
        bsk_poly_length: PolyLength::new(N),
        bsk_secret_distr: SecretKeyDistr::UniformBinary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: primus_tfhe::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: Some(DecompositionLevelCount::new(3)),
            },
            noise_standard_deviation: 0.7,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: primus_tfhe::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(4),
                level_count: Some(DecompositionLevelCount::new(6)),
            },
            noise_standard_deviation: 0.7,
        },
        method: primus_tfhe::BlindRotationMethod::Classic,
        messages: if ternary {
            PbsMessageConfig::new(T::as_from(16u32))
        } else {
            PbsMessageConfig::new(T::as_from(15u32)).with_output_modulus(T::as_from(10u32))
        },
        order,
    })
    .unwrap();
    let context = TfheContext::from_parameters(parameters.clone());
    (parameters, context)
}

fn value(m: usize, i: usize) -> usize {
    match i {
        0 => 9 - m,
        1 => 9 * (m % 2),
        _ => usize::from(m >= 3),
    }
}

fn check_complete<T: TorusFftValue, Table: FftTable>(order: PbsOrder, ternary: bool) {
    let (context_parameters, context) = self::context::<T, Table>(order, ternary);
    // Existing binary/ternary cases cover both an override and equal-message default.
    // t_out=10 retains the non-power-of-two even-scale case for both word sizes.
    let messages = context.parameters().messages();
    let mvb_codecs = context
        .parameters()
        .factorized_pbs_codecs(messages)
        .unwrap();
    let input_codec = *mvb_codecs.input_codec();
    let codec = *mvb_codecs.lut_output_codec();
    let modulus = NativeModulus::new();
    let mut rng = StdRng::seed_from_u64(0x4235_3201);
    let (client, server) = context.try_generate_keys(&mut rng).unwrap();
    let lut = context
        .compile_mvb_fn(DOMAIN, 3, |m, i| T::as_from(value(m, i)))
        .unwrap();
    assert_eq!(
        (
            lut.input_domain_len(),
            lut.output_count(),
            lut.output_plaintext_modulus()
        ),
        (DOMAIN, 3, messages.output_modulus)
    );
    let sparse = (!ternary).then(|| {
        KeyGenerator::new(&context)
            .try_generate_server_key_with_parameters(
                context_parameters.glwe_key_switching(),
                &client,
                BlindRotationMethod::Sparse {
                    copy_count: 3,
                    bucket_count: 8,
                },
                &mut rng,
            )
            .unwrap()
    });
    // Reuse the same client/program for classic and sparse binary controls.
    for server in std::iter::once(&server).chain(sparse.as_ref()) {
        let mut pbs = context.evaluator(server).unwrap();
        let mut evaluator = primus_tfhe_glwe_fourier::FactorizedEvaluator::new(&pbs);
        let encryptor = context.encryptor(client.external_lwe_secret_key()).unwrap();
        let decryptor = context
            .mvb_decryptor(client.external_lwe_secret_key())
            .unwrap();
        let dimension = context.parameters().external_lwe_dimension().get();
        assert_eq!(
            dimension,
            if order == PbsOrder::BootstrapKeyswitch {
                DIM
            } else {
                2 * N
            }
        );
        let mut outputs = vec![LweCiphertext::zero(dimension); 3];
        let singles: Vec<_> = (0..3)
            .map(|i| {
                LookupTable::try_new(
                    DOMAIN,
                    PolyLength::new(N),
                    input_codec.plaintext_modulus(),
                    modulus,
                    modulus,
                    |m| Ok(codec.encode_value(T::as_from(value(m, i)), Unsigned)),
                )
                .unwrap()
            })
            .collect();
        let mut reference = LweCiphertext::zero(dimension);
        for message in [0, 3, 7] {
            let input = encryptor
                .encrypt_padded(T::as_from(message), &mut rng)
                .unwrap();
            evaluator.apply_lookup_table_to(input.as_view(), &lut, &mut outputs, &mut pbs);
            for (i, output) in outputs.iter().enumerate() {
                let expected = T::as_from(value(message, i));
                let phase = decryptor.decrypt_phase(output.as_view()).unwrap();
                assert_eq!(codec.decode_value(phase), expected);
                // Keep a deterministic margin, not just a rounded decoding check.
                let error = phase
                    .wrapping_sub(codec.encode_value(expected, Unsigned))
                    .into_signed_f64()
                    .abs();
                assert!(error * T::TORUS_SCALE < 0.01);
                pbs.apply_lookup_table_to(input.as_view(), &singles[i], reference.as_mut_view());
                assert_eq!(decryptor.decrypt(reference.as_view()).unwrap(), expected);
            }
        }
    }
}

#[test]
fn factorized_pbs_preserves_both_external_secrets_and_integer_scales() {
    // Pair word sizes and secret distributions instead of repeating a full product
    // of all fixtures. Each FFT covers both orders and both distributions per width.
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let ternary = order == PbsOrder::KeyswitchBootstrap;
        check_complete::<u32, RustFftTable>(order, ternary);
        check_complete::<u32, TfheFftTable>(order, !ternary);
        check_complete::<u64, RustFftTable>(order, !ternary);
        check_complete::<u64, TfheFftTable>(order, ternary);
    }
}

#[test]
fn factorized_boundaries_precede_output_writes_and_recover_workspace() {
    let (_, context) = context::<u32, RustFftTable>(PbsOrder::BootstrapKeyswitch, false);
    let input_codec = primus_encoding::RoundedCodec::new(15, context.parameters().cipher_modulus());
    let mut rng = StdRng::seed_from_u64(0x4235_3202);
    let (client, server) = context.try_generate_keys(&mut rng).unwrap();
    // This raw program uses t_out=8 in a context whose default is t_out=10.
    let codec = ScaledCodec::new(8u32, NativeModulus::new());
    let compile = || {
        FactorizedLookupTable::try_new(
            DOMAIN,
            PolyLength::new(N),
            3,
            &input_codec,
            &codec,
            |m, i| ((m + i) % 8) as u32,
        )
        .unwrap()
    };
    let lut = FourierFactorizedLookupTable::new(&context, compile());
    let (_, other) = self::context::<u32, RustFftTable>(PbsOrder::BootstrapKeyswitch, false);
    let foreign = FourierFactorizedLookupTable::new(&other, compile());
    let input = context
        .encryptor(client.external_lwe_secret_key())
        .unwrap()
        .encrypt_padded(3, &mut rng)
        .unwrap();
    let wrong = LweCiphertext::zero(DIM - 1);
    let mut pbs = context.evaluator(&server).unwrap();
    let mut evaluator = primus_tfhe_glwe_fourier::FactorizedEvaluator::new(&pbs);
    let mut foreign_pbs = other.evaluator(&server).unwrap();
    for case in 0..5 {
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
                if case == 4 {
                    &mut foreign_pbs
                } else {
                    &mut pbs
                },
            )))
            .is_err()
        );
        assert_eq!(outputs, before);
    }
    let decryptor = context
        .parameters()
        .decryptor_with_codec(client.external_lwe_secret_key(), &codec)
        .unwrap();
    let outputs = evaluator.apply_lookup_table(input.as_view(), &lut, &mut pbs);
    assert_eq!(
        outputs
            .iter()
            .map(|output| decryptor.decrypt(output.as_view()).unwrap())
            .collect::<Vec<_>>(),
        [3, 4, 5]
    );
    let messages = PbsMessageConfig::new(input_codec.plaintext_modulus())
        .with_output_modulus(codec.plaintext_modulus());
    let single = context
        .compile_mvb_fn_with_messages(messages, DOMAIN, 1, |m, _| m as u32)
        .unwrap();
    assert_eq!(
        decryptor
            .decrypt(evaluator.apply_lookup_table(input.as_view(), &single, &mut pbs)[0].as_view())
            .unwrap(),
        3
    );

    let native = NativeModulus::new();
    let explicit = BarrettModulus::new(97);
    let mismatched = [
        FactorizedLookupTable::try_new(
            2,
            PolyLength::new(N / 2),
            1,
            &RoundedCodec::new(15, native),
            &codec,
            |_, _| 0,
        )
        .unwrap(),
        FactorizedLookupTable::try_new(
            2,
            PolyLength::new(N),
            1,
            &RoundedCodec::new(15, explicit),
            &codec,
            |_, _| 0,
        )
        .unwrap(),
        FactorizedLookupTable::try_new(
            2,
            PolyLength::new(N),
            1,
            &input_codec,
            &ScaledCodec::new(8, explicit),
            |_, _| 0,
        )
        .unwrap(),
    ];
    for raw in mismatched {
        assert!(
            catch_unwind(AssertUnwindSafe(|| FourierFactorizedLookupTable::new(
                &context, raw
            )))
            .is_err()
        );
    }
    assert!(matches!(
        context.compile_factorized_lookup_table_fn(
            &PbsMessageConfig::new(15)
                .with_output_modulus(8)
                .try_factorized_codecs(input_codec.ciphertext_modulus(), BarrettModulus::new(97))
                .unwrap(),
            DOMAIN,
            1,
            |_, _| panic!()
        ),
        Err(LookupTableError::OutputModulusMismatch)
    ));
    assert!(matches!(
        context.compile_factorized_lookup_table_fn(
            &PbsMessageConfig::new(15)
                .with_output_modulus(3)
                .try_factorized_codecs(input_codec.ciphertext_modulus(), NativeModulus::new())
                .unwrap(),
            DOMAIN,
            1,
            |_, _| panic!()
        ),
        Err(LookupTableError::OddFactorizationScale)
    ));
}
