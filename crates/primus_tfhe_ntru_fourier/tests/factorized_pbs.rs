use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_lattice::LweDimension;
use primus_lwe::LweEncryptionParameters;
use primus_poly::PolyLength;
use primus_tfhe::PbsMessageConfig;
use std::panic::{AssertUnwindSafe, catch_unwind};

use primus_encoding::{PlaintextEmbedding::Unsigned, RoundedCodec, ScaledCodec};
use primus_fft::{FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_lwe::LweCiphertext;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::SecretKeyDistr;
use primus_tfhe_ntru_fourier::{
    DecompositionConfig, FactorizedLookupTable, FourierFactorizedLookupTable,
    GadgetEncryptionConfig, LookupTable, LookupTableError, TfheConfig, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 128;
const DIM: usize = 8;
const DOMAIN: usize = 8;

fn context<T: TorusFftValue, Table: FftTable>(distr: SecretKeyDistr) -> TfheContext<T, Table> {
    let parameters = TfheParameters::try_from_config(TfheConfig {
        accumulator_modulus: NativeModulus::new(),
        external_lwe: LweEncryptionParameters::new(
            LweDimension::new(DIM),
            NativeModulus::new(),
            distr,
            0.7,
        ),
        poly_length: PolyLength::new(N),
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        blind_rotation: GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: Some(DecompositionLevelCount::new(3)),
            },
            noise_standard_deviation: 0.7,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: Some(DecompositionLevelCount::new(3)),
            },
            noise_standard_deviation: 0.7,
        },
    })
    .unwrap();
    TfheContext::from_parameters(parameters)
}

fn value(m: usize, i: usize) -> usize {
    match i {
        0 => 9 - m,
        1 => 9 * (m % 2),
        _ => usize::from(m >= i % DOMAIN),
    }
}

fn check_complete<T: TorusFftValue, Table: FftTable>(distr: SecretKeyDistr) {
    let context = context::<T, Table>(distr);
    // Existing binary/ternary cases cover both an override and equal-message default.
    // t_out=10 retains the non-power-of-two even-scale case for both word sizes.
    let messages = if matches!(distr, SecretKeyDistr::FixedCompositionTernary { .. }) {
        PbsMessageConfig::new(T::as_from(16u32))
    } else {
        PbsMessageConfig::new(T::as_from(15u32)).with_output_modulus(T::as_from(10u32))
    };
    let mvb_codecs = context
        .parameters()
        .factorized_pbs_codecs(messages)
        .unwrap();
    let input_codec = *mvb_codecs.input_codec();
    let codec = *mvb_codecs.lut_output_codec();
    let modulus = NativeModulus::new();
    let mut rng = StdRng::seed_from_u64(0x4235_3301);
    let (client, server) = context.try_generate_keys(None, &mut rng).unwrap();
    // Two full return tiles and a singleton tail reuse one polynomial buffer.
    let output_count = 17;
    let lut = context
        .compile_factorized_lookup_table_fn(&mvb_codecs, DOMAIN, output_count, |m, i| {
            T::as_from(value(m, i))
        })
        .unwrap();
    assert_eq!(
        (
            lut.input_domain_len(),
            lut.output_count(),
            lut.output_plaintext_modulus()
        ),
        (DOMAIN, output_count, messages.output_modulus)
    );
    let mut pbs = context.evaluator(&server).unwrap();
    let mut evaluator = primus_tfhe_ntru_fourier::FactorizedEvaluator::new(&pbs);
    let encryptor = context
        .encryptor(client.external_lwe_secret_key(), &input_codec)
        .unwrap();
    let decryptor = context
        .decryptor(client.external_lwe_secret_key(), &codec)
        .unwrap();
    let dimension = context.parameters().external_lwe_dimension().get();
    assert_eq!(dimension, (LweDimension::new(DIM)).get());
    let mut outputs = vec![LweCiphertext::zero(dimension); output_count];
    let singles: Vec<_> = (0..output_count)
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
    for message in [0, 3, 7, 0] {
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

#[test]
fn factorized_pbs_preserves_scaled_outputs_and_reuses_workspace() {
    for distr in [
        SecretKeyDistr::fixed_hamming_weight_binary(DIM, 3),
        SecretKeyDistr::fixed_composition_ternary(DIM, 1, 2),
    ] {
        check_complete::<u32, RustFftTable>(distr);
        check_complete::<u32, TfheFftTable>(distr);
        check_complete::<u64, RustFftTable>(distr);
        check_complete::<u64, TfheFftTable>(distr);
    }
}

#[test]
fn factorized_boundaries_precede_output_writes_and_recover_workspace() {
    let context = context::<u32, RustFftTable>(SecretKeyDistr::fixed_hamming_weight_binary(DIM, 3));
    let input_codec = RoundedCodec::new(15, context.parameters().external_lwe().cipher_modulus());
    let mut rng = StdRng::seed_from_u64(0x4235_3302);
    let (client, server) = context.try_generate_keys(None, &mut rng).unwrap();
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
    let other =
        self::context::<u32, RustFftTable>(SecretKeyDistr::fixed_hamming_weight_binary(DIM, 3));
    let foreign = FourierFactorizedLookupTable::new(&other, compile());
    let input = context
        .encryptor(client.external_lwe_secret_key(), &input_codec)
        .unwrap()
        .encrypt_padded(3, &mut rng)
        .unwrap();
    let wrong = LweCiphertext::zero(DIM - 1);
    let mut pbs = context.evaluator(&server).unwrap();
    let mut evaluator = primus_tfhe_ntru_fourier::FactorizedEvaluator::new(&pbs);
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
    let decryptor = context
        .decryptor(client.external_lwe_secret_key(), &codec)
        .unwrap();
    let outputs = evaluator.apply_lookup_table(input.as_view(), &lut, &mut pbs);
    assert_eq!(
        outputs
            .iter()
            .map(|output| decryptor.decrypt(output.as_view()).unwrap())
            .collect::<Vec<_>>(),
        [3, 4, 5]
    );
    let mvb_codecs = context
        .parameters()
        .factorized_pbs_codecs(
            PbsMessageConfig::new(input_codec.plaintext_modulus())
                .with_output_modulus(codec.plaintext_modulus()),
        )
        .unwrap();
    let single = context
        .compile_factorized_lookup_table_fn(&mvb_codecs, DOMAIN, 1, |m, _| m as u32)
        .unwrap();
    assert_eq!(
        decryptor
            .decrypt(evaluator.apply_lookup_table(input.as_view(), &single, &mut pbs)[0].as_view())
            .unwrap(),
        3
    );

    let native = NativeModulus::new();
    let explicit = BarrettModulus::new(97);
    let mut mismatched = vec![
        FactorizedLookupTable::try_new(
            2,
            PolyLength::new(N / 2),
            1,
            &RoundedCodec::new(15, native),
            &codec,
            |_, _| 0,
        )
        .unwrap(),
    ];

    mismatched.push(
        FactorizedLookupTable::try_new(
            2,
            PolyLength::new(N),
            1,
            &RoundedCodec::new(15, explicit),
            &codec,
            |_, _| 0,
        )
        .unwrap(),
    );
    mismatched.push(
        FactorizedLookupTable::try_new(
            2,
            PolyLength::new(N),
            1,
            &input_codec,
            &ScaledCodec::new(8, explicit),
            |_, _| 0,
        )
        .unwrap(),
    );
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
