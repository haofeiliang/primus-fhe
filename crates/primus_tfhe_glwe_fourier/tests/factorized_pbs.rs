use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_lattice::{GlweDimension, LweDimension};
use primus_poly::PolyLength;
use std::panic::{AssertUnwindSafe, catch_unwind};

use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::{PlaintextEmbedding::Unsigned, RoundedCodec, ScaledCodec};
use primus_fft::{FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_glwe::{GlweParameters, SecretKeyDistr};
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_test_allocations as allocations;
use primus_tfhe_glwe_fourier::{
    BlindRotationConfig, FactorizedLookupTable, FourierFactorizedLookupTable, KeyGenerator,
    LookupTable, LookupTableError, PbsOrder, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

const N: usize = 128;
const DIM: usize = 8;
const DOMAIN: usize = 8;

fn context<T: TorusFftValue, Table: FftTable>(
    order: PbsOrder,
    ternary: bool,
) -> TfheContext<T, Table> {
    let modulus = NativeModulus::new();
    let t = T::as_from(15usize);
    let distribution = if ternary {
        SecretKeyDistr::fixed_composition_ternary(DIM, 2, 2)
    } else {
        SecretKeyDistr::fixed_hamming_weight_binary(DIM, 4)
    };
    TfheContext::from_parameters(
        TfheParameters::try_new(
            (LweParameters::new(LweDimension::new(DIM), t, modulus, distribution, 0.7))
                .into_inner(),
            primus_glwe::GgswParameters::try_with_basis(
                &(
                    // Multiple masks and a different KS output dimension protect component reuse.
                    GlweParameters::new(
                        GlweDimension::new(2),
                        N,
                        t,
                        modulus,
                        SecretKeyDistr::UniformBinary,
                        0.7,
                    )
                ),
                ApproxSignedBasis::new(
                    None,
                    DecompositionBaseLog::new(8),
                    Some(DecompositionLevelCount::new(3)),
                ),
            )
            .unwrap(),
            ApproxSignedBasis::new(
                None,
                DecompositionBaseLog::new(4),
                Some(DecompositionLevelCount::new(6)),
            ),
            order,
        )
        .unwrap(),
    )
}

fn value(m: usize, i: usize) -> usize {
    match i {
        0 => 9 - m,
        1 => 9 * (m % 2),
        _ => usize::from(m >= 3),
    }
}

fn check_complete<T: TorusFftValue, Table: FftTable>(order: PbsOrder, ternary: bool) {
    let context = context::<T, Table>(order, ternary);
    let input_codec = primus_encoding::RoundedCodec::new(
        T::as_from(15u32),
        context.parameters().cipher_modulus(),
    );
    let mut rng = StdRng::seed_from_u64(0x4235_3201);
    let (client, server) = context.try_generate_keys(None, &mut rng).unwrap();
    let modulus = NativeModulus::new();
    // Nonbinary t_out=10 has an even actual delta for both u32 and u64.
    let codec = ScaledCodec::new(T::as_from(10usize), modulus);
    let lut = context
        .compile_factorized_lookup_table_fn(&input_codec, &codec, DOMAIN, 3, |m, i| {
            T::as_from(value(m, i))
        })
        .unwrap();
    assert_eq!(
        (
            lut.input_domain_len(),
            lut.output_count(),
            lut.output_plaintext_modulus()
        ),
        (DOMAIN, 3, T::as_from(10usize))
    );
    let sparse = (!ternary).then(|| {
        KeyGenerator::new(&context)
            .try_generate_server_key(
                &client,
                BlindRotationConfig::Sparse {
                    copy_count: 3,
                    bucket_count: 8,
                },
                None,
                &mut rng,
            )
            .unwrap()
    });
    // Reuse the same client/program for classic and sparse binary controls.
    for server in std::iter::once(&server).chain(sparse.as_ref()) {
        let mut pbs = context.evaluator(server).unwrap();
        let mut evaluator = primus_tfhe_glwe_fourier::FactorizedEvaluator::new(&pbs);
        let encryptor = context
            .encryptor(client.external_lwe_secret_key(), &input_codec)
            .unwrap();
        let decryptor = context
            .decryptor(client.external_lwe_secret_key(), &input_codec)
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
                    T::as_from(15usize),
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
            let (_, allocation) = allocations::measure(|| {
                evaluator.apply_lookup_table_to(input.as_view(), &lut, &mut outputs, &mut pbs)
            });
            assert_eq!(
                allocation.count, 0,
                "first and reused MVB calls must not allocate"
            );
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
                assert_eq!(
                    codec.decode_value(decryptor.decrypt_phase(reference.as_view()).unwrap()),
                    expected
                );
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
    let context = context::<u32, RustFftTable>(PbsOrder::BootstrapKeyswitch, false);
    let input_codec = primus_encoding::RoundedCodec::new(15, context.parameters().cipher_modulus());
    let mut rng = StdRng::seed_from_u64(0x4235_3202);
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
    let other = self::context::<u32, RustFftTable>(PbsOrder::BootstrapKeyswitch, false);
    let foreign = FourierFactorizedLookupTable::new(&other, compile());
    let input = context
        .encryptor(client.external_lwe_secret_key(), &input_codec)
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
        .decryptor(client.external_lwe_secret_key(), &input_codec)
        .unwrap();
    let outputs = evaluator.apply_lookup_table(input.as_view(), &lut, &mut pbs);
    assert_eq!(
        outputs
            .iter()
            .map(|output| codec.decode_value(decryptor.decrypt_phase(output.as_view()).unwrap()))
            .collect::<Vec<_>>(),
        [3, 4, 5]
    );
    let single = context
        .compile_factorized_lookup_table_fn(&input_codec, &codec, DOMAIN, 1, |m, _| m as u32)
        .unwrap();
    assert_eq!(
        codec.decode_value(
            decryptor
                .decrypt_phase(
                    evaluator.apply_lookup_table(input.as_view(), &single, &mut pbs)[0].as_view()
                )
                .unwrap()
        ),
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
            &input_codec,
            &ScaledCodec::new(8, BarrettModulus::new(97)),
            DOMAIN,
            1,
            |_, _| panic!()
        ),
        Err(LookupTableError::OutputModulusMismatch)
    ));
    assert!(matches!(
        context.compile_factorized_lookup_table_fn(
            &input_codec,
            &ScaledCodec::new(3, NativeModulus::new()),
            DOMAIN,
            1,
            |_, _| panic!()
        ),
        Err(LookupTableError::OddFactorizationScale)
    ));
}
