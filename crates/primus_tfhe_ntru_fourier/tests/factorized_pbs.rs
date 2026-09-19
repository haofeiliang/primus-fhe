use std::panic::{AssertUnwindSafe, catch_unwind};

use primus_encoding::{PlaintextEmbedding::Unsigned, RoundedCodec, ScaledCodec};
use primus_fft::{FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::SecretKeyDistr;
use primus_test_allocations as allocations;
use primus_tfhe_ntru_fourier::{
    DecompositionConfig, FactorizedLookupTable, FourierFactorizedLookupTable, LookupTable,
    LookupTableError, TfheConfig, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

const N: usize = 128;
const DIM: usize = 8;
const DOMAIN: usize = 8;

fn context<T: TorusFftValue, Table: FftTable>() -> TfheContext<T, Table> {
    let parameters = TfheParameters::try_from_config(TfheConfig {
        external_lwe: LweParameters::new(
            DIM,
            T::as_from(15usize),
            NativeModulus::new(),
            SecretKeyDistr::fixed_hamming_weight_binary(DIM, 3),
            0.7,
        ),
        poly_length: N,
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 0.7,
        blind_rotation: DecompositionConfig {
            log_basis: 8,
            level_count: Some(3),
        },
        key_switching: DecompositionConfig {
            log_basis: 8,
            level_count: Some(3),
        },
        key_switching_noise_standard_deviation: 0.7,
    })
    .unwrap();
    TfheContext::try_from_parameters(parameters).unwrap()
}

fn value(m: usize, i: usize) -> usize {
    match i {
        0 => 9 - m,
        1 => 9 * (m % 2),
        _ => usize::from(m >= 3),
    }
}

fn check_complete<T: TorusFftValue, Table: FftTable>() {
    let context = context::<T, Table>();
    let mut rng = StdRng::seed_from_u64(0x4235_3301);
    let (client, server) = context.try_generate_keys(None, &mut rng).unwrap();
    let modulus = NativeModulus::new();
    // Nonbinary t_out=10 has an even actual delta for both u32 and u64.
    let codec = ScaledCodec::new(T::as_from(10usize), modulus);
    let lut = context
        .compile_factorized_lookup_table_fn(&codec, DOMAIN, 3, |m, i| T::as_from(value(m, i)))
        .unwrap();
    assert_eq!(
        (
            lut.input_domain_len(),
            lut.output_count(),
            lut.output_plaintext_modulus()
        ),
        (DOMAIN, 3, T::as_from(10usize))
    );
    let mut evaluator = context.factorized_evaluator(&server).unwrap();
    let encryptor = context.encryptor(&client).unwrap();
    let decryptor = context.decryptor(&client).unwrap();
    let dimension = context.parameters().external_lwe_dimension();
    assert_eq!(dimension, DIM);
    let mut outputs = vec![LweCiphertext::zero(dimension); 3];
    let mut ordinary = context.evaluator(&server).unwrap();
    let singles: Vec<_> = (0..3)
        .map(|i| {
            LookupTable::try_new(DOMAIN, N, T::as_from(15usize), modulus, modulus, |m| {
                Ok(codec.encode_value(T::as_from(value(m, i)), Unsigned))
            })
            .unwrap()
        })
        .collect();
    let mut reference = LweCiphertext::zero(dimension);
    for message in [0, 3, 7, 0] {
        let input = encryptor
            .encrypt_padded(T::as_from(message), &mut rng)
            .unwrap();
        let (_, allocation) =
            allocations::measure(|| evaluator.apply_lookup_table_to(&input, &lut, &mut outputs));
        assert_eq!(
            allocation.count, 0,
            "first and reused MVB calls must not allocate"
        );
        for (i, output) in outputs.iter().enumerate() {
            let expected = T::as_from(value(message, i));
            let phase = decryptor.decrypt_phase(output).unwrap();
            assert_eq!(codec.decode_value(phase), expected);
            // Keep a deterministic margin, not just a rounded decoding check.
            let error = phase
                .wrapping_sub(codec.encode_value(expected, Unsigned))
                .into_signed_f64()
                .abs();
            assert!(error * T::TORUS_SCALE < 0.01);
            ordinary.apply_lookup_table_to(&input, &singles[i], &mut reference);
            assert_eq!(
                codec.decode_value(decryptor.decrypt_phase(&reference).unwrap()),
                expected
            );
        }
    }
}

#[test]
fn factorized_pbs_preserves_scaled_outputs_and_reuses_workspace() {
    check_complete::<u32, RustFftTable>();
    check_complete::<u32, TfheFftTable>();
    check_complete::<u64, RustFftTable>();
    check_complete::<u64, TfheFftTable>();
}

#[test]
fn factorized_boundaries_precede_output_writes_and_recover_workspace() {
    let context = context::<u32, RustFftTable>();
    let mut rng = StdRng::seed_from_u64(0x4235_3302);
    let (client, server) = context.try_generate_keys(None, &mut rng).unwrap();
    let codec = ScaledCodec::new(8u32, NativeModulus::new());
    let compile = |context: &TfheContext<u32, RustFftTable>| {
        FactorizedLookupTable::try_new(
            DOMAIN,
            N,
            3,
            context.parameters().input_plaintext_codec(),
            &codec,
            |m, i| ((m + i) % 8) as u32,
        )
        .unwrap()
    };
    let lut = FourierFactorizedLookupTable::new(&context, compile(&context));
    let other = self::context::<u32, RustFftTable>();
    let foreign = FourierFactorizedLookupTable::new(&other, compile(&other));
    let input = context
        .encryptor(&client)
        .unwrap()
        .encrypt_padded(3, &mut rng)
        .unwrap();
    let wrong = LweCiphertext::zero(DIM - 1);
    let mut evaluator = context.factorized_evaluator(&server).unwrap();
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
                &mut outputs
            )))
            .is_err()
        );
        assert_eq!(outputs, before);
    }
    let decryptor = context.decryptor(&client).unwrap();
    let outputs = evaluator.apply_lookup_table(&input, &lut);
    assert_eq!(
        outputs
            .iter()
            .map(|output| codec.decode_value(decryptor.decrypt_phase(output).unwrap()))
            .collect::<Vec<_>>(),
        [3, 4, 5]
    );
    let single = context
        .compile_factorized_lookup_table_fn(&codec, DOMAIN, 1, |m, _| m as u32)
        .unwrap();
    assert_eq!(
        codec.decode_value(
            decryptor
                .decrypt_phase(&evaluator.apply_lookup_table(&input, &single)[0])
                .unwrap()
        ),
        3
    );

    let native = NativeModulus::new();
    let explicit = BarrettModulus::new(97);
    let mut mismatched = Vec::new();
    for (n, t) in [(N / 2, 15), (N, 8)] {
        mismatched.push(
            FactorizedLookupTable::try_new(
                2,
                n,
                1,
                &RoundedCodec::new(t, native),
                &codec,
                |_, _| 0,
            )
            .unwrap(),
        );
    }
    mismatched.push(
        FactorizedLookupTable::try_new(2, N, 1, &RoundedCodec::new(15, explicit), &codec, |_, _| 0)
            .unwrap(),
    );
    mismatched.push(
        FactorizedLookupTable::try_new(
            2,
            N,
            1,
            context.parameters().input_plaintext_codec(),
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
            &ScaledCodec::new(8, BarrettModulus::new(97)),
            DOMAIN,
            1,
            |_, _| panic!()
        ),
        Err(LookupTableError::OutputModulusMismatch)
    ));
    assert!(matches!(
        context.compile_factorized_lookup_table_fn(
            &ScaledCodec::new(3, NativeModulus::new()),
            DOMAIN,
            1,
            |_, _| panic!()
        ),
        Err(LookupTableError::OddFactorizationScale)
    ));
}
