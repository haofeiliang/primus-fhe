//! PBS stages and complete evaluations with precomputed keys and reusable scratch.
//! Outputs and scratch are reused; setup is not timed.
//!
//! cargo bench -p primus_tfhe_glwe_fourier --bench pbs

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, RustFftTable, TfheFftTable};
use primus_glwe::{FourierGlweKeySwitchingContext, GlweCiphertext, GlweParameters, SecretKeyDistr};
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::NativeModulus;
use primus_tfhe_glwe_fourier::{
    BooleanGate, BootstrappingKey, FourierGlweBlindRotationContext, PbsOrder, TfheContext,
    TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

// Performance-comparison profile, not a security recommendation.
const LWE_DIMENSION: usize = 512;
const GLWE_DIMENSION: usize = 1;
const POLY_LENGTH: usize = 1024;
const PLAINTEXT_MODULUS: u32 = 4;

fn parameters(order: PbsOrder) -> TfheParameters<u32> {
    let lwe = LweParameters::new(
        LWE_DIMENSION,
        PLAINTEXT_MODULUS,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        3.2,
    );
    let glwe = GlweParameters::new(
        GLWE_DIMENSION,
        POLY_LENGTH,
        PLAINTEXT_MODULUS,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        3.2,
    );
    let bootstrapping = ApproxSignedBasis::new(glwe.cipher_modulus_value(), 8, Some(3));
    TfheParameters::try_new(
        lwe,
        glwe,
        bootstrapping,
        ApproxSignedBasis::new(None, 2, Some(13)),
        order,
    )
    .unwrap()
}

fn order_name(order: PbsOrder) -> &'static str {
    match order {
        PbsOrder::BootstrapKeyswitch => "bootstrap_keyswitch",
        PbsOrder::KeyswitchBootstrap => "keyswitch_bootstrap",
    }
}

fn bench_order<Table: FftTable>(c: &mut Criterion, order: PbsOrder, backend: &str) {
    let table = Table::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let context = TfheContext::try_new(parameters(order), table).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context.try_generate_keys(None, &mut rng).unwrap();
    let BootstrappingKey::Classic(bootstrapping_key) = server_key.bootstrapping_key() else {
        panic!("classic benchmark requires a classic key");
    };
    let parameters = context.parameters();
    let encryptor = context.encryptor(&client_key).unwrap();
    let input = encryptor.encrypt_padded(1u32, &mut rng).unwrap();
    let lookup_table = context
        .parameters()
        .compile_lookup_table_slice(context.parameters().input_plaintext_codec(), &[1u32, 0])
        .unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let mut output = input.clone();

    let modulus = parameters.accumulator_glwe().cipher_modulus();
    let mut fft = context.new_fft_engine();
    let mut blind_rotation = FourierGlweBlindRotationContext::new(bootstrapping_key);
    let key_switching_parameters = parameters.glwe_key_switching().output();
    let mut key_switching =
        FourierGlweKeySwitchingContext::new(key_switching_parameters.glwe_size());
    let mut main_glwe: GlweCiphertext<Vec<u32>> =
        GlweCiphertext::zero(parameters.accumulator_glwe().glwe_len());
    let mut switched: GlweCiphertext<Vec<u32>> =
        GlweCiphertext::zero(parameters.glwe_key_switching().output().glwe_len());
    let mut small_lwe: LweCiphertext<u32> = LweCiphertext::zero(parameters.small_lwe().dimension());

    match order {
        PbsOrder::BootstrapKeyswitch => bootstrapping_key.fourier_blind_rotate_lookup_table_to(
            &input,
            lookup_table.polynomial(),
            &mut main_glwe,
            &mut fft,
            &mut blind_rotation,
        ),
        PbsOrder::KeyswitchBootstrap => {
            input.inverse_extract_glwe_to(&mut main_glwe, POLY_LENGTH, modulus)
        }
    }
    server_key.glwe_key_switching_key().key_switch_to(
        &main_glwe,
        &mut switched,
        &mut fft,
        &mut key_switching,
    );
    switched.extract_compact_lwe_to(&mut small_lwe, POLY_LENGTH, modulus);

    let boolean_encryptor = context.boolean_encryptor(&client_key).unwrap();
    let boolean_lhs = boolean_encryptor.encrypt(true, &mut rng).unwrap();
    let boolean_rhs = boolean_encryptor.encrypt(false, &mut rng).unwrap();
    let mut boolean_output = boolean_lhs.clone();
    let mut boolean_evaluator = context.boolean_evaluator(&server_key).unwrap();

    let mut group = c.benchmark_group(format!(
        "tfhe_pbs/fourier/{backend}/u32/{}/n{POLY_LENGTH}/k{GLWE_DIMENSION}/small_lwe{}/external_lwe{}",
        order_name(order),
        parameters.small_lwe().dimension(),
        parameters.external_lwe_dimension(),
    ));
    group.sample_size(10);

    group.bench_function("glwe_key_switching", |b| {
        b.iter(|| {
            server_key.glwe_key_switching_key().key_switch_to(
                black_box(&main_glwe),
                black_box(&mut switched),
                &mut fft,
                &mut key_switching,
            );
            black_box(&switched);
        });
    });
    group.bench_function("blind_rotation", |b| {
        let blind_rotation_input = match order {
            PbsOrder::BootstrapKeyswitch => &input,
            PbsOrder::KeyswitchBootstrap => &small_lwe,
        };
        b.iter(|| {
            black_box(bootstrapping_key).fourier_blind_rotate_lookup_table_to(
                black_box(blind_rotation_input),
                black_box(lookup_table.polynomial()),
                black_box(&mut main_glwe),
                &mut fft,
                &mut blind_rotation,
            );
            black_box(&main_glwe);
        });
    });
    group.bench_function("complete_pbs_reused_output", |b| {
        b.iter(|| {
            evaluator.apply_lookup_table_to(
                black_box(&input),
                black_box(&lookup_table),
                black_box(&mut output),
            );
            black_box(&output);
        });
    });
    // One PBS for a binary gate; two PBS calls for MUX.
    group.bench_function("boolean_and", |b| {
        b.iter(|| {
            boolean_evaluator.evaluate_binary_to(
                BooleanGate::And,
                black_box(&boolean_lhs),
                black_box(&boolean_rhs),
                black_box(&mut boolean_output),
            );
            black_box(&boolean_output);
        });
    });
    group.bench_function("boolean_mux", |b| {
        b.iter(|| {
            boolean_evaluator.mux_to(
                black_box(&boolean_lhs),
                black_box(&boolean_lhs),
                black_box(&boolean_rhs),
                black_box(&mut boolean_output),
            );
            black_box(&boolean_output);
        });
    });
    // Each iteration produces the same 3/4 function outputs. Compare shared
    // BR/KS against separate PBS calls; k=3 also exercises a padded fourth slot.
    // All tables, keys and outputs are reused.
    for count in [3, 4] {
        let value = |input: usize, output| ((input + output) % 4) as u32;
        let many = context
            .parameters()
            .compile_interleaved_lookup_table_fn(
                context.parameters().input_plaintext_codec(),
                count,
                value,
            )
            .unwrap();
        let singles: Vec<_> = (0..count)
            .map(|output| {
                context
                    .parameters()
                    .compile_lookup_table_fn(
                        context.parameters().input_plaintext_codec(),
                        |input| value(input, output),
                    )
                    .unwrap()
            })
            .collect();
        let mut outputs = vec![input.clone(); count];
        for shared in [false, true] {
            let kind = if shared { "many" } else { "separate" };
            group.bench_function(format!("complete_pbs_{kind}_{count}_reused_outputs"), |b| {
                b.iter(|| {
                    if shared {
                        evaluator.apply_interleaved_lookup_table_to(
                            black_box(&input),
                            black_box(&many),
                            black_box(&mut outputs),
                        );
                    } else {
                        for (table, output) in singles.iter().zip(&mut outputs) {
                            evaluator.apply_lookup_table_to(
                                black_box(&input),
                                black_box(table),
                                black_box(output),
                            );
                        }
                    }
                    black_box(&outputs);
                });
            });
        }
    }
    group.finish();
}

fn bench_pbs(c: &mut Criterion) {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        bench_order::<RustFftTable>(c, order, "rustfft");
        bench_order::<TfheFftTable>(c, order, "tfhe");
    }
}

criterion_group!(benches, bench_pbs);
criterion_main!(benches);
