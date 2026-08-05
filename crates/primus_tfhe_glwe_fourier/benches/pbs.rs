// cargo bench -p primus_tfhe_glwe_fourier --bench pbs

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, RustFftTable};
use primus_glwe::{
    FourierGlweKeySwitchingContext, GgswParameters, GlweCiphertext, GlweParameters, SecretKeyDistr,
};
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::NativeModulus;
use primus_tfhe_glwe_fourier::{
    BooleanEncryptor, BooleanEvaluator, BooleanGate, FourierBlindRotationContext, PbsOrder,
    TfheContext, TfheParameters,
};

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
        SecretKeyDistr::Binary,
        3.2,
    );
    let glwe = GlweParameters::new(
        GLWE_DIMENSION,
        POLY_LENGTH,
        PLAINTEXT_MODULUS,
        NativeModulus::new(),
        SecretKeyDistr::Binary,
        3.2,
    );
    let bootstrapping = GgswParameters::with_glwe_params(&glwe, 8, Some(3));
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

fn bench_order(c: &mut Criterion, order: PbsOrder) {
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let context = TfheContext::try_new(parameters(order), table).unwrap();
    let mut rng = rand::rng();
    let (client_key, server_key) = context.generate_keys(&mut rng).unwrap();
    let parameters = context.parameters();
    let encryptor = context.encryptor(&client_key).unwrap();
    let input = encryptor.encrypt_padded(1u32, &mut rng).unwrap();
    let lookup_table = context.compile_lookup_table_slice(&[1u32, 0]).unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let mut output = input.clone();

    let modulus = parameters.glwe().cipher_modulus();
    let mut fft = context.new_fft_engine();
    let bootstrapping = parameters.bootstrapping();
    let mut blind_rotation = FourierBlindRotationContext::new(bootstrapping.size());
    let key_switching_parameters = parameters.glwe_key_switching().output();
    let mut key_switching =
        FourierGlweKeySwitchingContext::new(key_switching_parameters.glwe_size());
    let mut main_glwe: GlweCiphertext<Vec<u32>> =
        GlweCiphertext::zero(parameters.glwe().glwe_len());
    let mut switched: GlweCiphertext<Vec<u32>> =
        GlweCiphertext::zero(parameters.glwe_key_switching().output().glwe_len());
    let mut small_lwe: LweCiphertext<u32> = LweCiphertext::zero(parameters.small_lwe().dimension());
    let mut external_lwe: LweCiphertext<u32> =
        LweCiphertext::zero(parameters.ciphertext_lwe_dimension());

    match order {
        PbsOrder::BootstrapKeyswitch => server_key.bootstrapping_key().fourier_blind_rotate_to(
            input.as_lwe(),
            lookup_table.accumulator(),
            &mut main_glwe,
            bootstrapping,
            &mut fft,
            &mut blind_rotation,
        ),
        PbsOrder::KeyswitchBootstrap => {
            input
                .as_lwe()
                .inverse_extract_glwe_to(&mut main_glwe, POLY_LENGTH, modulus)
        }
    }
    server_key.glwe_key_switching_key().key_switch_to(
        &main_glwe,
        &mut switched,
        key_switching_parameters,
        &mut fft,
        &mut key_switching,
    );
    switched.extract_compact_lwe_to(&mut small_lwe, POLY_LENGTH, modulus);

    let boolean_encryptor = BooleanEncryptor::new(parameters, &client_key).unwrap();
    let boolean_lhs = boolean_encryptor.encrypt(true, &mut rng).unwrap();
    let boolean_rhs = boolean_encryptor.encrypt(false, &mut rng).unwrap();
    let mut boolean_output = boolean_lhs.clone();
    let pbs_evaluator = context.evaluator(&server_key).unwrap();
    let mut boolean_evaluator =
        BooleanEvaluator::try_new(context.parameters(), pbs_evaluator).unwrap();

    let mut group = c.benchmark_group(format!(
        "tfhe_pbs/fourier/u32/{}/n{POLY_LENGTH}/k{GLWE_DIMENSION}/small_lwe{}/external_lwe{}",
        order_name(order),
        parameters.small_lwe().dimension(),
        parameters.ciphertext_lwe_dimension(),
    ));
    group.sample_size(10);

    if order == PbsOrder::KeyswitchBootstrap {
        group.bench_function("inverse_sample_extraction", |b| {
            b.iter(|| {
                input.as_lwe().inverse_extract_glwe_to(
                    black_box(&mut main_glwe),
                    POLY_LENGTH,
                    modulus,
                );
                black_box(&main_glwe);
            });
        });
    }

    group.bench_function("glwe_key_switching", |b| {
        b.iter(|| {
            server_key.glwe_key_switching_key().key_switch_to(
                black_box(&main_glwe),
                black_box(&mut switched),
                key_switching_parameters,
                &mut fft,
                &mut key_switching,
            );
            black_box(&switched);
        });
    });
    group.bench_function("compact_sample_extraction", |b| {
        b.iter(|| {
            switched.extract_compact_lwe_to(black_box(&mut small_lwe), POLY_LENGTH, modulus);
            black_box(&small_lwe);
        });
    });
    group.bench_function("blind_rotation", |b| {
        let blind_rotation_input = match order {
            PbsOrder::BootstrapKeyswitch => input.as_lwe(),
            PbsOrder::KeyswitchBootstrap => &small_lwe,
        };
        b.iter(|| {
            black_box(server_key.bootstrapping_key()).fourier_blind_rotate_to(
                black_box(blind_rotation_input),
                black_box(lookup_table.accumulator()),
                black_box(&mut main_glwe),
                bootstrapping,
                &mut fft,
                &mut blind_rotation,
            );
            black_box(&main_glwe);
        });
    });

    if order == PbsOrder::KeyswitchBootstrap {
        group.bench_function("full_sample_extraction", |b| {
            b.iter(|| {
                main_glwe.extract_lwe_to(black_box(&mut external_lwe), POLY_LENGTH, modulus);
                black_box(&external_lwe);
            });
        });
    }

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
    group.bench_function("complete_pbs_allocating", |b| {
        b.iter(|| {
            black_box(evaluator.apply_lookup_table(black_box(&input), black_box(&lookup_table)));
        });
    });
    for gate in [
        BooleanGate::And,
        BooleanGate::Nand,
        BooleanGate::Or,
        BooleanGate::Nor,
        BooleanGate::Xor,
        BooleanGate::Xnor,
    ] {
        group.bench_function(format!("boolean_{gate:?}").to_lowercase(), |b| {
            b.iter(|| {
                boolean_evaluator.evaluate_binary_to(
                    gate,
                    black_box(&boolean_lhs),
                    black_box(&boolean_rhs),
                    black_box(&mut boolean_output),
                );
                black_box(&boolean_output);
            });
        });
    }
    group.bench_function("boolean_not", |b| {
        b.iter(|| {
            boolean_evaluator.not_to(black_box(&boolean_lhs), black_box(&mut boolean_output));
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
    group.finish();
}

fn bench_pbs(c: &mut Criterion) {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        bench_order(c, order);
    }
}

criterion_group!(benches, bench_pbs);
criterion_main!(benches);
