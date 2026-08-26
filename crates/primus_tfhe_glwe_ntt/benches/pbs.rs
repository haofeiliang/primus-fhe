// cargo bench -p primus_tfhe_glwe_ntt --bench pbs

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GlweCiphertext, NttGlweKeySwitchingContext};
use primus_lwe::LweCiphertext;
use primus_ntt::{NttTable, U32NttTable};
use primus_tfhe_glwe_ntt::{
    BooleanEncryptor, BooleanEvaluator, BooleanGate, NttGlweBlindRotationContext, PbsOrder,
    TfheContext, TfheParameters, boolean_parameters,
};

fn parameters_with_order(order: PbsOrder) -> TfheParameters<u32> {
    let parameters = boolean_parameters();
    let basis = parameters.glwe_key_switching().output().basis();
    let log_basis = basis.log_basis();
    let level_count = basis.decompose_length();
    TfheParameters::try_new(
        parameters.small_lwe().clone(),
        parameters.glwe().clone(),
        parameters.bootstrapping().clone(),
        ApproxSignedBasis::new(
            Some(parameters.glwe().cipher_modulus_value()),
            log_basis,
            Some(level_count),
        ),
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
    let parameters = parameters_with_order(order);
    let modulus = parameters.glwe().cipher_modulus();
    let poly_length = parameters.glwe().poly_length();
    let table = U32NttTable::new(poly_length.trailing_zeros(), modulus).unwrap();
    let context = TfheContext::try_new(parameters, table).unwrap();
    let mut rng = rand::rng();
    let (client_key, server_key) = context.generate_keys(&mut rng).unwrap();
    let parameters = context.parameters();
    let encryptor = context.encryptor(&client_key).unwrap();
    let input = encryptor.encrypt_padded(1u32, &mut rng).unwrap();
    let lookup_table = context.compile_lookup_table_slice(&[1u32, 0]).unwrap();
    let many_lookup_table = context
        .compile_many_lookup_table_fn(4, |input, output| match output {
            0 => input as u32,
            1 => (1 - input) as u32,
            2 => (input + 1) as u32,
            _ => 0,
        })
        .unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let mut output = input.clone();
    let mut many_outputs = vec![input.clone(); many_lookup_table.output_count()];

    let bootstrapping_domain = context.bootstrapping_domain();
    let mut blind_rotation = NttGlweBlindRotationContext::new(bootstrapping_domain.size());
    let key_switching_domain = context.key_switching_domain();
    let mut key_switching =
        NttGlweKeySwitchingContext::new(key_switching_domain.size().glwe_size());
    let mut main_glwe: GlweCiphertext<Vec<u32>> =
        GlweCiphertext::zero(parameters.glwe().glwe_len());
    let mut switched: GlweCiphertext<Vec<u32>> =
        GlweCiphertext::zero(parameters.glwe_key_switching().output().glwe_len());
    let mut small_lwe: LweCiphertext<u32> = LweCiphertext::zero(parameters.small_lwe().dimension());
    let mut external_lwe: LweCiphertext<u32> =
        LweCiphertext::zero(parameters.ciphertext_lwe_dimension());

    match order {
        PbsOrder::BootstrapKeyswitch => server_key
            .bootstrapping_key()
            .ntt_blind_rotate_lookup_table_to(
                input.as_lwe(),
                lookup_table.polynomial(),
                &mut main_glwe,
                &bootstrapping_domain,
                &mut blind_rotation,
            ),
        PbsOrder::KeyswitchBootstrap => {
            input
                .as_lwe()
                .inverse_extract_glwe_to(&mut main_glwe, poly_length, modulus)
        }
    }
    server_key.glwe_key_switching_key().key_switch_to(
        &main_glwe,
        &mut switched,
        &key_switching_domain,
        &mut key_switching,
    );
    switched.extract_compact_lwe_to(&mut small_lwe, poly_length, modulus);

    let boolean_encryptor = BooleanEncryptor::new(parameters, &client_key).unwrap();
    let boolean_lhs = boolean_encryptor.encrypt(true, &mut rng).unwrap();
    let boolean_rhs = boolean_encryptor.encrypt(false, &mut rng).unwrap();
    let mut boolean_output = boolean_lhs.clone();
    let pbs_evaluator = context.evaluator(&server_key).unwrap();
    let mut boolean_evaluator =
        BooleanEvaluator::try_new(context.parameters(), pbs_evaluator).unwrap();

    let glwe_dimension = parameters.glwe().dimension();
    let mut group = c.benchmark_group(format!(
        "tfhe_pbs/ntt/u32/{}/n{poly_length}/k{glwe_dimension}/small_lwe{}/external_lwe{}",
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
                    poly_length,
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
                &key_switching_domain,
                &mut key_switching,
            );
            black_box(&switched);
        });
    });
    group.bench_function("compact_sample_extraction", |b| {
        b.iter(|| {
            switched.extract_compact_lwe_to(black_box(&mut small_lwe), poly_length, modulus);
            black_box(&small_lwe);
        });
    });
    group.bench_function("blind_rotation", |b| {
        let blind_rotation_input = match order {
            PbsOrder::BootstrapKeyswitch => input.as_lwe(),
            PbsOrder::KeyswitchBootstrap => &small_lwe,
        };
        b.iter(|| {
            black_box(server_key.bootstrapping_key()).ntt_blind_rotate_lookup_table_to(
                black_box(blind_rotation_input),
                black_box(lookup_table.polynomial()),
                black_box(&mut main_glwe),
                &bootstrapping_domain,
                &mut blind_rotation,
            );
            black_box(&main_glwe);
        });
    });
    if order == PbsOrder::KeyswitchBootstrap {
        group.bench_function("full_sample_extraction", |b| {
            b.iter(|| {
                main_glwe.extract_lwe_to(black_box(&mut external_lwe), poly_length, modulus);
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
    group.bench_function("complete_pbs_many_4_reused_outputs", |b| {
        b.iter(|| {
            evaluator.apply_many_lookup_table_to(
                black_box(&input),
                black_box(&many_lookup_table),
                black_box(&mut many_outputs),
            );
            black_box(&many_outputs);
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
