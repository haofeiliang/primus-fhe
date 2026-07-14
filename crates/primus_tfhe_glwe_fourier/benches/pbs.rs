// cargo bench -p primus_tfhe_glwe_fourier --bench pbs

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, RustFftTable};
use primus_fhe_core::{
    FourierBlindRotationContext, GgswParameters, GlweCiphertext, GlweParameters, LweCiphertext,
    LweParameters, LweSecretKeyType, RingSecretKeyType, fourier_blind_rotate_to,
};
use primus_modulus::NativeModulus;
use primus_tfhe_glwe_fourier::{Encryptor, Evaluator, KeyGenerator, TfheContext, TfheParameters};

// Performance-comparison profile, not a security recommendation.
const LWE_DIMENSION: usize = 256;
const GLWE_DIMENSION: usize = 1;
const POLY_LENGTH: usize = 1024;
const PLAINTEXT_MODULUS: u32 = 4;

fn parameters() -> TfheParameters<u32> {
    let lwe = LweParameters::new(
        LWE_DIMENSION,
        PLAINTEXT_MODULUS,
        NativeModulus::new(),
        LweSecretKeyType::Binary,
        3.2,
    );
    let glwe = GlweParameters::new(
        GLWE_DIMENSION,
        POLY_LENGTH,
        PLAINTEXT_MODULUS,
        NativeModulus::new(),
        RingSecretKeyType::Binary,
        3.2,
    );
    let bootstrapping =
        GgswParameters::with_glwe_params(&glwe, ApproxSignedBasis::new(None, 8, Some(3)));
    TfheParameters::with_key_switching_basis(
        lwe,
        bootstrapping,
        ApproxSignedBasis::new(None, 4, Some(4)),
    )
    .unwrap()
}

fn bench_pbs(c: &mut Criterion) {
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let context = TfheContext::try_new(parameters(), table).unwrap();
    let mut rng = rand::rng();
    let mut key_generator = KeyGenerator::new(&context);
    let (client_key, server_key) = key_generator.generate(&mut rng).unwrap();
    let encryptor = Encryptor::with_client_key(context.parameters(), &client_key).unwrap();
    let input = encryptor.encrypt_padded(1u32, &mut rng).unwrap();
    let lookup_table = context.compile_lookup_table_slice(&[1u32, 0]).unwrap();
    let mut evaluator = Evaluator::try_new(&context, &server_key).unwrap();
    let mut output = input.clone();
    let parameters = context.parameters();
    let mut fft = context.new_fft_engine();
    let mut blind_rotation = FourierBlindRotationContext::new(GLWE_DIMENSION, POLY_LENGTH);
    let mut rotated: GlweCiphertext<Vec<u32>> = GlweCiphertext::zero(parameters.glwe().glwe_len());
    fourier_blind_rotate_to(
        input.as_lwe(),
        lookup_table.accumulator(),
        &mut rotated,
        server_key.bootstrapping_key(),
        parameters.lwe(),
        parameters.bootstrapping(),
        &mut fft,
        &mut blind_rotation,
    );
    let mut extracted: LweCiphertext<u32> = LweCiphertext::zero(parameters.glwe().secret_key_len());
    rotated.extract_lwe_to(
        &mut extracted,
        POLY_LENGTH,
        parameters.glwe().cipher_modulus(),
    );
    let mut switched: LweCiphertext<u32> = LweCiphertext::zero(parameters.lwe().dimension());

    let mut group = c.benchmark_group("tfhe_pbs/fourier/u32/n1024/k1/lwe256");
    group.sample_size(10);
    group.bench_function("blind_rotation", |b| {
        b.iter(|| {
            fourier_blind_rotate_to(
                black_box(input.as_lwe()),
                black_box(lookup_table.accumulator()),
                black_box(&mut rotated),
                black_box(server_key.bootstrapping_key()),
                parameters.lwe(),
                parameters.bootstrapping(),
                &mut fft,
                &mut blind_rotation,
            );
            black_box(&rotated);
        });
    });
    group.bench_function("sample_extraction", |b| {
        b.iter(|| {
            rotated.extract_lwe_to(
                black_box(&mut extracted),
                POLY_LENGTH,
                parameters.glwe().cipher_modulus(),
            );
            black_box(&extracted);
        });
    });
    group.bench_function("key_switching", |b| {
        b.iter(|| {
            server_key.key_switching_key().key_switch_to(
                black_box(&extracted),
                black_box(&mut switched),
                parameters.lwe().cipher_modulus(),
            );
            black_box(&switched);
        });
    });
    group.bench_function("complete_pbs_reused_output", |b| {
        b.iter(|| {
            evaluator
                .apply_lookup_table_to(
                    black_box(&input),
                    black_box(&lookup_table),
                    black_box(&mut output),
                )
                .unwrap();
            black_box(&output);
        });
    });
    group.bench_function("complete_pbs_allocating", |b| {
        b.iter(|| {
            black_box(
                evaluator
                    .apply_lookup_table(black_box(&input), black_box(&lookup_table))
                    .unwrap(),
            );
        });
    });
    group.finish();
}

criterion_group!(benches, bench_pbs);
criterion_main!(benches);
