// cargo bench -p primus_tfhe_glwe_ntt --bench key_switch

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_fhe_core::{
    GlweCiphertext, GlweSecretKey, LweCiphertext, LweKeySwitchingKey, LweKeySwitchingParameters,
    NttGadgetEncryptContext, NttGlweKeySwitchingContext, NttGlweKeySwitchingKey, NttGlweSecretKey,
};
use primus_ntt::{NttTable, U32NttTable};
use primus_tfhe_glwe_ntt::boolean_parameters;

fn bench_key_switch(c: &mut Criterion) {
    let parameters = boolean_parameters();
    let modulus = parameters.glwe().cipher_modulus();
    let poly_length = parameters.glwe().poly_length();
    let input_glwe_dimension = parameters.glwe().dimension();
    let lwe_dimension = parameters.small_lwe().dimension();
    let table = U32NttTable::new(poly_length.trailing_zeros(), modulus).unwrap();
    let mut rng = rand::rng();

    let lwe_secret_key = primus_fhe_core::LweSecretKey::generate(parameters.small_lwe(), &mut rng);
    let input_glwe_secret_key = GlweSecretKey::generate(parameters.glwe(), &mut rng);

    let lwe_key_switching_parameters = LweKeySwitchingParameters::new(
        parameters.glwe().secret_key_len(),
        lwe_dimension,
        parameters.glwe_key_switching().output().basis().clone(),
    );
    let lwe_key_switching_key = LweKeySwitchingKey::generate(
        input_glwe_secret_key.as_slice(),
        &lwe_secret_key,
        parameters.small_lwe(),
        &lwe_key_switching_parameters,
        &mut rng,
    );

    let padded_glwe_secret_key =
        GlweSecretKey::from_padded_lwe(&lwe_secret_key, poly_length).unwrap();
    let output_glwe_dimension = padded_glwe_secret_key.dimension();
    let output_ntt_secret_key =
        NttGlweSecretKey::from_coeff_secret_key(&padded_glwe_secret_key, &table);

    let glwe_key_switching_parameters = parameters.glwe_key_switching();
    let mut gadget_context = NttGadgetEncryptContext::new(
        poly_length,
        glwe_key_switching_parameters.output().decompose_length(),
    );
    let glwe_key_switching_key = NttGlweKeySwitchingKey::generate(
        &input_glwe_secret_key,
        &output_ntt_secret_key,
        glwe_key_switching_parameters,
        &table,
        &mut rng,
        &mut gadget_context,
    );

    let input_ntt_secret_key =
        NttGlweSecretKey::from_coeff_secret_key(&input_glwe_secret_key, &table);
    let input = input_ntt_secret_key
        .encrypt_zeros(parameters.glwe(), &table, &mut rng)
        .into_coeff_form(&table);
    let mut extracted = LweCiphertext::zero(parameters.glwe().secret_key_len());
    input.extract_lwe_to(&mut extracted, poly_length, modulus);

    let mut lwe_output = LweCiphertext::zero(lwe_dimension);
    let mut glwe_output: GlweCiphertext<Vec<u32>> =
        GlweCiphertext::zero(glwe_key_switching_parameters.output().glwe_len());
    let mut glwe_context = NttGlweKeySwitchingContext::new(output_glwe_dimension, poly_length);

    let mut group = c.benchmark_group(format!(
        "tfhe_key_switch/ntt/u32/n{poly_length}/k{input_glwe_dimension}/lwe{lwe_dimension}"
    ));
    group.sample_size(10);
    group.bench_function("lwe_kN_to_n", |b| {
        b.iter(|| {
            lwe_key_switching_key.key_switch_to(
                black_box(&extracted),
                black_box(&mut lwe_output),
                modulus,
            );
            black_box(&lwe_output);
        });
    });
    group.bench_function("glwe_k_to_k_prime", |b| {
        b.iter(|| {
            glwe_key_switching_key.key_switch_to(
                black_box(&input),
                black_box(&mut glwe_output),
                glwe_key_switching_parameters,
                &table,
                &mut glwe_context,
            );
            black_box(&glwe_output);
        });
    });
    group.finish();
}

criterion_group!(benches, bench_key_switch);
criterion_main!(benches);
