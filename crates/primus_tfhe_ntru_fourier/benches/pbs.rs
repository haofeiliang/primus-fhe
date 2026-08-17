// cargo bench -p primus_tfhe_ntru_fourier --bench pbs

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_fft::{FftTable, RustFftTable};
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_tfhe_ntru_fourier::{NtruTfheParameters, TfheContext};

fn pbs(c: &mut Criterion) {
    const N: usize = 1024;
    const LWE_DIMENSION: usize = 800;
    let modulus = NativeModulus::new();
    let external_lwe = LweParameters::new(
        LWE_DIMENSION,
        4,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let accumulator = NtruParameters::new(N, 4, modulus, SecretKeyDistr::SparseTernary, 0.7);
    let client = NtruParameters::new(N, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let parameters = NtruTfheParameters::try_new(
        external_lwe,
        NlevParameters::with_ntru_params(&accumulator, 9, None),
        NlevParameters::with_ntru_params(&client, 9, None),
    )
    .unwrap();
    let table = RustFftTable::new(N.trailing_zeros()).unwrap();
    let context = TfheContext::try_new(parameters, table).unwrap();
    let mut rng = rand::rng();
    let (client_key, server_key) = context.generate_keys(&mut rng).unwrap();
    let encryptor = context.encryptor(&client_key).unwrap();
    let input = encryptor.encrypt_padded(1u32, &mut rng).unwrap();
    let lut = context.compile_lookup_table_slice(&[1u32, 0]).unwrap();
    let mut output = input.clone();
    let mut evaluator = context.evaluator(&server_key).unwrap();

    c.bench_function("ntru_fourier/pbs", |bencher| {
        bencher.iter(|| {
            evaluator.apply_lookup_table_to(
                black_box(&input),
                black_box(&lut),
                black_box(&mut output),
            );
        });
    });
}

criterion_group!(benches, pbs);
criterion_main!(benches);
