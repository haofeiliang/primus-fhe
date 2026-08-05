use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_lwe::{LweCiphertext, LweParameters, LweSecretKey, SecretKeyDistr};
use primus_modulus::NativeModulus;

fn bench_encrypt(c: &mut Criterion) {
    type V = u16;

    let dimension = 512;
    let mod_t: NativeModulus<V> = NativeModulus::new();

    let mut rng = rand::rng();

    let params = LweParameters::new(dimension, 2, mod_t, SecretKeyDistr::Binary, 16.0);

    let sk = LweSecretKey::generate(&params, &mut rng);

    let mut cipher = vec![LweCiphertext::zero(dimension); 100_0000];

    c.bench_function(&format!("lwe encrypt dim:{}", dimension), |b| {
        b.iter(|| {
            black_box(&mut cipher).iter_mut().for_each(|c| {
                *c = sk.encrypt(black_box(1), &params, &mut rng);
            });
        })
    });

    c.bench_function(&format!("lwe decrypt dim:{}", dimension), |b| {
        b.iter(|| {
            black_box(&cipher).iter().for_each(|c| {
                let _msg: u8 = sk.decrypt(c, &params);
            });
        })
    });
}

criterion_group!(benches, bench_encrypt);
criterion_main!(benches);
