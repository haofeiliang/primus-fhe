use std::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use primus_fhe_core::{
    NttRlweCiphertext, NttRlweSecretKey, PlaintextCodec, PlaintextEmbedding, RingSecretKeyType,
    RlweParameters, RlweSecretKey,
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;

const BATCH_LEN: usize = 4096;
const PLAIN_MODULUS: u64 = 12_289;
const CIPHER_MODULUS: u64 = 1_125_899_906_826_241;
const PLAIN_MODULUS_U32: u32 = 12_289;
const CIPHER_MODULUS_U32: u32 = 536_813_569;

fn ciphertext_values(q: u64) -> Vec<u64> {
    (0..BATCH_LEN)
        .map(|index| {
            ((index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0xd1b5_4a32_d192_ed03) % q
        })
        .collect()
}

fn message_values(t: u64) -> Vec<u64> {
    (0..BATCH_LEN).map(|index| index as u64 % t).collect()
}

fn ciphertext_values_u32(q: u32) -> Vec<u32> {
    (0..BATCH_LEN)
        .map(|index| ((index as u32).wrapping_mul(0x9e37_79b9) ^ 0xd1b5_4a32) % q)
        .collect()
}

fn message_values_u32(t: u32) -> Vec<u32> {
    (0..BATCH_LEN).map(|index| index as u32 % t).collect()
}

fn bench_plaintext_codec_u64(c: &mut Criterion) {
    let t = PLAIN_MODULUS;
    let q = CIPHER_MODULUS;
    let ciphertexts = ciphertext_values(q);
    let messages = message_values(t);
    let modulus = BarrettModulus::new(q);
    let params = RlweParameters::new(BATCH_LEN, t, modulus, RingSecretKeyType::Binary, 3.2);
    let scaled_codec = *params.plaintext_codec();
    let native_scaled_codec = PlaintextCodec::new(t, None);
    let mut encoded = vec![0u64; BATCH_LEN];
    let accumulator = ciphertext_values(q);

    let mut group = c.benchmark_group("plaintext_codec/u64");

    // ——— decode ———

    group.bench_with_input(
        BenchmarkId::new("decode_slice/scaled", BATCH_LEN),
        &ciphertexts,
        |b, ciphertexts| {
            b.iter_batched(
                || black_box(ciphertexts).clone(),
                |mut values| {
                    scaled_codec.decode_slice_inplace(&mut values);
                    black_box(values);
                },
                BatchSize::SmallInput,
            );
        },
    );

    group.bench_with_input(
        BenchmarkId::new("decode_slice/native_scaled", BATCH_LEN),
        &ciphertexts,
        |b, ciphertexts| {
            b.iter_batched(
                || black_box(ciphertexts).clone(),
                |mut values| {
                    native_scaled_codec.decode_slice_inplace(&mut values);
                    black_box(values);
                },
                BatchSize::SmallInput,
            );
        },
    );

    // ——— encode ———

    group.bench_function(BenchmarkId::new("encode_slice/scaled", BATCH_LEN), |b| {
        b.iter(|| {
            scaled_codec.encode_slice_to(
                black_box(&messages),
                black_box(&mut encoded),
                PlaintextEmbedding::Unsigned,
            );
            black_box(&encoded);
        });
    });

    group.bench_function(
        BenchmarkId::new("encode_slice/native_scaled", BATCH_LEN),
        |b| {
            b.iter(|| {
                native_scaled_codec.encode_slice_to(
                    black_box(&messages),
                    black_box(&mut encoded),
                    PlaintextEmbedding::Unsigned,
                );
                black_box(&encoded);
            });
        },
    );

    // ——— delta-factor ———

    group.bench_function(
        BenchmarkId::new("add_encode_delta_slice/centered", BATCH_LEN),
        |b| {
            b.iter_batched(
                || black_box(&accumulator).clone(),
                |mut acc| {
                    scaled_codec.add_encode_slice_assign_with_delta(
                        &mut acc,
                        black_box(&messages),
                        PlaintextEmbedding::Centered,
                    );
                    black_box(acc);
                },
                BatchSize::SmallInput,
            );
        },
    );

    group.finish();
}

fn bench_plaintext_codec_u32(c: &mut Criterion) {
    let t = PLAIN_MODULUS_U32;
    let q = CIPHER_MODULUS_U32;
    let ciphertexts = ciphertext_values_u32(q);
    let messages = message_values_u32(t);
    let modulus = BarrettModulus::new(q);
    let params = RlweParameters::new(BATCH_LEN, t, modulus, RingSecretKeyType::Binary, 3.2);
    let scaled_codec = *params.plaintext_codec();
    let mut encoded = vec![0u32; BATCH_LEN];

    let mut group = c.benchmark_group("plaintext_codec/u32");

    group.bench_with_input(
        BenchmarkId::new("decode_slice/scaled", BATCH_LEN),
        &ciphertexts,
        |b, ciphertexts| {
            b.iter_batched(
                || black_box(ciphertexts).clone(),
                |mut values| {
                    scaled_codec.decode_slice_inplace(&mut values);
                    black_box(values);
                },
                BatchSize::SmallInput,
            );
        },
    );

    group.bench_function(BenchmarkId::new("encode_slice/scaled", BATCH_LEN), |b| {
        b.iter(|| {
            scaled_codec.encode_slice_to(
                black_box(&messages),
                black_box(&mut encoded),
                PlaintextEmbedding::Unsigned,
            );
            black_box(&encoded);
        });
    });

    group.finish();
}

fn bench_rlwe_decrypt_arbitrary_modulus(c: &mut Criterion) {
    type Value = u64;
    let mut group = c.benchmark_group("rlwe_decrypt/arbitrary_modulus");
    let mut rng = rand::rng();

    for log_n in [12u32, 13] {
        let poly_length = 1usize << log_n;
        let cipher_modulus = BarrettModulus::new(CIPHER_MODULUS);
        let table = UintNttTable::new(log_n, cipher_modulus).unwrap();
        let params = RlweParameters::new(
            poly_length,
            PLAIN_MODULUS,
            cipher_modulus,
            RingSecretKeyType::Binary,
            3.2,
        );

        let secret_key = RlweSecretKey::generate(&params, &mut rng);
        let secret_key = NttRlweSecretKey::from_coeff_secret_key(&secret_key, &table);
        let message = Polynomial::new(
            (0..poly_length)
                .map(|index| index as Value % PLAIN_MODULUS)
                .collect::<Vec<_>>(),
        );
        let mut ciphertext: NttRlweCiphertext<Vec<Value>> =
            NttRlweCiphertext::zero(poly_length * 2);
        secret_key.encrypt_inplace(&message, &mut ciphertext, &params, &table, &mut rng);

        let decrypted = secret_key.decrypt(&ciphertext, &params, &table);
        assert_eq!(decrypted.as_ref(), message.as_ref());

        group.bench_with_input(
            BenchmarkId::new("decrypt", poly_length),
            &ciphertext,
            |b, ct| {
                b.iter(|| {
                    let decrypted = secret_key.decrypt(black_box(ct), black_box(&params), &table);
                    black_box(decrypted);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_plaintext_codec_u64,
    bench_plaintext_codec_u32,
    bench_rlwe_decrypt_arbitrary_modulus,
);
criterion_main!(benches);
