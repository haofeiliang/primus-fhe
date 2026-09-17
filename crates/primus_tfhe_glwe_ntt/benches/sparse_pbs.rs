//! Complete classic/sparse PBS with the same fixed-weight client secret.
//! Experimental cost profile: n/h/N = 728/32/1024, c=3, buckets=2h.
//! PBS includes key switching and extraction, reusing keys, LUTs, four encrypted
//! inputs, evaluator and outputs. Keygen includes BSK + KSK and excludes the client
//! and NTT table; both orders use the same key-generation algorithm.
//!
//! cargo bench -p primus_tfhe_glwe_ntt --bench sparse_pbs

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::RoundedCodec;
use primus_glwe::{GlweParameters, SecretKeyDistr};
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable};
use primus_tfhe_glwe_ntt::{ClientKey, KeyGenerator, PbsOrder, TfheContext, TfheParameters};
use rand::{SeedableRng, rngs::StdRng};

const Q: u32 = 132_120_577;
const N: usize = 1024;
const DIMENSION: usize = 728;
const WEIGHT: usize = 32;

fn context(order: PbsOrder) -> TfheContext<u32, U32NttTable> {
    let modulus = BarrettModulus::new(Q);
    let lwe = LweParameters::new(
        DIMENSION,
        8,
        modulus,
        SecretKeyDistr::fixed_hamming_weight_binary(DIMENSION, WEIGHT),
        3.2 * f64::from(Q) / 16384.0,
    );
    let glwe = GlweParameters::new(1, N, 8, modulus, SecretKeyDistr::SparseTernary, 6.4);
    let parameters = TfheParameters::try_new(
        lwe,
        glwe,
        ApproxSignedBasis::new(Some(Q), 7, Some(3)),
        ApproxSignedBasis::new(Some(Q), 2, Some(13)),
        order,
    )
    .unwrap();
    let ntt = U32NttTable::new(N.trailing_zeros(), modulus).unwrap();
    TfheContext::try_new(parameters, ntt).unwrap()
}

fn bench_sparse(c: &mut Criterion) {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let context = context(order);
        let mut rng = StdRng::seed_from_u64(0x5035_4252 + DIMENSION as u64);
        let mut generator = KeyGenerator::new(&context);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        let classic = generator
            .try_generate_server_key(&client, &mut rng)
            .unwrap();
        let sparse = generator
            .try_generate_sparse_server_key(&client, 3, 2 * WEIGHT, &mut rng)
            .unwrap();
        let encryptor = context.encryptor(&client).unwrap();
        let decryptor = context.decryptor(&client).unwrap();
        let inputs: Vec<_> = (0..4)
            .map(|m| encryptor.encrypt_padded(m, &mut rng).unwrap())
            .collect();
        let codec = RoundedCodec::new(8, BarrettModulus::new(Q));
        let single = context
            .parameters()
            .compile_lookup_table_fn(&codec, |m| (3 * m as u32 + 1) % 8)
            .unwrap();
        let many = context
            .parameters()
            .compile_interleaved_lookup_table_fn(&codec, 3, |m, i| ((m + 2 * i) % 8) as u32)
            .unwrap();
        let dimension = context.parameters().external_lwe_dimension();
        let mut outputs = vec![LweCiphertext::zero(dimension); 3];
        let mut group =
            c.benchmark_group(format!("sparse_pbs/n{DIMENSION}/h{WEIGHT}/N{N}/{order:?}"));
        group.sample_size(30);
        for (name, key) in [("classic", &classic), ("sparse", &sparse)] {
            let mut evaluator = context.evaluator(key).unwrap();
            // Verify the exact inputs and output scales timed below.
            for (m, input) in inputs.iter().enumerate() {
                evaluator.apply_lookup_table_to(input, &single, &mut outputs[0]);
                assert_eq!(
                    decryptor.decrypt(&outputs[0]).unwrap(),
                    (3 * m as u32 + 1) % 8
                );
                evaluator.apply_interleaved_lookup_table_to(input, &many, &mut outputs);
                for (i, output) in outputs.iter().enumerate() {
                    assert_eq!(decryptor.decrypt(output).unwrap(), ((m + 2 * i) % 8) as u32);
                }
            }
            for interleaved in [false, true] {
                let layout = if interleaved {
                    "interleaved3"
                } else {
                    "single"
                };
                let mut next_input = 0;
                group.bench_function(format!("{name}/{layout}"), |b| {
                    b.iter(|| {
                        let input = black_box(&inputs[next_input]);
                        next_input = (next_input + 1) % inputs.len();
                        if interleaved {
                            evaluator.apply_interleaved_lookup_table_to(
                                input,
                                black_box(&many),
                                &mut outputs,
                            );
                        } else {
                            evaluator.apply_lookup_table_to(
                                input,
                                black_box(&single),
                                &mut outputs[0],
                            );
                        }
                        black_box(&outputs);
                    })
                });
            }
        }
        group.finish();
        if order == PbsOrder::BootstrapKeyswitch {
            let mut group = c.benchmark_group(format!("sparse_keygen/n{DIMENSION}/h{WEIGHT}/N{N}"));
            group.sample_size(10);
            group.bench_function("classic", |b| {
                b.iter(|| {
                    black_box(
                        generator
                            .try_generate_server_key(black_box(&client), &mut rng)
                            .unwrap(),
                    )
                })
            });
            group.bench_function("sparse", |b| {
                b.iter(|| {
                    black_box(
                        generator
                            .try_generate_sparse_server_key(
                                black_box(&client),
                                3,
                                2 * WEIGHT,
                                &mut rng,
                            )
                            .unwrap(),
                    )
                })
            });
            group.finish();
        }
    }
}
criterion_group!(benches, bench_sparse);
criterion_main!(benches);
