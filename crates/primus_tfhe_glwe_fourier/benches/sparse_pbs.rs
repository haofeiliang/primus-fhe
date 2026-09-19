//! Complete classic/sparse PBS with the same fixed-weight client secret.
//! Experimental Native u32 cost profile: n/h/N = 728/32/1024, c=3, buckets=2h.
//! PBS includes key switching and extraction, reusing keys, LUTs, four encrypted
//! inputs, evaluator and outputs. Keygen includes BSK + KSK and excludes the client
//! and FFT table as well as key destruction. Both orders generate the same key layout.
//!
//! cargo bench -p primus_tfhe_glwe_fourier --bench sparse_pbs
//! cargo +nightly bench -p primus_tfhe_glwe_fourier --bench sparse_pbs --features simd

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::RoundedCodec;
use primus_fft::{FftTable, RustFftTable, TfheFftTable};
use primus_glwe::{GlweParameters, SecretKeyDistr};
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::NativeModulus;
use primus_tfhe_glwe_fourier::{ClientKey, KeyGenerator, PbsOrder, TfheContext, TfheParameters};
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 1024;
const DIMENSION: usize = 728;
const WEIGHT: usize = 32;

fn context<Table: FftTable>(order: PbsOrder) -> TfheContext<u32, Table> {
    let modulus = NativeModulus::new();
    let lwe = LweParameters::new(
        DIMENSION,
        8,
        modulus,
        SecretKeyDistr::fixed_hamming_weight_binary(DIMENSION, WEIGHT),
        3.2 * 4294967296.0 / 16384.0,
    );
    let glwe = GlweParameters::new(1, N, 8, modulus, SecretKeyDistr::SparseTernary, 6.4);
    let parameters = TfheParameters::try_new(
        lwe,
        glwe,
        ApproxSignedBasis::new(None, 8, Some(3)),
        ApproxSignedBasis::new(None, 2, Some(13)),
        order,
    )
    .unwrap();
    TfheContext::try_from_parameters(parameters).unwrap()
}

fn bench_backend<Table: FftTable>(c: &mut Criterion, backend: &str) {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let context = context::<Table>(order);
        let mut rng = StdRng::seed_from_u64(0x5035_4252 + DIMENSION as u64);
        let mut generator = KeyGenerator::new(&context);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        let classic = generator
            .try_generate_server_key(&client, None, &mut rng)
            .unwrap();
        let sparse = generator
            .try_generate_sparse_server_key(&client, 3, 2 * WEIGHT, &mut rng)
            .unwrap();
        let encryptor = context.encryptor(&client).unwrap();
        let decryptor = context.decryptor(&client).unwrap();
        let inputs: Vec<_> = (0..4)
            .map(|m| encryptor.encrypt_padded(m, &mut rng).unwrap())
            .collect();
        let codec = RoundedCodec::new(8, NativeModulus::new());
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

        let mut group = c.benchmark_group(format!(
            "sparse_pbs/{backend}/n{DIMENSION}/h{WEIGHT}/N{N}/{order:?}"
        ));
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
            let mut group = c.benchmark_group(format!(
                "sparse_keygen/{backend}/n{DIMENSION}/h{WEIGHT}/N{N}"
            ));
            group.sample_size(10);
            for sparse in [false, true] {
                group.bench_function(if sparse { "sparse" } else { "classic" }, |b| {
                    b.iter_batched(
                        || (),
                        |()| {
                            if sparse {
                                generator
                                    .try_generate_sparse_server_key(
                                        black_box(&client),
                                        3,
                                        2 * WEIGHT,
                                        &mut rng,
                                    )
                                    .unwrap()
                            } else {
                                generator
                                    .try_generate_server_key(black_box(&client), None, &mut rng)
                                    .unwrap()
                            }
                        },
                        BatchSize::PerIteration,
                    )
                });
            }
            group.finish();
        }
    }
}

fn bench_sparse(c: &mut Criterion) {
    bench_backend::<RustFftTable>(c, "rustfft");
    bench_backend::<TfheFftTable>(c, "tfhe_fft");
}

criterion_group!(benches, bench_sparse);
criterion_main!(benches);
