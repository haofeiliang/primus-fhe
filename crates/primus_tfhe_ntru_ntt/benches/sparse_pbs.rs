//! Classic versus sparse PBS for the same fixed-weight secret: n728/h32/N1024.
//! One iteration is a complete PBS into reused output/workspace buffers.
//! Key generation, encryption and validation are outside timing.
//! Parameters: primus_tfhe_test_support::parameters (arithmetic cost profiles).
//! Fixtures are initialized only for selected IDs, then reused across samples.
//! Run: cargo bench -p primus_tfhe_ntru_ntt --bench sparse_pbs

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_modulus::PowOf2Modulus;
use primus_ntt::{MonomialNttTable, U64NttTable};
use primus_tfhe_ntru_ntt::{BlindRotationConfig, KeyGenerator, TfheContext};
use primus_tfhe_test_support::parameters::ntru;
use primus_tfhe_test_support::parameters::ntt_modulus;
use rand::{SeedableRng, rngs::StdRng};

fn pbs_pair<T: FheUint, Table: MonomialNttTable<ValueT = T>>(c: &mut Criterion, backend: &str) {
    let parameters = ntru::diagnostic(ntt_modulus::<T>());
    let input_codec =
        RoundedCodec::new(T::as_from(8u32), parameters.external_lwe().cipher_modulus());
    let name = format!("ntru/{backend}/u{}/fixed_weight/n728_h32_N1024", T::BITS);
    // Hold one context/client pair, but build each server key only when selected.
    let mut fixture = None;
    for sparse in [false, true] {
        let kind = if sparse { "sparse" } else { "classic" };
        let mut server = None;
        let mut verified = false;
        c.bench_function(&format!("{name}/{kind}/complete"), |b| {
            let (context, client) = fixture.get_or_insert_with(|| {
                let context = TfheContext::<T, Table, PowOf2Modulus<T>>::try_from_parameters(
                    parameters.clone(),
                )
                .unwrap();
                let mut rng = StdRng::seed_from_u64(42);
                let client = KeyGenerator::new(&context)
                    .try_generate_client_key(&mut rng)
                    .unwrap();
                (context, client)
            });
            let server = server.get_or_insert_with(|| {
                let mut generator = KeyGenerator::new(context);
                let mut rng = StdRng::seed_from_u64(4242);
                let blind_rotation = if sparse {
                    BlindRotationConfig::Sparse {
                        copy_count: 3,
                        bucket_count: 64,
                    }
                } else {
                    BlindRotationConfig::Classic
                };
                generator
                    .try_generate_server_key(client, blind_rotation, None, &mut rng)
                    .unwrap()
            });
            let mut rng = StdRng::seed_from_u64(43);
            let input = context
                .encryptor(client.external_lwe_secret_key(), &input_codec)
                .unwrap()
                .encrypt_padded(T::ONE, &mut rng)
                .unwrap();
            let lut = context
                .parameters()
                .lookup_table_compiler(&input_codec)
                .unwrap()
                .compile_fn(|m| T::as_from((m + 1) % 4))
                .unwrap();
            let mut evaluator = context.evaluator(server).unwrap();
            let mut output = context.allocate_lwe_ciphertext();
            if !verified {
                evaluator.apply_lookup_table_to(input.as_view(), &lut, output.as_mut_view());
                assert_eq!(
                    context
                        .decryptor(client.external_lwe_secret_key(), &input_codec)
                        .unwrap()
                        .decrypt(output.as_view())
                        .unwrap(),
                    T::TWO
                );
                verified = true;
            }
            b.iter(|| {
                evaluator.apply_lookup_table_to(
                    black_box(input.as_view()),
                    black_box(&lut),
                    black_box(output.as_mut_view()),
                )
            });
        });
    }
}

fn bench_sparse(c: &mut Criterion) {
    pbs_pair::<u64, U64NttTable>(c, "ntt");
}

criterion_group!(benches, bench_sparse);
criterion_main!(benches);
