//! Classic versus sparse PBS for the same fixed-weight secret: n728/h32/N1024.
//! One iteration is a complete PBS or one server-key generation. PBS reuses
//! buffers; encryption/setup/validation and returned-key drop are not timed.
//! Parameters: primus_tfhe_test_support::parameters (arithmetic cost profiles).
//! Fixtures are initialized only for selected IDs, then reused across samples.
//! Run: cargo bench -p primus_tfhe_ntru_ntt --bench sparse_pbs

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use primus_integer::FheUint;
use primus_modulus::PowOf2Modulus;
use primus_ntt::{MonomialNttTable, U32NttTable, U64NttTable};
use primus_tfhe_ntru_ntt::{KeyGenerator, TfheContext};
use primus_tfhe_test_support::parameters::ntru;
use primus_tfhe_test_support::parameters::ntt_modulus;
use rand::{SeedableRng, rngs::StdRng};

fn backend<T: FheUint, Table: MonomialNttTable<ValueT = T>>(c: &mut Criterion, backend: &str) {
    let parameters = ntru::diagnostic(ntt_modulus::<T>(), 8);
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
                if sparse {
                    generator
                        .try_generate_sparse_server_key(client, 3, 64, &mut rng)
                        .unwrap()
                } else {
                    generator
                        .try_generate_server_key(client, None, &mut rng)
                        .unwrap()
                }
            });
            let mut rng = StdRng::seed_from_u64(43);
            let input = context
                .encryptor(client)
                .unwrap()
                .encrypt_padded(T::ONE, &mut rng)
                .unwrap();
            let lut = context
                .parameters()
                .compile_lookup_table_fn(|m| T::as_from((m + 1) % 4))
                .unwrap();
            let mut evaluator = context.evaluator(server).unwrap();
            let mut output = context.allocate_lwe_ciphertext();
            if !verified {
                evaluator.apply_lookup_table_to(&input, &lut, &mut output);
                assert_eq!(
                    context.decryptor(client).unwrap().decrypt(&output).unwrap(),
                    T::TWO
                );
                verified = true;
            }
            b.iter(|| {
                evaluator.apply_lookup_table_to(
                    black_box(&input),
                    black_box(&lut),
                    black_box(&mut output),
                )
            });
        });
        // Generation reuses the client, but does not need the evaluation key.
        drop(server);
        c.bench_function(&format!("{name}/{kind}/server_keygen"), |b| {
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
            let mut generator = KeyGenerator::new(context);
            let mut rng = StdRng::seed_from_u64(4242);
            if sparse {
                b.iter_batched(
                    || (),
                    |()| {
                        generator
                            .try_generate_sparse_server_key(black_box(client), 3, 64, &mut rng)
                            .unwrap()
                    },
                    BatchSize::PerIteration,
                );
            } else {
                b.iter_batched(
                    || (),
                    |()| {
                        generator
                            .try_generate_server_key(black_box(client), None, &mut rng)
                            .unwrap()
                    },
                    BatchSize::PerIteration,
                );
            }
        });
    }
}

fn bench_sparse(c: &mut Criterion) {
    backend::<u32, U32NttTable>(c, "ntt");
    backend::<u64, U64NttTable>(c, "ntt");
}

criterion_group!(benches, bench_sparse);
criterion_main!(benches);
