//! Classic versus sparse PBS for the same fixed-weight secret: n728/h32/N1024.
//! One iteration is a complete PBS or one server-key generation. PBS reuses
//! buffers; encryption/setup/validation and returned-key drop are not timed.
//! Parameters: primus_tfhe_test_support::parameters (arithmetic cost profiles).
//! Fixtures are initialized only for selected IDs, then reused across samples.
//! Run: cargo bench -p primus_tfhe_ntru_fourier --bench sparse_pbs

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use primus_encoding::RoundedCodec;
#[cfg(feature = "rustfft")]
use primus_fft::RustFftTable;
#[cfg(feature = "tfhe-fft")]
use primus_fft::TfheFftTable;
use primus_fft::{FftTable, TorusFftValue};
use primus_modulus::NativeModulus;
use primus_modulus::PowOf2Modulus;
use primus_tfhe_ntru_fourier::{BlindRotationConfig, KeyGenerator, TfheContext};
use primus_tfhe_test_support::parameters::ntru;
use rand::{SeedableRng, rngs::StdRng};

fn pbs_pair<T: TorusFftValue, Table: FftTable>(c: &mut Criterion, backend: &str) {
    let parameters = ntru::diagnostic(NativeModulus::<T>::new());
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
                let context =
                    TfheContext::<T, Table, PowOf2Modulus<T>>::from_parameters(parameters.clone());
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

// Keygen pairs share a fixed client and separately seeded key-generation RNG.
fn keygen<T: TorusFftValue, Table: FftTable>(c: &mut Criterion, backend: &str) {
    let parameters = ntru::diagnostic(NativeModulus::<T>::new());
    let name = format!("ntru/{backend}/u{}/fixed_weight/n728_h32_N1024", T::BITS);
    let mut fixture = None;
    for sparse in [false, true] {
        let kind = if sparse { "sparse" } else { "classic" };
        c.bench_function(&format!("{name}/{kind}/server_keygen"), |b| {
            let (context, client) = fixture.get_or_insert_with(|| {
                let context =
                    TfheContext::<T, Table, PowOf2Modulus<T>>::from_parameters(parameters.clone());
                let mut rng = StdRng::seed_from_u64(42);
                let client = KeyGenerator::new(&context)
                    .try_generate_client_key(&mut rng)
                    .unwrap();
                (context, client)
            });
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
            b.iter_batched(
                || (),
                |()| {
                    generator
                        .try_generate_server_key(black_box(client), blind_rotation, None, &mut rng)
                        .unwrap()
                },
                BatchSize::PerIteration,
            );
        });
    }
}

fn bench_sparse(c: &mut Criterion) {
    #[cfg(feature = "rustfft")]
    {
        pbs_pair::<u32, RustFftTable>(c, "rustfft");
        pbs_pair::<u64, RustFftTable>(c, "rustfft");
    }
    #[cfg(all(not(feature = "rustfft"), feature = "tfhe-fft"))]
    {
        pbs_pair::<u32, TfheFftTable>(c, "tfhe_fft");
        pbs_pair::<u64, TfheFftTable>(c, "tfhe_fft");
    }

    // Register research/setup diagnostics independently of the online workloads.
    #[cfg(feature = "rustfft")]
    {
        keygen::<u32, RustFftTable>(c, "rustfft");
        keygen::<u64, RustFftTable>(c, "rustfft");
    }
    #[cfg(feature = "tfhe-fft")]
    {
        keygen::<u32, TfheFftTable>(c, "tfhe_fft");
        keygen::<u64, TfheFftTable>(c, "tfhe_fft");
    }
}

criterion_group!(benches, bench_sparse);
criterion_main!(benches);
