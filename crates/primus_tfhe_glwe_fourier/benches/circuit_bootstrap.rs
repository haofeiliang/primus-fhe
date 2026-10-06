//! One complete CBS into a reused gadget ciphertext. Keygen, encryption,
//! allocation and the CMux correctness probe are outside timing; t=4.
//! Classic/sparse share n728/h32/N1024, client seed and input randomness.
//! Parameters: primus_tfhe_test_support::parameters (arithmetic cost profiles).
//! Fixtures are initialized only for selected IDs, then reused across samples.
//! Run: cargo bench -p primus_tfhe_glwe_fourier --bench circuit_bootstrap --features rustfft

#[cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
mod enabled {
    use std::hint::black_box;

    use criterion::{Criterion, criterion_group};
    #[cfg(feature = "rustfft")]
    use primus_fft::RustFftTable;
    #[cfg(all(not(feature = "rustfft"), feature = "tfhe-fft"))]
    use primus_fft::TfheFftTable;
    use primus_fft::{FftTable, TorusFftValue};
    use primus_modulus::NativeModulus;
    use primus_tfhe_glwe_fourier::{
        BlindRotationConfig, CircuitBootstrapEvaluator, ClientKey, KeyGenerator, PbsOrder,
        TfheContext,
    };
    use primus_tfhe_test_support::parameters::{N, glwe};
    use rand::{SeedableRng, rngs::StdRng};

    // CBS consumes a bit and emits a gadget control, not an LWE result. Verify
    // that representation by selecting an encrypted ring message before timing.
    fn ordinary<T, Table>(c: &mut Criterion, backend: &str, order: PbsOrder, sparse: bool)
    where
        T: TorusFftValue,
        Table: FftTable,
    {
        let kind = if sparse { "sparse" } else { "classic" };
        // Pair classic and sparse BR using identical parameters and client seed.
        let parameters = glwe::diagnostic(NativeModulus::<T>::new(), order);
        let input_codec =
            primus_encoding::RoundedCodec::new(T::as_from(4u32), parameters.cipher_modulus());
        let name = format!(
            "glwe/{backend}/u{}/cbs/{kind}/n728_h32_N1024/{order:?}/complete",
            T::BITS
        );
        let mut fixture = None;
        let mut verified = false;
        c.bench_function(&name, |b| {
            let (context, client, server, input, lhs, rhs) = fixture.get_or_insert_with(|| {
                let context = TfheContext::<T, Table>::from_parameters(parameters.clone());
                let mut rng = StdRng::seed_from_u64(42);
                let mut generator = KeyGenerator::new(&context);
                let client = ClientKey::generate(context.parameters(), &mut rng);
                let blind_rotation = if sparse {
                    BlindRotationConfig::Sparse {
                        copy_count: 3,
                        bucket_count: 64,
                    }
                } else {
                    BlindRotationConfig::Classic
                };
                let server = generator
                    .try_generate_server_key(
                        &client,
                        blind_rotation,
                        Some(glwe::cbs::<T>()),
                        &mut rng,
                    )
                    .unwrap();
                // Separate input randomness from scheme-dependent key generation.
                let mut rng = StdRng::seed_from_u64(43);
                let input = context
                    .encryptor(client.external_lwe_secret_key(), &input_codec)
                    .unwrap()
                    .encrypt_padded(T::ONE, &mut rng)
                    .unwrap();
                let mut ring = context
                    .accumulator_client(
                        client.glwe_secret_key(),
                        primus_encoding::ScaledCodec::new(
                            input_codec.plaintext_modulus(),
                            input_codec.ciphertext_modulus(),
                        ),
                    )
                    .unwrap();
                let lhs = ring.encrypt(&[T::ZERO; N], &mut rng);
                let rhs = ring.encrypt(&[T::ONE; N], &mut rng);
                (context, client, server, input, lhs, rhs)
            });
            let mut resources = context.bootstrap_resources_from_server_key(server).unwrap();
            let circuit_key = server.circuit_bootstrap_key().unwrap();
            let mut evaluator =
                CircuitBootstrapEvaluator::try_new(&resources, circuit_key, &input_codec).unwrap();
            let mut output = evaluator.allocate_output();
            if !verified {
                evaluator.circuit_bootstrap_to(input.as_view(), &mut output, &mut resources);
                let mut selected = context.allocate_accumulator_ciphertext();
                evaluator.cmux_to(&output, lhs, rhs, &mut selected, &mut resources);
                let mut decoded = vec![T::ZERO; N];
                context
                    .accumulator_client(
                        client.glwe_secret_key(),
                        primus_encoding::ScaledCodec::new(
                            input_codec.plaintext_modulus(),
                            input_codec.ciphertext_modulus(),
                        ),
                    )
                    .unwrap()
                    .decrypt_to(&selected, &mut decoded);
                assert!(decoded.iter().all(|&value| value == T::ONE));
                verified = true;
            }
            b.iter(|| {
                evaluator.circuit_bootstrap_to(
                    black_box(input.as_view()),
                    black_box(&mut output),
                    &mut resources,
                )
            });
        });
    }

    fn bench_cbs(c: &mut Criterion) {
        for sparse in [false, true] {
            #[cfg(feature = "rustfft")]
            {
                ordinary::<u64, RustFftTable>(c, "rustfft", PbsOrder::KeyswitchBootstrap, sparse);
            }
            #[cfg(all(not(feature = "rustfft"), feature = "tfhe-fft"))]
            {
                ordinary::<u64, TfheFftTable>(c, "tfhe_fft", PbsOrder::KeyswitchBootstrap, sparse);
            }
        }
    }

    criterion_group!(benches, bench_cbs);
}

#[cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
criterion::criterion_main!(enabled::benches);

#[cfg(not(any(feature = "rustfft", feature = "tfhe-fft")))]
fn main() {
    eprintln!("Enable rustfft or tfhe-fft to run this benchmark.");
}
