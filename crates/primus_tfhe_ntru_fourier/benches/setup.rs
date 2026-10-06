//! Explicit u64 setup diagnostics: dense binary/ternary and fixed-weight classic/sparse keygen.
//! Generation includes allocations; returned-key destruction is outside timing.
//! Run: cargo bench -p primus_tfhe_ntru_fourier --bench setup --features rustfft

#[cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
mod enabled {
    use std::hint::black_box;

    use criterion::{BatchSize, Criterion, criterion_group};
    #[cfg(feature = "rustfft")]
    use primus_fft::RustFftTable;
    #[cfg(all(not(feature = "rustfft"), feature = "tfhe-fft"))]
    use primus_fft::TfheFftTable;
    use primus_fft::{FftTable, TorusFftValue};
    use primus_modulus::NativeModulus;
    use primus_modulus::PowOf2Modulus;
    use primus_ntru::SecretKeyDistr;
    use primus_tfhe_ntru_fourier::{BlindRotationConfig, KeyGenerator, TfheContext};
    use primus_tfhe_test_support::{benchmark::PBS_WORKLOADS, parameters::ntru};
    use rand::{SeedableRng, rngs::StdRng};

    // Keygen keeps one Boolean-sized fixture per secret distribution.
    fn keygen<T: TorusFftValue, Table: FftTable>(c: &mut Criterion, backend: &str, ternary: bool) {
        let workload = PBS_WORKLOADS[0];
        let secret = if ternary {
            SecretKeyDistr::UniformTernary
        } else {
            SecretKeyDistr::UniformBinary
        };
        let kind = if ternary { "ternary" } else { "binary" };
        let name = format!(
            "ntru/{backend}/u{}/{kind}/{}/n{}_N{}",
            T::BITS,
            workload.name,
            workload.lwe_dimension,
            workload.poly_length
        );
        let parameters = ntru::pbs(NativeModulus::<T>::new(), workload, secret);
        let mut fixture = None;
        c.bench_function(&format!("{name}/server_keygen"), |b| {
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
            b.iter_batched(
                || (),
                |()| {
                    generator
                        .try_generate_server_key(
                            black_box(client),
                            BlindRotationConfig::Classic,
                            None,
                            &mut rng,
                        )
                        .unwrap()
                },
                BatchSize::PerIteration,
            );
        });
    }

    // Keygen pairs share a fixed client and separately seeded key-generation RNG.
    fn fixed_weight_keygen<T: TorusFftValue, Table: FftTable>(c: &mut Criterion, backend: &str) {
        let parameters = ntru::diagnostic(NativeModulus::<T>::new());
        let name = format!("ntru/{backend}/u{}/fixed_weight/n728_h32_N1024", T::BITS);
        let mut fixture = None;
        for sparse in [false, true] {
            let kind = if sparse { "sparse" } else { "classic" };
            c.bench_function(&format!("{name}/{kind}/server_keygen"), |b| {
                let (context, client) = fixture.get_or_insert_with(|| {
                    let context = TfheContext::<T, Table, PowOf2Modulus<T>>::from_parameters(
                        parameters.clone(),
                    );
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
                            .try_generate_server_key(
                                black_box(client),
                                blind_rotation,
                                None,
                                &mut rng,
                            )
                            .unwrap()
                    },
                    BatchSize::PerIteration,
                );
            });
        }
    }

    fn bench_setup(c: &mut Criterion) {
        #[cfg(feature = "rustfft")]
        {
            for ternary in [false, true] {
                keygen::<u64, RustFftTable>(c, "rustfft", ternary);
            }
            fixed_weight_keygen::<u64, RustFftTable>(c, "rustfft");
        }
        #[cfg(all(not(feature = "rustfft"), feature = "tfhe-fft"))]
        {
            for ternary in [false, true] {
                keygen::<u64, TfheFftTable>(c, "tfhe_fft", ternary);
            }
            fixed_weight_keygen::<u64, TfheFftTable>(c, "tfhe_fft");
        }
    }

    criterion_group!(benches, bench_setup);
}

#[cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
criterion::criterion_main!(enabled::benches);

#[cfg(not(any(feature = "rustfft", feature = "tfhe-fft")))]
fn main() {
    eprintln!("Enable rustfft or tfhe-fft to run this benchmark.");
}
