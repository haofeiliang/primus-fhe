//! Dense binary/ternary PBS and server-key generation. One iteration is one operation.
//! LUTs, encryption, output allocation and validation are excluded; keygen includes
//! its allocations, with returned-key destruction outside the timer.
//! Parameters: primus_tfhe_test_support::parameters (arithmetic cost profiles).
//! Fixtures are initialized only for selected IDs, then reused across samples.
//! Run: cargo bench -p primus_tfhe_glwe_fourier --bench pbs

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
#[cfg(feature = "rustfft")]
use primus_fft::RustFftTable;
#[cfg(feature = "tfhe-fft")]
use primus_fft::TfheFftTable;
use primus_fft::{FftTable, TorusFftValue};
use primus_glwe::SecretKeyDistr;
use primus_glwe::{FourierGlweKeySwitchingWorkspace, GlweCiphertext};
use primus_lwe::LweCiphertext;
use primus_modulus::NativeModulus;
use primus_tfhe_glwe_fourier::{
    BlindRotationConfig, BlindRotationKey, FourierGlweBlindRotationWorkspace,
};
use primus_tfhe_glwe_fourier::{ClientKey, KeyGenerator, PbsOrder, TfheContext};
use primus_tfhe_test_support::{
    benchmark::{PBS_WORKLOADS, PbsWorkload},
    parameters::glwe,
};
use rand::{SeedableRng, rngs::StdRng};

// The ternary profile has its own decomposition/noise budget. Its timing must
// not be divided by the binary timing to claim a secret-distribution speedup.
fn pbs<T, Table>(
    c: &mut Criterion,
    backend: &str,
    order: PbsOrder,
    workload: PbsWorkload,
    ternary: bool,
) where
    T: TorusFftValue,
    Table: FftTable,
{
    let secret = if ternary {
        SecretKeyDistr::UniformTernary
    } else {
        SecretKeyDistr::UniformBinary
    };
    let kind = if ternary { "ternary" } else { "binary" };
    let name = format!(
        "glwe/{backend}/u{}/{kind}/{}/n{}_N{}/{order:?}",
        T::BITS,
        workload.name,
        workload.lwe_dimension,
        workload.poly_length
    );
    let parameters = if ternary {
        glwe::circuit(NativeModulus::<T>::new(), order, secret)
    } else {
        glwe::fourier_pbs::<T>(order, workload)
    };
    let input_codec = primus_encoding::RoundedCodec::new(
        T::as_from(workload.plaintext_modulus),
        parameters.cipher_modulus(),
    );
    // Cached owned state avoids both eager setup during --list and repeated key
    // generation for each Criterion sample. Evaluators borrow this state locally.
    let mut fixture = None;
    let mut verified = false;
    c.bench_function(&format!("{name}/complete"), |b| {
        let (context, client, server, input, lut) = fixture.get_or_insert_with(|| {
            let context = TfheContext::<T, Table>::from_parameters(parameters.clone());
            let mut rng = StdRng::seed_from_u64(42);
            let (client, server) = context.try_generate_keys(None, &mut rng).unwrap();
            let input = context
                .encryptor(client.external_lwe_secret_key(), &input_codec)
                .unwrap()
                .encrypt_padded(T::ONE, &mut rng)
                .unwrap();
            let domain = workload.plaintext_modulus as usize / 2;
            let lut = context
                .parameters()
                .lookup_table_compiler(&input_codec)
                .unwrap()
                .compile_fn(|x| T::as_from((x + domain - 1) % domain))
                .unwrap();
            (context, client, server, input, lut)
        });
        let mut evaluator = context.evaluator(server).unwrap();
        let mut output = context.allocate_lwe_ciphertext();
        if !verified {
            evaluator.apply_lookup_table_to(input.as_view(), lut, output.as_mut_view());
            assert_eq!(
                context
                    .decryptor(client.external_lwe_secret_key(), &input_codec)
                    .unwrap()
                    .decrypt(output.as_view())
                    .unwrap(),
                T::ZERO
            );
            verified = true;
        }
        b.iter(|| {
            evaluator.apply_lookup_table_to(
                black_box(input.as_view()),
                black_box(lut),
                black_box(output.as_mut_view()),
            )
        });
    });
}

// Keygen uses the Boolean geometry; PBS order does not change generation.
fn keygen<T, Table>(c: &mut Criterion, backend: &str, ternary: bool)
where
    T: TorusFftValue,
    Table: FftTable,
{
    let workload = PBS_WORKLOADS[0];
    let order = PbsOrder::BootstrapKeyswitch;
    let secret = if ternary {
        SecretKeyDistr::UniformTernary
    } else {
        SecretKeyDistr::UniformBinary
    };
    let kind = if ternary { "ternary" } else { "binary" };
    let name = format!(
        "glwe/{backend}/u{}/{kind}/{}/n{}_N{}/{order:?}",
        T::BITS,
        workload.name,
        workload.lwe_dimension,
        workload.poly_length
    );
    let parameters = if ternary {
        glwe::circuit(NativeModulus::<T>::new(), order, secret)
    } else {
        glwe::fourier_pbs::<T>(order, workload)
    };
    let mut fixture = None;
    c.bench_function(&format!("{name}/server_keygen"), |b| {
        let (context, client) = fixture.get_or_insert_with(|| {
            let context = TfheContext::<T, Table>::from_parameters(parameters.clone());
            let mut rng = StdRng::seed_from_u64(42);
            let client = ClientKey::generate(context.parameters(), &mut rng);
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

// Keep one representative BR/GLWE-KS split to diagnose a complete-PBS regression.
// Both kernels read fixed inputs and overwrite outputs; extraction and the
// prerequisite BR are setup only. Full PBS above covers both execution orders.
fn stages<T: TorusFftValue, Table: FftTable>(c: &mut Criterion, backend: &str) {
    let mut fixture = None;
    for stage in ["glwe_key_switching", "blind_rotation"] {
        let mut verified = false;
        c.bench_function(
            &format!("glwe/{backend}/u{}/stages/n800_N1024/{stage}", T::BITS),
            |b| {
                let (context, client, server_key) = fixture.get_or_insert_with(|| {
                    let context = TfheContext::<T, Table>::from_parameters(glwe::fourier_pbs(
                        PbsOrder::BootstrapKeyswitch,
                        PBS_WORKLOADS[0],
                    ));
                    let mut rng = StdRng::seed_from_u64(42);
                    let (client, server) = context.try_generate_keys(None, &mut rng).unwrap();
                    (context, client, server)
                });
                let parameters = context.parameters();
                let input_codec = primus_encoding::RoundedCodec::new(
                    T::as_from(4u32),
                    parameters.cipher_modulus(),
                );
                let poly_length = parameters.blind_rotation_ggsw().poly_length();

                let mut rng = StdRng::seed_from_u64(43);
                let input = context
                    .encryptor(client.external_lwe_secret_key(), &input_codec)
                    .unwrap()
                    .encrypt_padded(T::ONE, &mut rng)
                    .unwrap();
                let lookup_table = parameters
                    .lookup_table_compiler(&input_codec)
                    .unwrap()
                    .compile_fn(|m| T::as_from(m ^ 1))
                    .unwrap();
                let BlindRotationKey::Classic(bootstrapping_key) = server_key.blind_rotation_key()
                else {
                    panic!("stage fixture requires classic PBS");
                };
                let modulus = parameters.blind_rotation_ggsw().cipher_modulus();
                let mut fft = context.new_fft_engine();
                let mut blind_rotation = FourierGlweBlindRotationWorkspace::new(bootstrapping_key);
                let key_switching_parameters = parameters.glwe_key_switching().output();
                let mut key_switching =
                    FourierGlweKeySwitchingWorkspace::new(key_switching_parameters.glwe_size());
                let mut main_glwe: GlweCiphertext<Vec<T>> =
                    GlweCiphertext::zero(parameters.blind_rotation_ggsw().glwe_len());
                let mut switched: GlweCiphertext<Vec<T>> =
                    GlweCiphertext::zero(parameters.glwe_key_switching().output().glwe_len());
                let mut small_lwe: LweCiphertext<T> =
                    LweCiphertext::zero(parameters.small_lwe().dimension().get());

                bootstrapping_key.fourier_blind_rotate_lookup_table_to(
                    &input,
                    lookup_table.polynomial(),
                    &mut main_glwe,
                    &mut fft,
                    &mut blind_rotation,
                );
                server_key.glwe_key_switching_key().key_switch_to(
                    &main_glwe,
                    &mut switched,
                    &mut fft,
                    &mut key_switching,
                );
                switched.extract_compact_lwe_to(&mut small_lwe, poly_length.get(), modulus);
                if !verified {
                    assert_eq!(
                        context
                            .decryptor(client.external_lwe_secret_key(), &input_codec)
                            .unwrap()
                            .decrypt(small_lwe.as_view())
                            .unwrap(),
                        T::ZERO
                    );
                    verified = true;
                }

                if stage == "glwe_key_switching" {
                    b.iter(|| {
                        server_key.glwe_key_switching_key().key_switch_to(
                            black_box(&main_glwe),
                            black_box(&mut switched),
                            &mut fft,
                            &mut key_switching,
                        );
                        black_box(&switched);
                    });
                } else {
                    b.iter(|| {
                        black_box(bootstrapping_key).fourier_blind_rotate_lookup_table_to(
                            black_box(&input),
                            black_box(lookup_table.polynomial()),
                            black_box(&mut main_glwe),
                            &mut fft,
                            &mut blind_rotation,
                        );
                        black_box(&main_glwe);
                    });
                }
            },
        );
    }
}

// Register the primary engine's word, secret and order comparisons once.
fn primary<Table: FftTable>(c: &mut Criterion, backend: &str) {
    use PbsOrder::{BootstrapKeyswitch, KeyswitchBootstrap};
    let [boolean, shortint] = PBS_WORKLOADS;
    pbs::<u32, Table>(c, backend, KeyswitchBootstrap, boolean, false);
    pbs::<u64, Table>(c, backend, KeyswitchBootstrap, shortint, false);
    pbs::<u64, Table>(c, backend, KeyswitchBootstrap, boolean, true);
    pbs::<u64, Table>(c, backend, BootstrapKeyswitch, shortint, false);
}

fn bench_pbs(c: &mut Criterion) {
    #[cfg(feature = "rustfft")]
    primary::<RustFftTable>(c, "rustfft");
    #[cfg(all(not(feature = "rustfft"), feature = "tfhe-fft"))]
    primary::<TfheFftTable>(c, "tfhe_fft");
    #[cfg(all(feature = "rustfft", feature = "tfhe-fft"))]
    pbs::<u64, TfheFftTable>(
        c,
        "tfhe_fft",
        PbsOrder::KeyswitchBootstrap,
        PBS_WORKLOADS[1],
        false,
    );

    // Register setup/stage diagnostics independently of the online workloads.
    #[cfg(feature = "rustfft")]
    {
        stages::<u32, RustFftTable>(c, "rustfft");
        stages::<u64, RustFftTable>(c, "rustfft");
        for ternary in [false, true] {
            keygen::<u32, RustFftTable>(c, "rustfft", ternary);
            keygen::<u64, RustFftTable>(c, "rustfft", ternary);
        }
    }
    #[cfg(feature = "tfhe-fft")]
    {
        stages::<u32, TfheFftTable>(c, "tfhe_fft");
        stages::<u64, TfheFftTable>(c, "tfhe_fft");
        for ternary in [false, true] {
            keygen::<u32, TfheFftTable>(c, "tfhe_fft", ternary);
            keygen::<u64, TfheFftTable>(c, "tfhe_fft", ternary);
        }
    }
}

criterion_group!(benches, bench_pbs);
criterion_main!(benches);
