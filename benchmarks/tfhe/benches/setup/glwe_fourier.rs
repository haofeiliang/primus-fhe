//! Explicit u64 setup diagnostics: dense binary/ternary and fixed-weight classic/sparse keygen.
//! Generation includes allocations; returned-key destruction is outside timing.
//! Separate raw BR/GLWE-KS timings exclude prerequisite work and extraction.
//! Run: cargo bench -p primus_tfhe_benchmarks --bench setup --features glwe-fourier,rustfft,tfhe-fft

use primus_tfhe::PbsMessageConfig;
use primus_tfhe_benchmarks::measurement::{Case, Group, metadata};
use std::hint::black_box;

use criterion::BatchSize;
#[cfg(feature = "rustfft")]
use primus_fft::RustFftTable;
#[cfg(all(not(feature = "rustfft"), feature = "tfhe-fft"))]
use primus_fft::TfheFftTable;
use primus_fft::{FftTable, TorusFftValue};
use primus_glwe::SecretKeyDistr;
use primus_glwe::{FourierGlweKeySwitchingWorkspace, GlweCiphertext};
use primus_lwe::LweCiphertext;
use primus_modulus::NativeModulus;
use primus_tfhe_benchmarks::{benchmark::PBS_WORKLOADS, parameters::glwe};
use primus_tfhe_glwe_fourier::{BlindRotationKey, FourierGlweBlindRotationWorkspace};
use primus_tfhe_glwe_fourier::{ClientKey, KeyGenerator, PbsOrder, TfheContext};
use rand::{SeedableRng, rngs::StdRng};

// Keygen uses the Boolean geometry; PBS order does not change generation.
fn keygen<T, Table>(c: &mut Group<'_>, backend: &str, ternary: bool)
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
    let name = format!("{kind}/{}/{order:?}", workload.name);
    let parameters = if ternary {
        glwe::circuit(NativeModulus::<T>::new(), order, secret)
    } else {
        glwe::fourier_pbs::<T>(order, workload)
    };
    let fixture = std::cell::LazyCell::new(|| {
        let context_parameters = &parameters;
        let context = TfheContext::<T, Table>::from_parameters(context_parameters.clone());
        let mut rng = StdRng::seed_from_u64(42);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        (context, client)
    });
    let case = Case::new("glwe", backend, T::BITS, format!("{name}/server_keygen"));
    c.bench_function(case.id(), |b| {
        let (context, client) = &*fixture;
        let mut generator = KeyGenerator::new(context);
        let mut rng = StdRng::seed_from_u64(4242);

        metadata::record("setup", &case, || {
            serde_json::json!({
                "parameters": metadata::glwe(&parameters),
                "blind_rotation": metadata::blind_rotation(false),
                "drop": "outside keygen timing; stage buffers outside timing",
                "fft_layout_fingerprint": metadata::fft_layout(context.table()),
            })
        });
        b.iter_batched(
            || (),
            |()| {
                generator
                    .try_generate_server_key(black_box(client), &mut rng)
                    .unwrap()
            },
            BatchSize::PerIteration,
        );
    });
}

// Keep one representative BR/GLWE-KS split to diagnose a complete-PBS regression.
// Both kernels read fixed inputs and overwrite outputs; extraction and the
// prerequisite BR are setup only. The `pbs` target covers both execution orders.
fn stages<T: TorusFftValue, Table: FftTable>(c: &mut Group<'_>, backend: &str) {
    let fixture = std::cell::LazyCell::new(|| {
        let operation = glwe::fourier_pbs(PbsOrder::BootstrapKeyswitch, PBS_WORKLOADS[0])
            .with_messages(PbsMessageConfig::new(T::as_from(4u32)));
        let context = TfheContext::<T, Table>::from_parameters(operation.clone());
        let mut rng = StdRng::seed_from_u64(42);
        let (client, server) = context.try_generate_keys(&mut rng).unwrap();
        (operation, context, client, server)
    });
    for stage in ["glwe_key_switching", "blind_rotation"] {
        let mut verified = false;
        let case = Case::new("glwe", backend, T::BITS, format!("stages/{stage}"));
        c.bench_function(case.id(), |b| {
            let (operation, context, client, server_key) = &*fixture;
            let parameters = context.parameters();
            let poly_length = parameters.blind_rotation_params().poly_length();

            let mut rng = StdRng::seed_from_u64(43);
            let input = context
                .encryptor(client.external_lwe_secret_key())
                .unwrap()
                .encrypt_padded(T::ONE, &mut rng)
                .unwrap();
            let lookup_table = context
                .pbs_lookup_table_compiler()
                .unwrap()
                .compile_fn(|m| T::as_from(m ^ 1))
                .unwrap();
            let BlindRotationKey::Classic(bootstrapping_key) = server_key.blind_rotation_key()
            else {
                panic!("stage fixture requires classic PBS");
            };
            let modulus = parameters.blind_rotation_params().cipher_modulus();
            let mut fft = context.new_fft_engine();
            let mut blind_rotation = FourierGlweBlindRotationWorkspace::new(bootstrapping_key);
            let key_switching_parameters = operation.glwe_key_switching().output();
            let mut key_switching =
                FourierGlweKeySwitchingWorkspace::new(key_switching_parameters.glwe_size());
            let mut main_glwe: GlweCiphertext<Vec<T>> =
                GlweCiphertext::zero(parameters.blind_rotation_params().glwe_len());
            let mut switched: GlweCiphertext<Vec<T>> =
                GlweCiphertext::zero(operation.glwe_key_switching().output().glwe_len());
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
                        .pbs_decryptor(client.external_lwe_secret_key())
                        .unwrap()
                        .decrypt(small_lwe.as_view())
                        .unwrap(),
                    T::ZERO
                );
                verified = true;
            }

            metadata::record("setup", &case, || {
                serde_json::json!({
                    "parameters": metadata::glwe(operation),
                    "blind_rotation": metadata::blind_rotation(false),
                    "stage": stage,
                    "plaintext_modulus": 4,
                    "drop": "outside keygen timing; stage buffers outside timing",
                    "fft_layout_fingerprint": metadata::fft_layout(context.table()),
                })
            });
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
        });
    }
}

// Keygen pairs share a fixed client and separately seeded key-generation RNG.
fn fixed_weight_keygen<T: TorusFftValue, Table: FftTable>(
    c: &mut Group<'_>,
    backend: &str,
    order: PbsOrder,
) {
    let parameters = glwe::diagnostic(NativeModulus::<T>::new(), order);
    let name = format!("fixed_weight/{order:?}");
    let fixture = std::cell::LazyCell::new(|| {
        let context_parameters = &parameters;
        let context = TfheContext::<T, Table>::from_parameters(context_parameters.clone());
        let mut rng = StdRng::seed_from_u64(42);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        (context, client)
    });
    for sparse in [false, true] {
        let kind = if sparse { "sparse" } else { "classic" };
        let case = Case::new(
            "glwe",
            backend,
            T::BITS,
            format!("{name}/{kind}/server_keygen"),
        );
        c.bench_function(case.id(), |b| {
            let (context, client) = &*fixture;
            let mut generator = KeyGenerator::new(context);
            let mut rng = StdRng::seed_from_u64(4242);
            let blind_rotation = primus_tfhe_benchmarks::benchmark::blind_rotation(sparse);

            metadata::record("setup", &case, || {
                serde_json::json!({
                    "parameters": metadata::glwe(&parameters),
                    "blind_rotation": metadata::blind_rotation(sparse),
                    "drop": "outside keygen timing; stage buffers outside timing",
                    "fft_layout_fingerprint": metadata::fft_layout(context.table()),
                })
            });
            b.iter_batched(
                || (),
                |()| {
                    generator
                        .try_generate_server_key_with_parameters(
                            parameters.glwe_key_switching(),
                            black_box(client),
                            blind_rotation,
                            &mut rng,
                        )
                        .unwrap()
                },
                BatchSize::PerIteration,
            );
        });
    }
}

pub fn bench_setup(c: &mut Group<'_>) {
    #[cfg(feature = "rustfft")]
    {
        for ternary in [false, true] {
            keygen::<u64, RustFftTable>(c, "rustfft", ternary);
        }
        fixed_weight_keygen::<u64, RustFftTable>(c, "rustfft", PbsOrder::BootstrapKeyswitch);
        stages::<u64, RustFftTable>(c, "rustfft");
    }
    #[cfg(all(not(feature = "rustfft"), feature = "tfhe-fft"))]
    {
        for ternary in [false, true] {
            keygen::<u64, TfheFftTable>(c, "tfhe_fft", ternary);
        }
        fixed_weight_keygen::<u64, TfheFftTable>(c, "tfhe_fft", PbsOrder::BootstrapKeyswitch);
        stages::<u64, TfheFftTable>(c, "tfhe_fft");
    }
}
