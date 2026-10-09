//! Explicit u64 setup diagnostics: dense binary/ternary and fixed-weight classic/sparse keygen.
//! Generation includes allocations; returned-key destruction is outside timing.
//! Separate raw BR/GLWE-KS timings exclude prerequisite work and extraction.
//! Run: cargo bench -p primus_tfhe_benchmarks --bench setup --features glwe-ntt

use primus_tfhe::PbsMessageConfig;
use primus_tfhe_benchmarks::measurement::{Case, Group, metadata};
use std::hint::black_box;

use criterion::BatchSize;
use primus_glwe::SecretKeyDistr;
use primus_glwe::{GlweCiphertext, NttGlweKeySwitchingWorkspace};
use primus_integer::FheUint;
use primus_lwe::LweCiphertext;
use primus_ntt::{MonomialNttTable, U64NttTable};
use primus_tfhe_benchmarks::parameters::{ntt_circuit_modulus, ntt_modulus};
use primus_tfhe_benchmarks::{benchmark::PBS_WORKLOADS, parameters::glwe};
use primus_tfhe_glwe_ntt::{BlindRotationKey, NttGlweBlindRotationWorkspace};
use primus_tfhe_glwe_ntt::{ClientKey, KeyGenerator, PbsOrder, TfheContext};
use rand::{SeedableRng, rngs::StdRng};

// Keygen uses the Boolean geometry; PBS order does not change generation.
fn keygen<T, Table>(c: &mut Group<'_>, backend: &str, ternary: bool)
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
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
        glwe::circuit(ntt_circuit_modulus::<T>(), order, secret)
    } else {
        glwe::ntt_pbs::<T>(order, workload)
    };
    let fixture = std::cell::LazyCell::new(|| {
        let context_parameters = &parameters;
        let context =
            TfheContext::<T, Table>::try_from_parameters(context_parameters.clone()).unwrap();
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
fn stages<T: FheUint, Table: MonomialNttTable<ValueT = T>>(c: &mut Group<'_>, backend: &str) {
    let fixture = std::cell::LazyCell::new(|| {
        let operation = glwe::ntt_pbs(PbsOrder::BootstrapKeyswitch, PBS_WORKLOADS[0])
            .with_messages(PbsMessageConfig::new(T::as_from(4u32)));
        let context = TfheContext::<T, Table>::try_from_parameters(operation.clone()).unwrap();
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
            let modulus = parameters.blind_rotation_params().cipher_modulus();
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
            let mut blind_rotation = NttGlweBlindRotationWorkspace::new(bootstrapping_key);
            let mut key_switching = NttGlweKeySwitchingWorkspace::new(
                operation.glwe_key_switching().output().size().glwe_size(),
            );
            let mut main_glwe: GlweCiphertext<Vec<T>> =
                GlweCiphertext::zero(parameters.blind_rotation_params().glwe_len());
            let mut switched: GlweCiphertext<Vec<T>> =
                GlweCiphertext::zero(operation.glwe_key_switching().output().glwe_len());
            let mut small_lwe: LweCiphertext<T> =
                LweCiphertext::zero(parameters.small_lwe().dimension().get());

            bootstrapping_key.ntt_blind_rotate_lookup_table_to(
                &input,
                lookup_table.polynomial(),
                &mut main_glwe,
                modulus,
                context.table(),
                &mut blind_rotation,
            );
            server_key.glwe_key_switching_key().key_switch_to(
                &main_glwe,
                &mut switched,
                modulus,
                context.table(),
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
                })
            });
            if stage == "glwe_key_switching" {
                b.iter(|| {
                    server_key.glwe_key_switching_key().key_switch_to(
                        black_box(&main_glwe),
                        black_box(&mut switched),
                        modulus,
                        context.table(),
                        &mut key_switching,
                    );
                    black_box(&switched);
                });
            } else {
                b.iter(|| {
                    black_box(bootstrapping_key).ntt_blind_rotate_lookup_table_to(
                        black_box(&input),
                        black_box(lookup_table.polynomial()),
                        black_box(&mut main_glwe),
                        modulus,
                        context.table(),
                        &mut blind_rotation,
                    );
                    black_box(&main_glwe);
                });
            }
        });
    }
}

// Keygen pairs share a fixed client and separately seeded key-generation RNG.
fn fixed_weight_keygen<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    c: &mut Group<'_>,
    backend: &str,
    order: PbsOrder,
) {
    let parameters = glwe::diagnostic(ntt_modulus::<T>(), order);
    let name = format!("fixed_weight/{order:?}");
    let fixture = std::cell::LazyCell::new(|| {
        let context_parameters = &parameters;
        let context =
            TfheContext::<T, Table>::try_from_parameters(context_parameters.clone()).unwrap();
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
    for ternary in [false, true] {
        keygen::<u64, U64NttTable>(c, "ntt", ternary);
    }
    fixed_weight_keygen::<u64, U64NttTable>(c, "ntt", PbsOrder::BootstrapKeyswitch);
    stages::<u64, U64NttTable>(c, "ntt");
}
