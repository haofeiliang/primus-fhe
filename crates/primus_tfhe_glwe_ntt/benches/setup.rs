//! Explicit u64 setup diagnostics: dense binary/ternary and fixed-weight classic/sparse keygen.
//! Generation includes allocations; returned-key destruction is outside timing.
//! Separate raw BR/GLWE-KS timings exclude prerequisite work and extraction.
//! Run: cargo bench -p primus_tfhe_glwe_ntt --bench setup

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use primus_glwe::SecretKeyDistr;
use primus_glwe::{GlweCiphertext, NttGlweKeySwitchingWorkspace};
use primus_integer::FheUint;
use primus_lwe::LweCiphertext;
use primus_ntt::{MonomialNttTable, U64NttTable};
use primus_tfhe_glwe_ntt::{BlindRotationConfig, BlindRotationKey, NttGlweBlindRotationWorkspace};
use primus_tfhe_glwe_ntt::{ClientKey, KeyGenerator, PbsOrder, TfheContext};
use primus_tfhe_test_support::parameters::{ntt_circuit_modulus, ntt_modulus};
use primus_tfhe_test_support::{benchmark::PBS_WORKLOADS, parameters::glwe};
use rand::{SeedableRng, rngs::StdRng};

// Keygen uses the Boolean geometry; PBS order does not change generation.
fn keygen<T, Table>(c: &mut Criterion, backend: &str, ternary: bool)
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
    let name = format!(
        "glwe/{backend}/u{}/{kind}/{}/n{}_N{}/{order:?}",
        T::BITS,
        workload.name,
        workload.lwe_dimension,
        workload.poly_length
    );
    let parameters = if ternary {
        glwe::circuit(ntt_circuit_modulus::<T>(), order, secret)
    } else {
        glwe::ntt_pbs::<T>(order, workload)
    };
    let mut fixture = None;
    c.bench_function(&format!("{name}/server_keygen"), |b| {
        let (context, client) = fixture.get_or_insert_with(|| {
            let context = TfheContext::<T, Table>::try_from_parameters(parameters.clone()).unwrap();
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
// prerequisite BR are setup only. The `pbs` target covers both execution orders.
fn stages<T: FheUint, Table: MonomialNttTable<ValueT = T>>(c: &mut Criterion, backend: &str) {
    let mut fixture = None;
    for stage in ["glwe_key_switching", "blind_rotation"] {
        let mut verified = false;
        c.bench_function(
            &format!("glwe/{backend}/u{}/stages/n800_N1024/{stage}", T::BITS),
            |b| {
                let (context, client, server_key) = fixture.get_or_insert_with(|| {
                    let context = TfheContext::<T, Table>::try_from_parameters(glwe::ntt_pbs(
                        PbsOrder::BootstrapKeyswitch,
                        PBS_WORKLOADS[0],
                    ))
                    .unwrap();
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
                let modulus = parameters.blind_rotation_ggsw().cipher_modulus();
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
                let mut blind_rotation = NttGlweBlindRotationWorkspace::new(bootstrapping_key);
                let mut key_switching = NttGlweKeySwitchingWorkspace::new(
                    parameters.glwe_key_switching().output().size().glwe_size(),
                );
                let mut main_glwe: GlweCiphertext<Vec<T>> =
                    GlweCiphertext::zero(parameters.blind_rotation_ggsw().glwe_len());
                let mut switched: GlweCiphertext<Vec<T>> =
                    GlweCiphertext::zero(parameters.glwe_key_switching().output().glwe_len());
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
            },
        );
    }
}

// Keygen pairs share a fixed client and separately seeded key-generation RNG.
fn fixed_weight_keygen<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    c: &mut Criterion,
    backend: &str,
    order: PbsOrder,
) {
    let parameters = glwe::diagnostic(ntt_modulus::<T>(), order);
    let name = format!(
        "glwe/{backend}/u{}/fixed_weight/n728_h32_N1024/{order:?}",
        T::BITS
    );
    let mut fixture = None;
    for sparse in [false, true] {
        let kind = if sparse { "sparse" } else { "classic" };
        c.bench_function(&format!("{name}/{kind}/server_keygen"), |b| {
            let (context, client) = fixture.get_or_insert_with(|| {
                let context =
                    TfheContext::<T, Table>::try_from_parameters(parameters.clone()).unwrap();
                let mut rng = StdRng::seed_from_u64(42);
                let client = ClientKey::generate(context.parameters(), &mut rng);
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

fn bench_setup(c: &mut Criterion) {
    for ternary in [false, true] {
        keygen::<u64, U64NttTable>(c, "ntt", ternary);
    }
    fixed_weight_keygen::<u64, U64NttTable>(c, "ntt", PbsOrder::BootstrapKeyswitch);
    stages::<u64, U64NttTable>(c, "ntt");
}

criterion_group!(benches, bench_setup);
criterion_main!(benches);
