//! Dense binary/ternary PBS and server-key generation. One iteration is one operation.
//! LUTs, encryption, output allocation and validation are excluded; keygen includes
//! its allocations, with returned-key destruction outside the timer.
//! Parameters: primus_tfhe_test_support::parameters (arithmetic cost profiles).
//! Fixtures are initialized only for selected IDs, then reused across samples.
//! Run: cargo bench -p primus_tfhe_glwe_ntt --bench pbs

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use primus_glwe::SecretKeyDistr;
use primus_glwe::{GlweCiphertext, NttGlweKeySwitchingWorkspace};
use primus_integer::FheUint;
use primus_lwe::LweCiphertext;
use primus_ntt::{MonomialNttTable, U32NttTable, U64NttTable};
use primus_tfhe_glwe_ntt::{BootstrappingKey, NttGlweBlindRotationWorkspace};
use primus_tfhe_glwe_ntt::{ClientKey, KeyGenerator, PbsOrder, TfheContext};
use primus_tfhe_test_support::parameters::ntt_circuit_modulus;
use primus_tfhe_test_support::{
    benchmark::{PBS_WORKLOADS, PbsWorkload},
    parameters::glwe,
};
use rand::{SeedableRng, rngs::StdRng};

// The ternary profile has its own decomposition/noise budget. Its timing must
// not be divided by the binary timing to claim a secret-distribution speedup.
fn backend<T, Table>(
    c: &mut Criterion,
    backend: &str,
    order: PbsOrder,
    workload: PbsWorkload,
    ternary: bool,
) where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
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
        glwe::circuit(ntt_circuit_modulus::<T>(), order, secret)
    } else {
        glwe::ntt_pbs::<T>(order, workload)
    };
    // Cached owned state avoids both eager setup during --list and repeated key
    // generation for each Criterion sample. Evaluators borrow this state locally.
    let mut fixture = None;
    let mut verified = false;
    c.bench_function(&format!("{name}/complete"), |b| {
        let (context, client, server, input, lut) = fixture.get_or_insert_with(|| {
            let context = TfheContext::<T, Table>::try_from_parameters(parameters.clone()).unwrap();
            let mut rng = StdRng::seed_from_u64(42);
            let (client, server) = context.try_generate_keys(None, &mut rng).unwrap();
            let input = context
                .encryptor(&client)
                .unwrap()
                .encrypt_padded(T::ONE, &mut rng)
                .unwrap();
            let domain = workload.plaintext_modulus as usize / 2;
            let lut = context
                .parameters()
                .compile_lookup_table_fn(|x| T::as_from((x + domain - 1) % domain))
                .unwrap();
            (context, client, server, input, lut)
        });
        let mut evaluator = context.evaluator(server).unwrap();
        let mut output = context.allocate_lwe_ciphertext();
        if !verified {
            evaluator.apply_lookup_table_to(input, lut, &mut output);
            assert_eq!(
                context.decryptor(client).unwrap().decrypt(&output).unwrap(),
                T::ZERO
            );
            verified = true;
        }
        b.iter(|| {
            evaluator.apply_lookup_table_to(
                black_box(input),
                black_box(lut),
                black_box(&mut output),
            )
        });
    });

    // Release the evaluation fixture before measuring generation of new keys.
    drop(fixture);

    // One keygen geometry per secret/word/backend is enough; changing the PBS
    // order does not change the generation algorithm.
    if workload.plaintext_modulus != 4 || order != PbsOrder::BootstrapKeyswitch {
        return;
    }
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
                    .try_generate_server_key(black_box(client), None, &mut rng)
                    .unwrap()
            },
            BatchSize::PerIteration,
        );
    });
}

// Keep one representative BR/GLWE-KS split to diagnose a complete-PBS regression.
// Both kernels read fixed inputs and overwrite outputs; extraction and the
// prerequisite BR are setup only. Full PBS above covers both execution orders.
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
                let poly_length = parameters.accumulator_glwe().poly_length();
                let modulus = parameters.accumulator_glwe().cipher_modulus();
                let mut rng = StdRng::seed_from_u64(43);
                let input = context
                    .encryptor(client)
                    .unwrap()
                    .encrypt_padded(T::ONE, &mut rng)
                    .unwrap();
                let lookup_table = parameters
                    .compile_lookup_table_fn(|m| T::as_from(m ^ 1))
                    .unwrap();
                let BootstrappingKey::Classic(bootstrapping_key) = server_key.bootstrapping_key()
                else {
                    panic!("stage fixture requires classic PBS");
                };
                let mut blind_rotation = NttGlweBlindRotationWorkspace::new(bootstrapping_key);
                let mut key_switching = NttGlweKeySwitchingWorkspace::new(
                    parameters.glwe_key_switching().output().size().glwe_size(),
                );
                let mut main_glwe: GlweCiphertext<Vec<T>> =
                    GlweCiphertext::zero(parameters.accumulator_glwe().glwe_len());
                let mut switched: GlweCiphertext<Vec<T>> =
                    GlweCiphertext::zero(parameters.glwe_key_switching().output().glwe_len());
                let mut small_lwe: LweCiphertext<T> =
                    LweCiphertext::zero(parameters.small_lwe().dimension());

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
                switched.extract_compact_lwe_to(&mut small_lwe, poly_length, modulus);
                if !verified {
                    assert_eq!(
                        context
                            .decryptor(client)
                            .unwrap()
                            .decrypt(&small_lwe)
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

fn bench_pbs(c: &mut Criterion) {
    stages::<u32, U32NttTable>(c, "ntt");
    stages::<u64, U64NttTable>(c, "ntt");

    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        for workload in PBS_WORKLOADS {
            backend::<u32, U32NttTable>(c, "ntt", order, workload, false);
            backend::<u64, U64NttTable>(c, "ntt", order, workload, false);
        }
        backend::<u32, U32NttTable>(c, "ntt", order, PBS_WORKLOADS[0], true);
        backend::<u64, U64NttTable>(c, "ntt", order, PBS_WORKLOADS[0], true);
    }
}

criterion_group!(benches, bench_pbs);
criterion_main!(benches);
