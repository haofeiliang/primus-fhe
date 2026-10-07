//! Explicit u64 setup diagnostics: dense binary/ternary and fixed-weight classic/sparse keygen.
//! Generation includes allocations; returned-key destruction is outside timing.
//! Run: cargo bench -p primus_tfhe_benchmarks --bench setup --features ntru-ntt

use primus_tfhe_benchmarks::measurement::{Case, Group, metadata};
use std::hint::black_box;

use criterion::BatchSize;
use primus_integer::FheUint;
use primus_modulus::PowOf2Modulus;
use primus_ntru::SecretKeyDistr;
use primus_ntt::{MonomialNttTable, U64NttTable};
use primus_tfhe_benchmarks::parameters::ntt_modulus;
use primus_tfhe_benchmarks::{benchmark::PBS_WORKLOADS, parameters::ntru};
use primus_tfhe_ntru_ntt::{BlindRotationConfig, KeyGenerator, TfheContext};
use rand::{SeedableRng, rngs::StdRng};

// Keygen keeps one Boolean-sized fixture per secret distribution.
fn keygen<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    c: &mut Group<'_>,
    backend: &str,
    ternary: bool,
) {
    let workload = PBS_WORKLOADS[0];
    let secret = if ternary {
        SecretKeyDistr::UniformTernary
    } else {
        SecretKeyDistr::UniformBinary
    };
    let kind = if ternary { "ternary" } else { "binary" };
    let name = format!("{kind}/{}", workload.name);
    let parameters = ntru::pbs(ntt_modulus::<T>(), workload, secret);
    let fixture = std::cell::LazyCell::new(|| {
        let context =
            TfheContext::<T, Table, PowOf2Modulus<T>>::try_from_parameters(parameters).unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        let client = KeyGenerator::new(&context)
            .try_generate_client_key(&mut rng)
            .unwrap();
        (context, client)
    });
    let case = Case::new("ntru", backend, T::BITS, format!("{name}/server_keygen"));
    c.bench_function(case.id(), |b| {
        let (context, client) = &*fixture;
        let mut generator = KeyGenerator::new(context);
        let mut rng = StdRng::seed_from_u64(4242);

        metadata::record("setup", &case, || {
            serde_json::json!({
                "parameters": metadata::ntru(context.parameters()),
                "blind_rotation": metadata::blind_rotation(false),
                "drop": "outside keygen timing; stage buffers outside timing",
            })
        });
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
fn fixed_weight_keygen<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    c: &mut Group<'_>,
    backend: &str,
) {
    let parameters = ntru::diagnostic(ntt_modulus::<T>());
    let name = "fixed_weight";
    let fixture = std::cell::LazyCell::new(|| {
        let context =
            TfheContext::<T, Table, PowOf2Modulus<T>>::try_from_parameters(parameters).unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        let client = KeyGenerator::new(&context)
            .try_generate_client_key(&mut rng)
            .unwrap();
        (context, client)
    });
    for sparse in [false, true] {
        let kind = if sparse { "sparse" } else { "classic" };
        let case = Case::new(
            "ntru",
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
                    "parameters": metadata::ntru(context.parameters()),
                    "blind_rotation": metadata::blind_rotation(sparse),
                    "drop": "outside keygen timing; stage buffers outside timing",
                })
            });
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

pub fn bench_setup(c: &mut Group<'_>) {
    for ternary in [false, true] {
        keygen::<u64, U64NttTable>(c, "ntt", ternary);
    }
    fixed_weight_keygen::<u64, U64NttTable>(c, "ntt");
}
