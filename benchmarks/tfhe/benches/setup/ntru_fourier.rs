//! Explicit u64 setup diagnostics: dense binary/ternary and fixed-weight classic/sparse keygen.
//! Generation includes allocations; returned-key destruction is outside timing.
//! Run: cargo bench -p primus_tfhe_benchmarks --bench setup --features ntru-fourier,rustfft,tfhe-fft

use primus_tfhe_benchmarks::measurement::{Case, Group, metadata};
use std::hint::black_box;

use criterion::BatchSize;
#[cfg(feature = "rustfft")]
use primus_fft::RustFftTable;
#[cfg(all(not(feature = "rustfft"), feature = "tfhe-fft"))]
use primus_fft::TfheFftTable;
use primus_fft::{FftTable, TorusFftValue};
use primus_modulus::NativeModulus;
use primus_modulus::PowOf2Modulus;
use primus_ntru::SecretKeyDistr;
use primus_tfhe_benchmarks::{benchmark::PBS_WORKLOADS, parameters::ntru};
use primus_tfhe_ntru_fourier::{BlindRotationConfig, KeyGenerator, TfheContext};
use rand::{SeedableRng, rngs::StdRng};

// Keygen keeps one Boolean-sized fixture per secret distribution.
fn keygen<T: TorusFftValue, Table: FftTable>(c: &mut Group<'_>, backend: &str, ternary: bool) {
    let workload = PBS_WORKLOADS[0];
    let secret = if ternary {
        SecretKeyDistr::UniformTernary
    } else {
        SecretKeyDistr::UniformBinary
    };
    let kind = if ternary { "ternary" } else { "binary" };
    let name = format!("{kind}/{}", workload.name);
    let parameters = ntru::pbs(NativeModulus::<T>::new(), workload, secret);
    let fixture = std::cell::LazyCell::new(|| {
        let context = TfheContext::<T, Table, PowOf2Modulus<T>>::from_parameters(parameters);
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
                "fft_layout_fingerprint": metadata::fft_layout(context.table()),
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
fn fixed_weight_keygen<T: TorusFftValue, Table: FftTable>(c: &mut Group<'_>, backend: &str) {
    let parameters = ntru::diagnostic(NativeModulus::<T>::new());
    let name = "fixed_weight";
    let fixture = std::cell::LazyCell::new(|| {
        let context = TfheContext::<T, Table, PowOf2Modulus<T>>::from_parameters(parameters);
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
                    "fft_layout_fingerprint": metadata::fft_layout(context.table()),
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
