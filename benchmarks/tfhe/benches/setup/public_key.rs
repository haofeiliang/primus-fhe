//! External LWE public-key generation for GLWE TFHE in both PBS orders.
//! Uses existing dense Boolean profiles; parameter and client generation is setup.
//! Run: cargo bench -p primus_tfhe_benchmarks --bench setup --features glwe-ntt,glwe-fourier -- 'public_key/'

use criterion::BatchSize;
use primus_reduce::RingContext;
use primus_tfhe_benchmarks::{
    benchmark::PBS_WORKLOADS,
    measurement::{Case, Group, metadata},
    parameters::glwe,
};
use primus_tfhe_glwe::{ClientKey, Lwe, PbsOrder, PbsParameters};
use rand::{SeedableRng, rngs::StdRng};
use std::{cell::LazyCell, hint::black_box};

// A public key encrypts zero rows in the external LWE domain. No NTT/FFT
// environment is needed; the modulus label identifies the actual arithmetic.
fn register<M: RingContext<u64>>(
    group: &mut Group<'_>,
    modulus_name: &str,
    parameters: fn(PbsOrder) -> PbsParameters<u64, M>,
) {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let fixture = LazyCell::new(|| {
            let parameters = parameters(order);
            let client = ClientKey::generate(&parameters, &mut StdRng::seed_from_u64(42));
            (parameters, client)
        });
        let case = Case::new(
            "glwe",
            modulus_name,
            64,
            format!("public_key/boolean/{order:?}/generate"),
        );
        group.bench_function(case.id(), |b| {
            let (parameters, client) = &*fixture;
            let secret = client.external_lwe_secret_key();
            let mut rng = StdRng::seed_from_u64(4242);
            // Untimed probe: row zero must decrypt to zero under the external secret.
            let public = parameters
                .try_generate_public_key(secret, &mut rng)
                .unwrap();
            let row_len = public.dimension().ciphertext_len();
            assert_eq!(
                parameters
                    .pbs_decryptor(secret)
                    .unwrap()
                    .decrypt(Lwe::new(&public.as_slice()[..row_len]))
                    .unwrap(),
                0,
            );
            drop(public);
            metadata::record("setup", &case, || {
                serde_json::json!({
                    "parameters": metadata::glwe(parameters),
                    "generation": "external LWE public key; coefficient arithmetic only",
                    "drop": "outside timing; includes output allocation and all zero rows",
                })
            });
            b.iter_batched(
                || (),
                |()| {
                    parameters
                        .try_generate_public_key(black_box(secret), &mut rng)
                        .unwrap()
                },
                BatchSize::PerIteration,
            );
        });
    }
}

pub fn bench_generation(group: &mut Group<'_>) {
    #[cfg(feature = "glwe-ntt")]
    register(group, "barrett", |order| {
        glwe::ntt_pbs(order, PBS_WORKLOADS[0])
    });
    #[cfg(feature = "glwe-fourier")]
    register(group, "native", |order| {
        glwe::fourier_pbs(order, PBS_WORKLOADS[0])
    });
}
