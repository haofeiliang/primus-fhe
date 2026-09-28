//! Dense binary/ternary PBS and server-key generation. One iteration is one operation.
//! LUTs, encryption, output allocation and validation are excluded; keygen includes
//! its allocations, with returned-key destruction outside the timer.
//! Parameters: primus_tfhe_test_support::parameters (arithmetic cost profiles).
//! Fixtures are initialized only for selected IDs, then reused across samples.
//! Run: cargo bench -p primus_tfhe_ntru_fourier --bench pbs

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use primus_fft::{FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_modulus::NativeModulus;
use primus_modulus::PowOf2Modulus;
use primus_ntru::SecretKeyDistr;
use primus_tfhe_ntru_fourier::{KeyGenerator, TfheContext};
use primus_tfhe_test_support::{
    benchmark::{PBS_WORKLOADS, PbsWorkload},
    parameters::ntru,
};
use rand::{SeedableRng, rngs::StdRng};

// The ternary profile has its own decomposition/noise budget. Its timing must
// not be divided by the binary timing to claim a secret-distribution speedup.
fn backend<T: TorusFftValue, Table: FftTable>(
    c: &mut Criterion,
    backend: &str,
    workload: PbsWorkload,
    ternary: bool,
) {
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
    // Cached owned state avoids both eager setup during --list and repeated key
    // generation for each Criterion sample. Evaluators borrow this state locally.
    let mut fixture = None;
    let mut verified = false;
    c.bench_function(&format!("{name}/complete"), |b| {
        let (context, client, server, input, lut) = fixture.get_or_insert_with(|| {
            let context =
                TfheContext::<T, Table, PowOf2Modulus<T>>::try_from_parameters(parameters.clone())
                    .unwrap();
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
    if workload.plaintext_modulus != 4 {
        return;
    }
    let mut fixture = None;
    c.bench_function(&format!("{name}/server_keygen"), |b| {
        let (context, client) = fixture.get_or_insert_with(|| {
            let context =
                TfheContext::<T, Table, PowOf2Modulus<T>>::try_from_parameters(parameters.clone())
                    .unwrap();
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
                    .try_generate_server_key(black_box(client), None, &mut rng)
                    .unwrap()
            },
            BatchSize::PerIteration,
        );
    });
}

fn bench_pbs(c: &mut Criterion) {
    for workload in PBS_WORKLOADS {
        backend::<u32, RustFftTable>(c, "rustfft", workload, false);
        backend::<u64, RustFftTable>(c, "rustfft", workload, false);
        backend::<u32, TfheFftTable>(c, "tfhe_fft", workload, false);
        backend::<u64, TfheFftTable>(c, "tfhe_fft", workload, false);
    }
    backend::<u32, RustFftTable>(c, "rustfft", PBS_WORKLOADS[0], true);
    backend::<u64, RustFftTable>(c, "rustfft", PBS_WORKLOADS[0], true);
    backend::<u32, TfheFftTable>(c, "tfhe_fft", PBS_WORKLOADS[0], true);
    backend::<u64, TfheFftTable>(c, "tfhe_fft", PBS_WORKLOADS[0], true);
}

criterion_group!(benches, bench_pbs);
criterion_main!(benches);
