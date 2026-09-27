//! Complete u32/u64 CBS at n=728, N=1024: BR, reverse trace and scheme switching.
//! Functional/cost profiles, not security parameter recommendations. Key generation,
//! four encrypted inputs, correctness checks and allocation stay outside timing.
//! u32 uses logb=3 for BR/trace/scheme switching and output (4,2);
//! u64 retains logb=10 and output (8,2). Both use full decomposition internally.
//!
//! cargo bench -p primus_tfhe_ntru_fourier --bench circuit_bootstrap

use criterion::{Criterion, SamplingMode, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_integer::AsInto;
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_ntru::{
    FourierNtruDecryptContext, FourierNtruSecretKey, NlevParameters, NtruParameters, SecretKeyDistr,
};
use primus_poly::Polynomial;
use primus_test_allocations as allocations;
use primus_tfhe_ntru_fourier::{
    CircuitBootstrapEvaluator, CircuitBootstrapParameters, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};
use std::{hint::black_box, time::Duration};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

const N: usize = 1024;
const DIMENSION: usize = 728;

fn backend<T: TorusFftValue, Table: FftTable>(
    c: &mut Criterion,
    backend: &str,
    log_basis: u32,
    output_log_basis: u32,
) {
    let modulus = NativeModulus::<T>::new();
    let q128 = 1i128 << T::BITS;
    let acc = NtruParameters::new(
        N,
        T::as_from(4u32),
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );

    let parameters = TfheParameters::try_new(
        LweParameters::new(
            DIMENSION,
            T::as_from(4u32),
            modulus,
            SecretKeyDistr::UniformBinary,
            0.7,
        ),
        NlevParameters::with_ntru_params(&acc, log_basis, None),
        primus_tfhe_ntru::DecompositionConfig {
            log_basis,
            level_count: None,
        },
        0.7,
    )
    .unwrap();
    let cbs = CircuitBootstrapParameters::try_new(
        &parameters,
        ApproxSignedBasis::new(acc.cipher_modulus_value(), output_log_basis, Some(2)),
        NlevParameters::with_ntru_params(&acc, log_basis, None),
        NlevParameters::with_ntru_params(&acc, log_basis, None),
    )
    .unwrap();
    let context =
        TfheContext::try_new(parameters, Table::new(N.trailing_zeros()).unwrap()).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let (client, server) = context.try_generate_keys(None, &mut rng).unwrap();
    let bits = [0usize, 1, 0, 1];
    let inputs = bits.map(|bit| {
        context
            .encryptor(&client)
            .unwrap()
            .encrypt_padded(T::as_from(bit), &mut rng)
            .unwrap()
    });
    let (key, key_memory) = allocations::measure(|| {
        context
            .try_generate_circuit_bootstrap_key(&client, cbs.clone(), &mut rng)
            .unwrap()
    });
    let (mut evaluator, workspace_memory) = allocations::measure(|| {
        CircuitBootstrapEvaluator::try_from_parts(&context, &server, &key).unwrap()
    });
    let mut output = evaluator.allocate_output();
    let name = format!(
        "ntru_fourier/{backend}/cbs/u{}/n{DIMENSION}/N{N}/logb{log_basis}/output_logb{output_log_basis}_l2",
        T::BITS
    );
    // Net requested heap excludes allocator metadata, shared tables, ordinary
    // server keys and caller output; temporary generation allocations cancel.
    eprintln!(
        "{name}: cbs_key_heap={} evaluator_heap={} output_bytes={}",
        key_memory.allocated_bytes - key_memory.released_bytes,
        workspace_memory.allocated_bytes - workspace_memory.released_bytes,
        size_of_val(output.as_ref())
    );
    let messages = [0usize, 1].map(|offset| {
        (0..N)
            .map(|i| T::as_from((i + offset) % 4))
            .collect::<Vec<_>>()
    });
    let mut accumulator = context.accumulator_client(&client).unwrap();
    let choices = messages.each_ref().map(|message| {
        let mut ciphertext = context.allocate_accumulator_ciphertext();
        accumulator.encrypt_to(message, &mut ciphertext, &mut rng);
        ciphertext
    });
    let mut selected = context.allocate_accumulator_ciphertext();
    let mut decoded = vec![T::ZERO; N];
    let mut phase = Polynomial::<Vec<T>>::zero(N);
    let mut fft = context.new_fft_engine();
    let secret = FourierNtruSecretKey::try_from_coeff_secret_key(
        client.accumulator_ntru_secret_key(),
        &mut fft,
    )
    .unwrap();
    let mut decrypt = FourierNtruDecryptContext::new(N);
    // Check both bit values, every gadget scale and a nonconstant CMUX before timing.
    for (&bit, input) in bits.iter().zip(&inputs) {
        let (_, online) = allocations::measure(|| {
            evaluator.circuit_bootstrap_to(input, &mut output);
            evaluator.cmux_to(&output, &choices[0], &choices[1], &mut selected);
            accumulator.decrypt_to(&selected, &mut decoded);
        });
        assert_eq!(online.count, 0);
        assert_eq!(decoded, messages[bit], "{name}: CMUX bit={bit}");
        for (scalar, level) in cbs
            .output_basis()
            .scalar_iter()
            .zip(output.iter_ntru(N / 2))
        {
            secret.phase_to(&level, &mut phase, &mut fft, &mut decrypt);
            let scalar: i128 = scalar.as_into();
            for (&actual, &f) in phase
                .as_ref()
                .iter()
                .zip(client.accumulator_ntru_secret_key().as_slice())
            {
                let f: i128 = f.as_into();
                let actual: i128 = actual.as_into();
                let expected = (scalar * f * bit as i128).rem_euclid(q128);
                let error = (actual - expected).rem_euclid(q128);
                assert!(
                    error.min(q128 - error) < scalar / 8,
                    "{name}: gadget phase bit={bit}, scale={scalar}, error={}",
                    error.min(q128 - error)
                );
            }
        }
    }
    let mut group = c.benchmark_group(&name);
    group.sampling_mode(SamplingMode::Flat);
    let mut next_input = 0;
    group.bench_function("complete", |b| {
        b.iter(|| {
            evaluator.circuit_bootstrap_to(black_box(&inputs[next_input]), black_box(&mut output));
            next_input = (next_input + 1) % inputs.len();
            black_box(output.as_ref());
        });
    });
    group.finish();
}

fn circuit_bootstrap(c: &mut Criterion) {
    backend::<u32, RustFftTable>(c, "rustfft", 3, 4);
    backend::<u64, RustFftTable>(c, "rustfft", 10, 8);
    backend::<u32, TfheFftTable>(c, "tfhe", 3, 4);
    backend::<u64, TfheFftTable>(c, "tfhe", 10, 8);
}
criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20)
        .warm_up_time(Duration::from_secs(1)).measurement_time(Duration::from_secs(5));
    targets = circuit_bootstrap
}
criterion_main!(benches);
