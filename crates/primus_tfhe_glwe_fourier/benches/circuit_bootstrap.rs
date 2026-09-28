//! One complete CBS into a reused gadget ciphertext. Keygen, encryption,
//! allocation and the CMux correctness probe are outside timing; t=4.
//! Parameters: primus_tfhe_test_support::parameters (arithmetic cost profiles).
//! Fixtures are initialized only for selected IDs, then reused across samples.
//! Run: cargo bench -p primus_tfhe_glwe_fourier --bench circuit_bootstrap

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_fft::{FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_glwe::SecretKeyDistr;
use primus_modulus::NativeModulus;
use primus_tfhe_glwe_fourier::{
    CircuitBootstrapEvaluator, ClientKey, KeyGenerator, PbsOrder, TfheContext,
};
use primus_tfhe_test_support::parameters::{N, glwe};
use rand::{SeedableRng, rngs::StdRng};

// CBS consumes a bit and emits a gadget control, not an LWE result. Verify
// that representation by selecting an encrypted ring message before timing.
fn ordinary<T, Table>(c: &mut Criterion, backend: &str, order: PbsOrder, sparse: bool)
where
    T: TorusFftValue,
    Table: FftTable,
{
    let kind = if sparse { "sparse" } else { "classic" };
    let dimension = if sparse { 728 } else { 800 };
    let parameters = if sparse {
        glwe::diagnostic(NativeModulus::<T>::new(), order, 4)
    } else {
        glwe::circuit(
            NativeModulus::<T>::new(),
            order,
            SecretKeyDistr::UniformBinary,
        )
    };
    let name = format!(
        "glwe/{backend}/u{}/cbs/{kind}/n{dimension}_N1024/{order:?}/complete",
        T::BITS
    );
    let mut fixture = None;
    let mut verified = false;
    c.bench_function(&name, |b| {
        let (context, client, server, input, lhs, rhs) = fixture.get_or_insert_with(|| {
            let context = TfheContext::<T, Table>::try_from_parameters(parameters.clone()).unwrap();
            let mut rng = StdRng::seed_from_u64(42);
            let mut generator = KeyGenerator::new(&context);
            let client = ClientKey::generate(context.parameters(), &mut rng);
            let server = if sparse {
                generator
                    .try_generate_sparse_server_key(
                        &client,
                        3,
                        64,
                        Some(glwe::cbs::<T>()),
                        &mut rng,
                    )
                    .unwrap()
            } else {
                generator
                    .try_generate_server_key(&client, Some(glwe::cbs::<T>()), &mut rng)
                    .unwrap()
            };
            let input = context
                .encryptor(&client)
                .unwrap()
                .encrypt_padded(T::ONE, &mut rng)
                .unwrap();
            let mut ring = context.accumulator_client(&client).unwrap();
            let lhs = ring.encrypt(&[T::ZERO; N], &mut rng);
            let rhs = ring.encrypt(&[T::ONE; N], &mut rng);
            (context, client, server, input, lhs, rhs)
        });
        let mut evaluator = CircuitBootstrapEvaluator::try_new(context, server).unwrap();
        let mut output = evaluator.allocate_output();
        if !verified {
            evaluator.circuit_bootstrap_to(input, &mut output);
            let mut selected = context.allocate_accumulator_ciphertext();
            evaluator.cmux_to(&output, lhs, rhs, &mut selected);
            let mut decoded = vec![T::ZERO; N];
            context
                .accumulator_client(client)
                .unwrap()
                .decrypt_to(&selected, &mut decoded);
            assert!(decoded.iter().all(|&value| value == T::ONE));
            verified = true;
        }
        b.iter(|| evaluator.circuit_bootstrap_to(black_box(input), black_box(&mut output)));
    });
}

fn bench_cbs(c: &mut Criterion) {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        for sparse in [false, true] {
            ordinary::<u32, RustFftTable>(c, "rustfft", order, sparse);
            ordinary::<u64, RustFftTable>(c, "rustfft", order, sparse);
            ordinary::<u32, TfheFftTable>(c, "tfhe_fft", order, sparse);
            ordinary::<u64, TfheFftTable>(c, "tfhe_fft", order, sparse);
        }
    }
}

criterion_group!(benches, bench_cbs);
criterion_main!(benches);
