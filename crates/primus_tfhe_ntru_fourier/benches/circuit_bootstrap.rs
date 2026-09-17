//! Complete CBS: one BR, reverse-trace projections and NLev-to-NGSW conversion.
//! u64 functional workloads, not security parameter recommendations. Setup and
//! memory accounting are outside timing; no post-BR ring key switch/extraction.
//! cargo bench -p primus_tfhe_ntru_fourier --bench circuit_bootstrap -- 'n1024/logb10'
#[path = "../../primus_tfhe/tests/support/allocations.rs"]
mod allocations;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftTable, RustFftTable, TfheFftTable};
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_ntru::{FourierNgswCiphertext, NlevParameters, NtruParameters, SecretKeyDistr};
use primus_tfhe_ntru_fourier::{CircuitBootstrapParameters, TfheContext, TfheParameters};
use rand::{SeedableRng, rngs::StdRng};
use std::{hint::black_box, time::Duration};

fn backend<Table: FftTable>(c: &mut Criterion, backend: &str) {
    let modulus = NativeModulus::<u64>::new();
    for n in [1024usize, 4096] {
        for log_basis in [3, 10] {
            let acc = NtruParameters::new(n, 4, modulus, SecretKeyDistr::SparseTernary, 0.7);
            let client = NtruParameters::new(n, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
            let parameters = TfheParameters::try_new(
                LweParameters::new(n / 16, 4, modulus, SecretKeyDistr::UniformBinary, 0.7),
                NlevParameters::with_ntru_params(&acc, log_basis, None),
                NlevParameters::with_ntru_params(&client, log_basis, None),
            )
            .unwrap();
            let cbs = CircuitBootstrapParameters::try_new(
                &parameters,
                ApproxSignedBasis::new(acc.cipher_modulus_value(), 8, Some(2)),
                NlevParameters::with_ntru_params(&acc, log_basis, None),
                NlevParameters::with_ntru_params(&acc, log_basis, None),
            )
            .unwrap();
            let context =
                TfheContext::try_new(parameters, Table::new(n.trailing_zeros()).unwrap()).unwrap();
            let mut rng = StdRng::seed_from_u64(42);
            let (client, server) = context.try_generate_keys(&mut rng).unwrap();
            let input = context
                .encryptor(&client)
                .unwrap()
                .encrypt_padded(1u64, &mut rng)
                .unwrap();
            let (key, key_memory) = allocations::measure(|| {
                context
                    .try_generate_circuit_bootstrap_key(&client, &cbs, &mut rng)
                    .unwrap()
            });
            let (mut evaluator, workspace_memory) = allocations::measure(|| {
                context
                    .circuit_bootstrap_evaluator(&server, &cbs, &key)
                    .unwrap()
            });
            let mut output =
                FourierNgswCiphertext::<Vec<Complex64>>::zero(cbs.output_fourier_nlev_len());
            let name = format!(
                "ntru_fourier/{backend}/cbs/n{n}/logb{log_basis}/dim{}/output_logb8_l2",
                n / 16
            );
            // Live requested heap bytes exclude allocator metadata, shared tables,
            // ordinary server keys and caller output. Generation temporaries cancel.
            eprintln!(
                "{name}: cbs_key_heap={} evaluator_heap={} output_bytes={}",
                key_memory.allocated_bytes - key_memory.released_bytes,
                workspace_memory.allocated_bytes - workspace_memory.released_bytes,
                std::mem::size_of_val(output.as_ref())
            );
            c.bench_function(&name, |b| {
                b.iter(|| {
                    evaluator.circuit_bootstrap_to(black_box(&input), &mut output);
                    black_box(output.as_ref());
                })
            });
        }
    }
}

fn circuit_bootstrap(c: &mut Criterion) {
    backend::<RustFftTable>(c, "rustfft");
    backend::<TfheFftTable>(c, "tfhe");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20)
        .warm_up_time(Duration::from_secs(1)).measurement_time(Duration::from_secs(2));
    targets = circuit_bootstrap
}
criterion_main!(benches);
