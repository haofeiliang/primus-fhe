//! Complete CBS: one BR, reverse-trace projections and NLev-to-NGSW conversion.
//! u64 functional workloads, not security parameter recommendations. Setup and
//! memory accounting are outside timing; no post-BR ring key switch/extraction.
//! cargo bench -p primus_tfhe_ntru_ntt --bench circuit_bootstrap -- 'n1024/logb10'

use criterion::{Criterion, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntru::{NlevParameters, NtruParameters, NttNgswCiphertext, SecretKeyDistr};
use primus_ntt::{NttTable, U64NttTable};
use primus_test_allocations as allocations;
use primus_tfhe_ntru_ntt::{
    CircuitBootstrapEvaluator, CircuitBootstrapParameters, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};
use std::{hint::black_box, time::Duration};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

fn circuit_bootstrap(c: &mut Criterion) {
    let modulus = BarrettModulus::new(1_125_899_906_826_241u64);
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
            let context = TfheContext::try_new(
                parameters,
                U64NttTable::new(n.trailing_zeros(), modulus).unwrap(),
            )
            .unwrap();
            let mut rng = StdRng::seed_from_u64(42);
            let (client, server) = context.try_generate_keys(None, &mut rng).unwrap();
            let input = context
                .encryptor(&client)
                .unwrap()
                .encrypt_padded(1u64, &mut rng)
                .unwrap();
            // Standalone CBS generation isolates its heap cost from ordinary PBS keys.
            let (key, key_memory) = allocations::measure(|| {
                context
                    .try_generate_circuit_bootstrap_key(&client, cbs.clone(), &mut rng)
                    .unwrap()
            });
            let (mut evaluator, workspace_memory) = allocations::measure(|| {
                CircuitBootstrapEvaluator::try_from_parts(&context, &server, &key).unwrap()
            });
            let mut output = NttNgswCiphertext::<Vec<u64>>::zero(cbs.output_nlev_len());
            let name = format!(
                "ntru_ntt/cbs/n{n}/logb{log_basis}/dim{}/output_logb8_l2",
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

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20)
        .warm_up_time(Duration::from_secs(1)).measurement_time(Duration::from_secs(2));
    targets = circuit_bootstrap
}
criterion_main!(benches);
