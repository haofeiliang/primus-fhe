//! Complete CBS in both PBS orders: input preparation, BR, projection and scheme switching.
//! Fixed u64 functional fixture, not production parameters. Setup is outside timing.
//!
//! cargo bench -p primus_tfhe_glwe_ntt --bench circuit_bootstrap

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GgswParameters, GlweParameters, SecretKeyDistr};
use primus_lattice::ggsw::NttGgsw;
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U64NttTable};
use primus_tfhe_glwe_ntt::{
    CircuitBootstrapEvaluator, CircuitBootstrapParameters, PbsOrder, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

fn circuit_bootstrap(c: &mut Criterion) {
    const N: usize = 256;
    const Q: u64 = 1_125_899_906_826_241;
    let modulus = BarrettModulus::new(Q);
    for (order, name) in [
        (PbsOrder::BootstrapKeyswitch, "bootstrap_keyswitch"),
        (PbsOrder::KeyswitchBootstrap, "keyswitch_bootstrap"),
    ] {
        let glwe = GlweParameters::new(1, N, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
        let parameters = TfheParameters::try_new(
            LweParameters::new(4, 4, modulus, SecretKeyDistr::UniformBinary, 0.7),
            glwe.clone(),
            ApproxSignedBasis::new(Some(Q), 10, None),
            ApproxSignedBasis::new(Some(Q), 10, Some(4)),
            order,
        )
        .unwrap();
        let table = U64NttTable::new(N.trailing_zeros(), modulus).unwrap();
        let context = TfheContext::try_new(parameters, table).unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        let (client, server) = context.try_generate_keys(None, &mut rng).unwrap();
        let input = context
            .encryptor(&client)
            .unwrap()
            .encrypt_padded(1u64, &mut rng)
            .unwrap();
        for levels in [2, 3] {
            let parameters = CircuitBootstrapParameters::try_new(
                context.parameters(),
                ApproxSignedBasis::new(Some(Q), 9, Some(levels)),
                GgswParameters::with_glwe_params(&glwe, 10, None),
                GgswParameters::with_glwe_params(&glwe, 10, None),
            )
            .unwrap();
            // Reuse ordinary PBS material across the output-basis sweep.
            let key = context
                .try_generate_circuit_bootstrap_key(&client, parameters.clone(), &mut rng)
                .unwrap();
            let mut evaluator =
                CircuitBootstrapEvaluator::try_from_parts(&context, &server, &parameters, &key)
                    .unwrap();
            let mut output = NttGgsw::<Vec<u64>>::zero(parameters.output_size().ggsw_len());
            let mut group = c.benchmark_group(format!(
                "glwe_ntt/cbs/{name}/u64/n{N}/small_lwe4/output_logb9_l{levels}"
            ));
            group.bench_function("reused_output", |b| {
                b.iter(|| {
                    evaluator.circuit_bootstrap_to(black_box(&input), black_box(&mut output));
                    black_box(&output);
                });
            });
            group.finish();
        }
    }
}

criterion_group!(benches, circuit_bootstrap);
criterion_main!(benches);
