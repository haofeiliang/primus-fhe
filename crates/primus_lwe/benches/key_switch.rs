// cargo bench -p primus_lwe --bench key_switch
// cargo +nightly bench -p primus_lwe --bench key_switch --features simd

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_lattice::lwe::Lwe;
use primus_lwe::{
    LweKeySwitchingKey, LweKeySwitchingParameters, LweParameters, LweSecretKey, SecretKeyDistr,
};
use primus_modulus::BarrettModulus;
use rand::distr::{Distribution, Uniform};

const CIPHERTEXT_MODULUS: u32 = 132_120_577;
const OUTPUT_DIMENSION: usize = 800;
const LOG_BASIS: u32 = 2;
const LEVEL_COUNT: usize = 13;

fn bench_key_switch(c: &mut Criterion) {
    let modulus = BarrettModulus::new(CIPHERTEXT_MODULUS);
    let output_parameters =
        LweParameters::new(OUTPUT_DIMENSION, 4, modulus, SecretKeyDistr::Binary, 0.7);
    let basis = ApproxSignedBasis::new(Some(CIPHERTEXT_MODULUS), LOG_BASIS, Some(LEVEL_COUNT));
    let mut rng = rand::rng();
    let output_secret_key = LweSecretKey::generate(&output_parameters, &mut rng);
    let uniform = Uniform::new(0, CIPHERTEXT_MODULUS).unwrap();
    let mut group = c.benchmark_group("lwe_key_switch/u32/explicit");
    group.sample_size(10);

    for input_dimension in [1024, 2048] {
        let parameters =
            LweKeySwitchingParameters::new(input_dimension, OUTPUT_DIMENSION, basis.clone());
        let input_secret_key = vec![1u32; input_dimension];
        let key = LweKeySwitchingKey::generate(
            &input_secret_key,
            &output_secret_key,
            &output_parameters,
            &parameters,
            &mut rng,
        );
        let mut input: Lwe<Vec<u32>> = Lwe::zero(input_dimension);
        input
            .0
            .iter_mut()
            .zip(uniform.sample_iter(&mut rng))
            .for_each(|(output, sample)| *output = sample);
        let mut output: Lwe<Vec<u32>> = Lwe::zero(OUTPUT_DIMENSION);

        group.bench_with_input(
            BenchmarkId::new(
                format!("n{input_dimension}_to_n{OUTPUT_DIMENSION}"),
                format!("logB{LOG_BASIS}_L{LEVEL_COUNT}"),
            ),
            &input_dimension,
            |bencher, _| {
                bencher.iter(|| {
                    key.key_switch_to(
                        black_box(&input),
                        black_box(&mut output),
                        black_box(modulus),
                    );
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_key_switch);
criterion_main!(benches);
