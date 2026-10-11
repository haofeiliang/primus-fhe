//! Return k coefficients of one NTRU ciphertext to independent LWEs. One
//! iteration includes Q→q, extraction and all k key switches; setup is excluded.
//! Compare scalar calls with shared conversion and tiled key switching. k=1
//! checks the direct path, k=3 matches ManyLUT, and k=17 crosses two tile ends.
//! cargo bench -p primus_ntru --bench lwe_return
//! Arithmetic profiles match ManyLUT's N1024/n728/q24/logB3 return stage;
//! canonical input coefficients are synthetic, not a noise/security experiment.

use primus_decompose::DecompositionBaseLog;
use primus_lattice::LweDimension;
use primus_shape::PolyLength;
use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lwe::{LweCiphertext, LweParameters, LweSecretKey};
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus};
use primus_ntru::{
    NtruCiphertext, NtruLweKeySwitchingBatchWorkspace, NtruLweKeySwitchingKey,
    NtruLweKeySwitchingWorkspace, NtruSecretKey, SecretKeyDistr,
};
use primus_reduce::RingContext;
use rand::{RngExt, SeedableRng, rngs::StdRng};

const N: usize = 1024;
const DIMENSION: usize = 728;

fn source<T: FheUint, Q: RingContext<T>>(c: &mut Criterion, source: Q, name: &str) {
    let target = PowOf2Modulus::new(T::ONE << 24u32);
    let parameters = LweParameters::new(
        LweDimension::new(DIMENSION),
        T::TWO,
        target,
        SecretKeyDistr::UniformBinary,
        3.2,
    );
    let mut fixture = None;
    for count in [1, 3, 17] {
        let mut group = c.benchmark_group(format!(
            "ntru/lwe_return/{name}/u{}/N{N}_n{DIMENSION}/k{count}",
            T::BITS,
        ));
        group.throughput(Throughput::Elements(count as u64));
        for path in ["individual", "batch"] {
            group.bench_function(path, |b| {
                // Initialize only selected benchmark IDs; --list needs no keys.
                let (key, input) = fixture.get_or_insert_with(|| {
                    let mut rng = StdRng::seed_from_u64(42);
                    let f = NtruSecretKey::new(
                        (0..N)
                            .map(|_| {
                                T::as_from(rng.random_range(0u32..3)).cast_to_signed()
                                    - T::ONE.cast_to_signed()
                            })
                            .collect(),
                        SecretKeyDistr::UniformTernary,
                    );
                    let secret =
                        LweSecretKey::generate(parameters.encryption_parameters(), &mut rng);
                    let key = NtruLweKeySwitchingKey::generate(
                        &f,
                        source,
                        &secret,
                        parameters.encryption_parameters(),
                        ApproxSignedBasis::new(
                            Some(T::ONE << 24u32),
                            DecompositionBaseLog::new(3),
                            None,
                        ),
                        &mut rng,
                    );
                    let uniform = source.uniform_distribution();
                    let input = NtruCiphertext::new(
                        (0..N).map(|_| rng.sample(uniform)).collect::<Vec<_>>(),
                    );
                    (key, input)
                });
                let mut individual = NtruLweKeySwitchingWorkspace::new(PolyLength::new(N));
                let mut batch = NtruLweKeySwitchingBatchWorkspace::new(
                    PolyLength::new(N),
                    LweDimension::new(DIMENSION),
                );
                let mut outputs = vec![LweCiphertext::zero(DIMENSION); count];
                let mut expected = outputs.clone();
                for (index, output) in expected.iter_mut().enumerate() {
                    key.key_switch_at_to(input, index, output, target, &mut individual);
                }
                key.key_switch_many_at_to(input, 0..count, &mut outputs, target, &mut batch);
                assert_eq!(outputs, expected);
                if path == "individual" {
                    b.iter(|| {
                        for (index, output) in outputs.iter_mut().enumerate() {
                            key.key_switch_at_to(
                                black_box(input),
                                index,
                                output,
                                target,
                                &mut individual,
                            );
                        }
                        black_box(&outputs);
                    });
                } else {
                    b.iter(|| {
                        key.key_switch_many_at_to(
                            black_box(input),
                            0..count,
                            &mut outputs,
                            target,
                            &mut batch,
                        );
                        black_box(&outputs);
                    });
                }
            });
        }
        group.finish();
    }
}

fn bench_return(c: &mut Criterion) {
    source(c, BarrettModulus::new(132_120_577u32), "explicit");
    source(c, NativeModulus::<u32>::new(), "native");
    source(c, BarrettModulus::new(1_125_899_906_826_241u64), "explicit");
    source(c, NativeModulus::<u64>::new(), "native");
}

criterion_group!(benches, bench_return);
criterion_main!(benches);
