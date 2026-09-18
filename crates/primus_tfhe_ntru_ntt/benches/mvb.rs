//! Equivalent Scaled threshold outputs from repeated PBS, interleaved ManyLUT
//! (when it fits), and MVB. One iteration evaluates one input into all outputs,
//! including NLev initialization, BR, NTRU KS and compact extraction.
//! Keys, LUTs, inputs, outputs and evaluator workspace are prepared outside timing.
//! Functional cost parameters; NTRU invertibility rejection conditions the secret.
//!
//! cargo bench -p primus_tfhe_ntru_ntt --bench mvb -- --sample-size 20 --warm-up-time 1 --measurement-time 3
//! cargo +nightly bench -p primus_tfhe_ntru_ntt --features simd --bench mvb -- --sample-size 20 --warm-up-time 1 --measurement-time 3

use std::hint::black_box;

use criterion::{Criterion, SamplingMode, criterion_group, criterion_main};
use primus_encoding::{PlaintextEmbedding, ScaledCodec};
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntru::SecretKeyDistr;
use primus_ntt::U32NttTable;
use primus_tfhe_ntru_ntt::{
    DecompositionConfig, InterleavedLookupTable, LookupTable, LookupTableError, LweCiphertext,
    TfheConfig, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

const Q: u32 = 132_120_577;
const N: usize = 1024;
const DIMENSION: usize = 728;

fn context(domain: usize) -> TfheContext<u32, U32NttTable> {
    let parameters = TfheParameters::try_from_config(TfheConfig {
        external_lwe: LweParameters::new(
            DIMENSION,
            (2 * domain) as u32,
            BarrettModulus::new(Q),
            SecretKeyDistr::fixed_hamming_weight_binary(DIMENSION, 32),
            3.2 * f64::from(Q) / 16384.0,
        ),
        poly_length: N,
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 0.7,
        blind_rotation: DecompositionConfig {
            log_basis: 7,
            level_count: None,
        },
        key_switching: DecompositionConfig {
            log_basis: 7,
            level_count: None,
        },
        key_switching_noise_standard_deviation: 0.7,
    })
    .unwrap();
    TfheContext::try_from_parameters(parameters).unwrap()
}

fn bench_mvb(c: &mut Criterion) {
    for (domain, count) in [(8, 3), (64, 17)] {
        let context = context(domain);
        let modulus = context.parameters().accumulator_ntru().cipher_modulus();
        let codec = ScaledCodec::new(2, modulus);
        let value = |m: usize, i: usize| u32::from(m >= (i + 1) * domain / (count + 1));
        let encoded = |m, i| Ok(codec.encode_value(value(m, i), PlaintextEmbedding::Unsigned));
        let singles: Vec<_> = (0..count)
            .map(|i| {
                LookupTable::try_new(domain, N, (2 * domain) as u32, modulus, modulus, |m| {
                    encoded(m, i)
                })
                .unwrap()
            })
            .collect();
        let interleaved = match InterleavedLookupTable::try_new(
            domain,
            N,
            count,
            (2 * domain) as u32,
            modulus,
            modulus,
            encoded,
        ) {
            Ok(lut) => Some(lut),
            Err(LookupTableError::PlaintextDomainTooLarge { .. }) if domain == 64 => None,
            Err(error) => panic!("unexpected interleaved compilation error: {error}"),
        };
        let factorized = context
            .compile_factorized_lookup_table_fn(&codec, domain, count, value)
            .unwrap();
        let mut rng = StdRng::seed_from_u64(0xB302_0000 + domain as u64);
        let (client, server) = context.try_generate_keys(None, &mut rng).unwrap();
        let encryptor = context.encryptor(&client).unwrap();
        let decryptor = context.decryptor(&client).unwrap();
        let messages = [0, domain / 4 - 1, domain / 2, domain - 1];
        let inputs: Vec<_> = messages
            .iter()
            .map(|&m| encryptor.encrypt_padded(m as u32, &mut rng).unwrap())
            .collect();
        let mut outputs = vec![LweCiphertext::zero(DIMENSION); count];
        let mut ordinary = context.evaluator(&server).unwrap();
        let mut mvb = context.factorized_evaluator(&server).unwrap();
        let mut group = c.benchmark_group(format!("ntru_ntt/mvb/D{domain}/k{count}"));
        group.sampling_mode(SamplingMode::Flat);
        for path in ["independent", "interleaved", "factorized"] {
            if path == "interleaved" && interleaved.is_none() {
                continue;
            }
            let mut evaluate =
                |input: &LweCiphertext<u32>, outputs: &mut [LweCiphertext<u32>]| match path {
                    "independent" => {
                        for (lut, output) in singles.iter().zip(outputs) {
                            ordinary.apply_lookup_table_to(input, lut, output);
                        }
                    }
                    "interleaved" => ordinary.apply_interleaved_lookup_table_to(
                        input,
                        interleaved.as_ref().unwrap(),
                        outputs,
                    ),
                    _ => mvb.apply_lookup_table_to(input, &factorized, outputs),
                };
            for (&message, input) in messages.iter().zip(&inputs) {
                evaluate(input, &mut outputs);
                for (i, output) in outputs.iter().enumerate() {
                    assert_eq!(
                        codec.decode_value(decryptor.decrypt_phase(output).unwrap()),
                        value(message, i),
                        "{path}: message={message}, output={i}"
                    );
                }
            }
            let mut next_input = 0;
            group.bench_function(path, |b| {
                b.iter(|| {
                    evaluate(black_box(&inputs[next_input]), &mut outputs);
                    next_input = (next_input + 1) % inputs.len();
                    black_box(&outputs);
                });
            });
        }
        group.finish();
    }
}

criterion_group!(benches, bench_mvb);
criterion_main!(benches);
