//! Equivalent threshold outputs with Scaled encoding: independent PBS,
//! interleaved ManyLUT (when it fits), and factorized MVB. One iteration evaluates
//! one encrypted input into all outputs, including KS/extraction. Setup and
//! output allocation are outside online timing. Functional cost parameters only.
//!
//! cargo bench -p primus_tfhe_glwe_ntt --bench mvb -- --sample-size 20 --warm-up-time 1 --measurement-time 3
//! cargo +nightly bench -p primus_tfhe_glwe_ntt --features simd --bench mvb -- --sample-size 20 --warm-up-time 1 --measurement-time 3

use std::hint::black_box;

use criterion::{BatchSize, Criterion, SamplingMode, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::{PlaintextEmbedding, ScaledCodec};
use primus_glwe::{GlweParameters, SecretKeyDistr};
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable};
use primus_tfhe_glwe_ntt::{
    ClientKey, FactorizedLookupTable, InterleavedLookupTable, KeyGenerator, LookupTable,
    LookupTableError, NttFactorizedLookupTable, PbsOrder, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

const Q: u32 = 132_120_577;
const N: usize = 1024;
const DIMENSION: usize = 728;
const WEIGHT: usize = 32;

fn context(order: PbsOrder, domain: usize) -> TfheContext<u32, U32NttTable> {
    let modulus = BarrettModulus::new(Q);
    let plaintext_modulus = (2 * domain) as u32;
    let parameters = TfheParameters::try_new(
        LweParameters::new(
            DIMENSION,
            plaintext_modulus,
            modulus,
            SecretKeyDistr::fixed_hamming_weight_binary(DIMENSION, WEIGHT),
            3.2 * f64::from(Q) / 16384.0,
        ),
        GlweParameters::new(
            1,
            N,
            plaintext_modulus,
            modulus,
            SecretKeyDistr::SparseTernary,
            6.4,
        ),
        ApproxSignedBasis::new(Some(Q), 7, Some(3)),
        ApproxSignedBasis::new(Some(Q), 2, Some(13)),
        order,
    )
    .unwrap();
    TfheContext::try_new(
        parameters,
        U32NttTable::new(N.trailing_zeros(), modulus).unwrap(),
    )
    .unwrap()
}

fn threshold(message: usize, output: usize, domain: usize, count: usize) -> u32 {
    u32::from(message >= (output + 1) * domain / (count + 1))
}

fn bench_mvb(c: &mut Criterion) {
    for (domain, count) in [(8, 3), (64, 17)] {
        for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
            let context = context(order, domain);
            let modulus = context.parameters().accumulator_glwe().cipher_modulus();
            let codec = ScaledCodec::new(2, modulus);
            let value = |m, i| threshold(m, i, domain, count);
            let encoded = |m, i| Ok(codec.encode_value(value(m, i), PlaintextEmbedding::Unsigned));
            let compile_singles = || {
                (0..count)
                    .map(|i| {
                        LookupTable::try_new(
                            domain,
                            N,
                            (2 * domain) as u32,
                            modulus,
                            modulus,
                            |m| encoded(m, i),
                        )
                        .unwrap()
                    })
                    .collect::<Vec<_>>()
            };
            let compile_interleaved = || {
                InterleavedLookupTable::try_new(
                    domain,
                    N,
                    count,
                    (2 * domain) as u32,
                    modulus,
                    modulus,
                    encoded,
                )
            };
            let compile_factors = || {
                FactorizedLookupTable::try_new(
                    domain,
                    N,
                    count,
                    context.parameters().input_plaintext_codec(),
                    &codec,
                    value,
                )
                .unwrap()
            };
            let singles = compile_singles();
            let interleaved = match compile_interleaved() {
                Ok(lut) => Some(lut),
                Err(LookupTableError::PlaintextDomainTooLarge { .. }) if domain == 64 => None,
                Err(error) => panic!("unexpected interleaved compilation error: {error}"),
            };
            let factorized = NttFactorizedLookupTable::new(&context, compile_factors());

            // Compilation is independent of order and BSK. End-to-end construction
            // includes allocation and destruction; prepare_ntt excludes both its
            // coefficient-program setup and the prepared result's destruction.
            if order == PbsOrder::BootstrapKeyswitch {
                let mut group = c.benchmark_group(format!("mvb_compile/D{domain}/k{count}"));
                group.bench_function("independent", |b| b.iter(|| black_box(compile_singles())));
                if interleaved.is_some() {
                    group.bench_function("interleaved", |b| {
                        b.iter(|| black_box(compile_interleaved().unwrap()))
                    });
                }
                group.bench_function("factorized", |b| {
                    b.iter(|| {
                        black_box(
                            context
                                .compile_factorized_lookup_table_fn(&codec, domain, count, value)
                                .unwrap(),
                        )
                    })
                });
                group.bench_function("prepare_ntt", |b| {
                    b.iter_batched(
                        compile_factors,
                        |lut| NttFactorizedLookupTable::new(&context, lut),
                        BatchSize::SmallInput,
                    )
                });
                group.finish();
            }

            let mut rng = StdRng::seed_from_u64(0x5034_3300 + domain as u64);
            let mut generator = KeyGenerator::new(&context);
            let client = ClientKey::generate(context.parameters(), &mut rng);
            let classic = generator
                .try_generate_server_key(&client, &mut rng)
                .unwrap();
            let sparse = generator
                .try_generate_sparse_server_key(&client, 3, 2 * WEIGHT, &mut rng)
                .unwrap();
            let encryptor = context.encryptor(&client).unwrap();
            let decryptor = context.decryptor(&client).unwrap();
            let messages = [0, domain / 4 - 1, domain / 2, domain - 1];
            let inputs: Vec<_> = messages
                .iter()
                .map(|&m| encryptor.encrypt_padded(m as u32, &mut rng).unwrap())
                .collect();
            let mut outputs =
                vec![LweCiphertext::zero(context.parameters().external_lwe_dimension()); count];
            let mut group = c.benchmark_group(format!("mvb/D{domain}/k{count}/{order:?}"));
            group.sampling_mode(SamplingMode::Flat);
            for (name, key) in [("classic", &classic), ("sparse", &sparse)] {
                let mut ordinary = context.evaluator(key).unwrap();
                let mut mvb = context.factorized_evaluator(key).unwrap();
                for path in ["independent", "interleaved", "factorized"] {
                    if path == "interleaved" && interleaved.is_none() {
                        continue;
                    }
                    let mut evaluate =
                        |input: &LweCiphertext<u32>, outputs: &mut [LweCiphertext<u32>]| match path
                        {
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
                    // Verify every timed input with the exact output codec before timing.
                    for (&message, input) in messages.iter().zip(&inputs) {
                        evaluate(input, &mut outputs);
                        for (i, output) in outputs.iter().enumerate() {
                            assert_eq!(
                                codec.decode_value(decryptor.decrypt_phase(output).unwrap()),
                                value(message, i),
                                "{order:?}/{name}/{path}: message={message}, output={i}"
                            );
                        }
                    }
                    let mut next_input = 0;
                    group.bench_function(format!("{name}/{path}"), |b| {
                        b.iter(|| {
                            evaluate(black_box(&inputs[next_input]), &mut outputs);
                            next_input = (next_input + 1) % inputs.len();
                            black_box(&outputs);
                        })
                    });
                }
            }
            group.finish();
        }
    }
}

criterion_group!(benches, bench_mvb);
criterion_main!(benches);
