//! Equivalent threshold outputs with Scaled encoding: independent PBS,
//! interleaved ManyLUT (when it fits), and factorized MVB. One iteration evaluates
//! one encrypted input into all outputs, including KS/extraction. Setup and
//! output allocation are outside online timing. Native u32/u64, n=728, N=1024,
//! binary h=32; classic and sparse share the client. Functional cost parameters only.
//!
//! cargo bench -p primus_tfhe_glwe_fourier --bench mvb -- --sample-size 20 --warm-up-time 1 --measurement-time 2
//! cargo +nightly bench -p primus_tfhe_glwe_fourier --features simd --bench mvb -- --sample-size 20 --warm-up-time 1 --measurement-time 2

use std::hint::black_box;

use criterion::{Criterion, SamplingMode, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::{PlaintextEmbedding, ScaledCodec};
use primus_fft::{FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_glwe::{GlweParameters, SecretKeyDistr};
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::NativeModulus;
use primus_tfhe_glwe_fourier::{
    ClientKey, InterleavedLookupTable, KeyGenerator, LookupTable, LookupTableError, PbsOrder,
    TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 1024;
const DIMENSION: usize = 728;
const WEIGHT: usize = 32;

fn context<T: TorusFftValue, Table: FftTable>(
    order: PbsOrder,
    domain: usize,
) -> TfheContext<T, Table> {
    let modulus = NativeModulus::new();
    let plaintext_modulus = T::as_from(2 * domain);
    let parameters = TfheParameters::try_new(
        LweParameters::new(
            DIMENSION,
            plaintext_modulus,
            modulus,
            SecretKeyDistr::fixed_hamming_weight_binary(DIMENSION, WEIGHT),
            3.2 / T::TORUS_SCALE / 16384.0,
        ),
        GlweParameters::new(
            1,
            N,
            plaintext_modulus,
            modulus,
            SecretKeyDistr::SparseTernary,
            6.4,
        ),
        ApproxSignedBasis::new(None, 8, Some(3)),
        ApproxSignedBasis::new(None, 2, Some(13)),
        order,
    )
    .unwrap();
    TfheContext::try_from_parameters(parameters).unwrap()
}

fn backend<T: TorusFftValue, Table: FftTable>(c: &mut Criterion, fft: &str, order: PbsOrder) {
    for (domain, count) in [(8, 3), (64, 17)] {
        let context = context::<T, Table>(order, domain);
        let modulus = context.parameters().accumulator_glwe().cipher_modulus();
        let codec = ScaledCodec::new(T::TWO, modulus);
        let value = |m, i| T::as_from(m >= (i + 1) * domain / (count + 1));
        let encoded = |m, i| Ok(codec.encode_value(value(m, i), PlaintextEmbedding::Unsigned));
        let singles: Vec<_> = (0..count)
            .map(|i| {
                LookupTable::try_new(domain, N, T::as_from(2 * domain), modulus, modulus, |m| {
                    encoded(m, i)
                })
                .unwrap()
            })
            .collect();
        let interleaved = match InterleavedLookupTable::try_new(
            domain,
            N,
            count,
            T::as_from(2 * domain),
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

        let mut rng = StdRng::seed_from_u64(0x4235_3400 + domain as u64);
        let mut generator = KeyGenerator::new(&context);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        let classic = generator
            .try_generate_server_key(&client, None, &mut rng)
            .unwrap();
        let sparse = generator
            .try_generate_sparse_server_key(&client, 3, 2 * WEIGHT, None, &mut rng)
            .unwrap();
        let encryptor = context.encryptor(&client).unwrap();
        let decryptor = context.decryptor(&client).unwrap();
        let messages = [0, domain / 4 - 1, domain / 2, domain - 1];
        let inputs: Vec<_> = messages
            .iter()
            .map(|&m| encryptor.encrypt_padded(T::as_from(m), &mut rng).unwrap())
            .collect();
        let mut outputs =
            vec![LweCiphertext::zero(context.parameters().external_lwe_dimension()); count];
        let mut group = c.benchmark_group(format!(
            "glwe_fourier/mvb/{fft}/u{}/D{domain}/k{count}/{order:?}",
            T::BITS
        ));
        group.sampling_mode(SamplingMode::Flat);
        for (name, key) in [("classic", &classic), ("sparse", &sparse)] {
            let mut ordinary = context.evaluator(key).unwrap();
            let mut mvb = context.factorized_evaluator(key).unwrap();
            for path in ["independent", "interleaved", "factorized"] {
                if path == "interleaved" && interleaved.is_none() {
                    continue;
                }
                let mut evaluate =
                    |input: &LweCiphertext<T>, outputs: &mut [LweCiphertext<T>]| match path {
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

fn bench_mvb(c: &mut Criterion) {
    // Time representative FFT/width/order pairings. Separate tests cover
    // numerical and API contracts without a full timing Cartesian product.
    backend::<u32, RustFftTable>(c, "rustfft", PbsOrder::BootstrapKeyswitch);
    backend::<u64, TfheFftTable>(c, "tfhe_fft", PbsOrder::BootstrapKeyswitch);
    backend::<u32, TfheFftTable>(c, "tfhe_fft", PbsOrder::KeyswitchBootstrap);
    backend::<u64, RustFftTable>(c, "rustfft", PbsOrder::KeyswitchBootstrap);
}

criterion_group!(benches, bench_mvb);
criterion_main!(benches);
