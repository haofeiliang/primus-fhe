//! Full PBS cost at n=728: binary, fused ternary, and two-CMUX ternary.
//! Fixed arithmetic profile, not an equal-security or failure-rate comparison.
//! Online timing includes BR, ring KS and compact extraction; inputs, keys, LUT,
//! outputs and scratch are reused. Keygen measures BSK + KSK, excluding client
//! generation, transform tables and key destruction.
//!
//! cargo bench -p primus_tfhe_glwe_fourier --bench ternary_pbs
//! cargo +nightly bench -p primus_tfhe_glwe_fourier --bench ternary_pbs --features simd

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, RustFftTable, TfheFftTable};
use primus_glwe::{FourierGlweKeySwitchingContext, GlweCiphertext, GlweParameters, SecretKeyDistr};
use primus_lattice::context::FourierGlweExternalProductContext;
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;
use primus_tfhe::rotation::RotationQuantizer;
use primus_tfhe_glwe_fourier::{ClientKey, KeyGenerator, PbsOrder, TfheContext, TfheParameters};
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 1024;
const DIMENSION: usize = 728;

fn parameters(distribution: SecretKeyDistr) -> TfheParameters<u32> {
    let modulus = NativeModulus::new();
    let lwe = LweParameters::new(
        DIMENSION,
        4,
        modulus,
        distribution,
        3.2 * 4294967296.0 / 16384.0,
    );
    let glwe = GlweParameters::new(1, N, 4, modulus, SecretKeyDistr::SparseTernary, 6.4);
    TfheParameters::try_new(
        lwe,
        glwe,
        ApproxSignedBasis::new(None, 8, Some(3)),
        ApproxSignedBasis::new(None, 2, Some(13)),
        PbsOrder::BootstrapKeyswitch,
    )
    .unwrap()
}

fn bench_backend<Table: FftTable>(c: &mut Criterion, backend: &str) {
    for (name, distribution) in [
        ("binary", SecretKeyDistr::UniformBinary),
        ("ternary", SecretKeyDistr::UniformTernary),
    ] {
        let parameters = parameters(distribution);
        let modulus = parameters.accumulator_glwe().cipher_modulus();
        let table = Table::new(N.trailing_zeros()).unwrap();
        let context = TfheContext::try_new(parameters, table).unwrap();
        let mut rng = StdRng::seed_from_u64(0x5433_5042);
        let mut generator = KeyGenerator::new(&context);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        let server = generator
            .try_generate_server_key(&client, &mut rng)
            .unwrap();
        let bsk = server.bootstrapping_key();
        let encryptor = context.encryptor(&client).unwrap();
        let decryptor = context.decryptor(&client).unwrap();
        let inputs: Vec<_> = (0..2)
            .map(|m| encryptor.encrypt_padded(m, &mut rng).unwrap())
            .collect();
        let lut = context
            .parameters()
            .compile_lookup_table_slice(context.parameters().input_plaintext_codec(), &[1, 0])
            .unwrap();
        let mut output = LweCiphertext::zero(DIMENSION);
        let mut evaluator = context.evaluator(&server).unwrap();
        for (m, input) in inputs.iter().enumerate() {
            evaluator.apply_lookup_table_to(input, &lut, &mut output);
            assert_eq!(decryptor.decrypt(&output).unwrap(), 1 - m as u32);
        }
        let mut group = c.benchmark_group(format!("ternary_pbs/{backend}/n{DIMENSION}/N{N}"));
        let mut next_input = 0;
        let method = if distribution.is_binary() {
            "binary"
        } else {
            "ternary_fused"
        };
        group.bench_function(method, |b| {
            b.iter(|| {
                evaluator.apply_lookup_table_to(
                    black_box(&inputs[next_input]),
                    black_box(&lut),
                    black_box(&mut output),
                );
                next_input ^= 1;
                black_box(&output);
            })
        });

        if distribution.is_ternary() {
            // Same ternary BSK/input/LUT/KSK as fused; only the BR update differs.
            let quantizer = RotationQuantizer::new(modulus, 2 * N, 1);
            let mut main: GlweCiphertext<Vec<u32>> = GlweCiphertext::zero(2 * N);
            let mut temporary: GlweCiphertext<Vec<u32>> = GlweCiphertext::zero(2 * N);
            let mut switched: GlweCiphertext<Vec<u32>> = GlweCiphertext::zero(2 * N);
            let mut external_product = FourierGlweExternalProductContext::new(bsk.size());
            let mut key_switching = FourierGlweKeySwitchingContext::new(bsk.size().glwe_size());
            let mut fft = context.new_fft_engine();
            let mut two_cmux = |input: &LweCiphertext<u32>, output: &mut LweCiphertext<u32>| {
                let initial = quantizer.exponent(input.b()).wrapping_neg() & (2 * N - 1);
                let (mask, body) = main.a_b_mut_slices(N);
                mask.fill(0);
                lut.polynomial()
                    .mul_monomial_to(initial, &mut Polynomial(body), modulus);
                for (&a, (positive, negative)) in
                    input.a().iter().zip(bsk.iter_ternary_controls().unwrap())
                {
                    let exponent = quantizer.exponent(a);
                    if exponent == 0 {
                        continue;
                    }
                    positive.cmux_monomial_to(
                        &main,
                        exponent,
                        &mut temporary,
                        bsk.basis(),
                        &mut fft,
                        &mut external_product,
                    );
                    negative.cmux_monomial_to(
                        &temporary,
                        2 * N - exponent,
                        &mut main,
                        bsk.basis(),
                        &mut fft,
                        &mut external_product,
                    );
                }
                server.glwe_key_switching_key().key_switch_to(
                    &main,
                    &mut switched,
                    &mut fft,
                    &mut key_switching,
                );
                switched.extract_compact_lwe_to(output, N, modulus);
            };
            for (m, input) in inputs.iter().enumerate() {
                two_cmux(input, &mut output);
                assert_eq!(decryptor.decrypt(&output).unwrap(), 1 - m as u32);
            }
            group.bench_function("ternary_two_cmux", |b| {
                b.iter(|| {
                    two_cmux(black_box(&inputs[next_input]), black_box(&mut output));
                    next_input ^= 1;
                    black_box(&output);
                })
            });
        }
        group.finish();
        let mut keygen = c.benchmark_group(format!("ternary_keygen/{backend}/n{DIMENSION}/N{N}"));
        keygen.sample_size(10);
        keygen.bench_function(name, |b| {
            b.iter_batched(
                || (),
                |()| {
                    generator
                        .try_generate_server_key(black_box(&client), &mut rng)
                        .unwrap()
                },
                BatchSize::PerIteration,
            )
        });
        keygen.finish();
    }
}

fn bench_pbs(c: &mut Criterion) {
    bench_backend::<RustFftTable>(c, "rustfft");
    bench_backend::<TfheFftTable>(c, "tfhe_fft");
}

criterion_group!(benches, bench_pbs);
criterion_main!(benches);
