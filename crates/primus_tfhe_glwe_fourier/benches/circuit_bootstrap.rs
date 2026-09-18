//! Complete CBS plus its BR, projection and scheme-switch stages at n=728.
//! Setup, validation and allocation are outside timing; one invocation per iteration.
//! Stages use fixed intermediates from a real CBS and are not additive wall-time estimates.
//!
//! cargo bench -p primus_tfhe_glwe_fourier --bench circuit_bootstrap
//! cargo +nightly bench -p primus_tfhe_glwe_fourier --bench circuit_bootstrap --features simd

#[path = "../examples/support/circuit_bootstrap.rs"]
mod profile;

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_fft::{FftTable, RustFftTable, TfheFftTable};
use primus_glwe::{
    FourierGlweDecryptContext, FourierGlweSecretKey, FourierGlweTraceContext, GlevCiphertext,
    GlweCiphertext,
};
use primus_lattice::{context::FourierGlweExternalProductContext, ggsw::FourierGgsw};
use primus_poly::Polynomial;
use primus_tfhe::InterleavedLookupTable;
use primus_tfhe_glwe_fourier::{FourierGlweBlindRotationContext, PbsOrder};
use rand::{SeedableRng, rngs::StdRng};

fn bench_backend<Table: FftTable>(c: &mut Criterion, backend: &str) {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let context = profile::context::<Table>(order);
        let mut rng = StdRng::seed_from_u64(profile::SEED);
        let (client, server) = context
            .try_generate_keys(Some(profile::circuit_bootstrap()), &mut rng)
            .unwrap();
        let key = server.circuit_bootstrap_key().unwrap();
        let parameters = key.parameters();
        let encryptor = context.encryptor(&client).unwrap();
        let inputs = [0u64, 1].map(|m| encryptor.encrypt_padded(m, &mut rng).unwrap());
        let mut evaluator = context.circuit_bootstrap_evaluator(&server).unwrap();
        let mut output = FourierGgsw::<Vec<_>>::zero(parameters.output_size().fourier_ggsw_len());
        let glwe = context.parameters().accumulator_glwe();
        let mut fft = context.new_fft_engine();
        let secret =
            FourierGlweSecretKey::from_coeff_secret_key(client.glwe_secret_key(), &mut fft);
        let mut decrypt = FourierGlweDecryptContext::new(profile::N);
        let mut phase = Polynomial::<Vec<u64>>::zero(profile::N);
        let scalars: Vec<u64> = parameters.output_basis().scalar_iter().collect();
        let tolerance = scalars.iter().min().unwrap() / 4;
        // Validate every timed message, GGSW row, level and phase coefficient.
        for (bit, input) in inputs.iter().enumerate() {
            evaluator.circuit_bootstrap_to(input, &mut output);
            for (row, levels) in output
                .iter_glev(parameters.output_size().fourier_glev_len())
                .enumerate()
            {
                for (&scalar, ciphertext) in scalars
                    .iter()
                    .zip(levels.iter_glwe(glwe.size().fourier_glwe_len()))
                {
                    secret.phase_to(&ciphertext, &mut phase, &mut fft, &mut decrypt);
                    for (i, &actual) in phase.as_ref().iter().enumerate() {
                        let coefficient = if row == 1 {
                            u64::from(i == 0)
                        } else {
                            (client.glwe_secret_key().as_slice()[i] as u64).wrapping_neg()
                        };
                        let expected = coefficient.wrapping_mul(scalar).wrapping_mul(bit as u64);
                        let error = actual.wrapping_sub(expected);
                        assert!(error.min(error.wrapping_neg()) < tolerance);
                    }
                }
            }
        }
        let mut group = c.benchmark_group(format!("fourier_cbs/{backend}/{order:?}/n728/N1024/l3"));
        let mut next_input = 0;
        group.bench_function("complete", |b| {
            b.iter(|| {
                evaluator
                    .circuit_bootstrap_to(black_box(&inputs[next_input]), black_box(&mut output));
                next_input ^= 1;
                black_box(&output);
            })
        });

        // Post-BR stages are shared by both orders; measure them once per FFT.
        if order == PbsOrder::BootstrapKeyswitch {
            let modulus = glwe.cipher_modulus();
            let lut = InterleavedLookupTable::try_new(
                2,
                profile::N,
                scalars.len(),
                4,
                modulus,
                modulus,
                |m, level| Ok(scalars[level].wrapping_mul(m as u64)),
            )
            .unwrap();
            let mut blind_rotation =
                FourierGlweBlindRotationContext::new(server.bootstrapping_key());
            let mut accumulator = GlweCiphertext::<Vec<u64>>::zero(glwe.glwe_len());
            let mut trace = FourierGlweTraceContext::new(glwe.size());
            let mut projected =
                GlevCiphertext::<Vec<u64>>::zero(parameters.output_size().glev_len());
            let mut scheme_switch =
                FourierGlweExternalProductContext::new(parameters.scheme_switch().size());
            server
                .bootstrapping_key()
                .fourier_blind_rotate_interleaved_lookup_table_to(
                    &inputs[1],
                    lut.polynomial(),
                    lut.padded_output_count(),
                    &mut accumulator,
                    &mut fft,
                    &mut blind_rotation,
                );
            key.trace_key().project_prefix_coefficients_to(
                &accumulator,
                scalars.len(),
                projected.as_mut(),
                &mut fft,
                &mut trace,
            );
            group.bench_function("blind_rotation", |b| {
                b.iter(|| {
                    server
                        .bootstrapping_key()
                        .fourier_blind_rotate_interleaved_lookup_table_to(
                            black_box(&inputs[1]),
                            black_box(lut.polynomial()),
                            lut.padded_output_count(),
                            black_box(&mut accumulator),
                            &mut fft,
                            &mut blind_rotation,
                        );
                    black_box(&accumulator);
                })
            });
            group.bench_function("project_3", |b| {
                b.iter(|| {
                    key.trace_key().project_prefix_coefficients_to(
                        black_box(&accumulator),
                        scalars.len(),
                        black_box(projected.as_mut()),
                        &mut fft,
                        &mut trace,
                    );
                    black_box(&projected);
                })
            });
            group.bench_function("scheme_switch", |b| {
                b.iter(|| {
                    key.scheme_switch_key().apply_to(
                        black_box(&projected),
                        black_box(&mut output),
                        &mut fft,
                        &mut scheme_switch,
                    );
                    black_box(&output);
                })
            });
        }
        group.finish();
    }
}

fn circuit_bootstrap(c: &mut Criterion) {
    bench_backend::<RustFftTable>(c, "rustfft");
    bench_backend::<TfheFftTable>(c, "tfhe_fft");
}

criterion_group!(benches, circuit_bootstrap);
criterion_main!(benches);
