//! LWE packing key switching and GLev-to-GGSW scheme switching.
//! NTT q=1_125_899_906_826_241; Fourier native u64 with RustFFT.
//! Binary secrets and sigma 3.2. Most cases use base 2^10 / three levels;
//! single-LWE packing also uses base 2^3 / ten levels (both retain 30 bits).
//! Packing input dimension is 512, independent of the output GLWE secret.
//! These are regression workloads, not matched-security comparisons.
//! Setup, key generation, output and workspace allocations are outside timing.
//!
//! cargo bench -p primus_glwe --bench key_conversion
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_fft::{FftEngine, FftTable, RustFftTable};
use primus_glwe::{
    FourierGadgetEncryptContext, FourierGlweKeySwitchingContext, FourierGlweSchemeSwitchKey,
    FourierGlweSecretKey, FourierLwePackingKeySwitchingKey, GlevParameters, GlweParameters,
    NttGadgetEncryptContext, NttGlweKeySwitchingContext, NttGlweSchemeSwitchKey, NttGlweSecretKey,
    NttLwePackingKeySwitchingKey, SecretKeyDistr,
};
use primus_lattice::{
    context::{FourierGlweExternalProductContext, NttGlweExternalProductContext},
    ggsw::{FourierGgsw, NttGgsw},
    glev::{FourierGlev, Glev, NttGlev},
    glwe::Glwe,
    lwe::Lwe,
};
use primus_lwe::LweSecretKeyRef;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntt::{NttTable, U64NttTable};
use primus_poly::Polynomial;
use rand::{SeedableRng, rngs::StdRng};
use std::{hint::black_box, time::Duration};

const SIZES: [(usize, usize); 2] = [(1, 1024), (2, 4096)];
const INPUT_DIMENSION: usize = 512;

fn ntt_conversion(c: &mut Criterion) {
    for (k, n) in SIZES {
        let mut rng = StdRng::seed_from_u64(42);
        let modulus = BarrettModulus::new(1_125_899_906_826_241u64);
        let table = U64NttTable::new(n.trailing_zeros(), modulus).unwrap();
        let params = GlweParameters::new(k, n, 64, modulus, SecretKeyDistr::UniformBinary, 3.2);
        let size = params.size();
        let (coeff, sk) = NttGlweSecretKey::generate_pair(&params, &table, &mut rng);
        let glev = GlevParameters::with_glwe_params(&params, 10, Some(3));
        let mut gadget = NttGadgetEncryptContext::new(glev.size());
        let source = params
            .secret_key_sampler()
            .sample_signed(INPUT_DIMENSION, &mut rng);
        let source = LweSecretKeyRef::Signed(&source);
        let key = NttLwePackingKeySwitchingKey::generate(
            source,
            &sk,
            &glev,
            &table,
            &mut rng,
            &mut gadget,
        );
        let mut context = NttGlweKeySwitchingContext::new(size);
        let mut output = Glwe::new(vec![0; size.glwe_len()]);
        let mut batch = vec![0; n * (INPUT_DIMENSION + 1)];
        for (i, block) in batch
            .as_chunks_mut::<{ INPUT_DIMENSION + 1 }>()
            .0
            .iter_mut()
            .enumerate()
        {
            source.encrypt_encoded_to(
                (i % 16) as u64,
                &mut Lwe::new(block.as_mut_slice()),
                modulus,
                params.cipher_modulus_uniform_distr(),
                params.noise_distribution(),
                &mut rng,
            );
        }
        let mut group = c.benchmark_group(format!("glwe/ntt/k{k}_n{n}"));
        for count in [1, 8, n] {
            let input = &batch[..count * (INPUT_DIMENSION + 1)];
            group.throughput(Throughput::Elements(count as u64));
            group.bench_function(format!("packing_key_switch/b10_l3/{count}"), |b| {
                b.iter(|| {
                    key.pack_lwes_to(black_box(input), &mut output, modulus, &table, &mut context);
                    black_box(output.as_ref());
                })
            });
        }
        drop(key);
        // Keep a small-basis single-LWE case: its frequent 0/±1/±2 digits
        // exercise a different accumulation cost than the large-basis path.
        let small_glev = GlevParameters::with_glwe_params(&params, 3, Some(10));
        let key = NttLwePackingKeySwitchingKey::generate(
            source,
            &sk,
            &small_glev,
            &table,
            &mut rng,
            &mut gadget,
        );
        let input = &batch[..INPUT_DIMENSION + 1];
        group.throughput(Throughput::Elements(1));
        group.bench_function("packing_key_switch/b3_l10/1", |b| {
            b.iter(|| {
                key.pack_lwes_to(black_box(input), &mut output, modulus, &table, &mut context);
                black_box(output.as_ref());
            })
        });
        drop(key);

        let key = NttGlweSchemeSwitchKey::generate(
            &coeff,
            &sk,
            glev.size(),
            &glev,
            &table,
            &mut rng,
            &mut gadget,
        );
        let mut context = NttGlweExternalProductContext::new(glev.size());
        let mut message = Polynomial::new(vec![0; n]);
        message.as_mut()[0] = 1;
        let mut input = NttGlev::<Vec<_>>::zero(glev.glev_len());
        sk.encrypt_glev_to(&message, &mut input, &glev, &table, &mut rng, &mut gadget);
        let input = input.into_coeff_form(&table);
        let mut output = NttGgsw::<Vec<_>>::zero(glev.ggsw_len());
        group.throughput(Throughput::Elements(1));
        group.bench_function("scheme_switch", |b| {
            b.iter(|| {
                key.apply_to(
                    black_box(&input),
                    &mut output,
                    modulus,
                    &table,
                    &mut context,
                );
                black_box(output.as_ref());
            })
        });
        group.finish();
    }
}

fn fourier_conversion(c: &mut Criterion) {
    for (k, n) in SIZES {
        let mut rng = StdRng::seed_from_u64(42);
        let modulus = NativeModulus::<u64>::new();
        let table = RustFftTable::new(n.trailing_zeros()).unwrap();
        let mut fft = FftEngine::new(&table);
        let params = GlweParameters::new(k, n, 64, modulus, SecretKeyDistr::UniformBinary, 3.2);
        let size = params.size();
        let (coeff, sk) = FourierGlweSecretKey::generate_pair(&params, &mut fft, &mut rng);
        let glev = GlevParameters::with_glwe_params(&params, 10, Some(3));
        let mut gadget = FourierGadgetEncryptContext::new(glev.size());
        let source = params
            .secret_key_sampler()
            .sample_signed(INPUT_DIMENSION, &mut rng);
        let source = LweSecretKeyRef::Signed(&source);
        let key = FourierLwePackingKeySwitchingKey::generate(
            source,
            &sk,
            &glev,
            &mut fft,
            &mut rng,
            &mut gadget,
        );
        let mut context = FourierGlweKeySwitchingContext::new(size);
        let mut output = Glwe::new(vec![0; size.glwe_len()]);
        let mut batch = vec![0; n * (INPUT_DIMENSION + 1)];
        for (i, block) in batch
            .as_chunks_mut::<{ INPUT_DIMENSION + 1 }>()
            .0
            .iter_mut()
            .enumerate()
        {
            source.encrypt_encoded_to(
                (i % 16) as u64,
                &mut Lwe::new(block.as_mut_slice()),
                modulus,
                params.cipher_modulus_uniform_distr(),
                params.noise_distribution(),
                &mut rng,
            );
        }
        let mut group = c.benchmark_group(format!("glwe/fourier/k{k}_n{n}"));
        for count in [1, 8, n] {
            let input = &batch[..count * (INPUT_DIMENSION + 1)];
            group.throughput(Throughput::Elements(count as u64));
            group.bench_function(format!("packing_key_switch/b10_l3/{count}"), |b| {
                b.iter(|| {
                    key.pack_lwes_to(black_box(input), &mut output, &mut fft, &mut context);
                    black_box(output.as_ref());
                })
            });
        }
        drop(key);
        // Track zero-skipping with frequent zeros as well as the rare-zero large basis.
        let small_glev = GlevParameters::with_glwe_params(&params, 3, Some(10));
        let key = FourierLwePackingKeySwitchingKey::generate(
            source,
            &sk,
            &small_glev,
            &mut fft,
            &mut rng,
            &mut gadget,
        );
        let input = &batch[..INPUT_DIMENSION + 1];
        group.throughput(Throughput::Elements(1));
        group.bench_function("packing_key_switch/b3_l10/1", |b| {
            b.iter(|| {
                key.pack_lwes_to(black_box(input), &mut output, &mut fft, &mut context);
                black_box(output.as_ref());
            })
        });
        drop(key);

        let key = FourierGlweSchemeSwitchKey::generate(
            &coeff,
            &sk,
            glev.size(),
            &glev,
            &mut fft,
            &mut rng,
            &mut gadget,
        );
        let mut context = FourierGlweExternalProductContext::new(glev.size());
        let mut message = Polynomial::new(vec![0; n]);
        message.as_mut()[0] = 1;
        let mut input = FourierGlev::<Vec<_>>::zero(glev.fourier_glev_len());
        sk.encrypt_glev_to(&message, &mut input, &glev, &mut fft, &mut rng, &mut gadget);
        let mut coeff_input = Glev::new(vec![0u64; glev.glev_len()]);
        input.write_torus_form(&mut coeff_input, &mut fft);
        let input = coeff_input;
        let mut output = FourierGgsw::<Vec<_>>::zero(glev.fourier_ggsw_len());
        group.throughput(Throughput::Elements(1));
        group.bench_function("scheme_switch", |b| {
            b.iter(|| {
                key.apply_to(black_box(&input), &mut output, &mut fft, &mut context);
                black_box(output.as_ref());
            })
        });
        group.finish();
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10)
        .warm_up_time(Duration::from_millis(300)).measurement_time(Duration::from_secs(1));
    targets = ntt_conversion, fourier_conversion
}
criterion_main!(benches);
