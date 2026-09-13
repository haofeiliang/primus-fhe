//! Constant NLev initialization and 8-control NGSW batch generation.
//! Reuses keys, tables, output and scratch; sampling/transforms remain timed.
//! u64, sigma 3.2, sparse ternary key; NTT q = 1_125_899_906_826_241,
//! Fourier native torus. These workloads do not compare matched security.
//!
//! cargo bench -p primus_ntru --bench constant_gadget
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{
    FourierNlevCiphertext, FourierNtruGadgetEncryptContext, FourierNtruSecretKey, NlevParameters,
    NtruParameters, NttNlevCiphertext, NttNtruGadgetEncryptContext, NttNtruSecretKey,
    SecretKeyDistr,
};
use primus_ntt::{NttTable, UintNttTable};
use rand::{SeedableRng, rngs::StdRng};
use std::{hint::black_box, time::Duration};

const CONSTANTS: [i64; 8] = [0, 1, 0, 1, 1, 0, 1, 0];

fn ntt(c: &mut Criterion) {
    for n in [1024usize, 4096] {
        let mut rng = StdRng::seed_from_u64(42);
        let modulus = BarrettModulus::new(1_125_899_906_826_241u64);
        let params = NtruParameters::new(n, 16, modulus, SecretKeyDistr::SparseTernary, 3.2);
        let table = UintNttTable::new(n.trailing_zeros(), modulus).unwrap();
        let (_, key) = NttNtruSecretKey::generate_pair(&params, &table, &mut rng).unwrap();
        let mut context = NttNtruGadgetEncryptContext::new(n);
        for log_basis in [3, 10] {
            let gadget = NlevParameters::with_ntru_params(&params, log_basis, None);
            let mut nlev = NttNlevCiphertext::<Vec<u64>>::zero(gadget.nlev_len());
            let mut batch = vec![0; CONSTANTS.len() * gadget.nlev_len()];
            let mut group = c.benchmark_group(format!("ntru/ntt/n{n}/log_basis{log_basis}"));
            group.throughput(Throughput::Elements(1));
            group.bench_function("encrypt_nlev_constant_to", |b| {
                b.iter(|| {
                    key.encrypt_nlev_constant_to(
                        black_box(1),
                        &mut nlev,
                        &gadget,
                        &table,
                        &mut rng,
                        &mut context,
                    );
                    black_box(nlev.as_ref());
                })
            });
            group.throughput(Throughput::Elements(CONSTANTS.len() as u64));
            group.bench_function("encrypt_ngsw_signed_constant_batch_to", |b| {
                b.iter(|| {
                    key.encrypt_ngsw_signed_constant_batch_to(
                        black_box(&CONSTANTS),
                        &mut batch,
                        &gadget,
                        &table,
                        &mut rng,
                    );
                    black_box(&batch);
                })
            });
            group.finish();
        }
    }
}

fn fourier(c: &mut Criterion) {
    for n in [1024usize, 4096] {
        let mut rng = StdRng::seed_from_u64(42);
        let params = NtruParameters::new(
            n,
            16u64,
            NativeModulus::new(),
            SecretKeyDistr::SparseTernary,
            3.2,
        );
        let table = RustFftTable::new(n.trailing_zeros()).unwrap();
        let mut fft = FftEngine::new(&table);
        let (_, key) = FourierNtruSecretKey::generate_pair(&params, &mut fft, &mut rng).unwrap();
        let mut context = FourierNtruGadgetEncryptContext::new(n);
        for log_basis in [3, 10] {
            let gadget = NlevParameters::with_ntru_params(&params, log_basis, None);
            let mut nlev = FourierNlevCiphertext::<Vec<Complex64>>::zero(gadget.fourier_nlev_len());
            let mut batch = vec![Complex64::default(); CONSTANTS.len() * gadget.fourier_nlev_len()];
            let mut group = c.benchmark_group(format!("ntru/fourier/n{n}/log_basis{log_basis}"));
            group.throughput(Throughput::Elements(1));
            group.bench_function("encrypt_nlev_constant_to", |b| {
                b.iter(|| {
                    key.encrypt_nlev_constant_to(
                        black_box(1),
                        &mut nlev,
                        &gadget,
                        &mut fft,
                        &mut rng,
                        &mut context,
                    );
                    black_box(nlev.as_ref());
                })
            });
            group.throughput(Throughput::Elements(CONSTANTS.len() as u64));
            group.bench_function("encrypt_ngsw_signed_constant_batch_to", |b| {
                b.iter(|| {
                    key.encrypt_ngsw_signed_constant_batch_to(
                        black_box(&CONSTANTS),
                        &mut batch,
                        &gadget,
                        &mut fft,
                        &mut rng,
                        &mut context,
                    );
                    black_box(&batch);
                })
            });
            group.finish();
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50)
        .warm_up_time(Duration::from_secs(1)).measurement_time(Duration::from_secs(2));
    targets = ntt, fourier
}
criterion_main!(benches);
