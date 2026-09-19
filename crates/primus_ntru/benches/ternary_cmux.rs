//! One encrypted ternary NTRU rotation: fused versus two binary CMUXes.
//! Keys, monomial exponent, output and scratch allocation are outside timing.
//! cargo bench -p primus_ntru --bench ternary_cmux
//! SIMD comparison: cargo +nightly bench -p primus_ntru --bench ternary_cmux --features simd
use std::{hint::black_box, time::Duration};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use num_traits::{ConstOne, ConstZero};
use primus_integer::FheUint;
use primus_modulus::BarrettModulus;
use primus_ntru::{
    NlevParameters, NtruCiphertext, NtruParameters, NttNgswCiphertext,
    NttNtruExternalProductContext, NttNtruSecretKey, NttNtruTernaryCmuxContext, SecretKeyDistr,
};
use primus_ntt::{NttTable, PrimitiveRoot, UintNttTable};
use primus_poly::Polynomial;
use primus_test_allocations::{CountingAllocator, measure};
use rand::{SeedableRng, rngs::StdRng};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn ntt<T: FheUint + PrimitiveRoot>(c: &mut Criterion, q: T, levels: usize) {
    const N: usize = 1024;
    let modulus = BarrettModulus::new(q);
    let table = UintNttTable::new(N.trailing_zeros(), modulus).unwrap();
    let params = NtruParameters::new(
        N,
        T::try_from(16).unwrap(),
        modulus,
        SecretKeyDistr::SparseTernary,
        3.2,
    );
    let gadget = NlevParameters::with_ntru_params(&params, 8, Some(levels));
    let mut rng = StdRng::seed_from_u64(0xB702);
    let key = NttNtruSecretKey::generate(&params, &table, &mut rng).unwrap();
    let message = Polynomial::new(
        (0..N)
            .map(|i| T::try_from(i % 16).unwrap())
            .collect::<Vec<_>>(),
    );
    let input = key
        .encrypt(&message, &params, &table, &mut rng)
        .into_coeff_form(&table);
    let mut controls = vec![T::ZERO; 2 * gadget.nlev_len()];
    // Independent encryptions of (0,1); both algorithms read the same controls.
    key.encrypt_ngsw_signed_constant_batch_to(
        &[T::SignedInteger::ZERO, T::SignedInteger::ONE],
        &mut controls,
        &gadget,
        &table,
        &mut rng,
    );
    let (positive, negative) = controls.split_at(gadget.nlev_len());
    let positive = NttNgswCiphertext::new(positive);
    let negative = NttNgswCiphertext::new(negative);
    let exponent = N / 3;
    let mut output = NtruCiphertext::<Vec<T>>::zero(N);
    let (mut fused, fused_allocations) = measure(|| NttNtruTernaryCmuxContext::<T>::new(N, levels));
    let ((mut binary, mut intermediate), binary_allocations) = measure(|| {
        (
            NttNtruExternalProductContext::<T>::new(N),
            NtruCiphertext::<Vec<T>>::zero(N),
        )
    });
    eprintln!(
        "u{}: controls={} B, fused scratch={} B, two-CMUX scratch={} B (includes intermediate)",
        T::BITS,
        std::mem::size_of_val(controls.as_slice()),
        fused_allocations.allocated_bytes,
        binary_allocations.allocated_bytes,
    );
    let mut group = c.benchmark_group(format!(
        "ntru/ternary/ntt/u{}/n{N}/logb8/l{levels}",
        T::BITS
    ));
    group.throughput(Throughput::Elements(1));
    group.bench_function("fused", |b| {
        b.iter(|| {
            black_box(&positive).cmux_ternary_monomial_to(
                black_box(&negative),
                black_box(&input),
                black_box(exponent),
                &mut output,
                gadget.basis(),
                modulus,
                &table,
                &mut fused,
            );
            black_box(output.as_ref());
        })
    });
    group.bench_function("two_binary", |b| {
        b.iter(|| {
            black_box(&positive).cmux_monomial_to(
                black_box(&input),
                black_box(exponent),
                &mut intermediate,
                gadget.basis(),
                modulus,
                &table,
                &mut binary,
            );
            black_box(&negative).cmux_monomial_to(
                &intermediate,
                black_box(2 * N - exponent),
                &mut output,
                gadget.basis(),
                modulus,
                &table,
                &mut binary,
            );
            black_box(output.as_ref());
        })
    });
    group.finish();
}

fn benchmarks(c: &mut Criterion) {
    ntt(c, 132_120_577u32, 3);
    ntt(c, 1_125_899_906_826_241u64, 6);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(30)
        .warm_up_time(Duration::from_secs(1)).measurement_time(Duration::from_secs(2));
    targets = benchmarks
}
criterion_main!(benches);
