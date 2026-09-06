use std::hint::black_box;

#[path = "support/rns.rs"]
mod support;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_lattice::{
    GlweSize, RnsGadgetSize, RnsGlweSize,
    context::DcrtGlevMulContext,
    ggsw::CrtGgsw,
    glwe::{CrtGlwe, DcrtGlwe},
};
use primus_modulus::BarrettModulus;
use primus_ntt::U64DcrtTable;
use primus_rns::RNSBase;

fn benchmarks(c: &mut Criterion) {
    for &(log_n, dimension, count, log_b) in support::CASES {
        let n = 1usize << log_n;
        let qs = &support::MODULI[..count];
        let moduli: Vec<_> = qs.iter().copied().map(BarrettModulus::new).collect();
        let base = RNSBase::new(&moduli).unwrap();
        let table = U64DcrtTable::new(log_n, &moduli).unwrap();
        let basis = BigUintApproxSignedBasis::new(base.moduli_product(), log_b, None);
        let levels = basis.decompose_length();
        let size = RnsGadgetSize::new(RnsGlweSize::new(GlweSize::new(dimension, n), count), levels);
        let glwe_len = size.rns_glwe_size().rns_glwe_len();
        let key = CrtGgsw::new(support::coefficients(size.rns_ggsw_len(), n, qs, 17))
            .into_ntt_form(&table);
        let input = CrtGlwe::new(support::coefficients(glwe_len, n, qs, 29));
        let mut output = DcrtGlwe::new(vec![0; glwe_len]);
        let mut context = DcrtGlevMulContext::new(size, &base);
        let mut group = c.benchmark_group(format!(
            "rns/ggsw/u64/n{n}/k{dimension}/m{count}/logb{log_b}/l{levels}"
        ));
        group.throughput(Throughput::Elements(glwe_len as u64));
        group.bench_function("crt_to_dcrt", |b| {
            b.iter(|| {
                black_box(&input).mul_dcrt_ggsw_to(
                    black_box(&key),
                    black_box(&mut output),
                    black_box(&basis),
                    black_box(&table),
                    black_box(&base),
                    black_box(&mut context),
                )
            })
        });
        group.finish();
    }
}
criterion_group!(benches, benchmarks);
criterion_main!(benches);
