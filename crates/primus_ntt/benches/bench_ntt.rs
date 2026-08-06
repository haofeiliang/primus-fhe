// Run all benchmarks:
// cargo bench -p primus_ntt --bench bench_ntt
//
// Filter by value type or operation, for example:
// cargo bench -p primus_ntt --bench bench_ntt -- "monomial/u64"

use core::fmt::Display;
use std::{hint::black_box, time::Duration};

use criterion::{BatchSize, BenchmarkGroup, BenchmarkId, Criterion, measurement::WallTime};
use primus_integer::FheUint;
use primus_modulus::BarrettModulus;
use primus_ntt::{MonomialNttTable, NttTable, U32NttTable, U64NttTable, UintNttTable};
use rand::distr::{Distribution, Uniform};

const U32_CASES: &[(u32, usize)] = &[(268369921, 4096)];
const U64_CASES: &[(u64, usize)] = &[(1073692673, 4096), (1125899906826241, 4096)];
const INPUT_POOL_SIZE: usize = 16;

#[derive(Clone, Copy)]
struct BenchCase<Value> {
    value_type: &'static str,
    modulus: Value,
    n: usize,
    nontrivial_coeff: Value,
}

fn quick_criterion() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2))
}

fn generate_input_pool<Value>(
    distribution: &impl Distribution<Value>,
    n: usize,
) -> Vec<Vec<Value>> {
    let mut rng = rand::rng();
    (0..INPUT_POOL_SIZE)
        .map(|_| distribution.sample_iter(&mut rng).take(n).collect())
        .collect()
}

fn bench_transform<Value, Table>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    operation: &str,
    implementation: &str,
    table: &Table,
    input_pool: &[Vec<Value>],
    transform: impl Fn(&Table, &mut [Value]),
) where
    Value: FheUint,
    Table: NttTable<ValueT = Value>,
{
    let mut input_index = 0usize;
    group.bench_function(BenchmarkId::new(operation, implementation), |b| {
        b.iter_batched_ref(
            || {
                let input = input_pool[input_index % input_pool.len()].clone();
                input_index = input_index.wrapping_add(1);
                input
            },
            |input| transform(table, black_box(input.as_mut_slice())),
            BatchSize::SmallInput,
        )
    });
}

fn bench_ntt_table<Value, Table>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    implementation: &str,
    table: &Table,
    input_pool: &[Vec<Value>],
) where
    Value: FheUint,
    Table: NttTable<ValueT = Value>,
{
    bench_transform(
        group,
        "forward",
        implementation,
        table,
        input_pool,
        NttTable::transform_slice,
    );
    bench_transform(
        group,
        "inverse",
        implementation,
        table,
        input_pool,
        NttTable::inverse_transform_slice,
    );
}

fn bench_inplace<Value, Table>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    operation: &str,
    implementation: &str,
    table: &Table,
    output: &mut [Value],
    transform: impl Fn(&Table, &mut [Value]),
) where
    Value: FheUint,
    Table: MonomialNttTable<ValueT = Value>,
{
    group.bench_function(BenchmarkId::new(operation, implementation), |b| {
        b.iter(|| transform(table, black_box(&mut *output)))
    });
}

fn bench_monomial_table<Value, Table>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    implementation: &str,
    table: &Table,
    coeff: Value,
    degree: usize,
    output: &mut [Value],
) where
    Value: FheUint,
    Table: MonomialNttTable<ValueT = Value>,
{
    bench_inplace(
        group,
        "arbitrary_coeff",
        implementation,
        table,
        output,
        |table, output| {
            table.transform_monomial(black_box(coeff), black_box(degree), output);
        },
    );
    bench_inplace(
        group,
        "coeff_one",
        implementation,
        table,
        output,
        |table, output| {
            table.transform_coeff_one_monomial(black_box(degree), output);
        },
    );
    bench_inplace(
        group,
        "coeff_minus_one",
        implementation,
        table,
        output,
        |table, output| {
            table.transform_coeff_minus_one_monomial(black_box(degree), output);
        },
    );
}

fn bench_expansion_table<Value, Table>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    implementation: &str,
    table: &Table,
    output: &mut [Value],
) where
    Value: FheUint,
    Table: MonomialNttTable<ValueT = Value>,
{
    let n = output.len();
    let transform_count = n.trailing_zeros();
    let operation = format!("all_shifts_{transform_count}_transforms");
    bench_inplace(
        group,
        &operation,
        implementation,
        table,
        output,
        |table, output| {
            for shift in 0..transform_count {
                table.transform_coeff_one_monomial(black_box(2 * n - (1usize << shift)), output);
            }
        },
    );
}

fn bench_case<Value, Specialized, Generic>(
    criterion: &mut Criterion,
    case: BenchCase<Value>,
    specialized: &Specialized,
    generic: &Generic,
    input_pool: &[Vec<Value>],
) where
    Value: FheUint + Display,
    Specialized: MonomialNttTable<ValueT = Value>,
    Generic: MonomialNttTable<ValueT = Value>,
{
    let BenchCase {
        value_type,
        modulus,
        n,
        nontrivial_coeff,
    } = case;
    let case = format!("{value_type}/q={modulus}/n={n}");

    let mut ntt_group = criterion.benchmark_group(format!("ntt/{case}"));
    bench_ntt_table(&mut ntt_group, "specialized", specialized, input_pool);
    bench_ntt_table(&mut ntt_group, "generic", generic, input_pool);
    ntt_group.finish();

    let degree = n / 3;
    let mut specialized_output = vec![Value::ZERO; n];
    let mut generic_output = vec![Value::ZERO; n];

    let mut monomial_group = criterion.benchmark_group(format!("monomial/{case}"));
    bench_monomial_table(
        &mut monomial_group,
        "specialized",
        specialized,
        nontrivial_coeff,
        degree,
        &mut specialized_output,
    );
    bench_monomial_table(
        &mut monomial_group,
        "generic",
        generic,
        nontrivial_coeff,
        degree,
        &mut generic_output,
    );
    monomial_group.finish();

    let mut expansion_group = criterion.benchmark_group(format!("expansion/{case}"));
    bench_expansion_table(
        &mut expansion_group,
        "specialized",
        specialized,
        &mut specialized_output,
    );
    bench_expansion_table(
        &mut expansion_group,
        "generic",
        generic,
        &mut generic_output,
    );
    expansion_group.finish();
}

fn bench_u32(criterion: &mut Criterion) {
    for &(q, n) in U32_CASES {
        assert!((q - 1).is_multiple_of(2 * n as u32));

        let modulus = BarrettModulus::new(q);
        let log_n = n.trailing_zeros();
        let distribution = Uniform::new(0, q).unwrap();
        let input_pool = generate_input_pool(&distribution, n);
        let specialized = U32NttTable::new(log_n, modulus).unwrap();
        let generic = UintNttTable::<u32>::new(log_n, modulus).unwrap();

        bench_case(
            criterion,
            BenchCase {
                value_type: "u32",
                modulus: q,
                n,
                nontrivial_coeff: q / 3,
            },
            &specialized,
            &generic,
            &input_pool,
        );
    }
}

fn bench_u64(criterion: &mut Criterion) {
    for &(q, n) in U64_CASES {
        assert!((q - 1).is_multiple_of(2 * n as u64));

        let modulus = BarrettModulus::new(q);
        let log_n = n.trailing_zeros();
        let distribution = Uniform::new(0, q).unwrap();
        let input_pool = generate_input_pool(&distribution, n);
        let specialized = U64NttTable::new(log_n, modulus).unwrap();
        let generic = UintNttTable::<u64>::new(log_n, modulus).unwrap();

        bench_case(
            criterion,
            BenchCase {
                value_type: "u64",
                modulus: q,
                n,
                nontrivial_coeff: q / 3,
            },
            &specialized,
            &generic,
            &input_pool,
        );
    }
}

criterion::criterion_group! {
    name = benches;
    config = quick_criterion();
    targets = bench_u32, bench_u64
}
criterion::criterion_main!(benches);
