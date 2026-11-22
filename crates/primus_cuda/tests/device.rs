use std::sync::Arc;

use cudarc::driver::{CudaContext, CudaSlice, CudaStream, DeviceRepr};
use primus_cuda::{CudaError, CudaNttPlan32, CudaNttPlan64, cuda_smoke};
use primus_modulus::BarrettModulus;
use primus_ntt::{MonomialNttTable, NttTable, U32NttTable, U64NttTable};
use primus_poly::Polynomial;
use primus_shape::PolyLength;

const OMR_N: usize = 2048;
const OMR_Q32: u32 = 998_244_353;
const OMR_Q64: u64 = 1_125_899_906_826_241;

#[test]
fn smoke_wraps_and_covers_partial_block() {
    let stream = CudaContext::new(0).unwrap().new_stream().unwrap();
    let input: Vec<_> = (0..263_u32).map(|i| u32::MAX.wrapping_sub(i)).collect();
    let expected: Vec<_> = input.iter().map(|&value| value.wrapping_add(1)).collect();
    assert_eq!(cuda_smoke(&stream, &input).unwrap(), expected);
    assert!(cuda_smoke(&stream, &[]).unwrap().is_empty());
}

fn inputs<T: TryFrom<u64, Error: std::fmt::Debug>>(q: u64, count: usize, seed: u64) -> Vec<T> {
    let mut state = seed;
    let edges = [0, 1, q - 1, q - 2, q / 2];
    (0..count)
        .map(|i| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let value = edges.get(i % 29).copied().unwrap_or(state % q);
            T::try_from(value).unwrap()
        })
        .collect()
}

fn multiply(lhs: u64, rhs: u64, q: u64) -> u64 {
    (u128::from(lhs) * u128::from(rhs) % u128::from(q)) as u64
}

fn power(mut base: u64, mut exponent: usize, q: u64) -> u64 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = multiply(result, base, q);
        }
        base = multiply(base, base, q);
        exponent >>= 1;
    }
    result
}

fn direct_evaluation<T: Copy + Into<u64>>(polynomial: &[T], root: u64, q: u64) -> Vec<u64> {
    let n = polynomial.len();
    (0..n)
        .map(|i| {
            let reverse = i.reverse_bits() >> (usize::BITS - n.ilog2());
            let point = power(root, 2 * reverse + 1, q);
            polynomial.iter().rev().fold(0, |value, &coefficient| {
                (multiply(value, point, q) + coefficient.into()) % q
            })
        })
        .collect()
}

fn schoolbook<T: Copy + Into<u64>>(lhs: &[T], rhs: &[T], q: u64) -> Vec<u64> {
    let n = lhs.len();
    let mut product = vec![0; n];
    for (i, &a) in lhs.iter().enumerate() {
        for (j, &b) in rhs.iter().enumerate() {
            let term = multiply(a.into(), b.into(), q);
            let degree = i + j;
            if degree < n {
                product[degree] = (product[degree] + term) % q;
            } else {
                product[degree - n] = (product[degree - n] + q - term) % q;
            }
        }
    }
    product
}

fn compare<L: Copy + Into<u64>, R: Copy + Into<u64>>(actual: &[L], expected: &[R], case: &str) {
    assert_eq!(actual.len(), expected.len(), "{case} length");
    for (i, (&lhs, &rhs)) in actual.iter().zip(expected).enumerate() {
        assert_eq!(lhs.into(), rhs.into(), "{case}, coefficient {i}");
    }
}

fn download<T: Clone + Default + DeviceRepr>(
    stream: &Arc<CudaStream>,
    device: &CudaSlice<T>,
) -> Vec<T> {
    let mut host = vec![T::default(); device.len()];
    stream.memcpy_dtoh(device, &mut host).unwrap();
    stream.context().check_err().unwrap();
    host
}

macro_rules! check_ntt {
    ($test:ident, $word:ty, $table:ty, $plan:ty, $q:expr) => {
        #[test]
        fn $test() {
            let stream = CudaContext::new(0).unwrap().new_stream().unwrap();
            let modulus = BarrettModulus::new($q);
            let q = Into::<u64>::into($q);

            let n = 32;
            let table = <$table>::new(PolyLength::new(n), modulus).unwrap();
            let plan = <$plan>::new(&stream, &table).unwrap();
            let lhs = inputs::<$word>(q, n, 42);
            let rhs = inputs::<$word>(q, n, 43);
            // The CPU table supplies the choice of primitive root. Horner's
            // method independently computes the output points and values.
            let root = table.root_powers()[n / 2].into();
            let mut left = stream.clone_htod(&lhs).unwrap();
            let mut right = stream.clone_htod(&rhs).unwrap();
            plan.transform_assign(left.as_view_mut()).unwrap();
            plan.transform_assign(right.as_view_mut()).unwrap();
            compare(
                &stream.clone_dtoh(&left).unwrap(),
                &direct_evaluation(&lhs, root, q),
                "direct forward evaluation",
            );
            plan.mul_assign(left.as_view_mut(), right.as_view())
                .unwrap();
            plan.inverse_transform_assign(left.as_view_mut()).unwrap();
            compare(
                &stream.clone_dtoh(&left).unwrap(),
                &schoolbook(&lhs, &rhs, q),
                "negacyclic convolution",
            );

            let table = <$table>::new(PolyLength::new(OMR_N), modulus).unwrap();
            let plan = <$plan>::new(&stream, &table).unwrap();
            let input = inputs::<$word>(q, 3 * OMR_N, 2026);
            let mut device = stream.clone_htod(&input).unwrap();
            let mut expected = input.clone();
            for poly in expected.chunks_exact_mut(OMR_N) {
                table.transform_slice(poly);
            }
            plan.transform_assign(device.as_view_mut()).unwrap();
            compare(
                &stream.clone_dtoh(&device).unwrap(),
                &expected,
                "CPU forward",
            );

            // Feed the inverse an independent spectrum. A round trip alone
            // could hide a matching mistake in the forward and inverse.
            let spectrum = inputs::<$word>(q, input.len(), 2027);
            let mut device = stream.clone_htod(&spectrum).unwrap();
            expected.copy_from_slice(&spectrum);
            for poly in expected.chunks_exact_mut(OMR_N) {
                table.inverse_transform_slice(poly);
            }
            plan.inverse_transform_assign(device.as_view_mut()).unwrap();
            compare(
                &stream.clone_dtoh(&device).unwrap(),
                &expected,
                "CPU inverse",
            );

            let lhs = inputs::<$word>(q, 264, 101);
            let rhs = inputs::<$word>(q, 264, 102);
            let mut left = stream.clone_htod(&lhs).unwrap();
            let right = stream.clone_htod(&rhs).unwrap();
            plan.mul_assign(left.slice_mut(1..), right.slice(1..))
                .unwrap();
            let products = lhs
                .iter()
                .zip(&rhs)
                .skip(1)
                .map(|(&l, &r)| multiply(l.into(), r.into(), q));
            let expected: Vec<_> = std::iter::once(lhs[0].into()).chain(products).collect();
            compare(
                &stream.clone_dtoh(&left).unwrap(),
                &expected,
                "exact product with partial block",
            );
        }
    };
}

check_ntt!(
    omr_u32_matches_host,
    u32,
    U32NttTable,
    CudaNttPlan32,
    OMR_Q32
);
check_ntt!(
    omr_u64_matches_host,
    u64,
    U64NttTable,
    CudaNttPlan64,
    OMR_Q64
);

#[test]
fn u64_barrett_word_boundaries() {
    let stream = CudaContext::new(0).unwrap().new_stream().unwrap();
    // Exercise the below-word shift, exact-word shift, and the largest
    // supported bit length outside the OMR modulus's 50-bit case.
    for q in [u64::from(OMR_Q32), 3_221_225_473, 4_611_686_018_427_387_329] {
        let table = U64NttTable::new(PolyLength::new(32), BarrettModulus::new(q)).unwrap();
        let plan = CudaNttPlan64::new(&stream, &table).unwrap();
        let lhs = inputs::<u64>(q, 263, 151);
        let rhs = inputs::<u64>(q, 263, 152);
        let mut left = stream.clone_htod(&lhs).unwrap();
        let right = stream.clone_htod(&rhs).unwrap();
        plan.mul_assign(left.as_view_mut(), right.as_view())
            .unwrap();
        let expected: Vec<_> = lhs
            .iter()
            .zip(&rhs)
            .map(|(&a, &b)| multiply(a, b, q))
            .collect();
        compare(
            &stream.clone_dtoh(&left).unwrap(),
            &expected,
            "u64 Barrett shift boundaries",
        );
    }
}

#[test]
fn rejects_incompatible_shapes_before_writing() {
    let stream = CudaContext::new(0).unwrap().new_stream().unwrap();
    let modulus = BarrettModulus::new(OMR_Q32);
    let table = U32NttTable::new(PolyLength::new(OMR_N), modulus).unwrap();
    let plan = CudaNttPlan32::new(&stream, &table).unwrap();
    let input = [3, 5, 7];
    let mut lhs = stream.clone_htod(&input).unwrap();
    let rhs = stream.clone_htod(&[2]).unwrap();
    assert!(matches!(
        plan.transform_assign(lhs.as_view_mut()),
        Err(CudaError::IncompletePolynomialBatch { .. })
    ));
    assert!(matches!(
        plan.mul_assign(lhs.as_view_mut(), rhs.as_view()),
        Err(CudaError::LengthMismatch { .. })
    ));
    plan.transform_assign(lhs.slice_mut(..0)).unwrap();
    plan.mul_assign(lhs.slice_mut(..0), rhs.slice(..0)).unwrap();
    assert_eq!(stream.clone_dtoh(&lhs).unwrap(), input);

    let oversized = U32NttTable::new(PolyLength::new(2 * OMR_N), modulus).unwrap();
    assert!(matches!(
        CudaNttPlan32::new(&stream, &oversized),
        Err(CudaError::UnsupportedPolynomialLength { .. })
    ));
}

#[test]
fn device_views_must_use_the_plan_stream() {
    let context = CudaContext::new(0).unwrap();
    let stream = context.new_stream().unwrap();
    let table = U32NttTable::new(PolyLength::new(32), BarrettModulus::new(OMR_Q32)).unwrap();
    let plan = CudaNttPlan32::new(&stream, &table).unwrap();
    assert!(matches!(
        CudaNttPlan32::new(&context.per_thread_stream(), &table),
        Err(CudaError::UnsupportedStream)
    ));
    let input = inputs::<u32>(u64::from(OMR_Q32), 32, 60);
    let mut device = plan.stream().clone_htod(&input).unwrap();
    let other_stream = context.new_stream().unwrap();
    let mut foreign = other_stream.clone_htod(&input).unwrap();
    assert!(matches!(
        plan.transform_assign(foreign.as_view_mut()),
        Err(CudaError::StreamMismatch)
    ));
    assert!(matches!(
        plan.mul_assign(device.as_view_mut(), foreign.as_view()),
        Err(CudaError::StreamMismatch)
    ));
    compare(
        &other_stream.clone_dtoh(&foreign).unwrap(),
        &input,
        "foreign stream rejection",
    );
    plan.transform_assign(device.as_view_mut()).unwrap();
    let mut expected = input;
    table.transform_slice(&mut expected);
    compare(
        &stream.clone_dtoh(&device).unwrap(),
        &expected,
        "plan stream",
    );
}

macro_rules! check_coefficient_kernels {
    ($mac_test:ident, $monomial_test:ident, $word:ty, $table:ty, $plan:ty, $q:expr) => {
        #[test]
        fn $mac_test() {
            let stream = CudaContext::new(0).unwrap().new_stream().unwrap();
            let table = <$table>::new(PolyLength::new(OMR_N), BarrettModulus::new($q)).unwrap();
            let plan = <$plan>::new(&stream, &table).unwrap();
            let q = Into::<u64>::into($q);

            for count in [3 * OMR_N, 263] {
                let mut initial = inputs::<$word>(q, count + 2, 301);
                let mut lhs = inputs::<$word>(q, count + 2, 302);
                let mut rhs = inputs::<$word>(q, count + 2, 303);
                // Include reduction across q and nonzero accumulation, even
                // when multiplication itself yields zero or a small residue.
                for (index, (acc, a, b)) in [
                    (0, 0, q - 1),
                    (q - 1, 0, 1),
                    (q - 1, q - 1, q - 1),
                    (1, q - 1, 1),
                    (q - 1, 1, 1),
                    (q / 2, q - 1, q - 2),
                    (q - 2, q / 2, q / 2),
                ]
                .into_iter()
                .enumerate()
                {
                    initial[index + 1] = acc as $word;
                    lhs[index + 1] = a as $word;
                    rhs[index + 1] = b as $word;
                }
                let mut acc = stream.clone_htod(&initial).unwrap();
                let left = stream.clone_htod(&lhs).unwrap();
                let right = stream.clone_htod(&rhs).unwrap();
                let mut expected: Vec<u64> = initial.iter().map(|&value| value.into()).collect();
                // A second update distinguishes += from overwriting with a*b.
                for _ in 0..2 {
                    plan.add_mul_assign(
                        acc.slice_mut(1..count + 1),
                        left.slice(1..count + 1),
                        right.slice(1..count + 1),
                    )
                    .unwrap();
                    for ((sum, &a), &b) in expected[1..count + 1]
                        .iter_mut()
                        .zip(&lhs[1..count + 1])
                        .zip(&rhs[1..count + 1])
                    {
                        *sum = ((u128::from(*sum) + u128::from(a) * u128::from(b)) % u128::from(q))
                            as u64;
                    }
                    compare(
                        &download(&stream, &acc),
                        &expected,
                        "accumulating product and untouched view sentinels",
                    );
                }
                compare(&download(&stream, &left), &lhs, "MAC shared lhs");
                compare(&download(&stream, &right), &rhs, "MAC shared rhs");
            }

            let initial = [7 as $word; 5];
            let mut acc = stream.clone_htod(&initial).unwrap();
            let lhs = stream.clone_htod(&[3 as $word; 5]).unwrap();
            let rhs = stream.clone_htod(&[5 as $word; 5]).unwrap();
            assert!(matches!(
                plan.add_mul_assign(acc.as_view_mut(), lhs.slice(..4), rhs.as_view()),
                Err(CudaError::LengthMismatch { .. })
            ));
            assert!(matches!(
                plan.add_mul_assign(acc.as_view_mut(), lhs.as_view(), rhs.slice(..4)),
                Err(CudaError::LengthMismatch { .. })
            ));
            // Empty output must not bypass validation of the other operands.
            assert!(matches!(
                plan.add_mul_assign(acc.slice_mut(..0), lhs.slice(..1), rhs.slice(..0)),
                Err(CudaError::LengthMismatch { .. })
            ));
            assert!(matches!(
                plan.add_mul_assign(acc.slice_mut(..0), lhs.slice(..0), rhs.slice(..1)),
                Err(CudaError::LengthMismatch { .. })
            ));
            plan.add_mul_assign(acc.slice_mut(..0), lhs.slice(..0), rhs.slice(..0))
                .unwrap();
            compare(
                &download(&stream, &acc),
                &initial,
                "MAC shape rejection before accumulator writes",
            );
        }

        #[test]
        fn $monomial_test() {
            let stream = CudaContext::new(0).unwrap().new_stream().unwrap();
            let modulus = BarrettModulus::new($q);
            let table = <$table>::new(PolyLength::new(OMR_N), modulus).unwrap();
            let plan = <$plan>::new(&stream, &table).unwrap();
            let q = Into::<u64>::into($q);
            let count = 3 * OMR_N;
            let mut input = inputs::<$word>(q, count + 2, 401);
            input[1] = 0;
            input[OMR_N] = 0;
            input[OMR_N + 1] = (q - 1) as $word;
            input[2 * OMR_N] = 1;
            input[count] = (q - 1) as $word;
            let device_input = stream.clone_htod(&input).unwrap();
            let sentinel = 7 as $word;
            let mut output = stream.clone_htod(&vec![sentinel; count + 2]).unwrap();
            for degree in [
                0,
                1,
                OMR_N - 1,
                OMR_N,
                OMR_N + 1,
                2 * OMR_N - 1,
                2 * OMR_N,
                2 * OMR_N + 1,
                usize::MAX,
            ] {
                let mut expected = vec![sentinel; count + 2];
                for (source, destination) in input[1..count + 1]
                    .chunks_exact(OMR_N)
                    .zip(expected[1..count + 1].chunks_exact_mut(OMR_N))
                {
                    Polynomial::new(source).mul_monomial_to(
                        degree % (2 * OMR_N),
                        &mut Polynomial::new(destination),
                        modulus,
                    );
                }
                plan.mul_monomial_to(
                    device_input.slice(1..count + 1),
                    degree,
                    output.slice_mut(1..count + 1),
                )
                .unwrap();
                compare(
                    &download(&stream, &output),
                    &expected,
                    &format!("CPU monomial, degree={degree}, batch boundaries and sentinels"),
                );
            }
            compare(
                &download(&stream, &device_input),
                &input,
                "monomial shared input",
            );

            let initial = vec![sentinel; count + 2];
            stream.memcpy_htod(&initial, &mut output).unwrap();
            assert!(matches!(
                plan.mul_monomial_to(
                    device_input.slice(1..OMR_N + 1),
                    1,
                    output.slice_mut(1..2 * OMR_N + 1),
                ),
                Err(CudaError::LengthMismatch { .. })
            ));
            // A truncated final polynomial must be rejected before writing
            // any of the preceding complete polynomials.
            for invalid_count in [OMR_N - 1, 2 * OMR_N + 1] {
                assert!(matches!(
                    plan.mul_monomial_to(
                        device_input.slice(1..invalid_count + 1),
                        OMR_N,
                        output.slice_mut(1..invalid_count + 1),
                    ),
                    Err(CudaError::IncompletePolynomialBatch { .. })
                ));
            }
            assert!(matches!(
                plan.mul_monomial_to(device_input.slice(..OMR_N), 0, output.slice_mut(..0),),
                Err(CudaError::LengthMismatch { .. })
            ));
            plan.mul_monomial_to(device_input.slice(..0), usize::MAX, output.slice_mut(..0))
                .unwrap();
            compare(
                &download(&stream, &output),
                &initial,
                "monomial shape rejection before output writes",
            );
        }
    };
}

check_coefficient_kernels!(
    omr_u32_mac_matches_exact_arithmetic,
    omr_u32_monomial_matches_cpu,
    u32,
    U32NttTable,
    CudaNttPlan32,
    OMR_Q32
);
check_coefficient_kernels!(
    omr_u64_mac_matches_exact_arithmetic,
    omr_u64_monomial_matches_cpu,
    u64,
    U64NttTable,
    CudaNttPlan64,
    OMR_Q64
);
