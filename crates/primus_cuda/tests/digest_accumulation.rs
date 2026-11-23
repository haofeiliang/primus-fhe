use std::sync::Arc;

use cudarc::driver::{CudaContext, CudaSlice, CudaStream};
use primus_cuda::{CudaDigestAccumulation64, CudaNttPlan64};
use primus_lattice::{GlweDimension, GlweSize};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U64NttTable};
use primus_shape::PolyLength;

const CAPACITY: usize = 4;
const STORED: usize = CAPACITY + 1;

fn download(stream: &Arc<CudaStream>, device: &CudaSlice<u64>) -> Vec<u64> {
    let mut host = vec![0; device.len()];
    stream.memcpy_dtoh(device, &mut host).unwrap();
    stream.context().check_err().unwrap();
    host
}

fn transform_polynomials(table: &U64NttTable, values: &mut [u64]) {
    for polynomial in values.chunks_exact_mut(table.poly_length().get()) {
        table.transform_slice(polynomial);
    }
}

fn inverse_polynomials(table: &U64NttTable, values: &mut [u64]) {
    for polynomial in values.chunks_exact_mut(table.poly_length().get()) {
        table.inverse_transform_slice(polynomial);
    }
}

fn flags(n: usize, components: usize, q: u64, sentinel: u64) -> Vec<u64> {
    let mut values = vec![sentinel; STORED * components * n + 2];
    let edges = [0, 1, q - 1, q - 2, q / 2, q / 2 + 1];
    for (index, value) in values[1..1 + STORED * components * n]
        .iter_mut()
        .enumerate()
    {
        *value = if index % 11 < edges.len() {
            edges[index % 11]
        } else {
            ((index as u128 * 71_279 + 35_317) % u128::from(q)) as u64
        };
    }
    // A zero body constant does not make the full noisy GLWE zero. All mask
    // components and the remaining body coefficients must still contribute.
    values[1 + components * n + (components - 1) * n] = 0;
    values
}

fn public_polynomials(
    n: usize,
    q: u64,
    physical_count: usize,
    padding: usize,
    sentinel: u64,
) -> Vec<u64> {
    let mut values = vec![sentinel; STORED * physical_count * n + 2];
    for record in 0..STORED {
        for physical in 0..physical_count {
            let start = 1 + (record * physical_count + physical) * n;
            for (coefficient, value) in values[start..start + n].iter_mut().enumerate() {
                let digit = ((record * 29 + physical * 17 + coefficient * 13) % 257) as u64;
                // Already centered-lifted F257 coefficients, with no encoding scale.
                *value = if digit <= 128 {
                    digit
                } else {
                    q - (257 - digit)
                };
            }
            if physical == 0 {
                // The initial extension-field power sum is [1, 0, 0]. Index
                // and payload coefficients otherwise share this same polynomial.
                values[start..start + 3].copy_from_slice(&[1, 0, 0]);
                values[start + 3..start + 8].copy_from_slice(&[128, q - 128, q - 1, 0, 1]);
            }
            if physical + 1 == physical_count {
                // Only the public polynomial is padded. Full ring products can
                // carry nonconstant flag noise into these output coefficients.
                values[start + n - padding..start + n].fill(0);
            }
        }
    }
    values
}

fn add_ntt_oracle(
    sums: &mut [u64],
    flags: &[u64],
    public: &[u64],
    n: usize,
    components: usize,
    q: u64,
) {
    let physical_count = sums.len() / (components * n);
    for record in 0..flags.len() / (components * n) {
        for physical in 0..physical_count {
            for component in 0..components {
                for coefficient in 0..n {
                    let output_index = (physical * components + component) * n + coefficient;
                    let flag_index = (record * components + component) * n + coefficient;
                    let public_index = (record * physical_count + physical) * n + coefficient;
                    sums[output_index] = ((u128::from(sums[output_index])
                        + u128::from(flags[flag_index]) * u128::from(public[public_index]))
                        % u128::from(q)) as u64;
                }
            }
        }
    }
}

// Independent schoolbook multiplication in Z_q[X]/(X^N+1), used only for N=32.
fn add_coefficient_oracle(
    sums: &mut [u64],
    flags: &[u64],
    public: &[u64],
    n: usize,
    components: usize,
    q: u64,
) {
    let physical_count = sums.len() / (components * n);
    for record in 0..flags.len() / (components * n) {
        for physical in 0..physical_count {
            for component in 0..components {
                let output = (physical * components + component) * n;
                let flag = (record * components + component) * n;
                let public = &public[(record * physical_count + physical) * n..][..n];
                for (i, &lhs) in flags[flag..flag + n].iter().enumerate() {
                    for (j, &rhs) in public.iter().enumerate() {
                        let product = u128::from(lhs) * u128::from(rhs) % u128::from(q);
                        let index = output + (i + j) % n;
                        let value = u128::from(sums[index]);
                        sums[index] = if i + j < n {
                            ((value + product) % u128::from(q)) as u64
                        } else {
                            ((u128::from(q) + value - product) % u128::from(q)) as u64
                        };
                    }
                }
            }
        }
    }
}

fn check_accumulation(
    n: usize,
    dimension: usize,
    q: u64,
    physical_count: usize,
    padding: usize,
    direct_oracle: bool,
) {
    let stream = CudaContext::new(0).unwrap().new_stream().unwrap();
    let size = GlweSize::new(GlweDimension::new(dimension), PolyLength::new(n));
    let components = size.component_count();
    let glwe_len = size.glwe_len();
    let public_len = physical_count * n;
    let sum_len = physical_count * glwe_len;
    let table = U64NttTable::new(PolyLength::new(n), BarrettModulus::new(q)).unwrap();
    let plan = CudaNttPlan64::new(&stream, &table).unwrap();
    let operation = CudaDigestAccumulation64::new(&plan, size, physical_count, CAPACITY).unwrap();
    let sentinel = q - 7;
    let flags = flags(n, components, q, sentinel);
    let public = public_polynomials(n, q, physical_count, padding, sentinel);
    let mut expected_coefficients = (0..sum_len)
        .map(|i| ((i as u128 * 8_191 + 17) % u128::from(q)) as u64)
        .collect::<Vec<_>>();
    let mut expected_ntt = expected_coefficients.clone();
    transform_polynomials(&table, &mut expected_ntt);
    let mut initial = vec![sentinel; sum_len + 2];
    initial[1..1 + sum_len].copy_from_slice(&expected_ntt);
    let mut sums = stream.clone_htod(&initial).unwrap();
    let mut device_flags = stream.clone_htod(&flags).unwrap();
    let mut device_public = stream.clone_htod(&public).unwrap();
    let mut coefficient_copy = stream.alloc_zeros::<u64>(sum_len).unwrap();

    // Inputs are replenished in coefficient form before each submission. Sums
    // stay resident in NTT form, including across shorter workspace reuse.
    for active in [CAPACITY, 1, 3] {
        stream.memcpy_htod(&flags, &mut device_flags).unwrap();
        stream.memcpy_htod(&public, &mut device_public).unwrap();
        let mut expected_flags = flags.clone();
        let mut expected_public = public.clone();
        transform_polynomials(&table, &mut expected_flags[1..1 + active * glwe_len]);
        transform_polynomials(&table, &mut expected_public[1..1 + active * public_len]);
        add_ntt_oracle(
            &mut expected_ntt,
            &expected_flags[1..1 + active * glwe_len],
            &expected_public[1..1 + active * public_len],
            n,
            components,
            q,
        );
        if direct_oracle {
            add_coefficient_oracle(
                &mut expected_coefficients,
                &flags[1..1 + active * glwe_len],
                &public[1..1 + active * public_len],
                n,
                components,
                q,
            );
        } else {
            expected_coefficients.copy_from_slice(&expected_ntt);
            inverse_polynomials(&table, &mut expected_coefficients);
        }
        operation
            .accumulate_assign(
                sums.slice_mut(1..1 + sum_len),
                device_flags.slice_mut(1..1 + active * glwe_len),
                device_public.slice_mut(1..1 + active * public_len),
            )
            .unwrap();
        initial[1..1 + sum_len].copy_from_slice(&expected_ntt);
        assert_eq!(download(&stream, &sums), initial, "active={active}");
        assert_eq!(download(&stream, &device_flags), expected_flags);
        assert_eq!(download(&stream, &device_public), expected_public);
        stream
            .memcpy_dtod(&sums.slice(1..1 + sum_len), &mut coefficient_copy)
            .unwrap();
        plan.inverse_transform_assign(coefficient_copy.slice_mut(..))
            .unwrap();
        assert_eq!(download(&stream, &coefficient_copy), expected_coefficients);
    }

    stream.memcpy_htod(&flags, &mut device_flags).unwrap();
    stream.memcpy_htod(&public, &mut device_public).unwrap();
    for (sums_count, flags_count, public_count) in [
        (sum_len - 1, glwe_len, public_len),
        (sum_len + 1, glwe_len, public_len),
        (sum_len, glwe_len - 1, public_len),
        (sum_len, glwe_len, public_len - 1),
        (sum_len, glwe_len, 2 * public_len),
        (sum_len, STORED * glwe_len, STORED * public_len),
        (sum_len, 0, public_len),
        (sum_len, glwe_len, 0),
    ] {
        assert!(
            operation
                .accumulate_assign(
                    sums.slice_mut(1..1 + sums_count),
                    device_flags.slice_mut(1..1 + flags_count),
                    device_public.slice_mut(1..1 + public_count),
                )
                .is_err()
        );
        // All validation must precede both in-place input transforms and MACs.
        assert_eq!(download(&stream, &sums), initial);
        assert_eq!(download(&stream, &device_flags), flags);
        assert_eq!(download(&stream, &device_public), public);
    }
    operation
        .accumulate_assign(
            sums.slice_mut(1..1 + sum_len),
            device_flags.slice_mut(..0),
            device_public.slice_mut(..0),
        )
        .unwrap();
    assert_eq!(download(&stream, &sums), initial);

    let other_stream = stream.context().new_stream().unwrap();
    let mut foreign_flags = other_stream.clone_htod(&flags).unwrap();
    assert!(
        operation
            .accumulate_assign(
                sums.slice_mut(1..1 + sum_len),
                foreign_flags.slice_mut(1..1 + glwe_len),
                device_public.slice_mut(1..1 + public_len),
            )
            .is_err()
    );
    assert_eq!(download(&stream, &sums), initial);
    assert_eq!(download(&other_stream, &foreign_flags), flags);
    assert_eq!(download(&stream, &device_public), public);

    for (invalid_count, capacity) in [(0, CAPACITY), (physical_count, 0), (usize::MAX, CAPACITY)] {
        assert!(CudaDigestAccumulation64::new(&plan, size, invalid_count, capacity).is_err());
    }
    let wrong_size = GlweSize::new(GlweDimension::new(dimension), PolyLength::new(2 * n));
    assert!(CudaDigestAccumulation64::new(&plan, wrong_size, physical_count, CAPACITY).is_err());
}

#[test]
fn rank_two_digest_matches_independent_negacyclic_products() {
    check_accumulation(32, 2, 998_244_353, 3, 16, true);
}

#[test]
fn omr_digest_matches_cpu_ntt_and_u128_accumulation() {
    // 6*50 index coefficients plus 55 rows of 612 payload digits.
    check_accumulation(2048, 1, 1_125_899_906_826_241, 17, 856, false);
}
