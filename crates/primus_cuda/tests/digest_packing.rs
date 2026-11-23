use std::sync::Arc;

use cudarc::driver::{CudaContext, CudaSlice, CudaStream, DeviceRepr};
use primus_cuda::{CudaDigestPacking64, CudaNttPlan64};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U64NttTable};
use primus_shape::PolyLength;

fn download<T: DeviceRepr + Default + Clone>(
    stream: &Arc<CudaStream>,
    values: &CudaSlice<T>,
) -> Vec<T> {
    let mut host = vec![T::default(); values.len()];
    stream.memcpy_dtoh(values, &mut host).unwrap();
    stream.context().check_err().unwrap();
    host
}

// Build the logical stream row by row, independently of the kernel's output-index
// mapping. In particular one row's weight survives a physical-polynomial cut.
fn pack_oracle(record: &[u16], index_len: usize, digits: usize, n: usize, q: u64) -> Vec<u64> {
    let mut values = record[..index_len].to_vec();
    for &weight in &record[index_len + digits..] {
        values.extend(
            record[index_len..index_len + digits]
                .iter()
                .map(|&digit| (u32::from(weight) * u32::from(digit) % 257) as u16),
        );
    }
    values.resize(values.len().div_ceil(n) * n, 0);
    values
        .into_iter()
        .map(|value| {
            let signed = i64::from(value) - if value > 128 { 257 } else { 0 };
            signed.rem_euclid(q as i64) as u64
        })
        .collect()
}

#[test]
fn compact_f257_packing_matches_continuous_centered_stream() {
    const N: usize = 32;
    const Q: u64 = 998_244_353;
    const CAPACITY: usize = 3;
    const STORED: usize = CAPACITY + 1;
    let stream = CudaContext::new(0).unwrap().new_stream().unwrap();
    let table = U64NttTable::new(PolyLength::new(N), BarrettModulus::new(Q)).unwrap();
    let plan = CudaNttPlan64::new(&stream, &table).unwrap();
    for (index_len, digits, rows) in [(6, 11, 6), (N, 8, 4)] {
        let input_stride = index_len + digits + rows;
        let output_stride = (index_len + digits * rows).div_ceil(N) * N;
        let operation = CudaDigestPacking64::new(&plan, index_len, digits, rows, CAPACITY).unwrap();
        let mut input = vec![u16::MAX; STORED * input_stride + 2];
        let edges = [0, 1, 128, 129, 256, 3];
        for record in 0..STORED {
            for (position, value) in input[1 + record * input_stride..][..input_stride]
                .iter_mut()
                .enumerate()
            {
                *value = edges[(position + record) % edges.len()];
            }
        }
        let initial = vec![Q - 7; STORED * output_stride + 2];
        let device_input = stream.clone_htod(&input).unwrap();
        let mut output = stream.clone_htod(&initial).unwrap();
        for active in [CAPACITY, 1, 2] {
            stream.memcpy_htod(&initial, &mut output).unwrap();
            operation
                .pack_to(
                    device_input.slice(1..1 + active * input_stride),
                    output.slice_mut(1..1 + active * output_stride),
                )
                .unwrap();
            let mut expected = initial.clone();
            for record in 0..active {
                let packed = pack_oracle(
                    &input[1 + record * input_stride..][..input_stride],
                    index_len,
                    digits,
                    N,
                    Q,
                );
                expected[1 + record * output_stride..][..output_stride].copy_from_slice(&packed);
            }
            assert_eq!(download(&stream, &output), expected);
        }
        assert_eq!(download(&stream, &device_input), input);
        stream.memcpy_htod(&initial, &mut output).unwrap();
        for (input_len, output_len) in [
            (input_stride - 1, output_stride),
            (input_stride, output_stride - 1),
            (input_stride, 2 * output_stride),
            (STORED * input_stride, STORED * output_stride),
            (0, output_stride),
        ] {
            assert!(
                operation
                    .pack_to(
                        device_input.slice(1..1 + input_len),
                        output.slice_mut(1..1 + output_len),
                    )
                    .is_err()
            );
            assert_eq!(download(&stream, &output), initial);
        }
        operation
            .pack_to(device_input.slice(..0), output.slice_mut(..0))
            .unwrap();
        assert_eq!(download(&stream, &output), initial);

        let foreign_stream = stream.context().new_stream().unwrap();
        let foreign_input = foreign_stream.clone_htod(&input).unwrap();
        assert!(
            operation
                .pack_to(
                    foreign_input.slice(1..1 + input_stride),
                    output.slice_mut(1..1 + output_stride),
                )
                .is_err()
        );
        assert_eq!(download(&stream, &output), initial);
    }
    for (index, digits, rows, capacity) in [
        (N + 1, 11, 6, CAPACITY),
        (6, 0, 6, CAPACITY),
        (6, 11, 0, CAPACITY),
        (6, 11, 6, 0),
        (6, usize::MAX, 6, CAPACITY),
        (6, 11, usize::MAX, CAPACITY),
    ] {
        assert!(CudaDigestPacking64::new(&plan, index, digits, rows, capacity).is_err());
    }
    let small_table = U64NttTable::new(PolyLength::new(N), BarrettModulus::new(193)).unwrap();
    let small_plan = CudaNttPlan64::new(&stream, &small_table).unwrap();
    assert!(CudaDigestPacking64::new(&small_plan, 6, 11, 6, CAPACITY).is_err());
}
