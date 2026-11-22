use std::sync::Arc;

use cudarc::driver::{CudaContext, CudaSlice, CudaStream};
use primus_cuda::{CudaNttPlan32, CudaPackedLweExtraction32};
use primus_lattice::{LweDimension, lwe::MultiMsgLwe};
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_ntt::{NttTable, U32NttTable};
use primus_shape::PolyLength;

const Q: u32 = 1 << 19;
const MASK: u32 = Q - 1;
const PERIOD: usize = 4096;
const LANES: usize = 4;
const CAPACITY: usize = 4;
const STORED_CLUES: usize = CAPACITY + 1;
const SENTINEL: u32 = 0xfeed_babe;

fn download(stream: &Arc<CudaStream>, device: &CudaSlice<u32>) -> Vec<u32> {
    let mut host = vec![0; device.len()];
    stream.memcpy_dtoh(device, &mut host).unwrap();
    stream.context().check_err().unwrap();
    host
}

fn packed_inputs(dimension: usize) -> Vec<u32> {
    let mut data = Vec::with_capacity(STORED_CLUES * (dimension + LANES) + 2);
    data.push(SENTINEL);
    let edges = [0, 1, 63, 64, 65, 127, Q - 65, Q - 64, Q - 63, Q - 1];
    for clue in 0..STORED_CLUES {
        for index in 0..dimension {
            data.push(match clue {
                // Body zero and positive residual sum force signed floor in
                // centering. The next two masks bracket the rounding tie.
                0 => 63,
                1 => 64,
                2 => 65,
                _ => edges[(index * (2 * clue + 1) + clue) % edges.len()],
            });
        }
        let bodies = [0, Q - 1, 64, Q - 64];
        for lane in 0..LANES {
            data.push(bodies[(clue + lane) % LANES]);
        }
    }
    data.push(SENTINEL);
    data
}

fn cpu_expansion(input: &[u32], dimension: usize, centering: Option<usize>) -> Vec<u32> {
    let modulus = PowOf2Modulus::new(Q);
    let mut expected = Vec::with_capacity(STORED_CLUES * LANES * (dimension + 1));
    let grid = i128::from(Q) / PERIOD as i128;
    for clue in input.chunks_exact(dimension + LANES) {
        let mut samples = MultiMsgLwe::new(clue).extract_all(LANES, modulus);
        if let Some(width) = centering {
            for sample in &mut samples {
                let (mask, body) = sample.a_b_mut();
                // Recompute each rotated sample's complete residual sum in
                // i128, independently of any cross-lane recurrence on the GPU.
                let residual_sum: i128 = mask
                    .iter()
                    .map(|&coefficient| {
                        let coefficient = i128::from(coefficient);
                        coefficient - grid * ((coefficient + grid / 2).div_euclid(grid))
                    })
                    .sum();
                let divisor = width as i128 * grid;
                let numerator = width as i128 * i128::from(*body) - residual_sum + divisor / 2;
                let exponent = numerator.div_euclid(divisor).rem_euclid(PERIOD as i128);
                *body = (exponent * grid) as u32;
            }
        }
        for sample in samples {
            expected.extend_from_slice(sample.as_ref());
        }
    }
    expected
}

#[test]
fn retrieval_clue_expansion_matches_cpu_and_independent_centering() {
    let stream = CudaContext::new(0).unwrap().new_stream().unwrap();
    let table = U32NttTable::new(PolyLength::new(2048), BarrettModulus::new(998_244_353)).unwrap();
    let plan = CudaNttPlan32::new(&stream, &table).unwrap();
    // Four signed rotations require at least four independent mask positions.
    assert!(
        CudaPackedLweExtraction32::new(&plan, LweDimension::new(3), MASK, None, CAPACITY).is_err()
    );

    for (dimension, centering) in [(1160, None), (1224, Some(8))] {
        let input_stride = dimension + LANES;
        let output_stride = LANES * (dimension + 1);
        let inputs = packed_inputs(dimension);
        let cpu_output = cpu_expansion(
            &inputs[1..1 + STORED_CLUES * input_stride],
            dimension,
            centering,
        );
        let device_inputs = stream.clone_htod(&inputs).unwrap();
        let initial = vec![SENTINEL; STORED_CLUES * output_stride + 2];
        let mut expected = initial.clone();
        let mut output = stream.clone_htod(&initial).unwrap();
        let extraction = CudaPackedLweExtraction32::new(
            &plan,
            LweDimension::new(dimension),
            MASK,
            centering,
            CAPACITY,
        )
        .unwrap();

        // Every view starts after a guard word. Distinct clues, four ordered
        // lanes, and changing prefixes catch flattening and retained-state errors.
        for (first, active) in [(0, 1), (1, 3), (3, 1), (0, 4)] {
            extraction
                .extract_to(
                    device_inputs
                        .slice(1 + first * input_stride..1 + (first + active) * input_stride),
                    output
                        .slice_mut(1 + first * output_stride..1 + (first + active) * output_stride),
                )
                .unwrap();
            expected[1 + first * output_stride..1 + (first + active) * output_stride]
                .copy_from_slice(
                    &cpu_output[first * output_stride..(first + active) * output_stride],
                );
            assert_eq!(
                download(&stream, &output),
                expected,
                "n={dimension}, centering={centering:?}, first={first}, active={active}"
            );
        }
        assert_eq!(download(&stream, &device_inputs), inputs);

        stream.memcpy_htod(&initial, &mut output).unwrap();
        for (input_count, output_count) in [
            (input_stride - 1, output_stride),
            (2 * input_stride - 1, 2 * output_stride),
            (input_stride, output_stride - 1),
            (2 * input_stride, output_stride),
            (STORED_CLUES * input_stride, STORED_CLUES * output_stride),
            (input_stride, 0),
            (0, output_stride),
        ] {
            assert!(
                extraction
                    .extract_to(
                        device_inputs.slice(1..1 + input_count),
                        output.slice_mut(1..1 + output_count),
                    )
                    .is_err(),
                "accepted malformed extraction counts {input_count}/{output_count}"
            );
        }
        extraction
            .extract_to(device_inputs.slice(..0), output.slice_mut(..0))
            .unwrap();
        assert_eq!(download(&stream, &output), initial);
        assert_eq!(download(&stream, &device_inputs), inputs);
    }
}
