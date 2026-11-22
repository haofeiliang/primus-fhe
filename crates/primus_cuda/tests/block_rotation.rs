use std::sync::Arc;

use cudarc::driver::{CudaContext, CudaSlice, CudaStream, DeviceRepr};
use primus_cuda::{
    CudaBlockBlindRotationWorkspace32, CudaBlockBlindRotationWorkspace64, CudaNttPlan32,
    CudaNttPlan64,
};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_glwe::{
    BlockOccupancy, GgswParameters, GlweCiphertext, GlweDimension, GlweSize, LweDimension,
    NttGlweGadgetEncryptWorkspace, NttGlweSecretKey, SecretKeyDistr,
};
use primus_lattice::{ggsw::Ggsw, workspace::NttGlweExternalProductWorkspace};
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_ntt::{NttTable, U32NttTable, U64NttTable};
use primus_shape::PolyLength;
use primus_tfhe_glwe::BlockGlweBootstrappingKey;
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 2048;
const CAPACITY: usize = 4;
const STORED_BATCHES: usize = CAPACITY + 1;

fn download<T: Clone + Default + DeviceRepr>(
    stream: &Arc<CudaStream>,
    device: &CudaSlice<T>,
) -> Vec<T> {
    let mut host = vec![T::default(); device.len()];
    stream.memcpy_dtoh(device, &mut host).unwrap();
    stream.context().check_err().unwrap();
    host
}

fn inputs<T: TryFrom<u64, Error: std::fmt::Debug>>(q: u64, count: usize) -> Vec<T> {
    let edges = [0, 1, q - 1, q - 2, q / 2, q / 2 + 1];
    let mut state = 0x671a_b951_2963_0d1eu64;
    (0..count)
        .map(|index| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            T::try_from(edges.get(index % 29).copied().unwrap_or(state % q)).unwrap()
        })
        .collect()
}

macro_rules! check_block_rotation {
    ($test:ident, $word:ty, $table:ty, $plan:ty, $workspace:ty,
     $q:expr, $input_modulus:expr, $log_basis:expr, $levels:expr, $exact_width:expr) => {
        #[test]
        fn $test() {
            let stream = CudaContext::new(0).unwrap().new_stream().unwrap();
            let modulus = BarrettModulus::new($q);
            let q = Into::<u64>::into($q);
            let glwe_size = GlweSize::new(GlweDimension::new(1), PolyLength::new(N));
            let parameters = GgswParameters::try_new(
                glwe_size,
                modulus,
                SecretKeyDistr::SparseTernary,
                DecompositionConfig {
                    log_basis: DecompositionBaseLog::new($log_basis),
                    level_count: Some(DecompositionLevelCount::new($levels)),
                },
                0.7,
            )
            .unwrap();
            let table = <$table>::new(PolyLength::new(N), modulus).unwrap();
            let plan = <$plan>::new(&stream, &table).unwrap();
            let mut rng = StdRng::seed_from_u64(0x7921_0382);
            let (_, secret) = NttGlweSecretKey::generate_pair(
                glwe_size,
                parameters.encryption_parameters(),
                &table,
                &mut rng,
            );
            let size = parameters.size();
            let glwe_len = size.glwe_len();
            let ggsw_len = size.ggsw_len();
            let mut encryption = NttGlweGadgetEncryptWorkspace::new(size);

            for (width, occupancy, selected) in [
                (8, BlockOccupancy::AtMostOne, None),
                (8, BlockOccupancy::AtMostOne, Some(7)),
                (
                    $exact_width,
                    BlockOccupancy::ExactlyOne,
                    Some($exact_width / 2),
                ),
            ] {
                let has_dummy = occupancy == BlockOccupancy::AtMostOne;
                let controls_per_block = width + usize::from(has_dummy);
                let second_selected = if has_dummy {
                    selected.is_none().then_some(width / 3)
                } else {
                    Some((selected.unwrap() + 1) % width)
                };
                let mut constants = vec![0 as $word; 2 * controls_per_block];
                for (block, selected) in constants
                    .chunks_exact_mut(controls_per_block)
                    .zip([selected, second_selected])
                {
                    if let Some(position) = selected {
                        block[position] = 1;
                    } else {
                        block[width] = 1;
                    }
                }
                let mut data = vec![0 as $word; constants.len() * ggsw_len];
                // This is the same public coefficient-encryption entry used by
                // Block key generation. The dummy is encrypted independently;
                // encrypted-zero controls remain present in the CPU oracle.
                secret.encrypt_ggsw_constant_batch_coeff_to(
                    &constants,
                    &mut data,
                    &parameters,
                    &table,
                    &mut rng,
                    &mut encryption,
                );
                let key = BlockGlweBootstrappingKey::try_new(
                    data,
                    LweDimension::new(2 * width),
                    width,
                    occupancy,
                    &parameters,
                    PowOf2Modulus::new($input_modulus),
                )
                .unwrap();
                let host_inputs = inputs::<$word>(q, STORED_BATCHES * glwe_len + 2);
                let exponent_edges = [
                    0,
                    1,
                    N as u32 - 1,
                    N as u32,
                    N as u32 + 1,
                    2 * N as u32 - 1,
                    2 * N as u32,
                    2 * N as u32 + 1,
                    u32::MAX,
                ];
                let mut exponents = vec![0u32; STORED_BATCHES * width + 2];
                for (lane, row) in exponents[1..1 + STORED_BATCHES * width]
                    .chunks_exact_mut(width)
                    .enumerate()
                {
                    for (control, exponent) in row.iter_mut().enumerate() {
                        *exponent = exponent_edges[(lane * 3 + control) % exponent_edges.len()]
                            .wrapping_add((lane * 97) as u32);
                    }
                }
                let sentinel = 7 as $word;
                let mut cpu_outputs: [Vec<$word>; 2] =
                    std::array::from_fn(|_| vec![sentinel; STORED_BATCHES * glwe_len]);
                let mut cpu_workspace = NttGlweExternalProductWorkspace::new(size);
                for ((_, selections, dummy), block_output) in
                    key.blocks().zip(&mut cpu_outputs)
                {
                    for ((lane_exponents, input), output) in exponents
                        [1..1 + STORED_BATCHES * width]
                        .chunks_exact(width)
                        .zip(host_inputs[1..1 + STORED_BATCHES * glwe_len].chunks_exact(glwe_len))
                        .zip(block_output.chunks_exact_mut(glwe_len))
                    {
                        let mut aggregate = if dummy.is_empty() {
                            vec![0 as $word; ggsw_len]
                        } else {
                            dummy.to_vec()
                        };
                        for (control, &exponent) in
                            selections.chunks_exact(ggsw_len).zip(lane_exponents)
                        {
                            let degree = exponent as usize % (2 * N);
                            // Scatter source coefficients independently of the GPU
                            // gather kernel. Canonicalize after every contribution,
                            // then use the existing public CPU NTT/external product.
                            for (source, target) in control
                                .chunks_exact(N)
                                .zip(aggregate.chunks_exact_mut(N))
                            {
                                for (index, &value) in source.iter().enumerate() {
                                    let power = index + degree;
                                    let value = u128::from(value);
                                    let term = if (power / N).is_multiple_of(2) {
                                        value
                                    } else {
                                        (u128::from(q) - value) % u128::from(q)
                                    };
                                    let destination = &mut target[power % N];
                                    *destination = ((u128::from(*destination) + term) % u128::from(q))
                                        as $word;
                                }
                            }
                        }
                        Ggsw::new(aggregate)
                            .into_ntt_form(&table)
                            .external_product_to(
                                &GlweCiphertext::new(input),
                                &mut GlweCiphertext::new(output),
                                parameters.basis(),
                                modulus,
                                &table,
                                &mut cpu_workspace,
                            );
                    }
                }

                let device_inputs = stream.clone_htod(&host_inputs).unwrap();
                let device_exponents = stream.clone_htod(&exponents).unwrap();
                let initial = vec![sentinel; STORED_BATCHES * glwe_len + 2];
                let mut output = stream.clone_htod(&initial).unwrap();
                let mut expected = initial.clone();
                let mut workspace = <$workspace>::new(&plan, &key, CAPACITY).unwrap();
                // Alternate between independently encrypted blocks while changing
                // the active prefix, including reuse of block zero afterward.
                for (block, active) in [(0, 3), (0, 1), (0, 2), (1, 3), (1, 1), (0, 2)] {
                    workspace
                        .apply_block_to(
                            block,
                            device_exponents.slice(1..1 + active * width),
                            device_inputs.slice(1..1 + active * glwe_len),
                            output.slice_mut(1..1 + active * glwe_len),
                        )
                        .unwrap();
                    expected[1..1 + active * glwe_len]
                        .copy_from_slice(&cpu_outputs[block][..active * glwe_len]);
                    assert_eq!(
                        download(&stream, &output),
                        expected,
                        "width={width}, occupancy={occupancy:?}, selected={selected:?}, block={block}, active={active}"
                    );
                }
                assert_eq!(download(&stream, &device_inputs), host_inputs);
                assert_eq!(download(&stream, &device_exponents), exponents);

                stream.memcpy_htod(&initial, &mut output).unwrap();
                for (block, exponent_count, input_count, output_count) in [
                    (2, width, glwe_len, glwe_len),
                    (0, width - 1, glwe_len, glwe_len),
                    (0, 2 * width, glwe_len, glwe_len),
                    (0, width, glwe_len - 1, glwe_len),
                    (0, width, glwe_len, glwe_len - 1),
                    (
                        0,
                        2 * width,
                        2 * glwe_len - 1,
                        2 * glwe_len - 1,
                    ),
                    (
                        0,
                        STORED_BATCHES * width,
                        STORED_BATCHES * glwe_len,
                        STORED_BATCHES * glwe_len,
                    ),
                    (0, width, 0, 0),
                ] {
                    assert!(
                        workspace
                            .apply_block_to(
                                block,
                                device_exponents.slice(1..1 + exponent_count),
                                device_inputs.slice(1..1 + input_count),
                                output.slice_mut(1..1 + output_count),
                            )
                            .is_err(),
                        "accepted malformed request: block={block}, counts={exponent_count}/{input_count}/{output_count}"
                    );
                }
                workspace
                    .apply_block_to(
                        0,
                        device_exponents.slice(..0),
                        device_inputs.slice(..0),
                        output.slice_mut(..0),
                    )
                    .unwrap();
                assert_eq!(download(&stream, &output), initial);
            }
        }
    };
}

check_block_rotation!(
    omr_u32_block_update_matches_cpu,
    u32,
    U32NttTable,
    CudaNttPlan32,
    CudaBlockBlindRotationWorkspace32,
    998_244_353u32,
    524_288u32,
    9,
    2,
    8
);
check_block_rotation!(
    omr_u64_block_update_matches_cpu,
    u64,
    U64NttTable,
    CudaNttPlan64,
    CudaBlockBlindRotationWorkspace64,
    1_125_899_906_826_241u64,
    4096u64,
    12,
    3,
    10
);
