use std::sync::Arc;

use cudarc::driver::{CudaContext, CudaSlice, CudaStream, DeviceRepr};
use primus_cuda::{
    CudaBlockBlindRotationWorkspace32, CudaBlockBlindRotationWorkspace64, CudaNttPlan32,
    CudaNttPlan64,
};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_encoding::RoundedCodec;
use primus_glwe::{
    BlockOccupancy, GgswParameters, GlweCiphertext, GlweDimension, GlweSize,
    NttGlweGadgetEncryptWorkspace, NttGlweSecretKey, SecretKeyDistr,
};
use primus_lwe::LweSecretKey;
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_ntt::{NttTable, U32NttTable, U64NttTable};
use primus_shape::PolyLength;
use primus_tfhe::{LookupTableCompiler, rotation::RotationModulusSwitch};
use primus_tfhe_glwe_ntt::{
    BlindRotationMethod, Lwe, block::BlockGlweBlindRotationWorkspace, key::BlindRotationKey,
};
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 2048;

fn download<T: Clone + Default + DeviceRepr>(
    stream: &Arc<CudaStream>,
    device: &CudaSlice<T>,
) -> Vec<T> {
    let mut host = vec![T::default(); device.len()];
    stream.memcpy_dtoh(device, &mut host).unwrap();
    stream.context().check_err().unwrap();
    host
}

fn lwe_records<T: Clone + TryFrom<u64, Error: std::fmt::Debug>>(
    q: u64,
    dimension: usize,
    messages: usize,
    lanes: usize,
) -> Vec<T> {
    let grid = q / (2 * N) as u64;
    let mut mask_edges = vec![0, 1, q - 1, q / 2 - 1, q / 2, q / 2 + 1];
    let bodies = if grid > 1 {
        let half = grid / 2;
        mask_edges.extend_from_slice(&[
            half - 1,
            half,
            half + 1,
            q - half - 1,
            q - half,
            q - half + 1,
        ]);
        // The final three bodies straddle rounding to the endpoint 2N,
        // which wraps to zero before the initial negative-body rotation.
        [0, q - 1, q - half - 1, q - half, q - half + 1]
    } else {
        // q=2N has exact integer quantization; cross the sign boundary
        // instead of attempting to construct an unreachable half-grid tie.
        [0, q - 1, q / 2, q / 2 - 1, q / 2 + 1]
    };
    let record_len = dimension + 1;
    let mut state = 0x43e9_b7a0_1261_958du64;
    let mut output = Vec::with_capacity((messages * lanes + 1) * record_len + 2);
    output.push(T::try_from(q - 1).unwrap());
    for message in 0..messages {
        let mask: Vec<T> = (0..dimension)
            .map(|index| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let edge = (index + message * 3) % 31;
                T::try_from(mask_edges.get(edge).copied().unwrap_or(state % q)).unwrap()
            })
            .collect();
        // BR1 mirrors the four bodies sharing one OMR clue mask. BR2 uses
        // one lane per message, giving independently varying masks as well.
        for lane in 0..lanes {
            output.extend_from_slice(&mask);
            output.push(T::try_from(bodies[(message * lanes + lane) % bodies.len()]).unwrap());
        }
    }
    // Retain one additional valid record solely to test capacity rejection.
    output.extend_from_within(1..1 + record_len);
    output.push(T::try_from(q - 1).unwrap());
    output
}

macro_rules! check_full_blind_rotation {
    ($test:ident, $word:ty, $table:ty, $plan:ty, $workspace:ty,
     $q:expr, $input_q:expr, $log_basis:expr, $levels:expr,
     $input_messages:expr, $output_messages:expr, $selected_message:expr,
     $at_most_dimension:expr, $exact_dimension:expr, $exact_width:expr,
     $messages:expr, $lanes:expr, $calls:expr) => {
        #[test]
        fn $test() {
            let stream = CudaContext::new(0).unwrap().new_stream().unwrap();
            let modulus = BarrettModulus::new($q);
            let input_modulus = PowOf2Modulus::new($input_q);
            let length = PolyLength::new(N);
            let glwe_size = GlweSize::new(GlweDimension::new(1), length);
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
            let table = <$table>::new(length, modulus).unwrap();
            let plan = <$plan>::new(&stream, &table).unwrap();
            let input_codec = RoundedCodec::new($input_messages as $word, input_modulus);
            let output_codec = RoundedCodec::new($output_messages as $word, modulus);
            // Exactly the retrieval LUT constructions in OMR parameters:
            // BR1 tests m=0; BR2 tests whether all four predicates matched.
            let lut = LookupTableCompiler::try_new(length, &input_codec, modulus, &output_codec)
                .unwrap()
                .compile_fn(|message| <$word>::from(message == $selected_message))
                .unwrap()
                .into_polynomial();
            let mut padded_lut = vec![7 as $word; N + 2];
            padded_lut[1..N + 1].copy_from_slice(lut.as_ref());
            let device_lut = stream.clone_htod(&padded_lut).unwrap();
            let rotation = RotationModulusSwitch::new(input_modulus, 2 * N, 1);
            let records = $messages * $lanes;
            let capacity = records;

            // Production key geometry exercises the whole block loop and its
            // retained state. Large keys are released one fixture at a time.
            for (dimension, width, occupancy) in [
                ($at_most_dimension, 8, BlockOccupancy::AtMostOne),
                ($exact_dimension, $exact_width, BlockOccupancy::ExactlyOne),
            ] {
                let distribution = SecretKeyDistr::BlockBinary {
                    block_size: width,
                    occupancy,
                };
                let mut secret_bits = vec![0 as $word; dimension];
                for (block_index, block) in secret_bits.chunks_exact_mut(width).enumerate() {
                    if occupancy == BlockOccupancy::ExactlyOne || block_index % 3 != 0 {
                        block[(block_index * 5 + 1) % width] = 1;
                    }
                }
                let lwe_secret = LweSecretKey::new(secret_bits, distribution, input_modulus);
                let mut rng = StdRng::seed_from_u64(0x4319_0000 + dimension as u64);
                let (_, ring_secret) = NttGlweSecretKey::generate_pair(
                    glwe_size,
                    parameters.encryption_parameters(),
                    &table,
                    &mut rng,
                );
                let mut encryption = NttGlweGadgetEncryptWorkspace::new(parameters.size());
                let BlindRotationKey::Block(key) = BlindRotationKey::try_generate(
                    &lwe_secret,
                    &ring_secret,
                    &parameters,
                    BlindRotationMethod::Block,
                    &table,
                    &mut rng,
                    &mut encryption,
                )
                .unwrap()
                else {
                    panic!("expected the requested encrypted Block key");
                };
                drop(encryption);
                drop(ring_secret);
                drop(lwe_secret);

                let record_len = dimension + 1;
                let glwe_len = parameters.glwe_len();
                let inputs = lwe_records::<$word>(
                    Into::<u64>::into($input_q),
                    dimension,
                    $messages,
                    $lanes,
                );
                let mut cpu_output = vec![0 as $word; records * glwe_len];
                let mut cpu_workspace = BlockGlweBlindRotationWorkspace::new(&key);
                for (input, output) in inputs[1..1 + records * record_len]
                    .chunks_exact(record_len)
                    .zip(cpu_output.chunks_exact_mut(glwe_len))
                {
                    cpu_workspace.blind_rotate_lookup_table_to(
                        &key,
                        &Lwe::new(input),
                        &lut,
                        &rotation,
                        &mut GlweCiphertext::new(output),
                        &table,
                    );
                }
                let device_inputs = stream.clone_htod(&inputs).unwrap();
                let initial = vec![7 as $word; (records + 1) * glwe_len + 2];
                let mut output = stream.clone_htod(&initial).unwrap();
                let mut expected = initial.clone();
                let mut workspace = <$workspace>::new(&plan, &key, capacity).unwrap();
                // Exercise one message, independent batches, and a shorter
                // subsequent request without resetting workspace allocations.
                for (first, active) in $calls {
                    workspace
                        .blind_rotate_lookup_table_to(
                            device_inputs
                                .slice(1 + first * record_len..1 + (first + active) * record_len),
                            device_lut.slice(1..N + 1),
                            output
                                .slice_mut(1 + first * glwe_len..1 + (first + active) * glwe_len),
                        )
                        .unwrap();
                    expected[1 + first * glwe_len..1 + (first + active) * glwe_len]
                        .copy_from_slice(
                            &cpu_output[first * glwe_len..(first + active) * glwe_len],
                        );
                    assert_eq!(
                        download(&stream, &output),
                        expected,
                        "n={dimension}, width={width}, occupancy={occupancy:?}, first={first}, active={active}"
                    );
                }
                assert_eq!(download(&stream, &device_inputs), inputs);
                assert_eq!(download(&stream, &device_lut), padded_lut);

                stream.memcpy_htod(&initial, &mut output).unwrap();
                for (input_count, lut_count, output_count) in [
                    (record_len, N - 1, glwe_len),
                    (3 * record_len - 1, N, 3 * glwe_len),
                    (record_len, N, glwe_len - 1),
                    ((capacity + 1) * record_len, N, (capacity + 1) * glwe_len),
                    (record_len, N, 0),
                ] {
                    assert!(
                        workspace
                            .blind_rotate_lookup_table_to(
                                device_inputs.slice(1..1 + input_count),
                                device_lut.slice(1..1 + lut_count),
                                output.slice_mut(1..1 + output_count),
                            )
                            .is_err(),
                        "accepted malformed full-BR counts {input_count}/{lut_count}/{output_count}"
                    );
                }
                workspace
                    .blind_rotate_lookup_table_to(
                        device_inputs.slice(..0),
                        device_lut.slice(1..N + 1),
                        output.slice_mut(..0),
                    )
                    .unwrap();
                assert_eq!(download(&stream, &output), initial);
            }
        }
    };
}

check_full_blind_rotation!(
    retrieval_br1_full_block_matches_cpu,
    u32,
    U32NttTable,
    CudaNttPlan32,
    CudaBlockBlindRotationWorkspace32,
    998_244_353u32,
    524_288u32,
    9,
    2,
    64,
    18,
    0,
    1160,
    1224,
    8,
    2,
    4,
    [(0, 4), (4, 1), (0, 8), (4, 4)]
);
check_full_blind_rotation!(
    retrieval_br2_full_block_matches_cpu,
    u64,
    U64NttTable,
    CudaNttPlan64,
    CudaBlockBlindRotationWorkspace64,
    1_125_899_906_826_241u64,
    4096u64,
    12,
    3,
    18,
    257,
    4,
    1160,
    1380,
    10,
    3,
    1,
    [(0, 1), (0, 3), (2, 1)]
);
