use std::sync::Arc;

use cudarc::driver::{CudaContext, CudaSlice, CudaStream, DeviceRepr};
use primus_cuda::{
    CudaExternalProductWorkspace32, CudaExternalProductWorkspace64, CudaNttPlan32, CudaNttPlan64,
};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_glwe::{
    GgswParameters, GlweCiphertext, GlweDimension, GlweSize, NttGgswCiphertext,
    NttGlweGadgetEncryptWorkspace, NttGlweSecretKey, SecretKeyDistr,
};
use primus_lattice::workspace::NttGlweExternalProductWorkspace;
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable, U64NttTable};
use primus_poly::Polynomial;
use primus_shape::PolyLength;
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

fn input_coefficients<T: TryFrom<u64, Error: std::fmt::Debug>>(
    q: u64,
    log_basis: u32,
    levels: usize,
    drop_bits: u32,
    count: usize,
) -> Vec<T> {
    let rounding_half = 1u64 << (drop_bits - 1);
    let positive_digit = (1u64 << (log_basis - 1)) - 1;
    let positive_limit = (0..levels).fold(0, |limit, _| (limit << log_basis) | positive_digit);
    let adjustment_threshold = (positive_limit << drop_bits) + rounding_half;
    // Exercise both sides of rounding, signed digit carry, and the adjustment
    // into the binary decomposition domain, as well as the residue endpoints.
    let digit_half = 1u64 << (drop_bits + log_basis - 1);
    let edges = [
        0,
        1,
        q - 1,
        q - 2,
        rounding_half - 1,
        rounding_half,
        rounding_half + 1,
        digit_half - 1,
        digit_half,
        digit_half + 1,
        adjustment_threshold - 1,
        adjustment_threshold,
        adjustment_threshold + 1,
        q / 2,
        q / 2 + 1,
    ];
    let mut state = 0x2e91_403d_863f_a781u64;
    (0..count)
        .map(|index| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            T::try_from(edges.get(index % 31).copied().unwrap_or(state % q)).unwrap()
        })
        .collect()
}

macro_rules! check_external_product {
    ($test:ident, $word:ty, $table:ty, $plan:ty, $workspace:ty, $q:expr, $bases:expr) => {
        #[test]
        fn $test() {
            let stream = CudaContext::new(0).unwrap().new_stream().unwrap();
            let modulus = BarrettModulus::new($q);
            let q = Into::<u64>::into($q);
            let glwe_size = GlweSize::new(GlweDimension::new(1), PolyLength::new(N));
            let table = <$table>::new(PolyLength::new(N), modulus).unwrap();
            let plan = <$plan>::new(&stream, &table).unwrap();

            for (log_basis, levels) in $bases {
                let parameters = GgswParameters::try_new(
                    glwe_size,
                    modulus,
                    SecretKeyDistr::SparseTernary,
                    DecompositionConfig {
                        log_basis: DecompositionBaseLog::new(log_basis),
                        level_count: Some(DecompositionLevelCount::new(levels)),
                    },
                    0.7,
                )
                .unwrap();
                let basis = parameters.basis();
                let size = parameters.size();
                let glwe_len = size.glwe_len();
                let ggsw_len = size.ggsw_len();
                let mut rng = StdRng::seed_from_u64(0x7451_8254);
                let (_, secret) = NttGlweSecretKey::generate_pair(
                    glwe_size,
                    parameters.encryption_parameters(),
                    &table,
                    &mut rng,
                );
                let mut encrypt_workspace = NttGlweGadgetEncryptWorkspace::new(size);
                let sentinel = 7 as $word;
                let mut gadgets = vec![sentinel; STORED_BATCHES * ggsw_len + 2];
                for (batch, storage) in gadgets[1..1 + STORED_BATCHES * ggsw_len]
                    .chunks_exact_mut(ggsw_len)
                    .enumerate()
                {
                    // Genuine GGSWs under one sampled secret, with distinct
                    // controls and randomness to expose cross-batch key reuse.
                    let mut message = vec![0 as $word; N];
                    if batch % 3 != 0 {
                        message[batch % 3 - 1] = 1;
                    }
                    secret.encrypt_ggsw_to(
                        &Polynomial::new(message),
                        &mut NttGgswCiphertext::new(storage),
                        &parameters,
                        &table,
                        &mut rng,
                        &mut encrypt_workspace,
                    );
                }
                let inputs = input_coefficients::<$word>(
                    q,
                    log_basis,
                    levels,
                    basis.drop_bits(),
                    STORED_BATCHES * glwe_len + 2,
                );
                let mut cpu_output = vec![sentinel; STORED_BATCHES * glwe_len];
                let mut cpu_workspace = NttGlweExternalProductWorkspace::new(size);
                for ((gadget, input), output) in gadgets[1..1 + STORED_BATCHES * ggsw_len]
                    .chunks_exact(ggsw_len)
                    .zip(inputs[1..1 + STORED_BATCHES * glwe_len].chunks_exact(glwe_len))
                    .zip(cpu_output.chunks_exact_mut(glwe_len))
                {
                    NttGgswCiphertext::new(gadget).external_product_to(
                        &GlweCiphertext::new(input),
                        &mut GlweCiphertext::new(output),
                        basis,
                        modulus,
                        &table,
                        &mut cpu_workspace,
                    );
                }

                let device_gadgets = stream.clone_htod(&gadgets).unwrap();
                let device_inputs = stream.clone_htod(&inputs).unwrap();
                let initial = vec![sentinel; STORED_BATCHES * glwe_len + 2];
                let mut output = stream.clone_htod(&initial).unwrap();
                let mut expected = initial.clone();
                let mut workspace = <$workspace>::new(&plan, size, basis, CAPACITY).unwrap();
                // Short batches reuse a workspace previously used by a larger
                // request. Overwrite semantics must hold without clearing it.
                for active in [3, 1, 2, 3] {
                    workspace
                        .external_product_to(
                            device_gadgets.slice(1..1 + active * ggsw_len),
                            device_inputs.slice(1..1 + active * glwe_len),
                            output.slice_mut(1..1 + active * glwe_len),
                        )
                        .unwrap();
                    expected[1..1 + active * glwe_len]
                        .copy_from_slice(&cpu_output[..active * glwe_len]);
                    assert_eq!(
                        download(&stream, &output),
                        expected,
                        "log_basis={log_basis}, levels={levels}, active={active}"
                    );
                }
                assert_eq!(download(&stream, &device_gadgets), gadgets);
                assert_eq!(download(&stream, &device_inputs), inputs);

                stream.memcpy_htod(&initial, &mut output).unwrap();
                for (gadget_count, input_count, output_count) in [
                    (ggsw_len - 1, glwe_len, glwe_len),
                    (2 * ggsw_len, glwe_len, glwe_len),
                    (ggsw_len, glwe_len - 1, glwe_len),
                    (ggsw_len, glwe_len, glwe_len - 1),
                    (2 * ggsw_len, 2 * glwe_len - 1, 2 * glwe_len - 1),
                    (
                        STORED_BATCHES * ggsw_len,
                        STORED_BATCHES * glwe_len,
                        STORED_BATCHES * glwe_len,
                    ),
                    (ggsw_len, 0, 0),
                ] {
                    assert!(
                        workspace
                            .external_product_to(
                                device_gadgets.slice(1..1 + gadget_count),
                                device_inputs.slice(1..1 + input_count),
                                output.slice_mut(1..1 + output_count),
                            )
                            .is_err(),
                        "accepted malformed lengths: {gadget_count}/{input_count}/{output_count}"
                    );
                }
                workspace
                    .external_product_to(
                        device_gadgets.slice(..0),
                        device_inputs.slice(..0),
                        output.slice_mut(..0),
                    )
                    .unwrap();
                assert_eq!(download(&stream, &output), initial);
            }
        }
    };
}

check_external_product!(
    omr_u32_external_product_matches_cpu,
    u32,
    U32NttTable,
    CudaNttPlan32,
    CudaExternalProductWorkspace32,
    998_244_353u32,
    [(9, 2)]
);
check_external_product!(
    omr_u64_external_product_matches_cpu,
    u64,
    U64NttTable,
    CudaNttPlan64,
    CudaExternalProductWorkspace64,
    1_125_899_906_826_241u64,
    [(12, 3), (24, 1)]
);
