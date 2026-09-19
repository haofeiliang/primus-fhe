use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_fft::{FftEngine, FftTable, RustFftTable, TfheFftTable};
use primus_glwe::{GlweParameters, SecretKeyDistr};
use primus_lattice::{glwe::TorusGlwe, lwe::Lwe};
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;
use primus_test_allocations as allocations;
use primus_tfhe_glwe_fourier::{
    BootstrappingKey, ClientKey, FourierGlweBlindRotationContext, KeyGenerator, PbsOrder,
    SparseGlweBlindRotationContext, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

const N: usize = 16;
const TWO_N: usize = 2 * N;

// Independent integer oracle for per-coefficient quantization and negacyclic rotation.
fn quantize(value: u32, step: usize) -> usize {
    let domain = TWO_N / step;
    (((u64::from(value) * domain as u64 + (1 << 31)) >> 32) as usize % domain) * step
}

fn expected_rotation(lut: &[u32], input: &[u32], secret: &[u32], step: usize) -> Vec<u32> {
    let exponent = (TWO_N - quantize(input[secret.len()], step)
        + input
            .iter()
            .zip(secret)
            .map(|(&a, &s)| quantize(a, step) * s as usize)
            .sum::<usize>())
        % TWO_N;
    let mut expected = vec![0; N];
    for (source, &value) in lut.iter().enumerate() {
        let degree = source + exponent;
        expected[degree % N] = if (degree / N).is_multiple_of(2) {
            value
        } else {
            value.wrapping_neg()
        };
    }
    expected
}

// Exact native-ring phase; independent of FFT conversion, decryption and extraction.
fn phase(ciphertext: &[u32], secret: &[i32]) -> Vec<u32> {
    let (mask, body) = ciphertext.split_at(secret.len());
    let mut phase = body.to_vec();
    for (a, s) in mask
        .as_chunks::<N>()
        .0
        .iter()
        .zip(secret.as_chunks::<N>().0)
    {
        for (i, &a) in a.iter().enumerate() {
            for (j, &s) in s.iter().enumerate() {
                let product = a.wrapping_mul(s as u32);
                let value = &mut phase[(i + j) % N];
                *value = if i + j < N {
                    value.wrapping_sub(product)
                } else {
                    value.wrapping_add(product)
                };
            }
        }
    }
    phase
}

fn check_raw<Table: FftTable>() {
    // Even buckets, then odd buckets with a guaranteed public empty bucket.
    // k=2 checks every GGSW row; odd bucket count requires the final buffer copy.
    for (dimension, copies, buckets) in [(1, 3, 8), (2, 1, 17)] {
        let modulus = NativeModulus::new();
        let basis = ApproxSignedBasis::new(None, 8, Some(3));
        let parameters = TfheParameters::try_new(
            LweParameters::new(
                16,
                8,
                modulus,
                SecretKeyDistr::fixed_hamming_weight_binary(16, 4),
                0.7,
            ),
            GlweParameters::new(
                dimension,
                N,
                8,
                modulus,
                SecretKeyDistr::UniformTernary,
                0.7,
            ),
            basis.clone(),
            basis,
            PbsOrder::BootstrapKeyswitch,
        )
        .unwrap();
        let context = TfheContext::<u32, Table>::try_from_parameters(parameters).unwrap();
        let mut rng = StdRng::seed_from_u64(0x4234_3252 + dimension as u64);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        let mut generator = KeyGenerator::new(&context);
        let sparse = generator
            .try_generate_sparse_bootstrapping_key(&client, copies, buckets, &mut rng)
            .unwrap();
        let server = generator
            .try_generate_server_key(&client, None, &mut rng)
            .unwrap();
        let BootstrappingKey::Classic(classic) = server.bootstrapping_key() else {
            panic!("expected classic key")
        };
        let mut sparse_scratch = SparseGlweBlindRotationContext::new(&sparse);
        let mut classic_scratch = FourierGlweBlindRotationContext::new(classic);
        let mut fft = context.new_fft_engine();
        let mut sparse_output = TorusGlwe::<Vec<u32>>::zero(sparse.size().glwe_len());
        let mut classic_output = sparse_output.clone();
        let codec = RoundedCodec::new(8, modulus);
        let lut = Polynomial::new(
            (0..N)
                .map(|i| codec.encode_value((3 * i as u32 + 1) % 8, PlaintextEmbedding::Unsigned))
                .collect::<Vec<_>>(),
        );
        let mut check = |input: &Lwe<Vec<u32>>, step| {
            let (_, allocation) = allocations::measure(|| {
                if step == 1 {
                    sparse.fourier_blind_rotate_lookup_table_to(
                        input,
                        &lut,
                        &mut sparse_output,
                        &mut fft,
                        &mut sparse_scratch,
                    );
                } else {
                    sparse.fourier_blind_rotate_interleaved_lookup_table_to(
                        input,
                        &lut,
                        step,
                        &mut sparse_output,
                        &mut fft,
                        &mut sparse_scratch,
                    );
                }
            });
            assert_eq!(allocation.count, 0);
            classic.fourier_blind_rotate_interleaved_lookup_table_to(
                input,
                &lut,
                step,
                &mut classic_output,
                &mut fft,
                &mut classic_scratch,
            );
            let expected = expected_rotation(
                lut.as_ref(),
                input.as_ref(),
                client.small_lwe_secret_key().as_ref(),
                step,
            );
            for output in [&sparse_output, &classic_output] {
                for (actual, &expected) in
                    phase(output.as_ref(), client.glwe_secret_key().as_slice())
                        .into_iter()
                        .zip(&expected)
                {
                    let error = actual.wrapping_sub(expected);
                    assert!(
                        error.min(error.wrapping_neg()) < 1 << 28,
                        "phase escaped decoding radius"
                    );
                    assert_eq!(codec.decode_value(actual), codec.decode_value(expected));
                }
            }
        };
        for step in [1, 4] {
            let encode_exponent = |r: usize| (r as u32) << (32 - TWO_N.trailing_zeros());
            for target in (0..TWO_N).step_by(step) {
                let mut input: Vec<_> = (0..16)
                    .map(|i| encode_exponent((target + 5 * i) % TWO_N))
                    .collect();
                let sum = input
                    .iter()
                    .zip(client.small_lwe_secret_key().as_ref())
                    .map(|(&a, &s)| quantize(a, step) * s as usize)
                    .sum::<usize>();
                input.push(encode_exponent((sum + TWO_N - target) % TWO_N));
                check(&Lwe::new(input), step);
            }
            // Values just below/at/above a half interval, and wrap-to-zero.
            let half = 1u32 << (31 - (TWO_N / step).trailing_zeros());
            check(
                &Lwe::new(
                    (0..17)
                        .map(|i| [half - 1, half, half + 1, u32::MAX][i % 4])
                        .collect(),
                ),
                step,
            );
        }
        // Return to step one with both mask and body wrapping to exponent zero.
        check(&Lwe::new(vec![u32::MAX; 17]), 1);
        if dimension != 1 {
            continue;
        }
        let wrong_table = Table::new((N / 2).trailing_zeros()).unwrap();
        let mut wrong_fft = FftEngine::new(&wrong_table);
        for (step, input_len, lut_len, output_len, bad_fft) in [
            (0, 17, N, sparse.size().glwe_len(), false),
            (3, 17, N, sparse.size().glwe_len(), false),
            (1, 16, N, sparse.size().glwe_len(), false),
            (1, 17, N - 1, sparse.size().glwe_len(), false),
            (1, 17, N, sparse.size().glwe_len() - 1, false),
            (1, 17, N, sparse.size().glwe_len(), true),
        ] {
            let input = Lwe::new(vec![0; input_len]);
            let lut = Polynomial::new(vec![0; lut_len]);
            let mut output = TorusGlwe::new(vec![7; output_len]);
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    sparse.fourier_blind_rotate_interleaved_lookup_table_to(
                        &input,
                        &lut,
                        step,
                        &mut output,
                        if bad_fft { &mut wrong_fft } else { &mut fft },
                        &mut sparse_scratch,
                    );
                }))
                .is_err()
            );
            assert!(output.as_ref().iter().all(|&value| value == 7));
        }
    }
}

#[test]
fn sparse_rotation_matches_exact_phase_and_classic_with_reused_scratch() {
    check_raw::<RustFftTable>();
    check_raw::<TfheFftTable>();
}
