use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_glwe::{GlweParameters, NttGadgetEncryptContext, NttGlweSecretKey, SecretKeyDistr};
use primus_lattice::{glwe::Glwe, lwe::Lwe};
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable};
use primus_poly::Polynomial;
use primus_test_allocations as allocations;
use primus_tfhe_glwe_ntt::{
    ClientKey, KeyGenerator, NttGlweBlindRotationContext, NttGlweBootstrappingKey, PbsOrder,
    SparseGlweBlindRotationContext, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

const Q: u32 = 132_120_577;
const T: u32 = 8;

// Integer arithmetic independent of RotationQuantizer and polynomial rotation kernels.
fn quantize(value: u32, two_n: usize) -> usize {
    ((u64::from(value) * two_n as u64 + u64::from(Q / 2)) / u64::from(Q)) as usize % two_n
}

fn expected_rotation(lut: &[u32], input: &[u32], secret: &[u32]) -> Vec<u32> {
    let n = lut.len();
    let two_n = 2 * n;
    let exponent = (two_n - quantize(input[secret.len()], two_n)
        + input
            .iter()
            .zip(secret)
            .map(|(&a, &s)| quantize(a, two_n) * s as usize)
            .sum::<usize>())
        % two_n;
    let mut expected = vec![0; n];
    for (source, &value) in lut.iter().enumerate() {
        let degree = source + exponent;
        expected[degree % n] = if (degree / n).is_multiple_of(2) {
            value
        } else {
            (Q - value) % Q
        };
    }
    expected
}

#[test]
fn sparse_rotation_matches_direct_phase_and_classic_with_reused_scratch() {
    // Small rings exhaust all rotations; odd buckets exercise the final copy and
    // guarantee a publicly empty bucket (16 entries in 17 buckets). k=2 covers
    // aggregation across every GGSW row. The larger k=2 ring uses encrypted LWE
    // inputs and spans multiple aggregation tiles, including a short final tile.
    for (n, k, copies, buckets) in [(16usize, 1, 3, 8), (16, 2, 1, 17), (256, 2, 3, 8)] {
        let modulus = BarrettModulus::new(Q);
        let lwe = LweParameters::new(
            16,
            T,
            modulus,
            SecretKeyDistr::fixed_hamming_weight_binary(16, 4),
            0.7,
        );
        let glwe = GlweParameters::new(k, n, T, modulus, SecretKeyDistr::UniformBinary, 0.7);
        // The small rings use exact decomposition; the encrypted-input case
        // also exercises the truncated basis used by the cost profile.
        let basis = if n == 16 {
            ApproxSignedBasis::new(Some(Q), 9, None)
        } else {
            ApproxSignedBasis::new(Some(Q), 7, Some(3))
        };
        let parameters = TfheParameters::try_new(
            lwe,
            glwe,
            basis.clone(),
            basis,
            PbsOrder::KeyswitchBootstrap,
        )
        .unwrap();
        let ntt = U32NttTable::new(n.trailing_zeros(), modulus).unwrap();
        let context = TfheContext::try_new(parameters, ntt).unwrap();
        let parameters = context.parameters();
        let ntt = context.table();
        let mut rng = StdRng::seed_from_u64(0x5033_4252 + n as u64 + k as u64);
        let mut generator = KeyGenerator::new(&context);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        let sparse = generator
            .try_generate_sparse_bootstrapping_key(&client, copies, buckets, &mut rng)
            .unwrap();
        let output_key = NttGlweSecretKey::from_coeff_secret_key(client.glwe_secret_key(), ntt);
        let size = sparse.size();
        let classic = NttGlweBootstrappingKey::generate_ntt(
            client.small_lwe_secret_key(),
            parameters.small_lwe(),
            &output_key,
            parameters.blind_rotation_ggsw(),
            ntt,
            &mut rng,
            &mut NttGadgetEncryptContext::new(size),
        );
        let mut sparse_scratch = SparseGlweBlindRotationContext::new(&sparse);
        let mut classic_scratch = NttGlweBlindRotationContext::new(&classic);
        let mut sparse_output = Glwe::<Vec<u32>>::zero(size.glwe_len());
        let mut classic_output = Glwe::<Vec<u32>>::zero(size.glwe_len());
        let codec = RoundedCodec::new(T, modulus);
        let mut check = |input: &Lwe<Vec<u32>>, lut: &Polynomial<Vec<u32>>| {
            let (_, allocation) = allocations::measure(|| {
                sparse.ntt_blind_rotate_lookup_table_to(
                    input,
                    lut,
                    &mut sparse_output,
                    ntt,
                    &mut sparse_scratch,
                );
            });
            assert_eq!(allocation.count, 0);
            classic.ntt_blind_rotate_lookup_table_to(
                input,
                lut,
                &mut classic_output,
                modulus,
                ntt,
                &mut classic_scratch,
            );
            let expected = expected_rotation(
                lut.as_ref(),
                input.as_ref(),
                client.small_lwe_secret_key().as_ref(),
            );
            for output in [&sparse_output, &classic_output] {
                let output_ntt = output.clone().into_ntt_form(ntt);
                let mut phase = Polynomial::<Vec<u32>>::zero(n);
                output_key.phase_to(&output_ntt, &mut phase, modulus, ntt);
                for (&actual, &expected) in phase.as_ref().iter().zip(&expected) {
                    let distance = actual.abs_diff(expected);
                    let error = distance.min(Q - distance);
                    // Stay inside the decoding radius; no equality of noisy ciphertexts.
                    assert!(
                        error < Q / (2 * T) - 1,
                        "phase error {error} at N={n}, k={k}"
                    );
                    assert_eq!(codec.decode_value(actual), codec.decode_value(expected));
                }
            }
            codec.decode_value(expected[0])
        };

        if n == 16 {
            let lut = Polynomial::new(
                (0..n)
                    .map(|i| {
                        codec.encode_value((3 * i as u32 + 1) % T, PlaintextEmbedding::Unsigned)
                    })
                    .collect(),
            );
            let two_n = 2 * n;
            let encode_exponent =
                |r: usize| ((r as u64 * u64::from(Q) + n as u64) / two_n as u64) as u32;
            for target in 0..two_n {
                let mut input: Vec<_> = (0..16)
                    .map(|i| encode_exponent((target + 5 * i) % two_n))
                    .collect();
                let sum = input
                    .iter()
                    .zip(client.small_lwe_secret_key().as_ref())
                    .map(|(&a, &s)| quantize(a, two_n) * s as usize)
                    .sum::<usize>();
                input.push(encode_exponent((sum + two_n - target) % two_n));
                check(&Lwe::new(input), &lut);
            }
            // q-1 rounds through 2N back to zero for both the mask and body.
            check(&Lwe::new(vec![Q - 1; 17]), &lut);
        } else {
            let function = |m: usize| (3 * m as u32 + 1) % T;
            let lut = context
                .parameters()
                .compile_lookup_table_fn(&codec, function)
                .unwrap();
            for message in 0..T / 2 {
                let input = client.small_lwe_secret_key().encrypt(
                    message,
                    parameters.small_lwe(),
                    &mut rng,
                );
                assert_eq!(check(&input, lut.polynomial()), function(message as usize));
            }
        }

        if n != 16 || k != 1 {
            continue;
        }
        // A rejected raw call must leave the caller's accumulator untouched.
        let wrong_modulus = BarrettModulus::new(998_244_353u32);
        let wrong_table = U32NttTable::new(n.trailing_zeros(), wrong_modulus).unwrap();
        for (input_len, lut_len, output_len, table) in [
            (16, n, size.glwe_len(), ntt),
            (17, n - 1, size.glwe_len(), ntt),
            (17, n, size.glwe_len() - 1, ntt),
            (17, n, size.glwe_len(), &wrong_table),
        ] {
            let input = Lwe::new(vec![0; input_len]);
            let lut = Polynomial::<Vec<u32>>::zero(lut_len);
            let mut output = Glwe::new(vec![7; output_len]);
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    sparse.ntt_blind_rotate_lookup_table_to(
                        &input,
                        &lut,
                        &mut output,
                        table,
                        &mut sparse_scratch,
                    );
                }))
                .is_err()
            );
            assert!(output.as_ref().iter().all(|&value| value == 7));
        }
    }
}
