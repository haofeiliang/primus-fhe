use num_traits::ConstOne;
use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_fft::{FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_integer::AsInto;
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::NativeModulus;
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_test_allocations::{CountingAllocator, measure};
use primus_tfhe::rotation::RotationQuantizer;
use primus_tfhe_ntru_fourier::{KeyGenerator, TfheContext, TfheEvaluationError, TfheParameters};
use rand::{SeedableRng, rngs::StdRng};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

const N: usize = 256;
const DIM: usize = 16;

fn context<T: TorusFftValue, Table: FftTable>(distr: SecretKeyDistr) -> TfheContext<T, Table> {
    let modulus = NativeModulus::new();
    let lwe = LweParameters::new(DIM, T::as_from(16usize), modulus, distr, 0.7);
    let client = NtruParameters::new(N, T::as_from(16usize), modulus, distr, 0.7);
    let acc = NtruParameters::new(
        N,
        T::as_from(16usize),
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    TfheContext::try_from_parameters(
        TfheParameters::try_new(
            lwe,
            NlevParameters::with_ntru_params(&acc, 8, None),
            NlevParameters::with_ntru_params(&client, 8, None),
        )
        .unwrap(),
    )
    .unwrap()
}

// Independent LWE phase under the original signed prefix; no backend decryption.
fn phase<T: TorusFftValue>(
    cipher: &LweCiphertext<T>,
    secret: &[T::SignedInteger],
    q: i128,
) -> i128 {
    let body: i128 = cipher.b().as_into();
    (body
        - cipher
            .a()
            .iter()
            .zip(secret)
            .map(|(&a, &s)| {
                let a: i128 = a.as_into();
                let s: i128 = s.as_into();
                a * s
            })
            .sum::<i128>())
    .rem_euclid(q)
}

fn check_complete<T: TorusFftValue, Table: FftTable>() {
    let context = context::<T, Table>(SecretKeyDistr::fixed_hamming_weight_binary(DIM, 5));
    let mut rng = StdRng::seed_from_u64(0xB803);
    let mut generator = KeyGenerator::new(&context);
    let (client, classic_key) = generator.try_generate(None, &mut rng).unwrap();
    let mut classic = context.evaluator(&classic_key).unwrap();
    let modulus = context.parameters().external_lwe().cipher_modulus();
    let q_wide: i128 = 1i128 << T::BITS;
    let codec = RoundedCodec::new(T::as_from(8usize), modulus);
    let value = |m: usize, i: usize| T::as_from((m + 2 * i) % 8);
    let single = context
        .parameters()
        .compile_lookup_table_fn(&codec, |m| value(m, 0))
        .unwrap();
    let many = context
        .parameters()
        .compile_interleaved_lookup_table_fn(&codec, 3, value)
        .unwrap();
    let mut output = LweCiphertext::zero(DIM);
    let mut reference = output.clone();
    let mut outputs = vec![output.clone(); 3];

    // Odd/even bucket counts exercise ownership swaps; b>n guarantees public empty buckets.
    for (copies, buckets) in [(3, 10), (1, DIM + 1)] {
        let server = generator
            .try_generate_sparse_server_key(&client, copies, buckets, &mut rng)
            .unwrap();
        assert_eq!(
            context.factorized_evaluator(&server).err(),
            Some(TfheEvaluationError::UnsupportedSparseBootstrapping)
        );
        assert_eq!(
            context.circuit_bootstrap_evaluator(&server).err(),
            Some(TfheEvaluationError::UnsupportedSparseBootstrapping)
        );
        let mut sparse = context.evaluator(&server).unwrap();
        for (message, zero_mask) in [(0, true), (3, false), (7, false), (1, true)] {
            let mut input = context
                .encryptor(&client)
                .unwrap()
                .encrypt_padded(T::as_from(message), &mut rng)
                .unwrap();
            if zero_mask {
                input.a_mut().fill(T::ZERO);
                *input.b_mut() = context
                    .parameters()
                    .input_plaintext_codec()
                    .encode_value(T::as_from(message), PlaintextEmbedding::Unsigned);
            }
            let (_, allocation) =
                measure(|| sparse.apply_lookup_table_to(&input, &single, &mut output));
            assert_eq!(allocation.count, 0);
            classic.apply_lookup_table_to(&input, &single, &mut reference);
            for cipher in [&output, &reference] {
                assert_eq!(
                    codec.decode_value(T::as_from(phase(
                        cipher,
                        client.external_lwe_secret_coefficients(),
                        q_wide
                    ))),
                    value(message, 0)
                );
            }
            let (_, allocation) =
                measure(|| sparse.apply_interleaved_lookup_table_to(&input, &many, &mut outputs));
            assert_eq!(allocation.count, 0);
            // Derive the complete public rotation from quantized mask/body and original secret.
            let quantizer = RotationQuantizer::new(modulus, 2 * N, many.padded_output_count());
            let exponent = client
                .external_lwe_secret_coefficients()
                .iter()
                .zip(input.a())
                .fold(
                    (2 * N - quantizer.exponent(input.b())) % (2 * N),
                    |e, (&s, &a)| {
                        if s == T::SignedInteger::ONE {
                            (e + quantizer.exponent(a)) % (2 * N)
                        } else {
                            e
                        }
                    },
                );
            for (i, cipher) in outputs.iter().enumerate() {
                let source = (i + 2 * N - exponent) % (2 * N);
                let target: i128 = many.polynomial().as_ref()[source % N].as_into();
                let target = if source < N { target } else { -target }.rem_euclid(q_wide);
                let actual = phase(cipher, client.external_lwe_secret_coefficients(), q_wide);
                let difference = (actual - target).rem_euclid(q_wide);
                assert!(difference.min(q_wide - difference) < q_wide / 64);
                assert_eq!(codec.decode_value(T::as_from(actual)), value(message, i));
            }
        }
        // A rejected call leaves outputs untouched.
        let before = outputs.clone();
        let invalid = LweCiphertext::zero(DIM - 1);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sparse.apply_interleaved_lookup_table_to(&invalid, &many, &mut outputs);
            }))
            .is_err()
        );
        assert_eq!(before, outputs);
    }
}

#[test]
fn sparse_pbs_matches_classic_outputs_and_independent_rotation_without_allocations() {
    check_complete::<u32, RustFftTable>();
    check_complete::<u32, TfheFftTable>();
    check_complete::<u64, RustFftTable>();
    check_complete::<u64, TfheFftTable>();
}

#[test]
fn sparse_generation_boundaries_and_unsupported_combinations() {
    use primus_ntru::NtruSecretKey;
    use primus_tfhe::sparse::BucketMapError;
    use primus_tfhe_ntru_fourier::{
        CircuitBootstrapConfig, CircuitBootstrapEvaluator, CircuitBootstrapParameters, ClientKey,
        DecompositionConfig, KeyGenerationError as Error,
        SparseBootstrappingKeyError as SparseError,
    };
    use rand::Rng;
    let mut rng = StdRng::seed_from_u64(0xB80201);
    for (distr, weight, expected) in [
        (
            SecretKeyDistr::UniformBinary,
            4,
            Error::SparseBootstrapping(SparseError::UnsupportedSecretDistribution),
        ),
        (
            SecretKeyDistr::fixed_hamming_weight_binary(DIM, 4),
            4,
            Error::Ntru(primus_ntru::NtruError::NonInvertibleSecretKey),
        ),
        (
            SecretKeyDistr::fixed_hamming_weight_binary(DIM, 0),
            1,
            Error::SparseBootstrapping(SparseError::InvalidHammingWeight),
        ),
        (
            SecretKeyDistr::fixed_hamming_weight_binary(DIM, DIM),
            DIM,
            Error::SparseBootstrapping(SparseError::InvalidHammingWeight),
        ),
        (
            SecretKeyDistr::fixed_hamming_weight_binary(DIM, 5),
            3,
            Error::SparseBootstrapping(SparseError::InvalidSecretWeight),
        ),
    ] {
        let context = context::<u32, RustFftTable>(distr);
        let mut secret = vec![0; N];
        secret[..weight].fill(i32::ONE);
        let mut acc = vec![0; N];
        acc[0] = 1;
        let client = ClientKey::new(
            NtruSecretKey::new(secret, distr),
            NtruSecretKey::new(acc, SecretKeyDistr::SparseTernary),
            DIM,
        );
        rng = StdRng::seed_from_u64(0xBAD);
        let mut untouched = StdRng::seed_from_u64(0xBAD);
        assert_eq!(
            context
                .try_generate_sparse_server_key(&client, 3, 8, &mut rng)
                .err(),
            Some(expected)
        );
        assert_eq!(rng.next_u64(), untouched.next_u64());
    }
    let context = context::<u32, RustFftTable>(SecretKeyDistr::fixed_hamming_weight_binary(DIM, 5));
    let mut generator = KeyGenerator::new(&context);
    let (client, _) = generator.try_generate(None, &mut rng).unwrap();
    for (copies, buckets, expected) in [
        (
            0,
            8,
            SparseError::BucketMap(BucketMapError::InvalidBucketParameters),
        ),
        (
            3,
            3,
            SparseError::BucketMap(BucketMapError::InvalidBucketParameters),
        ),
        (usize::MAX, 8, SparseError::StorageSizeOverflow),
    ] {
        rng = StdRng::seed_from_u64(0xBAD);
        let mut untouched = StdRng::seed_from_u64(0xBAD);
        assert_eq!(
            generator
                .try_generate_sparse_server_key(&client, copies, buckets, &mut rng)
                .err(),
            Some(Error::SparseBootstrapping(expected))
        );
        assert_eq!(rng.next_u64(), untouched.next_u64());
    }
    let even =
        self::context::<u32, RustFftTable>(SecretKeyDistr::fixed_hamming_weight_binary(DIM, 4));
    let mut even_rng = StdRng::seed_from_u64(0xBAD);
    let mut untouched = StdRng::seed_from_u64(0xBAD);
    assert_eq!(
        KeyGenerator::new(&even)
            .try_generate_client_key(&mut even_rng)
            .err(),
        Some(Error::Ntru(primus_ntru::NtruError::NonInvertibleSecretKey))
    );
    assert_eq!(even_rng.next_u64(), untouched.next_u64());
    let noninvertible = ClientKey::new(
        client.client_ntru_secret_key().clone(),
        NtruSecretKey::new(vec![0; N], SecretKeyDistr::SparseTernary),
        DIM,
    );
    rng = StdRng::seed_from_u64(0xBAD);
    let mut untouched = StdRng::seed_from_u64(0xBAD);
    assert_eq!(
        generator
            .try_generate_sparse_server_key(&noninvertible, 3, 8, &mut rng)
            .err(),
        Some(Error::Ntru(primus_ntru::NtruError::NonInvertibleSecretKey))
    );
    assert_eq!(rng.next_u64(), untouched.next_u64());

    // Supplying valid standalone CBS material must not bypass the sparse gate.
    let decomposition = DecompositionConfig {
        log_basis: 8,
        level_count: None,
    };
    let parameters = CircuitBootstrapParameters::try_from_config(
        context.parameters(),
        CircuitBootstrapConfig {
            output: DecompositionConfig {
                log_basis: 8,
                level_count: Some(1),
            },
            trace: decomposition,
            trace_noise_standard_deviation: 0.7,
            scheme_switch: decomposition,
            scheme_switch_noise_standard_deviation: 0.7,
        },
    )
    .unwrap();
    let circuit = generator
        .try_generate_circuit_bootstrap_key(&client, parameters, &mut rng)
        .unwrap();
    let server = generator
        .try_generate_sparse_server_key(&client, 3, 8, &mut rng)
        .unwrap();
    assert_eq!(
        CircuitBootstrapEvaluator::try_from_parts(
            &context,
            &server,
            circuit.parameters(),
            &circuit
        )
        .err(),
        Some(TfheEvaluationError::UnsupportedSparseBootstrapping)
    );
}
