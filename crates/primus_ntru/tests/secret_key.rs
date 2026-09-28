//! Encoding entry points, NTRU key acceptance and validation before mutation.
//! Arithmetic kernels and fused-lift phase identities have separate oracles.
use primus_distr::sample_gaussian_values_to;
use primus_encoding::PlaintextEmbedding;
use primus_fft::{FftEngine, FftTable, RustFftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{
    FourierNtruDecryptWorkspace, FourierNtruEncryptWorkspace, FourierNtruSecretKey, NtruError,
    NtruParameters, NtruSecretKey, NttNtruSecretKey, SecretKeyDistr,
};
use primus_ntt::{NttTable, PrimitiveRoot, UintNttTable};
use primus_poly::Polynomial;
use rand::{Rng, SeedableRng, rngs::StdRng};

// Small functional ring; both word widths retain their original moduli and noise.
const POLY_LENGTH: usize = 32;
const PLAIN_MODULUS: usize = 16;

// Include both sides of the centered encoding boundary.
fn messages<T: FheUint>() -> Vec<T> {
    (0..POLY_LENGTH)
        .map(|index| T::try_from(index % PLAIN_MODULUS).unwrap())
        .collect()
}

// Replay noise independently and overwrite one ciphertext through all encodings.
fn assert_ntt_roundtrip<T>(cipher_modulus: T)
where
    T: FheUint + PrimitiveRoot,
{
    let modulus = BarrettModulus::new(cipher_modulus);
    let ntt = UintNttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let params = NtruParameters::new(
        POLY_LENGTH,
        T::try_from(PLAIN_MODULUS).unwrap(),
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let mut rng = StdRng::seed_from_u64(42);
    let secret_key = NttNtruSecretKey::generate(&params, &ntt, &mut rng).unwrap();
    let messages = messages::<T>();
    let message = Polynomial::new(messages.as_slice());

    let mut rng = StdRng::seed_from_u64(43);
    let mut noise_rng = StdRng::seed_from_u64(43);
    let mut cipher = secret_key.encrypt(&message, &params, &ntt, &mut rng);
    assert_eq!(
        secret_key.decrypt(&cipher, &params, &ntt).as_ref(),
        messages
    );

    let (decrypted, noise) = secret_key.decrypt_with_noise(&cipher, &params, &ntt);
    assert_eq!(decrypted.as_ref(), messages);
    let mut expected_noise = vec![T::ZERO; POLY_LENGTH];
    sample_gaussian_values_to(
        &mut expected_noise,
        params.noise_distribution(),
        &mut noise_rng,
    );
    // The diagnostic returns absolute circular distance, not a signed residue.
    for value in &mut expected_noise {
        *value = (*value).min(cipher_modulus - *value);
    }
    assert_eq!(noise.as_ref(), expected_noise);

    secret_key.encrypt_centered_to(&message, &mut cipher, &params, &ntt, &mut rng);
    assert_eq!(
        secret_key.decrypt(&cipher, &params, &ntt).as_ref(),
        messages
    );

    let mut encoded = vec![T::ZERO; POLY_LENGTH];
    params.plaintext_codec().add_encode_slice_assign(
        &mut encoded,
        &messages,
        PlaintextEmbedding::Unsigned,
    );
    secret_key.encrypt_encoded_to(
        &Polynomial::new(encoded),
        &mut cipher,
        &params,
        &ntt,
        &mut rng,
    );
    assert_eq!(
        secret_key.decrypt(&cipher, &params, &ntt).as_ref(),
        messages
    );

    secret_key.encrypt_zeros_to(&mut cipher, &params, &ntt, &mut rng);
    assert_eq!(
        secret_key.decrypt(&cipher, &params, &ntt).as_ref(),
        vec![T::ZERO; POLY_LENGTH]
    );
}

#[test]
fn ntt_secret_key_encodings_reuse_ciphertext_storage() {
    assert_ntt_roundtrip(132_120_577u32);
    assert_ntt_roundtrip(1_125_899_906_826_241u64);
}

// Native torus encryption reuses both ciphertext and FFT workspaces.
fn assert_fourier_roundtrip<T>()
where
    T: FheUint + TorusFftValue,
{
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    let params = NtruParameters::new(
        POLY_LENGTH,
        T::try_from(PLAIN_MODULUS).unwrap(),
        NativeModulus::new(),
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let mut rng = StdRng::seed_from_u64(42);
    let secret_key = FourierNtruSecretKey::generate(&params, &mut fft, &mut rng).unwrap();
    let mut encrypt_workspace = FourierNtruEncryptWorkspace::new(POLY_LENGTH);
    let mut decrypt_workspace = FourierNtruDecryptWorkspace::new(POLY_LENGTH);
    let messages = messages::<T>();
    let message = Polynomial::new(messages.as_slice());

    let mut cipher = secret_key.encrypt(
        &message,
        &params,
        &mut fft,
        &mut rng,
        &mut encrypt_workspace,
    );
    assert_eq!(
        secret_key
            .decrypt(&cipher, &params, &mut fft, &mut decrypt_workspace,)
            .as_ref(),
        messages
    );

    secret_key.encrypt_centered_to(
        &message,
        &mut cipher,
        &params,
        &mut fft,
        &mut rng,
        &mut encrypt_workspace,
    );
    assert_eq!(
        secret_key
            .decrypt(&cipher, &params, &mut fft, &mut decrypt_workspace,)
            .as_ref(),
        messages
    );

    let mut encoded = vec![T::ZERO; POLY_LENGTH];
    params.plaintext_codec().add_encode_slice_assign(
        &mut encoded,
        &messages,
        PlaintextEmbedding::Unsigned,
    );
    secret_key.encrypt_encoded_to(
        &Polynomial::new(encoded),
        &mut cipher,
        &params,
        &mut fft,
        &mut rng,
        &mut encrypt_workspace,
    );
    assert_eq!(
        secret_key
            .decrypt(&cipher, &params, &mut fft, &mut decrypt_workspace,)
            .as_ref(),
        messages
    );

    secret_key.encrypt_zeros_to(
        &mut cipher,
        &params,
        &mut fft,
        &mut rng,
        &mut encrypt_workspace,
    );
    assert_eq!(
        secret_key
            .decrypt(&cipher, &params, &mut fft, &mut decrypt_workspace,)
            .as_ref(),
        vec![T::ZERO; POLY_LENGTH]
    );
}

#[test]
fn fourier_secret_key_encodings_reuse_ciphertext_storage() {
    assert_fourier_roundtrip::<u32>();
    assert_fourier_roundtrip::<u64>();
}

#[test]
fn transform_backends_reject_the_zero_key() {
    let zero_key = NtruSecretKey::<u32>::new(
        vec![i32::default(); POLY_LENGTH],
        SecretKeyDistr::SparseTernary,
    );

    let modulus = BarrettModulus::new(132_120_577u32);
    let ntt = UintNttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    assert!(matches!(
        NttNtruSecretKey::try_from_coeff_secret_key(&zero_key, modulus, &ntt),
        Err(NtruError::NonInvertibleSecretKey)
    ));

    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    assert!(matches!(
        FourierNtruSecretKey::try_from_coeff_secret_key(&zero_key, &mut fft),
        Err(NtruError::NonInvertibleSecretKey)
    ));
}

#[test]
fn key_generation_supports_small_coefficient_distributions() {
    let mut rng = StdRng::seed_from_u64(42);
    let modulus = BarrettModulus::new(132_120_577u32);
    let ntt = UintNttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let fft_table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&fft_table);

    for distribution in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::SparseTernary,
        SecretKeyDistr::gaussian(3.2),
    ] {
        let ntt_params = NtruParameters::new(
            POLY_LENGTH,
            PLAIN_MODULUS as u32,
            modulus,
            distribution,
            0.7,
        );
        NttNtruSecretKey::generate(&ntt_params, &ntt, &mut rng).unwrap();

        let fourier_params = NtruParameters::new(
            POLY_LENGTH,
            PLAIN_MODULUS as u32,
            NativeModulus::new(),
            distribution,
            0.7,
        );
        FourierNtruSecretKey::generate(&fourier_params, &mut fft, &mut rng).unwrap();
    }
}

#[test]
fn parameters_require_secret_support_below_explicit_modulus() {
    // The support endpoints 12 * sigma are exact integers here. Test both
    // Gaussian backends at the strict q boundary, independently of sampling.
    for (sigma, maximum_magnitude) in [(3.0, 36u32), (30.0, 360)] {
        let distribution = SecretKeyDistr::gaussian(sigma);
        for q in [maximum_magnitude - 1, maximum_magnitude] {
            assert_eq!(
                NtruParameters::try_new(POLY_LENGTH, 2, BarrettModulus::new(q), distribution, 0.7)
                    .err(),
                Some(primus_ntru::NtruParameterError::SecretKey(
                    primus_distr::SecretKeySamplerError::ModulusTooSmall {
                        maximum_magnitude: u128::from(maximum_magnitude),
                        modulus_minus_one: u128::from(q - 1),
                    },
                ))
            );
            assert!(
                std::panic::catch_unwind(|| NtruParameters::new(
                    POLY_LENGTH,
                    2,
                    BarrettModulus::new(q),
                    distribution,
                    0.7,
                ))
                .is_err()
            );
        }
        assert!(
            NtruParameters::try_new(
                POLY_LENGTH,
                2,
                BarrettModulus::new(maximum_magnitude + 1),
                distribution,
                0.7,
            )
            .is_ok()
        );
        assert!(
            NtruParameters::try_new(
                POLY_LENGTH,
                2,
                NativeModulus::<u32>::new(),
                distribution,
                0.7,
            )
            .is_ok()
        );
    }
}

#[test]
fn fallible_parameters_check_ring_codec_and_samplers() {
    use primus_ntru::NtruParameterError as Error;
    let make = |n, t, distr, noise| {
        NtruParameters::try_new(n, t, NativeModulus::<u32>::new(), distr, noise)
    };
    for n in [0, 3, usize::MAX] {
        assert_eq!(
            make(n, 4, SecretKeyDistr::UniformBinary, 0.7).err(),
            Some(Error::InvalidPolynomialLength)
        );
    }
    assert!(matches!(
        make(8, 1, SecretKeyDistr::UniformBinary, 0.7),
        Err(Error::Encoding(_))
    ));
    assert!(matches!(
        make(8, 4, SecretKeyDistr::UniformBinary, f64::INFINITY),
        Err(Error::Noise(_))
    ));
    assert!(matches!(
        make(
            8,
            4,
            SecretKeyDistr::FixedCompositionTernary {
                negative_one_weight: 4,
                one_weight: 5
            },
            0.7
        ),
        Err(Error::SecretKey(_))
    ));
    assert!(matches!(
        NtruParameters::try_new(
            8,
            12,
            BarrettModulus::new(17u32),
            SecretKeyDistr::UniformBinary,
            0.7
        ),
        Err(Error::Encoding(
            primus_encoding::CodecError::InsufficientScaleRecovery
        ))
    ));
}

#[test]
fn ordinary_operations_validate_before_sampling_or_writing() {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    let mut rng = StdRng::seed_from_u64(73);
    let modulus = BarrettModulus::new(132_120_577u32);
    let ntt = UintNttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let params = NtruParameters::new(POLY_LENGTH, 16, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let short_params = NtruParameters::new(
        POLY_LENGTH / 2,
        16,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let key = NttNtruSecretKey::generate(&params, &ntt, &mut rng).unwrap();
    let input = key.encrypt_zeros(&params, &ntt, &mut rng);
    let mut output = Polynomial::new(vec![7; POLY_LENGTH]);
    assert!(
        catch_unwind(AssertUnwindSafe(|| key.decrypt_to(
            &input,
            &mut output,
            &short_params,
            &ntt
        )))
        .is_err()
    );
    assert!(output.iter().all(|&value| value == 7));
    let mut wrong_output = primus_ntru::NttNtruCiphertext::new(vec![7; POLY_LENGTH / 2]);
    let mut rng = StdRng::seed_from_u64(91);
    let mut expected_rng = StdRng::seed_from_u64(91);
    assert!(
        catch_unwind(AssertUnwindSafe(|| key.encrypt_zeros_to(
            &mut wrong_output,
            &params,
            &ntt,
            &mut rng
        )))
        .is_err()
    );
    assert_eq!(rng.next_u64(), expected_rng.next_u64());
    assert!(wrong_output.as_ref().iter().all(|&value| value == 7));

    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    let params = NtruParameters::new(
        POLY_LENGTH,
        16u32,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let short_params = NtruParameters::new(
        POLY_LENGTH / 2,
        16u32,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let key = FourierNtruSecretKey::generate(&params, &mut fft, &mut rng).unwrap();
    let mut encrypt = FourierNtruEncryptWorkspace::new(POLY_LENGTH);
    let mut decrypt = FourierNtruDecryptWorkspace::new(POLY_LENGTH);
    let mut input = key.encrypt_zeros(&params, &mut fft, &mut rng, &mut encrypt);
    assert!(
        catch_unwind(AssertUnwindSafe(|| key.decrypt_to(
            &input,
            &mut output,
            &short_params,
            &mut fft,
            &mut decrypt
        )))
        .is_err()
    );
    assert!(output.iter().all(|&value| value == 7));
    let before = input.as_ref().to_vec();
    let mut short_encrypt = FourierNtruEncryptWorkspace::new(POLY_LENGTH / 2);
    let mut rng = StdRng::seed_from_u64(91);
    let mut expected_rng = StdRng::seed_from_u64(91);
    assert!(
        catch_unwind(AssertUnwindSafe(|| key.encrypt_zeros_to(
            &mut input,
            &params,
            &mut fft,
            &mut rng,
            &mut short_encrypt
        )))
        .is_err()
    );
    assert_eq!(rng.next_u64(), expected_rng.next_u64());
    assert_eq!(input.as_ref(), before);
}
