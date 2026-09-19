//! Prefix sampling and backend acceptance are separate from TFHE control support.
use primus_distr::sample_gaussian_values_to;
use primus_encoding::PlaintextEmbedding;
use primus_fft::{FftEngine, FftTable, RustFftTable, TfheFftTable};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{
    FourierNtruDecryptContext, FourierNtruEncryptContext, FourierNtruSecretKey, NtruError,
    NtruParameters, NtruSecretKey, NttNtruSecretKey, SecretKeyDistr,
};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
use primus_reduce::{ReduceAdd, ReduceSub};
use rand::{Rng, SeedableRng, rngs::StdRng};

const N: usize = 32;
const ACTIVE_LENGTH: usize = 23;
const DISTRIBUTIONS: [SecretKeyDistr; 5] = [
    SecretKeyDistr::UniformTernary,
    SecretKeyDistr::SparseTernary,
    SecretKeyDistr::Ternary {
        negative_one_probability: 0.125,
        one_probability: 0.375,
    },
    SecretKeyDistr::FixedHammingWeightTernary { hamming_weight: 7 },
    SecretKeyDistr::FixedCompositionTernary {
        negative_one_weight: 3,
        one_weight: 4,
    },
];

fn assert_prefix(key: &NtruSecretKey<u64>, distribution: SecretKeyDistr) {
    assert_eq!(key.distr(), distribution);
    assert_eq!(key.poly_length(), N);
    let prefix = &key.as_slice()[..ACTIVE_LENGTH];
    assert!(prefix.iter().all(|value| (-1..=1).contains(value)));
    assert!(
        key.as_slice()[ACTIVE_LENGTH..]
            .iter()
            .all(|&value| value == 0)
    );
    match distribution {
        SecretKeyDistr::FixedHammingWeightTernary { hamming_weight } => {
            assert_eq!(prefix.iter().filter(|&&v| v != 0).count(), hamming_weight);
        }
        SecretKeyDistr::FixedCompositionTernary {
            negative_one_weight,
            one_weight,
        } => {
            assert_eq!(
                prefix.iter().filter(|&&v| v == -1).count(),
                negative_one_weight
            );
            assert_eq!(prefix.iter().filter(|&&v| v == 1).count(), one_weight);
        }
        _ => {}
    }
}

#[test]
fn ntt_padded_ternary_has_exact_coefficient_phase() {
    let modulus = BarrettModulus::new(1_125_899_906_826_241u64);
    let table = UintNttTable::new(N.trailing_zeros(), modulus).unwrap();
    let message = Polynomial::new((0..N as u64).map(|i| i % 16).collect::<Vec<_>>());
    let mut rng = StdRng::seed_from_u64(0xB701);
    // Even total weight is admissible over the NTT field; Native rejects it.
    let even = SecretKeyDistr::FixedCompositionTernary {
        negative_one_weight: 1,
        one_weight: 1,
    };
    for distribution in DISTRIBUTIONS.into_iter().chain([even]) {
        let params = NtruParameters::new(N, 16, modulus, distribution, 0.7);
        let (coeff, key) =
            NttNtruSecretKey::generate_padded_pair(&params, ACTIVE_LENGTH, &table, &mut rng)
                .unwrap();
        assert_prefix(&coeff, distribution);

        // Replay only the encryption noise. Compute f*c directly in the
        // coefficient ring, independently of the key's cached NTT and inverse.
        let mut expected = vec![0; N];
        sample_gaussian_values_to(
            &mut expected,
            params.noise_distribution(),
            &mut StdRng::seed_from_u64(0xB711),
        );
        params.plaintext_codec().add_encode_slice_assign(
            &mut expected,
            message.as_ref(),
            PlaintextEmbedding::Unsigned,
        );
        let cipher = key.encrypt(
            &message,
            &params,
            &table,
            &mut StdRng::seed_from_u64(0xB711),
        );
        let mut cipher_coeff = cipher.as_ref().to_vec();
        table.inverse_transform_slice(&mut cipher_coeff);
        let mut phase = vec![0; N];
        for (i, &secret) in coeff.as_slice().iter().enumerate() {
            for (j, &value) in cipher_coeff.iter().enumerate() {
                let index = (i + j) % N;
                let sign = if i + j < N { secret } else { -secret };
                phase[index] = match sign {
                    1 => modulus.reduce_add(phase[index], value),
                    -1 => modulus.reduce_sub(phase[index], value),
                    _ => phase[index],
                };
            }
        }
        assert_eq!(phase, expected);
    }
}

fn assert_fourier_prefix<Table: FftTable>(table: &Table) {
    let mut fft = FftEngine::new(table);
    let mut rng = StdRng::seed_from_u64(0xB701);
    let message = Polynomial::new((0..N as u64).map(|i| i % 16).collect::<Vec<_>>());
    let mut encrypt = FourierNtruEncryptContext::new(N);
    let mut decrypt = FourierNtruDecryptContext::new(N);
    for distribution in DISTRIBUTIONS {
        let params = NtruParameters::new(N, 16, NativeModulus::new(), distribution, 0.7);
        let (coeff, key) =
            FourierNtruSecretKey::generate_padded_pair(&params, ACTIVE_LENGTH, &mut fft, &mut rng)
                .unwrap();
        assert_prefix(&coeff, distribution);
        assert_eq!(coeff.as_slice().iter().sum::<i64>().rem_euclid(2), 1);
        // Reimport the returned signed key to check the pair's identity, rather
        // than decrypting with the same opaque key that encrypted the message.
        let check_key = FourierNtruSecretKey::try_from_coeff_secret_key(&coeff, &mut fft).unwrap();
        let cipher = key.encrypt(&message, &params, &mut fft, &mut rng, &mut encrypt);
        assert_eq!(
            check_key
                .decrypt(&cipher, &params, &mut fft, &mut decrypt)
                .as_ref(),
            message.as_ref(),
        );
    }
}

#[test]
fn fourier_padded_ternary_preserves_prefix_and_key_identity() {
    assert_fourier_prefix(&RustFftTable::new(N.trailing_zeros()).unwrap());
    assert_fourier_prefix(&TfheFftTable::new(N.trailing_zeros()).unwrap());
}

#[test]
fn native_fixed_even_weights_fail_without_sampling() {
    let table = RustFftTable::new(N.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    for distribution in [
        SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 2 },
        SecretKeyDistr::FixedHammingWeightTernary { hamming_weight: 2 },
        SecretKeyDistr::FixedCompositionTernary {
            negative_one_weight: 1,
            one_weight: 1,
        },
        SecretKeyDistr::FixedCompositionTernary {
            negative_one_weight: 0,
            one_weight: 0,
        },
    ] {
        let params = NtruParameters::new(N, 16u64, NativeModulus::new(), distribution, 0.7);
        for padded in [false, true] {
            let mut rng = StdRng::seed_from_u64(0xB701);
            let mut untouched = StdRng::seed_from_u64(0xB701);
            let result = if padded {
                FourierNtruSecretKey::generate_padded_pair(
                    &params,
                    ACTIVE_LENGTH,
                    &mut fft,
                    &mut rng,
                )
            } else {
                FourierNtruSecretKey::generate_pair(&params, &mut fft, &mut rng)
            };
            assert!(matches!(result, Err(NtruError::NonInvertibleSecretKey)));
            assert_eq!(rng.next_u64(), untouched.next_u64());
        }
    }
}

fn assert_unstable_inverse<Table: FftTable>(table: &Table, coeff: &NtruSecretKey<u64>) {
    assert!(matches!(
        FourierNtruSecretKey::try_from_coeff_secret_key(coeff, &mut FftEngine::new(table)),
        Err(NtruError::UnstableFourierInverse),
    ));
}

#[test]
fn native_invertibility_does_not_imply_fourier_stability() {
    // f = (1-X+X^2)^8 has f(1)=1, hence is a native-ring unit. At the
    // negacyclic root exp(11*pi*i/32), |f| is about 1e-10. This imported
    // integer key isolates the numerical gate; it is not a ternary sample.
    let mut coefficients = vec![0i64; N];
    coefficients[0] = 1;
    for _ in 0..8 {
        let mut product = vec![0; N];
        for i in 0..N - 2 {
            product[i] += coefficients[i];
            product[i + 1] -= coefficients[i];
            product[i + 2] += coefficients[i];
        }
        coefficients = product;
    }
    assert_eq!(coefficients.iter().sum::<i64>(), 1);
    let coeff = NtruSecretKey::<u64>::new(coefficients, SecretKeyDistr::gaussian(3.2));
    assert_unstable_inverse(&RustFftTable::new(N.trailing_zeros()).unwrap(), &coeff);
    assert_unstable_inverse(&TfheFftTable::new(N.trailing_zeros()).unwrap(), &coeff);
}
