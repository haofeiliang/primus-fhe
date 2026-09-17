use primus_encoding::RoundedCodec;
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_ntru::{NlevParameters, NtruParameters, NtruSecretKey, SecretKeyDistr};
use primus_tfhe_ntru::{
    ClientKey, Decryptor, Encryptor, LookupTableError, TfheClientError, TfheParameters,
};

const N: usize = 8;
const LWE_DIMENSION: usize = 4;

fn parameters_with_plaintext(t: u32) -> TfheParameters<u32, NativeModulus<u32>> {
    let modulus = NativeModulus::new();
    let client = NtruParameters::new(N, t, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let accumulator = NtruParameters::new(N, t, modulus, SecretKeyDistr::gaussian(3.2), 0.7);
    TfheParameters::try_new(
        LweParameters::new(
            LWE_DIMENSION,
            t,
            modulus,
            SecretKeyDistr::UniformBinary,
            0.7,
        ),
        NlevParameters::with_ntru_params(&accumulator, 8, None),
        NlevParameters::with_ntru_params(&client, 8, None),
    )
    .unwrap()
}

fn imported_key(client: [i32; N]) -> ClientKey<u32> {
    // General NTRU secrets and the accumulator retain nonbinary coefficients.
    let accumulator =
        NtruSecretKey::new(vec![2, 1, 0, 0, 0, 0, 0, 0], SecretKeyDistr::gaussian(3.2));
    ClientKey::new(
        NtruSecretKey::new(client.to_vec(), SecretKeyDistr::UniformBinary),
        accumulator,
        LWE_DIMENSION,
    )
}

#[test]
fn padded_inputs_and_lut_output_codecs_use_independent_domains() {
    use rand::{SeedableRng, rngs::StdRng};
    let mut rng = StdRng::seed_from_u64(0x5041_4444_4544);
    let key = imported_key([1, 0, 1, 1, 0, 0, 0, 0]);
    for t in [3u32, 4, 5] {
        let parameters = parameters_with_plaintext(t);
        let encryptor = Encryptor::try_new(&parameters, &key).unwrap();
        let decryptor = Decryptor::try_new(&parameters, &key).unwrap();
        let domain_len = t.div_ceil(2);
        assert!(
            parameters
                .compile_lookup_table_slice(
                    parameters.input_plaintext_codec(),
                    &vec![0; domain_len as usize]
                )
                .is_ok()
        );
        let input = encryptor.encrypt_padded(domain_len - 1, &mut rng).unwrap();
        assert_eq!(decryptor.decrypt(&input).unwrap(), domain_len - 1);
        assert_eq!(
            encryptor.encrypt_padded(domain_len, &mut rng).unwrap_err(),
            TfheClientError::MessageOutsidePaddedDomain
        );
        let full_codec = RoundedCodec::new(8, NativeModulus::new());
        if t % 2 == 1 {
            assert_eq!(
                parameters
                    .compile_odd_full_domain_lookup_table_slice(&full_codec, &[0])
                    .unwrap_err(),
                LookupTableError::DomainLengthMismatch {
                    expected: t as usize,
                    actual: 1
                },
            );
            assert_eq!(
                parameters
                    .compile_odd_full_domain_lookup_table_fn(&full_codec, |_| 8)
                    .unwrap_err(),
                LookupTableError::OutputOutOfRange { input: 0 },
            );
            let wrong_codec = RoundedCodec::new(8, primus_modulus::PowOf2Modulus::new(1 << 16));
            assert_eq!(
                parameters
                    .compile_odd_full_domain_lookup_table_fn(&wrong_codec, |_| panic!(
                        "must reject before callback"
                    ))
                    .unwrap_err(),
                LookupTableError::OutputModulusMismatch,
            );
        } else {
            assert_eq!(
                parameters
                    .compile_odd_full_domain_lookup_table_fn(&full_codec, |_| panic!(
                        "must reject before callback"
                    ))
                    .unwrap_err(),
                LookupTableError::EvenPlaintextModulus,
            );
        }
        if t == 4 {
            // Callers supply D*k values; the compiler owns the padding to D*s.
            assert_eq!(
                parameters
                    .compile_interleaved_lookup_table_slice(
                        parameters.input_plaintext_codec(),
                        3,
                        &[0; 8]
                    )
                    .unwrap_err(),
                primus_tfhe_ntru::LookupTableError::DomainLengthMismatch {
                    expected: 6,
                    actual: 8
                }
            );

            // Larger output domain, unchanged two-entry input domain.
            let output_codec = RoundedCodec::new(8, NativeModulus::new());
            let single = parameters
                .compile_lookup_table_slice(&output_codec, &[7, 4])
                .unwrap();
            let many = parameters
                .compile_interleaved_lookup_table_fn(&output_codec, 1, |input, _| [7, 4][input])
                .unwrap();
            assert_eq!(single.input_domain_len(), 2);
            assert_eq!(single.polynomial(), many.polynomial());
            assert_eq!(single.polynomial().as_ref()[0], 7u32 << 29);
            assert_eq!(
                parameters
                    .compile_lookup_table_fn(&output_codec, |_| 8)
                    .unwrap_err(),
                LookupTableError::OutputOutOfRange { input: 0 }
            );
            assert_eq!(
                parameters
                    .compile_interleaved_lookup_table_slice(&output_codec, 1, &[0, 8])
                    .unwrap_err(),
                LookupTableError::OutputOutOfRange { input: 1 }
            );
            // Canonical residues alone cannot detect a codec with the wrong q.
            let wrong_codec = RoundedCodec::new(8, primus_modulus::PowOf2Modulus::new(1 << 16));
            assert_eq!(
                parameters
                    .compile_lookup_table_fn(&wrong_codec, |_| panic!(
                        "must reject before callback"
                    ))
                    .unwrap_err(),
                LookupTableError::OutputModulusMismatch
            );
            assert_eq!(
                parameters
                    .compile_interleaved_lookup_table_fn(&wrong_codec, 1, |_, _| panic!(
                        "must reject before callback"
                    ))
                    .unwrap_err(),
                LookupTableError::OutputModulusMismatch
            );
        }

        assert_eq!(
            parameters
                .compile_interleaved_lookup_table_slice(
                    parameters.input_plaintext_codec(),
                    usize::MAX,
                    &[]
                )
                .unwrap_err(),
            primus_tfhe_ntru::LookupTableError::ManyTableLengthOverflow
        );
    }
}
