//! Public encryption boundaries reject incompatible domains and storage before writes.
use std::panic::{AssertUnwindSafe, catch_unwind};

use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable};
use primus_glwe::{
    FourierGadgetEncryptContext, FourierGgswCiphertext, FourierGlevCiphertext,
    FourierGlweCiphertext, FourierGlweEncryptContext, FourierGlweSecretKey, GadgetSize,
    GlevParameters, GlweCiphertext, GlweParameters, GlweSecretKey, NttGadgetEncryptContext,
    NttGgswCiphertext, NttGlevCiphertext, NttGlweCiphertext, NttGlweKeySwitchingContext,
    NttGlweKeySwitchingKey, NttGlwePublicEncryptContext, NttGlwePublicKey, NttGlweSecretKey,
    SecretKeyDistr,
};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
use rand::{Rng, SeedableRng, rngs::StdRng};

const N: usize = 16;

#[test]
fn secret_generation_rejects_incompatible_tables_before_sampling() {
    let modulus = BarrettModulus::new(257u32);
    let params = GlweParameters::new(1, N, 16, modulus, SecretKeyDistr::UniformBinary, 0.7);
    for table in [
        UintNttTable::new(N.trailing_zeros(), BarrettModulus::new(769u32)).unwrap(),
        UintNttTable::new((N * 2).trailing_zeros(), modulus).unwrap(),
    ] {
        let mut rng = StdRng::seed_from_u64(42);
        let mut expected_rng = StdRng::seed_from_u64(42);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _ = NttGlweSecretKey::generate_pair(&params, &table, &mut rng);
            }))
            .is_err()
        );
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }

    let params = GlweParameters::new(
        1,
        N,
        16u32,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let table = RustFftTable::new((N * 2).trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    let mut rng = StdRng::seed_from_u64(42);
    let mut expected_rng = StdRng::seed_from_u64(42);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _ = FourierGlweSecretKey::generate_pair(&params, &mut fft, &mut rng);
        }))
        .is_err()
    );
    assert_eq!(rng.next_u64(), expected_rng.next_u64());
}

#[test]
fn secret_support_is_checked_at_parameter_construction() {
    for (sigma, valid) in [(1.0, true), (1.1, false)] {
        let result = catch_unwind(|| {
            GlweParameters::new(
                1,
                N,
                2u32,
                BarrettModulus::new(13),
                SecretKeyDistr::gaussian(sigma),
                0.7,
            )
        });
        assert_eq!(result.is_ok(), valid);
    }
}

#[test]
fn fourier_encryption_rejects_incomplete_and_excess_masks_before_writes() {
    let params = GlweParameters::new(
        1,
        N,
        16u32,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let table = RustFftTable::new(N.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    let mut rng = StdRng::seed_from_u64(42);
    let (_, key) = FourierGlweSecretKey::generate_pair(&params, &mut fft, &mut rng);
    let mut context = FourierGlweEncryptContext::new(N);
    let message = Polynomial::new(vec![3u32; N]);
    let sentinel = Complex64::new(7.0, 9.0);

    // A body without a mask used to return recoverable plaintext; excess masks
    // used to be silently ignored by the secret/mask zip.
    for len in [N / 2, params.fourier_glwe_len() + N / 2] {
        let mut output = FourierGlweCiphertext::new(vec![sentinel; len]);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                key.encrypt_to(
                    &message,
                    &mut output,
                    &params,
                    &mut fft,
                    &mut rng,
                    &mut context,
                );
            }))
            .is_err()
        );
        assert_eq!(output.as_ref(), vec![sentinel; len]);
    }
}

#[test]
fn ntt_operations_reject_incompatible_domains_and_workspace_before_writes() {
    let modulus = BarrettModulus::new(257u32);
    let params = GlweParameters::new(1, N, 16, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let table = UintNttTable::new(N.trailing_zeros(), modulus).unwrap();
    let wrong_table = UintNttTable::new(N.trailing_zeros(), BarrettModulus::new(769u32)).unwrap();
    let wrong_length_table = UintNttTable::new((N * 2).trailing_zeros(), modulus).unwrap();
    let gadget = GlevParameters::with_glwe_params(&params, 4, None);
    let mut rng = StdRng::seed_from_u64(42);
    let (_, key) = NttGlweSecretKey::generate_pair(&params, &table, &mut rng);
    let public_key = NttGlwePublicKey::generate(&key, &params, &table, &mut rng);
    let message = Polynomial::new(vec![3u32; N]);
    let mut context = NttGlwePublicEncryptContext::new(N);

    let mut gadget_context = NttGadgetEncryptContext::new(gadget.size());
    for wrong_ntt in [&wrong_table, &wrong_length_table] {
        for ggsw in [false, true] {
            let len = if ggsw {
                gadget.ggsw_len()
            } else {
                gadget.glev_len()
            };
            let mut output = vec![7u32; len];
            let mut rng = StdRng::seed_from_u64(43);
            let mut expected_rng = StdRng::seed_from_u64(43);
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    if ggsw {
                        key.encrypt_ggsw_to(
                            &message,
                            &mut NttGgswCiphertext::new(output.as_mut_slice()),
                            &gadget,
                            wrong_ntt,
                            &mut rng,
                            &mut gadget_context,
                        );
                    } else {
                        key.encrypt_glev_to(
                            &message,
                            &mut NttGlevCiphertext::new(output.as_mut_slice()),
                            &gadget,
                            wrong_ntt,
                            &mut rng,
                            &mut gadget_context,
                        );
                    }
                }))
                .is_err()
            );
            assert_eq!(output, vec![7; len]);
            assert_eq!(rng.next_u64(), expected_rng.next_u64());
        }
    }
    let coeff_key = GlweSecretKey::generate(params.size(), params.secret_key_sampler(), &mut rng);
    let switching_key = NttGlweKeySwitchingKey::generate(
        &coeff_key,
        &key,
        &gadget,
        &table,
        &mut rng,
        &mut gadget_context,
    );
    let input = GlweCiphertext::new(vec![0u32; params.glwe_len()]);
    let mut switching_context = NttGlweKeySwitchingContext::new(params.size());
    // Also reject a mutually compatible modulus/table pair belonging to a different key.
    for (modulus, ntt) in [
        (modulus, &wrong_table),
        (modulus, &wrong_length_table),
        (BarrettModulus::new(769), &wrong_table),
    ] {
        let mut output = GlweCiphertext::new(vec![7u32; params.glwe_len()]);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                switching_key.key_switch_to(
                    &input,
                    &mut output,
                    modulus,
                    ntt,
                    &mut switching_context,
                );
            }))
            .is_err()
        );
        assert_eq!(output.as_ref(), vec![7u32; params.glwe_len()]);
    }

    for public in [false, true] {
        let mut output = NttGlweCiphertext::new(vec![7u32; params.glwe_len()]);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                if public {
                    public_key.encrypt_to(
                        &message,
                        &mut output,
                        &params,
                        &wrong_table,
                        &mut rng,
                        &mut context,
                    );
                } else {
                    key.encrypt_to(&message, &mut output, &params, &wrong_table, &mut rng);
                }
            }))
            .is_err()
        );
        assert_eq!(output.as_ref(), vec![7u32; params.glwe_len()]);
    }
    for length in [N / 2, N * 2] {
        let mut wrong_context = NttGlwePublicEncryptContext::new(length);
        let mut output = NttGlweCiphertext::new(vec![7u32; params.glwe_len()]);
        let mut rng = StdRng::seed_from_u64(43);
        let mut expected_rng = StdRng::seed_from_u64(43);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                public_key.encrypt_to(
                    &message,
                    &mut output,
                    &params,
                    &table,
                    &mut rng,
                    &mut wrong_context,
                );
            }))
            .is_err()
        );
        assert_eq!(output.as_ref(), vec![7u32; params.glwe_len()]);
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }
    let input = NttGlweCiphertext::new(vec![0u32; params.glwe_len()]);
    let mut phase = Polynomial::new(vec![7u32; N]);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            key.phase_to(&input, &mut phase, modulus, &wrong_table);
        }))
        .is_err()
    );
    assert_eq!(phase.as_ref(), vec![7u32; N]);

    // Coefficient entry points share these checks; no RNG, output or scratch
    // change is allowed for a bad layout or transform domain.
    for (polynomial_len, ciphertext_len, scratch_len, ntt) in [
        (N - 1, 2 * N, N, &table),
        (N, 2 * N - 1, N, &table),
        (N, 3 * N, N, &table),
        (N, 2 * N, N - 1, &table),
        (N, 2 * N, N + 1, &table),
        (N, 2 * N, N, &wrong_table),
        (N, 2 * N, N, &wrong_length_table),
    ] {
        let mut polynomial = Polynomial::new(vec![7; polynomial_len]);
        let mut ciphertext = GlweCiphertext::new(vec![7; ciphertext_len]);
        let mut scratch = vec![7; scratch_len];
        let mut rng = StdRng::seed_from_u64(43);
        let mut expected_rng = StdRng::seed_from_u64(43);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                key.encrypt_coeff_to(
                    &polynomial,
                    &mut ciphertext,
                    &params,
                    ntt,
                    &mut rng,
                    &mut scratch,
                );
            }))
            .is_err()
        );
        assert_eq!(ciphertext.as_ref(), vec![7; ciphertext_len]);
        assert_eq!(scratch, vec![7; scratch_len]);
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                key.decrypt_coeff_to(&ciphertext, &mut polynomial, &params, ntt, &mut scratch);
            }))
            .is_err()
        );
        assert_eq!(polynomial.as_ref(), vec![7; polynomial_len]);
        assert_eq!(scratch, vec![7; scratch_len]);
    }
}

#[test]
fn only_ggsw_requires_matching_workspace_levels_in_both_domains() {
    let mut rng = StdRng::seed_from_u64(42);
    let modulus = BarrettModulus::new(132_120_577u32);
    let ntt_params = GlweParameters::new(1, N, 16, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let fourier_params = GlweParameters::new(
        1,
        N,
        16u32,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let ntt_gadget = GlevParameters::with_glwe_params(&ntt_params, 8, Some(3));
    let fourier_gadget = GlevParameters::with_glwe_params(&fourier_params, 8, Some(3));
    let ntt = UintNttTable::new(N.trailing_zeros(), modulus).unwrap();
    let table = RustFftTable::new(N.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    let (_, ntt_key) = NttGlweSecretKey::generate_pair(&ntt_params, &ntt, &mut rng);
    let (_, fourier_key) = FourierGlweSecretKey::generate_pair(&fourier_params, &mut fft, &mut rng);
    let message = Polynomial::new(vec![1u32; N]);

    for levels in [1, 4] {
        let size = GadgetSize::new(ntt_params.size(), levels);
        let mut ntt_context = NttGadgetEncryptContext::new(size);
        let mut fourier_context = FourierGadgetEncryptContext::new(size);
        let mut ntt_glev = NttGlevCiphertext::<Vec<u32>>::zero(ntt_gadget.glev_len());
        let mut fourier_glev =
            FourierGlevCiphertext::<Vec<Complex64>>::zero(fourier_gadget.fourier_glev_len());
        ntt_key.encrypt_glev_to(
            &message,
            &mut ntt_glev,
            &ntt_gadget,
            &ntt,
            &mut rng,
            &mut ntt_context,
        );
        fourier_key.encrypt_glev_to(
            &message,
            &mut fourier_glev,
            &fourier_gadget,
            &mut fft,
            &mut rng,
            &mut fourier_context,
        );
        let mut ntt_output = NttGgswCiphertext::new(vec![7u32; ntt_gadget.ggsw_len()]);
        let sentinel = Complex64::new(7.0, 9.0);
        let mut fourier_output =
            FourierGgswCiphertext::new(vec![sentinel; fourier_gadget.fourier_ggsw_len()]);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                ntt_key.encrypt_ggsw_to(
                    &message,
                    &mut ntt_output,
                    &ntt_gadget,
                    &ntt,
                    &mut rng,
                    &mut ntt_context,
                );
            }))
            .is_err()
        );
        assert_eq!(ntt_output.as_ref(), vec![7u32; ntt_gadget.ggsw_len()]);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                fourier_key.encrypt_ggsw_to(
                    &message,
                    &mut fourier_output,
                    &fourier_gadget,
                    &mut fft,
                    &mut rng,
                    &mut fourier_context,
                );
            }))
            .is_err()
        );
        assert_eq!(
            fourier_output.as_ref(),
            vec![sentinel; fourier_gadget.fourier_ggsw_len()]
        );
    }
}

#[test]
fn glev_construction_reuses_basis_and_rejects_incompatible_domains_or_layouts() {
    use primus_decompose::primitive::ApproxSignedBasis;
    use primus_glwe::GlevParameterError;

    let native = GlweParameters::new(
        2,
        N,
        16u32,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let explicit = GlweParameters::new(
        2,
        N,
        16u32,
        BarrettModulus::new(257),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    assert_eq!(native.cipher_modulus_value(), None);
    assert_eq!(explicit.cipher_modulus_value(), Some(257));
    for levels in [None, Some(2)] {
        let basis = ApproxSignedBasis::new(None, 3, levels);
        let params = GlevParameters::try_with_basis(&native, basis.clone()).unwrap();
        assert_eq!(params.basis(), &basis);
        assert_eq!(params.glwe_size(), native.size());
        let basis = ApproxSignedBasis::new(Some(257), 3, levels);
        let params = GlevParameters::try_with_basis(&explicit, basis.clone()).unwrap();
        assert_eq!(params.basis(), &basis);
        assert_eq!(params.glwe_size(), explicit.size());
    }
    for modulus in [Some(257), Some(769)] {
        assert!(matches!(
            GlevParameters::try_with_basis(&native, ApproxSignedBasis::new(modulus, 3, None)),
            Err(GlevParameterError::BasisModulusMismatch)
        ));
    }
    for modulus in [None, Some(769)] {
        assert!(matches!(
            GlevParameters::try_with_basis(&explicit, ApproxSignedBasis::new(modulus, 3, None)),
            Err(GlevParameterError::BasisModulusMismatch)
        ));
    }
    // GLWE lengths fit but the quadratic GGSW layout overflows, without allocating it.
    let huge = GlweParameters::new(
        1usize << (usize::BITS / 2),
        N,
        16u32,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    assert!(matches!(
        GlevParameters::try_with_glwe_params(&huge, 3, None),
        Err(GlevParameterError::InvalidSize(_))
    ));
}
