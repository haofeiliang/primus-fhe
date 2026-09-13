//! Constant batches preserve polynomial encryption and RNG consumption exactly.
use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_glwe::{
    FourierGadgetEncryptContext, FourierGgswCiphertext, FourierGlweSecretKey, GlevParameters,
    GlweParameters, NttGadgetEncryptContext, NttGlweSecretKey, SecretKeyDistr,
};
use primus_lattice::ggsw::NttGgsw;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::PolynomialOwned;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

#[test]
fn ntt_constant_ggsw_batch_matches_individual_encryptions() {
    let n = 16usize;
    let modulus = BarrettModulus::new(257u32);
    let glwe = GlweParameters::new(2, n, 16, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let params = GlevParameters::with_glwe_params(&glwe, 4, None);
    let table = UintNttTable::new(n.trailing_zeros(), modulus).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let (_, key) = NttGlweSecretKey::generate_pair(&glwe, &table, &mut rng);
    let mut context = NttGadgetEncryptContext::new(params.size());
    let mut single_context = NttGadgetEncryptContext::new(params.size());
    // Include empty input, binary BSK inputs and general canonical constants.
    for constants in [&[][..], &[0, 1, 256, 17][..]] {
        let mut batch = vec![7; constants.len() * params.ggsw_len()];
        let mut singles = batch.clone();
        let mut rng = StdRng::seed_from_u64(43);
        let mut single_rng = StdRng::seed_from_u64(43);
        key.encrypt_ggsw_constant_batch_to(
            constants,
            &mut batch,
            &params,
            &table,
            &mut rng,
            &mut context,
        );
        let mut message = PolynomialOwned::zero(n);
        for (&constant, chunk) in constants
            .iter()
            .zip(singles.chunks_exact_mut(params.ggsw_len()))
        {
            message.as_mut()[0] = constant;
            key.encrypt_ggsw_to(
                &message,
                &mut NttGgsw::new(chunk),
                &params,
                &table,
                &mut single_rng,
                &mut single_context,
            );
        }
        assert_eq!(batch, singles);
        assert_eq!(rng.next_u64(), single_rng.next_u64());
    }
    // An invalid total length must fail before writing or consuming randomness.
    for len in [params.ggsw_len(), 2 * params.ggsw_len() + 1] {
        let mut output = vec![7; len];
        let mut rng = StdRng::seed_from_u64(43);
        let mut expected_rng = StdRng::seed_from_u64(43);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                key.encrypt_ggsw_constant_batch_to(
                    &[0, 1],
                    &mut output,
                    &params,
                    &table,
                    &mut rng,
                    &mut context,
                );
            }))
            .is_err()
        );
        assert_eq!(output, vec![7; len]);
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }
}

#[test]
fn fourier_constant_ggsw_batches_match_individual_encryptions() {
    check_fourier_batch::<u32, RustFftTable>();
    check_fourier_batch::<u64, RustFftTable>();
    check_fourier_batch::<u32, TfheFftTable>();
    check_fourier_batch::<u64, TfheFftTable>();
}

fn check_fourier_batch<T: TorusFftValue, Table: FftTable>() {
    let n = 16usize;
    let glwe = GlweParameters::new(
        2,
        n,
        T::try_from(16usize).unwrap(),
        NativeModulus::new(),
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let params = GlevParameters::with_glwe_params(&glwe, 3, Some(3));
    let table = Table::new(n.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    let mut rng = StdRng::seed_from_u64(42);
    let (_, key) = FourierGlweSecretKey::generate_pair(&glwe, &mut fft, &mut rng);
    let mut context = FourierGadgetEncryptContext::new(params.size());
    let sentinel = Complex64::new(7.0, 9.0);
    let constants = [
        T::ZERO,
        T::ONE,
        T::MAX,
        T::MAX / T::try_from(3usize).unwrap(),
    ];
    for input in [&[][..], &constants[..1], &constants[..]] {
        let mut expected = vec![sentinel; input.len() * params.fourier_ggsw_len()];
        let mut actual = expected.clone();
        let mut reference_rng = StdRng::seed_from_u64(43);
        let mut actual_rng = StdRng::seed_from_u64(43);
        let mut message = PolynomialOwned::zero(n);
        for (&constant, block) in input
            .iter()
            .zip(expected.chunks_exact_mut(params.fourier_ggsw_len()))
        {
            message.as_mut()[0] = constant;
            key.encrypt_ggsw_to(
                &message,
                &mut FourierGgswCiphertext::new(block),
                &params,
                &mut fft,
                &mut reference_rng,
                &mut context,
            );
        }
        // A preceding nonconstant encryption leaves a nonzero workspace tail.
        if let Some(block) = actual.chunks_exact_mut(params.fourier_ggsw_len()).next() {
            message.as_mut().fill(T::ONE);
            key.encrypt_ggsw_to(
                &message,
                &mut FourierGgswCiphertext::new(block),
                &params,
                &mut fft,
                &mut rng,
                &mut context,
            );
        }
        key.encrypt_ggsw_constant_batch_to(
            input,
            &mut actual,
            &params,
            &mut fft,
            &mut actual_rng,
            &mut context,
        );
        assert_eq!(actual, expected);
        assert_eq!(actual_rng.next_u64(), reference_rng.next_u64());
    }
    let wrong_levels = GlevParameters::with_glwe_params(&glwe, 3, Some(2));
    for (input, len, size) in [
        (
            &constants[..1],
            params.fourier_ggsw_len() + 1,
            params.size(),
        ),
        (&[][..], 0, wrong_levels.size()),
    ] {
        let mut output = vec![sentinel; len];
        let mut context = FourierGadgetEncryptContext::new(size);
        let mut rng = StdRng::seed_from_u64(44);
        let mut expected_rng = StdRng::seed_from_u64(44);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                key.encrypt_ggsw_constant_batch_to(
                    input,
                    &mut output,
                    &params,
                    &mut fft,
                    &mut rng,
                    &mut context,
                );
            }))
            .is_err()
        );
        assert!(output.iter().all(|&value| value == sentinel));
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }
}
