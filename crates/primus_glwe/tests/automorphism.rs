use primus_fft::{FftEngine, FftTable, RustFftTable};
use primus_glwe::{
    FourierGadgetEncryptContext, FourierGlweAutomorphismContext, FourierGlweAutomorphismKey,
    FourierGlweSecretKey, GlevParameters, GlweParameters, GlweSecretKey, GlweSize,
    NttGadgetEncryptContext, NttGlweAutomorphismContext, NttGlweAutomorphismKey, NttGlweSecretKey,
    SecretKeyDistr,
};
use primus_lattice::glwe::{Glwe, NttGlwe};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntt::{NttTable, U64NttTable};
use primus_poly::Polynomial;
use rand::{SeedableRng, rngs::StdRng};

mod common;
use common::{K, N, assert_phase, encrypt, message, secret};

const POLY_LENGTH: usize = 256;
const DIMENSION: usize = 2;
const PLAINTEXT_MODULUS: u64 = 16;
const MODULUS: u64 = 1_125_899_906_826_241;

fn automorphism_plaintext(input: &[u64], degree: usize) -> Vec<u64> {
    let mut output = vec![0; input.len()];
    for (source, &value) in input.iter().enumerate() {
        let mapped = source * degree % (2 * input.len());
        if mapped < input.len() {
            output[mapped] = value;
        } else {
            output[mapped - input.len()] = (PLAINTEXT_MODULUS - value) % PLAINTEXT_MODULUS;
        }
    }
    output
}

#[test]
fn ntt_and_coefficient_inputs_reuse_the_automorphism_key() {
    let modulus = BarrettModulus::new(MODULUS);
    let ntt = U64NttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let glwe_parameters = GlweParameters::new(
        DIMENSION,
        POLY_LENGTH,
        PLAINTEXT_MODULUS,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let glev_parameters = GlevParameters::with_glwe_params(&glwe_parameters, 10, Some(3));
    let mut rng = StdRng::seed_from_u64(0x0043_4253_5052_494d);
    let (coefficient_secret, secret) =
        NttGlweSecretKey::generate_pair(&glwe_parameters, &ntt, &mut rng);
    let mut gadget = NttGadgetEncryptContext::new(glev_parameters.size());

    let automorphism_key = NttGlweAutomorphismKey::generate(
        3,
        &coefficient_secret,
        &secret,
        &glev_parameters,
        &ntt,
        &mut rng,
        &mut gadget,
    );
    let message: Vec<u64> = (0..POLY_LENGTH)
        .map(|index| (3 * index as u64 + 1) % PLAINTEXT_MODULUS)
        .collect();
    let mut encrypted: NttGlwe<Vec<u64>> = NttGlwe::zero(glwe_parameters.glwe_len());
    secret.encrypt_to(
        &Polynomial::new(message.as_slice()),
        &mut encrypted,
        &glwe_parameters,
        &ntt,
        &mut rng,
    );
    let coefficient_encrypted = encrypted.clone().into_coeff_form(&ntt);
    let mut automated: Glwe<Vec<u64>> = Glwe::zero(glwe_parameters.glwe_len());
    let mut automorphism_context = NttGlweAutomorphismContext::new(glwe_parameters.size());
    automorphism_key.apply_to(
        &coefficient_encrypted,
        &mut automated,
        modulus,
        &ntt,
        &mut automorphism_context,
    );
    let automated = automated.into_ntt_form(&ntt);
    let expected_automorphism = automorphism_plaintext(&message, 3);
    assert_eq!(
        secret.decrypt(&automated, &glwe_parameters, &ntt).as_ref(),
        expected_automorphism
    );

    let mut automated_ntt: NttGlwe<Vec<u64>> = NttGlwe::zero(glwe_parameters.glwe_len());
    automorphism_key.apply_ntt_to(
        &encrypted,
        &mut automated_ntt,
        modulus,
        &ntt,
        &mut automorphism_context,
    );
    assert_eq!(automated_ntt.as_ref(), automated.as_ref());

    // Layout validation includes a different N with the same total GLWE length.
    for size in [
        GlweSize::new(5, POLY_LENGTH / 2),
        GlweSize::new(3, POLY_LENGTH),
    ] {
        let mut context = NttGlweAutomorphismContext::new(size);
        let mut output = Glwe::new(vec![7; glwe_parameters.glwe_len()]);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                automorphism_key.apply_to(
                    &coefficient_encrypted,
                    &mut output,
                    modulus,
                    &ntt,
                    &mut context,
                );
            }))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&value| value == 7));
    }
}

fn fourier_automorphism_input<Table: FftTable>() {
    use primus_fft::Complex64;
    use primus_lattice::glwe::FourierGlwe;
    let table = Table::new(N.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    let size = GlweSize::new(K, N);
    let params = GlweParameters::new(
        K,
        N,
        64,
        NativeModulus::new(),
        SecretKeyDistr::UniformTernary,
        0.7,
    );
    let glev = GlevParameters::with_glwe_params(&params, 8, Some(7));
    let s = secret();
    let coeff = GlweSecretKey::<u64>::new(s.clone(), size, SecretKeyDistr::UniformTernary);
    let sk = FourierGlweSecretKey::from_coeff_secret_key(&coeff, &mut fft);
    let mut rng = StdRng::seed_from_u64(0x4646544155544f);
    let mut gadget = FourierGadgetEncryptContext::new(glev.size());
    let mut context = FourierGlweAutomorphismContext::new(size);
    let q = 1u128 << 64;
    let m = message(q);
    let input = encrypt(&m, &s, q, &mut rng);
    let mut fourier_input = FourierGlwe::<Vec<Complex64>>::zero(size.fourier_glwe_len());
    input.write_fourier_form(&mut fourier_input, &mut fft);
    let mut fourier_output = fourier_input.clone();
    let mut output = Glwe::new(vec![0; size.glwe_len()]);
    for degree in [1, 3, N + 1, 2 * N - 1] {
        let key = FourierGlweAutomorphismKey::generate(
            degree,
            &coeff,
            &sk,
            &glev,
            &mut fft,
            &mut rng,
            &mut gadget,
        );
        let mut expected = vec![0; N];
        for (i, &value) in m.iter().enumerate() {
            let dest = i * degree % (2 * N);
            expected[dest % N] = if dest < N {
                value
            } else {
                value.wrapping_neg()
            };
        }
        key.apply_to(&input, &mut output, &mut fft, &mut context);
        assert_phase(output.as_ref(), &expected, &s, q);
        key.apply_fourier_to(&fourier_input, &mut fourier_output, &mut fft, &mut context);
        fourier_output.write_torus_form(&mut output, &mut fft);
        assert_phase(output.as_ref(), &expected, &s, q);
        // A different N with the same total storage must fail before output writes.
        let mut wrong_context = FourierGlweAutomorphismContext::new(GlweSize::new(5, N / 2));
        fourier_output.as_mut().fill(Complex64::new(7.0, 0.0));
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                key.apply_fourier_to(
                    &fourier_input,
                    &mut fourier_output,
                    &mut fft,
                    &mut wrong_context,
                );
            }))
            .is_err()
        );
        assert!(
            fourier_output
                .as_ref()
                .iter()
                .all(|&v| v == Complex64::new(7.0, 0.0))
        );
    }
}

#[test]
fn fourier_and_coefficient_inputs_reuse_the_automorphism_key() {
    fourier_automorphism_input::<RustFftTable>();
    fourier_automorphism_input::<primus_fft::TfheFftTable>();
}
