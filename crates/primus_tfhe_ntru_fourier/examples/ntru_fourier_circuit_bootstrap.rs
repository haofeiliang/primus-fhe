//! NTRU/Fourier circuit bootstrapping followed by CMUX.
//!
//! Fixed seed and small functional parameters for demonstration only. CBS noise
//! and secret-dependent-message security require a separate production assessment.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftTable, RustFftTable};
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_ntru::{
    FourierNgswCiphertext, FourierNtruCiphertext, FourierNtruExternalProductContext,
    FourierNtruSecretKey, NlevParameters, NtruCiphertext, NtruParameters, SecretKeyDistr,
};
use primus_poly::Polynomial;
use primus_tfhe_ntru_fourier::{CircuitBootstrapParameters, NtruTfheParameters, TfheContext};
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 256;

fn main() {
    let modulus = NativeModulus::<u64>::new();
    let lwe = LweParameters::new(16, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let accumulator = NtruParameters::new(N, 4, modulus, SecretKeyDistr::SparseTernary, 0.7);
    let client_parameters = NtruParameters::new(N, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let tfhe = NtruTfheParameters::try_new(
        lwe,
        NlevParameters::with_ntru_params(&accumulator, 10, None),
        NlevParameters::with_ntru_params(&client_parameters, 10, None),
    )
    .unwrap();
    let context =
        TfheContext::try_new(tfhe, RustFftTable::new(N.trailing_zeros()).unwrap()).unwrap();
    let mut rng = StdRng::seed_from_u64(0x004e_5454_5f43_4253);
    let (client_key, server_key) = context.generate_keys(&mut rng).unwrap();
    // All transformed values share this context's FFT table.
    let mut fft = context.new_fft_engine();
    // CMUX candidates are encrypted under f_acc, the CBS output secret.
    let accumulator_key = FourierNtruSecretKey::try_from_coeff_secret_key(
        client_key.accumulator_ntru_secret_key(),
        &mut fft,
    )
    .unwrap();
    let mut encrypt = primus_ntru::FourierNtruEncryptContext::new(N);
    let mut decrypt = primus_ntru::FourierNtruDecryptContext::new(N);
    let encryptor = context.encryptor(&client_key).unwrap();
    let choices = [1, 3].map(|message| {
        let transformed = accumulator_key.encrypt(
            &Polynomial::new(vec![message; N]),
            &accumulator,
            &mut fft,
            &mut rng,
            &mut encrypt,
        );
        let mut output = NtruCiphertext::<Vec<u64>>::zero(N);
        transformed.write_torus_form(&mut output, &mut fft);
        output
    });
    // CBS adds independent output, trace and scheme-switch bases.
    let output_basis = ApproxSignedBasis::new(None, 8, Some(2));
    let cbs_parameters = CircuitBootstrapParameters::try_new(
        context.parameters(),
        output_basis,
        NlevParameters::with_ntru_params(&accumulator, 10, None),
        NlevParameters::with_ntru_params(&accumulator, 10, None),
    )
    .unwrap();
    let cbs_key = context
        .generate_circuit_bootstrap_key(&client_key, &cbs_parameters, &mut rng)
        .unwrap();
    let mut evaluator = context
        .circuit_bootstrap_evaluator(&server_key, &cbs_parameters, &cbs_key)
        .unwrap();
    let mut control =
        FourierNgswCiphertext::<Vec<Complex64>>::zero(cbs_parameters.output_fourier_nlev_len());
    let mut selected = NtruCiphertext::<Vec<u64>>::zero(N);
    let mut transformed = FourierNtruCiphertext::<Vec<Complex64>>::zero(N / 2);
    let mut scratch = FourierNtruExternalProductContext::new(N);
    let mut input =
        primus_tfhe::LweCiphertext::zero(context.parameters().external_lwe().dimension());
    for bit in [0u64, 1, 0] {
        encryptor
            .encrypt_padded_to(bit, &mut input, &mut rng)
            .unwrap();
        // Server-side: ordinary LWE bit -> gadget-scaled NGSW -> selected NTRU.
        evaluator.circuit_bootstrap_to(&input, &mut control);
        control.cmux_to(
            &choices[0],
            &choices[1],
            &mut selected,
            cbs_parameters.output_basis(),
            &mut fft,
            &mut scratch,
        );
        // Client-side verification in the transform representation.
        selected.write_fourier_form(&mut transformed, &mut fft);
        assert_eq!(
            accumulator_key
                .decrypt(&transformed, &accumulator, &mut fft, &mut decrypt)
                .as_ref(),
            &[if bit == 0 { 1 } else { 3 }; N]
        );
    }
    println!("CBS -> CMUX selected 1, 3, 1");
}
