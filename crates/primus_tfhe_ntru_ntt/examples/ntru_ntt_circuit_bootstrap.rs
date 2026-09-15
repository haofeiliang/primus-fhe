//! NTRU/NTT circuit bootstrapping followed by CMUX.
//!
//! Fixed seed and small functional parameters for demonstration only. CBS noise
//! and secret-dependent-message security require a separate production assessment.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntru::{
    NlevParameters, NtruCiphertext, NtruParameters, NttNgswCiphertext, NttNtruCiphertext,
    NttNtruExternalProductContext, NttNtruSecretKey, SecretKeyDistr,
};
use primus_ntt::{NttTable, U64NttTable};
use primus_poly::Polynomial;
use primus_tfhe_ntru_ntt::{CircuitBootstrapParameters, NtruTfheParameters, TfheContext};
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 256;
const Q: u64 = 1_125_899_906_826_241;

fn main() {
    let modulus = BarrettModulus::new(Q);
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
        TfheContext::try_new(tfhe, U64NttTable::new(N.trailing_zeros(), modulus).unwrap()).unwrap();
    let mut rng = StdRng::seed_from_u64(0x004e_5454_5f43_4253);
    let (client_key, server_key) = context.generate_keys(&mut rng).unwrap();
    // CMUX candidates are encrypted under f_acc, the CBS output secret.
    let accumulator_key = NttNtruSecretKey::try_from_coeff_secret_key(
        client_key.accumulator_ntru_secret_key(),
        modulus,
        context.table(),
    )
    .unwrap();
    let encryptor = context.encryptor(&client_key).unwrap();
    let choices = [1, 3].map(|message| {
        let transformed = accumulator_key.encrypt(
            &Polynomial::new(vec![message; N]),
            &accumulator,
            context.table(),
            &mut rng,
        );
        let mut output = NtruCiphertext::<Vec<u64>>::zero(N);
        transformed.write_coeff_form(&mut output, context.table());
        output
    });
    // CBS adds independent output, trace and scheme-switch bases.
    let output_basis = ApproxSignedBasis::new(Some(Q), 8, Some(2));
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
    let mut control = NttNgswCiphertext::<Vec<u64>>::zero(cbs_parameters.output_nlev_len());
    let mut selected = NtruCiphertext::<Vec<u64>>::zero(N);
    let mut transformed = NttNtruCiphertext::<Vec<u64>>::zero(N);
    let mut scratch = NttNtruExternalProductContext::new(N);
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
            modulus,
            context.table(),
            &mut scratch,
        );
        // Client-side verification in the transform representation.
        selected.write_ntt_form(&mut transformed, context.table());
        assert_eq!(
            accumulator_key
                .decrypt(&transformed, &accumulator, context.table())
                .as_ref(),
            &[if bit == 0 { 1 } else { 3 }; N]
        );
    }
    println!("CBS -> CMUX selected 1, 3, 1");
}
