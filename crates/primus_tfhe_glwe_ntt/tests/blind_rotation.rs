use primus_glwe::{
    GlevParameters, GlweParameters, GlweSecretKey, NttGadgetDomain, NttGadgetEncryptContext,
    NttGlweSecretKey, SecretKeyDistr,
};
use primus_lattice::{
    glwe::{Glwe, NttGlwe},
    lwe::Lwe,
};
use primus_lwe::{LweParameters, LweSecretKey};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
use primus_tfhe_glwe_ntt::{NttBlindRotationContext, NttFunctionalBootstrappingKey};

const LWE_DIMENSION: usize = 4;
const GLWE_DIMENSION: usize = 1;
const POLY_LENGTH: usize = 256;
const PLAINTEXT_MODULUS: u32 = 16;
const TWO_N: usize = 2 * POLY_LENGTH;

fn accumulator_message() -> Vec<u32> {
    (0..POLY_LENGTH)
        .map(|index| (3 * index as u32 + 1) % PLAINTEXT_MODULUS)
        .collect()
}

fn rotate_plaintext(input: &[u32], exponent: usize) -> Vec<u32> {
    let shift = exponent & (POLY_LENGTH - 1);
    let negate_rotation = exponent >= POLY_LENGTH;
    (0..POLY_LENGTH)
        .map(|destination| {
            let wraps = destination < shift;
            let source = destination.wrapping_sub(shift) & (POLY_LENGTH - 1);
            let value = input[source];
            if wraps ^ negate_rotation {
                (PLAINTEXT_MODULUS - value) % PLAINTEXT_MODULUS
            } else {
                value
            }
        })
        .collect()
}

#[test]
fn functional_bootstrapping_key_blind_rotates() {
    const MODULUS: u32 = 132_120_577;

    let modulus = BarrettModulus::new(MODULUS);
    let ntt = UintNttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let mut rng = rand::rng();
    let lwe_params = LweParameters::new(
        LWE_DIMENSION,
        PLAINTEXT_MODULUS,
        modulus,
        SecretKeyDistr::Binary,
        0.7,
    );
    let glwe_params = GlweParameters::new(
        GLWE_DIMENSION,
        POLY_LENGTH,
        PLAINTEXT_MODULUS,
        modulus,
        SecretKeyDistr::Ternary,
        0.7,
    );
    let ggsw_params = GlevParameters::with_glwe_params(&glwe_params, 8, None);
    let domain = NttGadgetDomain::try_new(&ggsw_params, &ntt).unwrap();
    let input_secret_key = LweSecretKey::new(vec![1u32, 0, 1, 1], SecretKeyDistr::Binary);
    let coeff_output_secret_key = GlweSecretKey::generate(&glwe_params, &mut rng);
    let output_secret_key = NttGlweSecretKey::from_coeff_secret_key(&coeff_output_secret_key, &ntt);
    let mut gadget_context = NttGadgetEncryptContext::new(domain.size());
    let key = NttFunctionalBootstrappingKey::generate_ntt(
        &input_secret_key,
        &lwe_params,
        &output_secret_key,
        &domain,
        &mut rng,
        &mut gadget_context,
    );

    let switched_a = [3usize, 0, 7, 11];
    let switched_b = 23usize;
    let encode_exponent =
        |value: usize| ((value as u64 * MODULUS as u64 + (TWO_N / 2) as u64) / TWO_N as u64) as u32;
    let mut lwe_data: Vec<u32> = switched_a
        .iter()
        .map(|&value| encode_exponent(value))
        .collect();
    lwe_data.push(encode_exponent(switched_b));
    let input = Lwe::new(lwe_data);

    let message = accumulator_message();
    let mut accumulator_ntt: NttGlwe<Vec<u32>> = NttGlwe::zero(ggsw_params.glwe_len());
    output_secret_key.encrypt_to(
        &Polynomial::new(message.as_slice()),
        &mut accumulator_ntt,
        &glwe_params,
        &ntt,
        &mut rng,
    );
    let accumulator = accumulator_ntt.into_coeff_form(&ntt);

    let mut output: Glwe<Vec<u32>> = Glwe::zero(ggsw_params.glwe_len());
    let mut blind_rotation_context = NttBlindRotationContext::new(domain.size());
    key.ntt_blind_rotate_to(
        &input,
        &accumulator,
        &mut output,
        &domain,
        &mut blind_rotation_context,
    );

    let expected_exponent = (TWO_N + 3 + 7 + 11 - switched_b) & (TWO_N - 1);
    let output_ntt = output.into_ntt_form(&ntt);
    assert_eq!(
        output_secret_key
            .decrypt(&output_ntt, &glwe_params, &ntt)
            .as_ref(),
        rotate_plaintext(&message, expected_exponent)
    );

    let exponent_input = Lwe::new(vec![3u32, 0, 7, 11, 23]);
    let mut direct_output: Glwe<Vec<u32>> = Glwe::zero(ggsw_params.glwe_len());
    key.ntt_blind_rotate_exponents_to(
        &exponent_input,
        &accumulator,
        &mut direct_output,
        &domain,
        &mut blind_rotation_context,
    );
    let direct_output_ntt = direct_output.into_ntt_form(&ntt);
    assert_eq!(
        output_secret_key
            .decrypt(&direct_output_ntt, &glwe_params, &ntt)
            .as_ref(),
        rotate_plaintext(&message, expected_exponent)
    );
}
