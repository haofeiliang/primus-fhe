use primus_glwe::{
    GlevParameters, GlweParameters, GlweSecretKey, NttGadgetEncryptContext, NttGlweSecretKey,
    SecretKeyDistr,
};
use primus_lattice::{
    glwe::{Glwe, NttGlwe},
    lwe::Lwe,
};
use primus_lwe::{LweParameters, LweSecretKey};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
use primus_tfhe_glwe_ntt::{NttGlweBlindRotationContext, NttGlweBootstrappingKey};
use rand::{SeedableRng, rngs::StdRng};

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
    let mut rng = StdRng::seed_from_u64(42);
    // Input quantization uses a different modulus from the accumulator.
    let lwe_params = LweParameters::new(
        LWE_DIMENSION,
        PLAINTEXT_MODULUS,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let glwe_params = GlweParameters::new(
        GLWE_DIMENSION,
        POLY_LENGTH,
        PLAINTEXT_MODULUS,
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let ggsw_params = GlevParameters::with_glwe_params(&glwe_params, 8, None);
    let input_secret_key = LweSecretKey::new(vec![1u32, 0, 1, 1], SecretKeyDistr::UniformBinary);
    let coeff_output_secret_key = GlweSecretKey::generate(
        glwe_params.size(),
        glwe_params.secret_key_sampler(),
        &mut rng,
    );
    let output_secret_key = NttGlweSecretKey::from_coeff_secret_key(&coeff_output_secret_key, &ntt);
    let mut gadget_context = NttGadgetEncryptContext::new(ggsw_params.size());
    let key = NttGlweBootstrappingKey::generate_ntt(
        &input_secret_key,
        &lwe_params,
        &output_secret_key,
        &ggsw_params,
        &ntt,
        &mut rng,
        &mut gadget_context,
    );

    let switched_a = [3usize, 0, 7, 11];
    let switched_b = 23usize;
    let encode_exponent =
        |value: usize| ((value as u64 * (1u64 << 32) + (TWO_N / 2) as u64) / TWO_N as u64) as u32;
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
    let mut blind_rotation_context = NttGlweBlindRotationContext::new(ggsw_params.size());
    key.ntt_blind_rotate_to(
        &input,
        &accumulator,
        &mut output,
        modulus,
        &ntt,
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
        modulus,
        &ntt,
        &mut blind_rotation_context,
    );
    let direct_output_ntt = direct_output.into_ntt_form(&ntt);
    assert_eq!(
        output_secret_key
            .decrypt(&direct_output_ntt, &glwe_params, &ntt)
            .as_ref(),
        rotate_plaintext(&message, expected_exponent)
    );

    // Resource validation must precede accumulator initialization, including LUT paths.
    let wrong_modulus = BarrettModulus::new(998_244_353u32);
    let wrong_modulus_table =
        UintNttTable::new(POLY_LENGTH.trailing_zeros(), wrong_modulus).unwrap();
    let wrong_length_table =
        UintNttTable::new((POLY_LENGTH * 2).trailing_zeros(), modulus).unwrap();
    let lookup_table = Polynomial::new(message.as_slice());
    for (modulus, table, size) in [
        (modulus, &wrong_modulus_table, ggsw_params.size()),
        (wrong_modulus, &wrong_modulus_table, ggsw_params.size()),
        (modulus, &wrong_length_table, ggsw_params.size()),
        (
            modulus,
            &ntt,
            primus_glwe::GadgetSize::new(glwe_params.size(), ggsw_params.decompose_length() + 1),
        ),
    ] {
        blind_rotation_context.resize(size);
        for path in 0..4 {
            let mut output = Glwe::new(vec![7u32; ggsw_params.glwe_len()]);
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    match path {
                        0 => key.ntt_blind_rotate_to(
                            &input,
                            &accumulator,
                            &mut output,
                            modulus,
                            table,
                            &mut blind_rotation_context,
                        ),
                        1 => key.ntt_blind_rotate_exponents_to(
                            &exponent_input,
                            &accumulator,
                            &mut output,
                            modulus,
                            table,
                            &mut blind_rotation_context,
                        ),
                        2 => key.ntt_blind_rotate_lookup_table_to(
                            &input,
                            &lookup_table,
                            &mut output,
                            modulus,
                            table,
                            &mut blind_rotation_context,
                        ),
                        _ => key.ntt_blind_rotate_interleaved_lookup_table_to(
                            &input,
                            &lookup_table,
                            1,
                            &mut output,
                            modulus,
                            table,
                            &mut blind_rotation_context,
                        ),
                    }
                }))
                .is_err()
            );
            assert_eq!(output.as_ref(), vec![7u32; ggsw_params.glwe_len()]);
        }
    }
    // Per-call layout checks belong to each public raw LUT API, even when
    // the transform and workspace already match the key.
    blind_rotation_context.resize(ggsw_params.size());
    let input_len = LWE_DIMENSION + 1;
    let glwe_len = ggsw_params.glwe_len();
    for (input_len, lookup_len, output_len, stride) in [
        (input_len - 1, POLY_LENGTH, glwe_len, None),
        (input_len, POLY_LENGTH - 1, glwe_len, None),
        (input_len, POLY_LENGTH, glwe_len - 1, None),
        (input_len - 1, POLY_LENGTH, glwe_len, Some(2)),
        (input_len, POLY_LENGTH - 1, glwe_len, Some(2)),
        (input_len, POLY_LENGTH, glwe_len - 1, Some(2)),
        (input_len, POLY_LENGTH, glwe_len, Some(0)),
        (input_len, POLY_LENGTH, glwe_len, Some(3)),
        (input_len, POLY_LENGTH, glwe_len, Some(POLY_LENGTH * 2)),
    ] {
        let input = Lwe::new(vec![0u32; input_len]);
        let lookup = Polynomial::<Vec<u32>>::zero(lookup_len);
        let mut output = Glwe::new(vec![17u32; output_len]);
        let before = output.as_ref().to_vec();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if let Some(stride) = stride {
                    key.ntt_blind_rotate_interleaved_lookup_table_to(
                        &input,
                        &lookup,
                        stride,
                        &mut output,
                        modulus,
                        &ntt,
                        &mut blind_rotation_context,
                    );
                } else {
                    key.ntt_blind_rotate_lookup_table_to(
                        &input,
                        &lookup,
                        &mut output,
                        modulus,
                        &ntt,
                        &mut blind_rotation_context,
                    );
                }
            }))
            .is_err()
        );
        assert_eq!(output.as_ref(), before);
    }
}
