use primus_decompose::primitive::ApproxSignedBasis;
use primus_fhe_core::{
    GgswParameters, GlweParameters, LweParameters, LweSecretKeyType, RingSecretKeyType,
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable};
use primus_tfhe_glwe_ntt::{
    BooleanDecryptor, BooleanEncryptor, BooleanGate, KeyGenerator, TfheContext, TfheParameters,
};

const POLY_LENGTH: usize = 256;
const MODULUS: u32 = 132_120_577;

fn parameters() -> TfheParameters<u32> {
    let modulus = BarrettModulus::new(MODULUS);
    let lwe = LweParameters::new(4, 4, modulus, LweSecretKeyType::Binary, 0.7);
    let glwe = GlweParameters::new(1, POLY_LENGTH, 4, modulus, RingSecretKeyType::Binary, 0.7);
    let bootstrapping =
        GgswParameters::with_glwe_params(&glwe, ApproxSignedBasis::new(Some(MODULUS), 8, Some(3)));
    TfheParameters::with_key_switching_basis(
        lwe,
        glwe,
        bootstrapping,
        ApproxSignedBasis::new(Some(MODULUS), 4, Some(4)),
    )
    .unwrap()
}

#[test]
fn evaluates_boolean_truth_tables_and_a_deep_circuit() {
    let modulus = BarrettModulus::new(MODULUS);
    let table = U32NttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let context = TfheContext::try_new(parameters(), table).unwrap();
    let mut rng = rand::rng();
    let mut generator = KeyGenerator::new(&context);
    let (client_key, server_key) = generator.generate(&mut rng).unwrap();
    let encryptor = BooleanEncryptor::new(context.parameters(), &client_key).unwrap();
    let decryptor = BooleanDecryptor::new(context.parameters(), &client_key).unwrap();
    let mut evaluator = context.new_boolean_evaluator(&server_key).unwrap();

    for _ in 0..64 {
        for lhs in [false, true] {
            for rhs in [false, true] {
                let lhs_ciphertext = encryptor.encrypt(lhs, &mut rng).unwrap();
                let rhs_ciphertext = encryptor.encrypt(rhs, &mut rng).unwrap();
                for (gate, expected) in [
                    (BooleanGate::And, lhs & rhs),
                    (BooleanGate::Nand, !(lhs & rhs)),
                    (BooleanGate::Or, lhs | rhs),
                    (BooleanGate::Nor, !(lhs | rhs)),
                    (BooleanGate::Xor, lhs ^ rhs),
                    (BooleanGate::Xnor, !(lhs ^ rhs)),
                ] {
                    let output = evaluator
                        .evaluate_binary(gate, &lhs_ciphertext, &rhs_ciphertext)
                        .unwrap();
                    assert_eq!(decryptor.decrypt(&output).unwrap(), expected, "{gate:?}");
                }

                let output = evaluator.not(&lhs_ciphertext).unwrap();
                assert_eq!(decryptor.decrypt(&output).unwrap(), !lhs);
            }
        }
    }

    for condition in [false, true] {
        for then_value in [false, true] {
            for else_value in [false, true] {
                let condition_ciphertext = encryptor.encrypt(condition, &mut rng).unwrap();
                let then_ciphertext = encryptor.encrypt(then_value, &mut rng).unwrap();
                let else_ciphertext = encryptor.encrypt(else_value, &mut rng).unwrap();
                let output = evaluator
                    .mux(&condition_ciphertext, &then_ciphertext, &else_ciphertext)
                    .unwrap();
                assert_eq!(
                    decryptor.decrypt(&output).unwrap(),
                    if condition { then_value } else { else_value }
                );
            }
        }
    }

    let true_ciphertext = encryptor.encrypt(true, &mut rng).unwrap();
    let mut current = encryptor.encrypt(false, &mut rng).unwrap();
    let mut next = current.clone();
    for _ in 0..16 {
        evaluator
            .evaluate_binary_to(BooleanGate::Nand, &current, &true_ciphertext, &mut next)
            .unwrap();
        core::mem::swap(&mut current, &mut next);
    }
    assert!(!decryptor.decrypt(&current).unwrap());
}
