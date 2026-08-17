use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, RustFftTable};
use primus_glwe::{GgswParameters, GlweParameters, SecretKeyDistr};
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_tfhe_glwe_fourier::{PbsOrder, TfheContext, TfheContextError, TfheParameters};

const POLY_LENGTH: usize = 256;

fn parameters(order: PbsOrder) -> TfheParameters<u32> {
    let lwe = LweParameters::new(
        4,
        4,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let glwe = GlweParameters::new(
        1,
        POLY_LENGTH,
        4,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let bootstrapping = GgswParameters::with_glwe_params(&glwe, 8, Some(3));
    TfheParameters::try_new(
        lwe,
        glwe,
        bootstrapping,
        ApproxSignedBasis::new(None, 4, Some(4)),
        order,
    )
    .unwrap()
}

#[test]
fn rejects_a_fourier_table_with_the_wrong_length() {
    let table = RustFftTable::new((POLY_LENGTH * 2).trailing_zeros()).unwrap();
    let error = TfheContext::try_new(parameters(PbsOrder::BootstrapKeyswitch), table)
        .err()
        .expect("the mismatched table must be rejected");

    assert_eq!(
        error,
        TfheContextError::PolynomialLengthMismatch {
            expected: POLY_LENGTH,
            actual: POLY_LENGTH * 2,
        }
    );
}

#[test]
fn evaluates_both_programmable_bootstrap_orders() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
        let context = TfheContext::try_new(parameters(order), table).unwrap();
        let mut rng = rand::rng();
        let (client_key, server_key) = context.generate_keys(&mut rng).unwrap();
        let encryptor = context.encryptor(&client_key).unwrap();
        let decryptor = context.decryptor(&client_key).unwrap();
        let lookup_table = context.compile_lookup_table_slice(&[1u32, 0]).unwrap();
        let mut evaluator = context.evaluator(&server_key).unwrap();

        let input = encryptor.encrypt_padded(0u32, &mut rng).unwrap();
        let output = evaluator.apply_lookup_table(&input, &lookup_table);
        assert_eq!(decryptor.decrypt::<u32>(&output).unwrap(), 1);
    }
}
