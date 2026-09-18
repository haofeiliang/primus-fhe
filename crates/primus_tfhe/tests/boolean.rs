use primus_encoding::RoundedCodec;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_tfhe::{
    BooleanEvaluator, LookupTable, LweCiphertext, ProgrammableBootstrap, TfheEvaluationError,
};

struct UnusedBootstrap;

impl ProgrammableBootstrap<u32> for UnusedBootstrap {
    fn apply_lookup_table_to(
        &mut self,
        _: &LweCiphertext<u32>,
        _: &LookupTable<u32>,
        _: &mut LweCiphertext<u32>,
    ) {
        panic!("constructor must not invoke PBS");
    }
}

#[test]
fn boolean_constructor_checks_both_encoding_scales() {
    // An ordinary t=4 codec can be valid even when q cannot represent t=8.
    for (t, input_q, accumulator_q) in [(8, 257, 257), (4, 7, 257), (4, 257, 7)] {
        let codec = RoundedCodec::new(t, BarrettModulus::new(input_q));
        assert_eq!(
            BooleanEvaluator::try_new(
                3,
                16,
                &codec,
                BarrettModulus::new(accumulator_q),
                UnusedBootstrap
            )
            .err(),
            Some(TfheEvaluationError::InvalidBooleanEncoding),
        );
    }
    let codec = RoundedCodec::new(4, NativeModulus::new());
    assert!(matches!(
        BooleanEvaluator::try_new(3, 1, &codec, NativeModulus::new(), UnusedBootstrap),
        Err(TfheEvaluationError::LookupTable(_))
    ));
}
