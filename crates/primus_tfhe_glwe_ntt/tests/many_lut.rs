use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GgswParameters, GlweParameters, SecretKeyDistr};
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable};
use primus_tfhe_glwe_ntt::{LookupTableError, PbsOrder, TfheContext, TfheParameters};
use rand::{SeedableRng, rngs::StdRng};

const POLY_LENGTH: usize = 256;
const MODULUS: u32 = 132_120_577;

fn parameters(order: PbsOrder) -> TfheParameters<u32> {
    let modulus = BarrettModulus::new(MODULUS);
    let lwe = LweParameters::new(4, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let glwe = GlweParameters::new(
        1,
        POLY_LENGTH,
        4,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let bootstrapping = GgswParameters::with_glwe_params(&glwe, 8, Some(3));
    TfheParameters::try_new(
        lwe,
        glwe,
        bootstrapping,
        ApproxSignedBasis::new(Some(MODULUS), 4, Some(4)),
        order,
    )
    .unwrap()
}

#[test]
fn one_blind_rotation_evaluates_four_lookup_tables_in_both_orders() {
    let functions: [fn(usize) -> usize; 4] = [
        |value| value,
        |value| 1 - value,
        |value| value + 1,
        |_value| 3,
    ];

    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let modulus = BarrettModulus::new(MODULUS);
        let table = U32NttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
        let context = TfheContext::try_new(parameters(order), table).unwrap();
        let many_lut = context
            .compile_many_lookup_table_fn(4, |input, output| functions[output](input) as u32)
            .unwrap();
        let mut rng = StdRng::seed_from_u64(0x004d_414e_594c_5554);
        let (client_key, server_key) = context.generate_keys(&mut rng).unwrap();
        let encryptor = context.encryptor(&client_key).unwrap();
        let decryptor = context.decryptor(&client_key).unwrap();
        let mut evaluator = context.evaluator(&server_key).unwrap();

        for input_value in 0..2 {
            let input = encryptor
                .encrypt_padded(input_value as u32, &mut rng)
                .unwrap();
            let outputs = if input_value == 0 {
                evaluator.apply_many_lookup_table(&input, &many_lut)
            } else {
                let mut outputs = vec![input.clone(); many_lut.output_count()];
                evaluator.apply_many_lookup_table_to(&input, &many_lut, &mut outputs);
                outputs
            };

            let actual: Vec<u32> = outputs
                .iter()
                .map(|output| decryptor.decrypt(output).unwrap())
                .collect();
            let expected: Vec<u32> = functions
                .iter()
                .map(|function| function(input_value) as u32)
                .collect();
            assert_eq!(actual, expected, "PBS order {order:?}, input {input_value}");
        }
    }
}

#[test]
fn many_lookup_table_compilation_rejects_invalid_layouts() {
    let modulus = BarrettModulus::new(MODULUS);
    let table = U32NttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let context = TfheContext::try_new(parameters(PbsOrder::BootstrapKeyswitch), table).unwrap();

    assert!(matches!(
        context.compile_many_lookup_table_fn(3, |_input, _output| 0),
        Err(LookupTableError::OutputCountMustBePowerOfTwo { output_count: 3 })
    ));
    assert!(matches!(
        context.compile_many_lookup_table_fn(POLY_LENGTH, |_input, _output| 0),
        Err(LookupTableError::PlaintextDomainTooLarge { .. })
    ));
    assert!(matches!(
        context.compile_many_lookup_table_slice(usize::MAX, &[]),
        Err(LookupTableError::ManyTableLengthOverflow)
    ));
}
