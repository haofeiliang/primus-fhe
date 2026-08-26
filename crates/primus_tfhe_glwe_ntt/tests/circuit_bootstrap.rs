use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GgswParameters, GlweParameters, NttGlweSecretKey, SecretKeyDistr};
use primus_lattice::{
    context::NttExternalProductContext,
    glwe::{Glwe, NttGlwe},
};
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U64NttTable};
use primus_poly::Polynomial;
use primus_tfhe_glwe_ntt::{
    CircuitBootstrapEvaluationError, CircuitBootstrapParameters, PbsOrder, TfheContext,
    TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

const POLY_LENGTH: usize = 256;
const MODULUS: u64 = 1_125_899_906_826_241;

fn parameters(
    order: PbsOrder,
) -> (
    TfheParameters<u64>,
    [GgswParameters<u64, BarrettModulus<u64>>; 3],
) {
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
    let bootstrapping = GgswParameters::with_glwe_params(&glwe, 10, Some(3));
    let output = GgswParameters::with_glwe_params(&glwe, 10, Some(2));
    let trace = GgswParameters::with_glwe_params(&glwe, 10, Some(3));
    let scheme_switch = GgswParameters::with_glwe_params(&glwe, 10, Some(3));
    let tfhe = TfheParameters::try_new(
        lwe,
        glwe,
        bootstrapping,
        ApproxSignedBasis::new(Some(MODULUS), 10, Some(4)),
        order,
    )
    .unwrap();
    (tfhe, [output, trace, scheme_switch])
}

fn constant_polynomial(value: u64) -> Vec<u64> {
    vec![value; POLY_LENGTH]
}

#[test]
fn patched_ntt_circuit_bootstrap_produces_a_cmux_control() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let (tfhe, [output, trace, scheme_switch]) = parameters(order);
        let circuit_parameters =
            CircuitBootstrapParameters::try_new(&tfhe, output, trace, scheme_switch).unwrap();
        let modulus = BarrettModulus::new(MODULUS);
        let table = U64NttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
        let context = TfheContext::try_new(tfhe, table).unwrap();
        let mut rng = StdRng::seed_from_u64(0x0050_4154_4348_4544 ^ order as u64);
        let (client_key, server_key) = context.generate_keys(&mut rng).unwrap();
        let circuit_key = context
            .generate_circuit_bootstrap_key(&client_key, &circuit_parameters, &mut rng)
            .unwrap();
        let incompatible_trace =
            GgswParameters::with_glwe_params(context.parameters().glwe(), 9, Some(3));
        let incompatible_parameters = CircuitBootstrapParameters::try_new(
            context.parameters(),
            circuit_parameters.output().clone(),
            incompatible_trace,
            circuit_parameters.scheme_switch().clone(),
        )
        .unwrap();
        assert!(matches!(
            context.circuit_bootstrap_evaluator(
                &server_key,
                &incompatible_parameters,
                &circuit_key,
            ),
            Err(CircuitBootstrapEvaluationError::IncompatibleCircuitBootstrapKey)
        ));
        let encryptor = context.encryptor(&client_key).unwrap();
        let mut evaluator = context
            .circuit_bootstrap_evaluator(&server_key, &circuit_parameters, &circuit_key)
            .unwrap();

        let main_secret =
            NttGlweSecretKey::from_coeff_secret_key(client_key.glwe_secret_key(), context.table());
        let glwe = context.parameters().glwe();
        let mut choices: [Glwe<Vec<u64>>; 2] =
            core::array::from_fn(|_| Glwe::zero(glwe.glwe_len()));
        for (value, choice) in [1u64, 3].into_iter().zip(&mut choices) {
            let mut encrypted: NttGlwe<Vec<u64>> = NttGlwe::zero(glwe.glwe_len());
            main_secret.encrypt_to(
                &Polynomial::new(constant_polynomial(value)),
                &mut encrypted,
                glwe,
                context.table(),
                &mut rng,
            );
            encrypted.write_coeff_form(choice, context.table());
        }

        for bit in 0..=1u64 {
            let input = encryptor.encrypt_padded(bit, &mut rng).unwrap();
            let control = evaluator.circuit_bootstrap(&input);
            let mut selected: Glwe<Vec<u64>> = Glwe::zero(glwe.glwe_len());
            let mut external_product =
                NttExternalProductContext::new(circuit_parameters.output().size());
            control.cmux_to(
                &choices[0],
                &choices[1],
                &mut selected,
                circuit_parameters.output().basis(),
                modulus,
                context.table(),
                &mut external_product,
            );
            let selected = selected.into_ntt_form(context.table());
            assert_eq!(
                main_secret
                    .decrypt(&selected, glwe, context.table())
                    .as_ref(),
                constant_polynomial(if bit == 0 { 1 } else { 3 }),
                "PBS order {order:?}, control bit {bit}"
            );
        }
    }
}
