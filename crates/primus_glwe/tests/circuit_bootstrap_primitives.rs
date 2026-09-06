use primus_glwe::{
    GlevParameters, GlweParameters, GlweSecretKey, NttGadgetDomain, NttGadgetEncryptContext,
    NttGlweAutomorphismContext, NttGlweAutomorphismKey, NttGlweSchemeSwitchContext,
    NttGlweSchemeSwitchKey, NttGlweSecretKey, NttGlweTraceContext, NttGlweTraceKey, SecretKeyDistr,
};
use primus_lattice::{
    context::NttGlweExternalProductContext,
    ggsw::NttGgsw,
    glev::NttGlev,
    glwe::{Glwe, NttGlwe},
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U64NttTable};
use primus_poly::Polynomial;
use primus_reduce::ReduceMul;
use rand::{SeedableRng, rngs::StdRng};

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
fn ntt_automorphism_trace_and_scheme_switch_have_expected_semantics() {
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
    let output_parameters = GlevParameters::with_glwe_params(&glwe_parameters, 10, Some(2));
    let trace_parameters = GlevParameters::with_glwe_params(&glwe_parameters, 10, Some(3));
    let scheme_parameters = GlevParameters::with_glwe_params(&glwe_parameters, 10, Some(3));
    let output_domain = NttGadgetDomain::try_new(&output_parameters, &ntt).unwrap();
    let trace_domain = NttGadgetDomain::try_new(&trace_parameters, &ntt).unwrap();
    let scheme_domain = NttGadgetDomain::try_new(&scheme_parameters, &ntt).unwrap();
    let mut rng = StdRng::seed_from_u64(0x0043_4253_5052_494d);
    let coefficient_secret = GlweSecretKey::generate(&glwe_parameters, &mut rng);
    let secret = NttGlweSecretKey::from_coeff_secret_key(&coefficient_secret, &ntt);
    let mut gadget = NttGadgetEncryptContext::new(trace_domain.size());

    let automorphism_key = NttGlweAutomorphismKey::generate(
        3,
        &coefficient_secret,
        &secret,
        &trace_domain,
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
        &trace_domain,
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
        &trace_domain,
        &mut automorphism_context,
    );
    assert_eq!(automated_ntt.as_ref(), automated.as_ref());
    assert_eq!(
        secret
            .decrypt(&automated_ntt, &glwe_parameters, &ntt)
            .as_ref(),
        expected_automorphism
    );

    gadget.resize(trace_domain.size());
    let trace_key = NttGlweTraceKey::generate(
        &coefficient_secret,
        &secret,
        &trace_domain,
        &mut rng,
        &mut gadget,
    );
    let mut trivial: Glwe<Vec<u64>> = Glwe::zero(glwe_parameters.glwe_len());
    let (_, body) = trivial.a_b_mut_slices(POLY_LENGTH);
    for (index, value) in body.iter_mut().enumerate() {
        *value = index as u64 + 7;
    }
    let mut traced: Glwe<Vec<u64>> = Glwe::zero(glwe_parameters.glwe_len());
    let mut trace_context = NttGlweTraceContext::new(glwe_parameters.size());
    trace_key.apply_to(&trivial, &mut traced, &trace_domain, &mut trace_context);
    let (trace_mask, trace_body) = traced.a_b_slices(POLY_LENGTH);
    assert!(trace_mask.iter().all(|&value| value == 0));
    assert_eq!(trace_body[0], modulus.reduce_mul(POLY_LENGTH as u64, 7));
    assert!(trace_body[1..].iter().all(|&value| value == 0));

    gadget.resize(scheme_domain.size());
    let scheme_key = NttGlweSchemeSwitchKey::generate(
        &coefficient_secret,
        &secret,
        &scheme_domain,
        output_parameters.size(),
        &mut rng,
        &mut gadget,
    );
    gadget.resize(output_domain.size());
    let mut control_message = vec![0; POLY_LENGTH];
    control_message[0] = 1;
    let mut input_glev: NttGlev<Vec<u64>> = NttGlev::zero(output_parameters.glev_len());
    secret.encrypt_glev_to(
        &Polynomial::new(control_message),
        &mut input_glev,
        &output_domain,
        &mut rng,
        &mut gadget,
    );
    let input_glev = input_glev.into_coeff_form(&ntt);
    let mut control: NttGgsw<Vec<u64>> = NttGgsw::zero(output_parameters.ggsw_len());
    let mut scheme_context = NttGlweSchemeSwitchContext::new(scheme_domain.size());
    scheme_key.apply_to(
        &input_glev,
        &mut control,
        &scheme_domain,
        &mut scheme_context,
    );

    let selected_message = vec![5; POLY_LENGTH];
    let mut selected: NttGlwe<Vec<u64>> = NttGlwe::zero(glwe_parameters.glwe_len());
    secret.encrypt_to(
        &Polynomial::new(selected_message.as_slice()),
        &mut selected,
        &glwe_parameters,
        &ntt,
        &mut rng,
    );
    let selected = selected.into_coeff_form(&ntt);
    let mut product: Glwe<Vec<u64>> = Glwe::zero(glwe_parameters.glwe_len());
    let mut external_product = NttGlweExternalProductContext::new(output_domain.size());
    control.external_product_to(
        &selected,
        &mut product,
        output_parameters.basis(),
        modulus,
        &ntt,
        &mut external_product,
    );
    let product = product.into_ntt_form(&ntt);
    assert_eq!(
        secret.decrypt(&product, &glwe_parameters, &ntt).as_ref(),
        selected_message
    );
}
