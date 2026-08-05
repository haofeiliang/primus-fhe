use primus_glwe_rns::RnsCoeffCodec;
use primus_modulus::BarrettModulus;
use primus_poly::{CrtPolynomial, DcrtPolynomial, Polynomial};
use primus_rns::RNSBase;

#[test]
fn decodes_without_t_gamma_workspace() {
    type ValueT = u64;

    let moduli_value: [ValueT; 2] = [1125899906826241, 1125899906629633];
    let moduli = moduli_value.map(BarrettModulus::new);
    let base_q = RNSBase::new(&moduli).unwrap();
    let t = 12289;
    let gamma = 2305843009213554689;
    let codec = RnsCoeffCodec::new(BarrettModulus::new(t), base_q, BarrettModulus::new(gamma));
    let poly_length = 32;
    let rns_poly_len = codec.moduli_count() * poly_length;
    let input_values: Vec<ValueT> = (0..poly_length)
        .map(|i| ((i * i + 3 * i + 7) as ValueT) % t)
        .collect();
    let input = Polynomial::new(input_values.clone());
    let mut encoded: CrtPolynomial<Vec<ValueT>> = CrtPolynomial::zero(rns_poly_len);

    codec.centered_encode_coeffs(&input, &mut encoded, poly_length);

    let mut fused_q = DcrtPolynomial::new(encoded.into_owned());
    let mut fused_decoded: Polynomial<Vec<ValueT>> = Polynomial::zero(poly_length);
    let mut fused_fast_convert_buffer = vec![0; rns_poly_len];
    codec.decode_coeffs(
        &mut fused_q,
        &mut fused_decoded,
        poly_length,
        &mut fused_fast_convert_buffer,
    );
    assert_eq!(fused_decoded.as_ref(), input_values);
}
