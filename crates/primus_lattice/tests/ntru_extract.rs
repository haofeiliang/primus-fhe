use primus_lattice::{lwe::Lwe, ntru::Ntru};
use primus_modulus::BarrettModulus;
use primus_reduce::{ReduceAdd, ReduceDotProduct, ReduceMul, ReduceSub};

#[test]
fn ntru_extraction_preserves_the_constant_negacyclic_phase() {
    const MODULUS: u32 = 97;
    let modulus = BarrettModulus::new(MODULUS);
    let ciphertext = Ntru::new(vec![13u32, 21, 34, 55, 8, 19, 27, 41]);
    let secret = [1u32, 0, 1, 1, 0, 1, 0, 1];
    let mut extracted: Lwe<Vec<u32>> = Lwe::zero(secret.len());

    ciphertext.extract_lwe_to(&mut extracted, modulus);

    let direct_phase = ciphertext.as_ref()[0..1]
        .iter()
        .zip(secret[0..1].iter())
        .fold(0, |accumulator, (&lhs, &rhs)| {
            modulus.reduce_add(accumulator, modulus.reduce_mul(lhs, rhs))
        });
    let direct_phase = ciphertext.as_ref()[1..]
        .iter()
        .rev()
        .zip(secret[1..].iter())
        .fold(direct_phase, |accumulator, (&lhs, &rhs)| {
            modulus.reduce_sub(accumulator, modulus.reduce_mul(lhs, rhs))
        });
    let (mask, body) = extracted.a_b();
    let extracted_phase = modulus.reduce_sub(body, modulus.reduce_dot_product(mask, &secret));

    assert_eq!(extracted_phase, direct_phase);

    let padded_secret = [1u32, 0, 1, 1, 0, 0, 0, 0];
    let mut compact: Lwe<Vec<u32>> = Lwe::zero(5);
    ciphertext.extract_compact_lwe_to(&mut compact, modulus);
    let compact_direct_phase = ciphertext.as_ref()[0..1]
        .iter()
        .zip(padded_secret[0..1].iter())
        .fold(0, |accumulator, (&lhs, &rhs)| {
            modulus.reduce_add(accumulator, modulus.reduce_mul(lhs, rhs))
        });
    let compact_direct_phase = ciphertext.as_ref()[1..]
        .iter()
        .rev()
        .zip(padded_secret[1..5].iter())
        .fold(compact_direct_phase, |accumulator, (&lhs, &rhs)| {
            modulus.reduce_sub(accumulator, modulus.reduce_mul(lhs, rhs))
        });
    let (mask, body) = compact.a_b();
    let compact_phase =
        modulus.reduce_sub(body, modulus.reduce_dot_product(mask, &padded_secret[..5]));

    assert_eq!(compact_phase, compact_direct_phase);
}
