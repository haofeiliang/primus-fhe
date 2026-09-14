//! Coefficient/NTT key pair and an automorphism under the original secret.
//! These are functional example parameters, not a security recommendation.
use primus_modulus::BarrettModulus;
use primus_ntru::{
    NlevParameters, NtruParameters, NttNtruAutomorphismContext, NttNtruAutomorphismKey,
    NttNtruCiphertext, NttNtruGadgetEncryptContext, NttNtruSecretKey, SecretKeyDistr,
};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
use rand::{SeedableRng, rngs::StdRng};

fn main() {
    const N: usize = 1024;
    let modulus = BarrettModulus::new(132_120_577u32);
    let table = UintNttTable::new(N.trailing_zeros(), modulus).unwrap();
    let parameters = NtruParameters::new(N, 16, modulus, SecretKeyDistr::SparseTernary, 0.7);
    let mut rng = StdRng::seed_from_u64(42);
    let (coeff_secret, secret) =
        NttNtruSecretKey::generate_pair(&parameters, &table, &mut rng).unwrap();
    let key_parameters = NlevParameters::with_ntru_params(&parameters, 3, None);
    let auto = NttNtruAutomorphismKey::generate(
        3,
        &coeff_secret,
        &secret,
        &key_parameters,
        &table,
        &mut rng,
        &mut NttNtruGadgetEncryptContext::new(N),
    );

    let mut message = Polynomial::<Vec<u32>>::zero(N);
    message.as_mut()[0] = 1;
    message.as_mut()[1] = 2;
    message.as_mut()[N / 2] = 3;
    let input = secret.encrypt(&message, &parameters, &table, &mut rng);
    let mut output = NttNtruCiphertext::<Vec<u32>>::zero(N);
    let mut context = NttNtruAutomorphismContext::new(N);
    auto.apply_ntt_to(&input, &mut output, modulus, &table, &mut context);

    // X^(3N/2) = -X^(N/2). The output is still under the original secret.
    let mut expected = vec![0; N];
    expected[0] = 1;
    expected[3] = 2;
    expected[N / 2] = 16 - 3;
    assert_eq!(
        secret.decrypt(&output, &parameters, &table).as_ref(),
        expected
    );
}
