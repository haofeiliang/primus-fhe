//! Minimal complete NTRU/NTT programmable-bootstrap workflow.
//!
//! These small parameters are for demonstration only, not for production.

use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_ntt::{NttTable, U32NttTable};
use primus_tfhe_ntru_ntt::{NtruTfheParameters, TfheContext};

fn main() {
    const N: usize = 256;
    const LWE_DIMENSION: usize = 64;
    const Q: u32 = 132_120_577;
    let modulus = BarrettModulus::new(Q);
    let external_lwe = LweParameters::new(
        LWE_DIMENSION,
        4,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let accumulator = NtruParameters::new(N, 4, modulus, SecretKeyDistr::SparseTernary, 0.7);
    let client = NtruParameters::new(N, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let parameters = NtruTfheParameters::try_new(
        external_lwe,
        NlevParameters::with_ntru_params(&accumulator, 9, None),
        NlevParameters::with_ntru_params(&client, 9, None),
    )
    .unwrap();
    let table = U32NttTable::new(N.trailing_zeros(), modulus).unwrap();
    let context = TfheContext::try_new(parameters, table).unwrap();

    let mut rng = rand::rng();
    let (client_key, server_key) = context.generate_keys(&mut rng).unwrap();
    let encryptor = context.encryptor(&client_key).unwrap();
    let decryptor = context.decryptor(&client_key).unwrap();
    let lut = context.compile_lookup_table_slice(&[1u32, 0]).unwrap();
    let input = encryptor.encrypt_padded(0u32, &mut rng).unwrap();
    let output = context
        .evaluator(&server_key)
        .unwrap()
        .apply_lookup_table(&input, &lut);

    assert_eq!(decryptor.decrypt::<u32>(&output).unwrap(), 1);
    println!("NTRU/NTT programmable bootstrap succeeded");
}
