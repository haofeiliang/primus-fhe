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
    const LWE_DIMENSION: usize = 8;
    const Q: u32 = 132_120_577;
    let modulus = BarrettModulus::new(Q);
    let external_lwe = LweParameters::new(
        LWE_DIMENSION,
        16,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let accumulator = NtruParameters::new(N, 16, modulus, SecretKeyDistr::SparseTernary, 0.7);
    let client = NtruParameters::new(N, 16, modulus, SecretKeyDistr::UniformBinary, 0.7);
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
    // Publish this LWE key to encrypt inputs; keep the client key for decryption.
    // These demonstration parameters have no public-key security/noise assessment.
    let public_key = client_key
        .try_generate_public_key(context.parameters(), &mut rng)
        .unwrap();
    let encryptor = context.encryptor(&public_key).unwrap();
    let decryptor = context.decryptor(&client_key).unwrap();
    // t=16 leaves the programmable inputs 0..8. Split a short integer into
    // its two low message bits and a carry with one shared PBS.
    let lut = context
        .compile_many_lookup_table_fn(2, |input, output| {
            if output == 0 {
                (input % 4) as u32
            } else {
                (input / 4) as u32
            }
        })
        .unwrap();
    let input = encryptor.encrypt_padded(7u32, &mut rng).unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let mut outputs = vec![input.clone(); lut.output_count()];
    evaluator.apply_many_lookup_table_to(&input, &lut, &mut outputs);
    assert_eq!(decryptor.decrypt::<u32>(&outputs[0]).unwrap(), 3);
    assert_eq!(decryptor.decrypt::<u32>(&outputs[1]).unwrap(), 1);
    println!("NTRU/NTT programmable bootstrap succeeded");
}
