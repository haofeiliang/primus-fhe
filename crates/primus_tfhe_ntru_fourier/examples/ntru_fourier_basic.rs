//! Minimal complete NTRU/Fourier programmable-bootstrap workflow.
//!
//! These small parameters are for demonstration only, not for production.

use primus_fft::{FftTable, RustFftTable};
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::NativeModulus;
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_tfhe_ntru_fourier::{NtruTfheParameters, TfheContext};

fn main() {
    const N: usize = 256;
    const LWE_DIMENSION: usize = 8;
    let modulus = NativeModulus::new();
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
        NlevParameters::with_ntru_params(&accumulator, 8, Some(4)),
        NlevParameters::with_ntru_params(&client, 8, Some(4)),
    )
    .unwrap();
    let table = RustFftTable::new(N.trailing_zeros()).unwrap();
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
    // its two low message bits and a carry with one shared PBS. This is
    // one input with two outputs, not a complete encrypted-integer system.
    let lut = context
        .compile_many_lookup_table_fn(2, |input, output| {
            if output == 0 {
                (input % 4) as u32
            } else {
                (input / 4) as u32
            }
        })
        .unwrap();
    let mut input = LweCiphertext::zero(LWE_DIMENSION);
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let mut outputs = vec![input.clone(); lut.output_count()];
    for message in [7u32, 2] {
        encryptor
            .encrypt_padded_to(message, &mut input, &mut rng)
            .unwrap();
        evaluator.apply_many_lookup_table_to(&input, &lut, &mut outputs);
        assert_eq!(decryptor.decrypt::<u32>(&outputs[0]).unwrap(), message % 4);
        assert_eq!(decryptor.decrypt::<u32>(&outputs[1]).unwrap(), message / 4);
    }
    println!("NTRU/Fourier programmable bootstrap succeeded");
}
