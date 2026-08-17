//! Minimal LWE encryption and decryption workflow.
//!
//! Run with `cargo run -p primus_lwe --example basic`.
//! The small dimension keeps the example fast and is not a security recommendation.

use primus_lwe::{LweParameters, LweSecretKey, SecretKeyDistr};
use primus_modulus::NativeModulus;

const LWE_DIMENSION: usize = 64;
const PLAINTEXT_MODULUS: u32 = 4;

fn main() {
    let parameters = LweParameters::new(
        LWE_DIMENSION,
        PLAINTEXT_MODULUS,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let mut rng = rand::rng();
    let secret_key = LweSecretKey::generate(&parameters, &mut rng);

    let message = 3u32;
    let ciphertext = secret_key.encrypt(message, &parameters, &mut rng);
    let decrypted: u32 = secret_key.decrypt(&ciphertext, &parameters);

    assert_eq!(decrypted, message);
}
