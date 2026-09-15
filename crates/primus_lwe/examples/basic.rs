//! Minimal LWE encryption and decryption workflow.
//!
//! Run with `cargo run -p primus_lwe --example basic`.
//! The small dimension keeps the example fast and is not a security recommendation.

use primus_lattice::lwe::{Lwe, LweIter};
use primus_lwe::{LweParameters, LwePublicKey, LweSecretKey, SecretKeyDistr};
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

    // Reuse caller-owned storage; decryption accepts the borrowed ciphertext too.
    let mut storage = [0u32; LWE_DIMENSION + 1];
    let mut output = Lwe::new(&mut storage[..]);
    secret_key.encrypt_to(message, &mut output, &parameters, &mut rng);
    assert_eq!(secret_key.decrypt::<_, u32>(&output, &parameters), message);

    // The public key can be given to a sender who does not have the secret.
    // Public-key output noise grows with the secret and ephemeral vector norms;
    // these demonstration parameters are not a security recommendation.
    let public_key = LwePublicKey::generate(secret_key.as_view(), &parameters, &mut rng);
    let ciphertext = public_key.encrypt(message, &parameters, &mut rng);
    assert_eq!(
        secret_key.decrypt::<_, u32>(&ciphertext, &parameters),
        message
    );
    public_key.encrypt_to(message, &mut output, &parameters, &mut rng);
    assert_eq!(secret_key.decrypt::<_, u32>(&output, &parameters), message);

    // Independent samples share one allocation and remain usable individually.
    let messages = [0u32, 1, 2, 3];
    let batch = public_key.encrypt_batch(&messages, &parameters, &mut rng);
    assert_eq!(
        secret_key.decrypt_batch::<_, u32>(&batch, &parameters),
        messages
    );
    for (ciphertext, &message) in LweIter::new(&batch, ciphertext.lwe_len()).zip(&messages) {
        assert_eq!(
            secret_key.decrypt::<_, u32>(&ciphertext, &parameters),
            message
        );
    }
    let mut storage = [0u32; 4 * (LWE_DIMENSION + 1)];
    secret_key.encrypt_batch_to(&messages, &mut storage, &parameters, &mut rng);
    let mut decoded = [0u32; 4];
    secret_key.decrypt_batch_to(&storage, &mut decoded, &parameters);
    assert_eq!(decoded, messages);
}
