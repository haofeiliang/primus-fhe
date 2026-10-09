//! Compute x % 4 and x / 4 from one encrypted input with interleaved ManyLUT.
//!
//! Run: `cargo run --release -p primus_tfhe_ntru_ntt --example ntru_ntt_many_lut`
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_ntt::U64NttTable as Table;
use primus_tfhe_ntru_ntt::{TfheContext, experimental};
use rand::{SeedableRng, rngs::StdRng};

// The paired experimental entry fixes u64 coefficients and the operation domains.
type Word = u64;

fn main() {
    let config = experimental::CLASSIC_MANY_LUT_U64;
    let context = TfheContext::<Word, Table, _>::try_from_pbs_config(config).unwrap();

    // One padded input in 0..8 uses Rounded t=16; both outputs use Rounded t=8.
    // The context derives input/output encodings from config.messages.

    // Client: keep the external secret; send server_key to the server.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context.try_generate_keys(&mut rng).unwrap();
    // Clients borrow only the external secret; no LUT or codec is needed.
    let external_secret = client_key.external_lwe_secret_key();
    let encryptor = context.encryptor(external_secret).unwrap();
    let decryptor = context.pbs_decryptor(external_secret).unwrap();
    let mut input = context.allocate_lwe_ciphertext();

    // Server: interleave two functions in one LUT to share a blind rotation.
    let compiler = context.pbs_lookup_table_compiler().unwrap();
    let lut = compiler
        .compile_interleaved_fn(2, |x, output| {
            if output == 0 {
                (x % 4) as Word
            } else {
                (x / 4) as Word
            }
        })
        .unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let mut outputs = vec![context.allocate_lwe_ciphertext(); 2];

    for message in [7, 2] {
        // Client -> server: send an encrypted padded input in 0..8.
        encryptor
            .encrypt_padded_to(message, input.as_mut_view(), &mut rng)
            .unwrap();

        // Server -> client: return two ciphertexts, reusing the LUT and buffers.
        evaluator.apply_interleaved_lookup_table_to(input.as_view(), &lut, &mut outputs);

        // Client: decrypt both results with the Rounded t=8 output codec.
        let results = [
            decryptor.decrypt(outputs[0].as_view()).unwrap(),
            decryptor.decrypt(outputs[1].as_view()).unwrap(),
        ];
        assert_eq!(results, [message % 4, message / 4]);
        println!(
            "input {message}: x % 4 = {}, x / 4 = {}",
            results[0], results[1]
        );
    }
}
