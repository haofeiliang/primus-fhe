//! Compute x % 4 with sparse PBS; reuse the same LUT and evaluator.
//!
//! Run: `cargo run --release -p primus_tfhe_ntru_ntt --example ntru_ntt_sparse`
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_ntt::U64NttTable as Table;
use primus_tfhe_ntru_ntt::{TfheContext, experimental};
use rand::{SeedableRng, rngs::StdRng};

// The paired experimental entry fixes u64 coefficients and the operation domains.
type Word = u64;

fn main() {
    let config = experimental::SPARSE_PBS_U64;
    let context = TfheContext::<Word, Table, _>::try_from_pbs_config(config).unwrap();
    let parameters = context.parameters();

    // Like basic PBS, input and output use the same message modulus.
    let codecs = context
        .parameters()
        .pbs_codecs(parameters.messages())
        .unwrap();

    // Client: generate sparse BR material from the fixed-weight secret.
    let mut rng = StdRng::seed_from_u64(42);
    // Three copies, 64 buckets. Map retries retain the same client secret.
    let (client_key, server_key) = context.try_generate_keys(&mut rng).unwrap();
    // Ordinary messages borrow only the external secret from the setup bundle.
    let external_secret = client_key.external_lwe_secret_key();
    let encryptor = context
        .encryptor(external_secret, codecs.input_codec())
        .unwrap();
    let decryptor = context
        .decryptor(external_secret, codecs.output_codec())
        .unwrap();
    let mut input = context.allocate_lwe_ciphertext();

    // Server: the ordinary PBS API also accepts sparse BR material.
    let compiler = context.parameters().lookup_table_compiler(&codecs).unwrap();
    let lut = compiler.compile_fn(|x| (x % 4) as Word).unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let mut output = context.allocate_lwe_ciphertext();

    for message in [7, 2] {
        // Client -> server: send one encrypted, padded input.
        encryptor
            .encrypt_padded_to(message, input.as_mut_view(), &mut rng)
            .unwrap();

        // Server -> client: reuse the LUT, evaluator and output buffer.
        evaluator.apply_lookup_table_to(input.as_view(), &lut, output.as_mut_view());

        // Client: decode with the configured output codec.
        let result = decryptor.decrypt(output.as_view()).unwrap();
        assert_eq!(result, message % 4);
        println!("f({message}) = {result}");
    }
}
