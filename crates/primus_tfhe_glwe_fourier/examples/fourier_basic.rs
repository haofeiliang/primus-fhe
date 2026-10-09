//! Compute x % 4 with one LUT and reuse the PBS evaluator for a second request.
//!
//! Run: `cargo run --release -p primus_tfhe_glwe_fourier --example fourier_basic --features rustfft`
//! To use TfheFftTable, switch the Table import, this target's
//! required-features and the command above to tfhe-fft.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_fft::RustFftTable as Table;
use primus_tfhe_glwe_fourier::{TfheContext, experimental};
use rand::{SeedableRng, rngs::StdRng};

// The paired experimental entry fixes u64 coefficients and the input/output domains.
type Word = u64;

fn main() {
    let config = experimental::CLASSIC_PBS_U64;
    let context = TfheContext::<Word, Table>::try_from_pbs_config(config).unwrap();
    let parameters = context.parameters();

    // Input and output messages both use t=32, independently of the keys.
    // To change only the output domain, use parameters.messages().with_output_modulus(t_out) here.
    let codecs = context
        .parameters()
        .pbs_codecs(parameters.messages())
        .unwrap();

    // Client: keep client_key secret; send only server_key to the server.
    let mut rng = StdRng::seed_from_u64(42);
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

    // Server: prepare public LUT and reusable buffers without the client secret.
    let compiler = context.parameters().lookup_table_compiler(&codecs).unwrap();
    let lut = compiler.compile_fn(|x| (x % 4) as Word).unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let mut output = context.allocate_lwe_ciphertext();

    for message in [7, 2] {
        // Client -> server: send one encrypted, padded input.
        encryptor
            .encrypt_padded_to(message, input.as_mut_view(), &mut rng)
            .unwrap();

        // Server -> client: return the result, reusing the LUT and buffers.
        evaluator.apply_lookup_table_to(input.as_view(), &lut, output.as_mut_view());

        // Client: decrypt with the original external LWE secret.
        let result = decryptor.decrypt(output.as_view()).unwrap();
        assert_eq!(result, message % 4);
        println!("f({message}) = {result}");
    }
}
