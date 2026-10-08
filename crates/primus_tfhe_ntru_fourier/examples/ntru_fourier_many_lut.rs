//! Compute x % 4 and x / 4 from one encrypted input with interleaved ManyLUT.
//!
//! Run: `cargo run --release -p primus_tfhe_ntru_fourier --example ntru_fourier_many_lut --features rustfft`
//! To use TfheFftTable, switch the Table import, this target's
//! required-features and the command above to tfhe-fft.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_fft::RustFftTable as Table;
use primus_tfhe_ntru_fourier::{TfheContext, experimental};
use rand::{SeedableRng, rngs::StdRng};

// The paired experimental entry fixes u64 coefficients and the operation domains.
type Word = u64;

fn main() {
    let config = experimental::CLASSIC_MANY_LUT_U64;
    let parameters = config.try_prepare().unwrap();
    let context = TfheContext::<Word, Table, _>::from_parameters(parameters);

    // One padded input in 0..8 uses Rounded t=16; both outputs use Rounded t=8.
    // config.messages carries both domains; with_output_modulus overrides only the output.
    let codecs = context.parameters().pbs_codecs(config.messages).unwrap();

    // Client: keep the external secret; send server_key to the server.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context
        .try_generate_keys(config.blind_rotation.algorithm, None, &mut rng)
        .unwrap();
    // Ordinary messages borrow only the external secret from the setup bundle.
    let external_secret = client_key.external_lwe_secret_key();
    let encryptor = context
        .encryptor(external_secret, codecs.input_codec())
        .unwrap();
    let decryptor = context
        .decryptor(external_secret, codecs.output_codec())
        .unwrap();
    let mut input = context.allocate_lwe_ciphertext();

    // Server: interleave two functions in one LUT to share a blind rotation.
    let compiler = context.parameters().lookup_table_compiler(&codecs).unwrap();
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
