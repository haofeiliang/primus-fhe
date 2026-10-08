//! Evaluate an encrypted integer predicate with CBS, then select a ring message via CMux.
//!
//! Run: `cargo run --release -p primus_tfhe_glwe_fourier --example fourier_circuit_bootstrap --features rustfft`
//! To use TfheFftTable, switch the Table import, this target's
//! required-features and the command above to tfhe-fft.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_fft::RustFftTable as Table;
use primus_tfhe_glwe_fourier::{CircuitBootstrapEvaluator, TfheContext, experimental};
use rand::{SeedableRng, rngs::StdRng};

// The paired experimental entry fixes u64 coefficients and the operation domains.
type Word = u64;

fn main() {
    let config = experimental::CLASSIC_CBS_U64;
    let parameters = config.try_prepare().unwrap();
    let context = TfheContext::<Word, Table>::from_parameters(parameters);
    let poly_length = config.blind_rotation.acc_poly_length.get();

    // Padded t=8 accepts integers 0..4, independently of the candidate ring messages.
    let (input_codec, ring_message_codec) = context
        .parameters()
        .circuit_bootstrap_codecs(config.input_modulus, 8)
        .unwrap();

    // Client: generate BR and CBS material from the same accumulator secret.
    // This BR→KS ring-output workflow needs neither an input KS nor a return key.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context
        .try_generate_circuit_bootstrap_keys(
            config.blind_rotation.algorithm,
            config.gadget,
            &mut rng,
        )
        .unwrap();
    // The integer input is encrypted with the external LWE secret.
    let external_secret = client_key.external_lwe_secret_key();
    let encryptor = context.encryptor(external_secret, &input_codec).unwrap();

    // Candidate ring messages use an independent t=8 space under the accumulator secret.
    let mut ring_client = context
        .accumulator_client(client_key.glwe_secret_key(), ring_message_codec)
        .unwrap();
    // Encrypt both candidates with the accumulator secret used by the CBS output.
    let lhs_message = vec![1; poly_length];
    let rhs_message = vec![3; poly_length];
    let lhs = ring_client.encrypt(&lhs_message, &mut rng);
    let rhs = ring_client.encrypt(&rhs_message, &mut rng);
    let mut input = context.allocate_lwe_ciphertext();
    let mut decoded = vec![0; poly_length];

    // Server: receive BR/CBS material and encrypted candidates.
    let mut resources = server_key.bootstrap_resources(&context).unwrap();
    // Compile F(m) = [m >= 2] once. CBS emits gadget-scaled F(m), so CMux
    // consumes a bit even when the encrypted input itself is not a bit.
    let program = server_key
        .circuit_bootstrap_key()
        .parameters()
        .compile_lookup_table_fn(&input_codec, |m| Word::from(m >= 2))
        .unwrap();
    let mut cbs = CircuitBootstrapEvaluator::try_with_lookup_table(
        &resources,
        server_key.circuit_bootstrap_key(),
        program,
    )
    .unwrap();
    let mut control = cbs.allocate_output();
    let mut selected = context.allocate_accumulator_ciphertext();

    for message in [3, 1] {
        // Client -> server: send the encrypted integer.
        encryptor
            .encrypt_padded_to(message, input.as_mut_view(), &mut rng)
            .unwrap();

        // Server: one CBS computes the predicate; CMux selects rhs when it is true.
        cbs.circuit_bootstrap_to(input.as_view(), &mut control, &mut resources);
        cbs.cmux_to(&control, &lhs, &rhs, &mut selected, &mut resources);

        // Client: decrypt the returned ring ciphertext, reusing the decoding buffer.
        ring_client.decrypt_to(&selected, &mut decoded);
        let expected = if message >= 2 {
            &rhs_message
        } else {
            &lhs_message
        };
        assert_eq!(&decoded, expected);
        println!(
            "input {message}, predicate m >= 2: selected coefficients {}",
            decoded[0]
        );
    }
}
