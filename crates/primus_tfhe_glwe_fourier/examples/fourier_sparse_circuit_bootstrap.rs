//! Evaluate an encrypted integer predicate with sparse CBS, then select a ring message via CMux.
//!
//! Run: `cargo run --release -p primus_tfhe_glwe_fourier --example fourier_sparse_circuit_bootstrap --features rustfft`
//! To use TfheFftTable, switch the Table import, this target's
//! required-features and the command above to tfhe-fft.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_fft::RustFftTable as Table;
use primus_tfhe_glwe_fourier::{TfheContext, experimental};
use rand::{SeedableRng, rngs::StdRng};

// The paired experimental entry fixes u64 coefficients and the operation domains.
type Word = u64;

fn main() {
    let config = experimental::SPARSE_CBS_U64;
    let context = TfheContext::<Word, Table>::try_from_cbs_config(config).unwrap();
    let poly_length = config.pbs.bsk_poly_length.get();

    // Client: generate sparse BR/CBS material and KS for downstream LWE returns.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context
        .try_generate_circuit_bootstrap_keys(&mut rng)
        .unwrap();
    // The integer input is encrypted with the external LWE secret.
    let external_secret = client_key.external_lwe_secret_key();
    let encryptor = context.encryptor(external_secret).unwrap();

    // Candidate ring messages use an independent t=8 space under the accumulator secret.
    let mut ring_client = context
        .accumulator_client(client_key.glwe_secret_key(), 8)
        .unwrap();
    // Encrypt both candidates with the accumulator secret used by the CBS output.
    let lhs_message = vec![1; poly_length];
    let rhs_message = vec![3; poly_length];
    let lhs = ring_client.encrypt(&lhs_message, &mut rng);
    let rhs = ring_client.encrypt(&rhs_message, &mut rng);
    let mut input = context.allocate_lwe_ciphertext();
    let mut decoded = vec![0; poly_length];

    // Server: receive the encrypted candidates; allocate the control and result.
    // Compile F(m) = [m >= 2] once. CBS emits gadget-scaled F(m), so CMux
    // consumes a bit even when the encrypted input itself is not a bit.
    let program = context.compile_cbs_fn(|m| Word::from(m >= 2)).unwrap();
    let mut cbs = context
        .circuit_bootstrap_evaluator_with_lookup_table(&server_key, program)
        .unwrap();
    let mut control = cbs.allocate_output();
    let mut selected = context.allocate_accumulator_ciphertext();

    for message in [3, 1] {
        // Client -> server: send the encrypted integer.
        encryptor
            .encrypt_padded_to(message, input.as_mut_view(), &mut rng)
            .unwrap();

        // Server: one CBS computes the predicate; CMux selects rhs when it is true.
        cbs.circuit_bootstrap_to(input.as_view(), control.as_mut_view());
        cbs.cmux_to(
            control.as_view(),
            lhs.as_view(),
            rhs.as_view(),
            selected.as_mut_view(),
        );

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
