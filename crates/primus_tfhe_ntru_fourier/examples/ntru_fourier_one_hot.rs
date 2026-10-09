//! Build four one-hot gadget controls from a two-bit input; use delta_2 in a CMux.
//!
//! Run: `cargo run --release -p primus_tfhe_ntru_fourier --example ntru_fourier_one_hot --features rustfft`
//! To use TfheFftTable, switch the Table import, this target's
//! required-features and the command above to tfhe-fft.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_fft::RustFftTable as Table;
use primus_tfhe_ntru_fourier::{TfheContext, experimental};
use rand::{SeedableRng, rngs::StdRng};

// The paired experimental entry fixes u64 coefficients and the operation domains.
type Word = u64;
const TARGET: usize = 2; // Public selector r in 0..4; delta_r encrypts [input == r].

fn main() {
    let config = experimental::CLASSIC_ONE_HOT_U64;
    let context = TfheContext::<Word, Table, _>::try_from_cbs_config(config).unwrap();
    let poly_length = config.pbs.bsk_poly_length.get();

    // Client: independent LWE/NTRU secrets; send evaluation material and both encrypted choices.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context
        .try_generate_circuit_bootstrap_keys(&mut rng)
        .unwrap();
    // The selector is encrypted with the external LWE secret.
    let external_secret = client_key.external_lwe_secret_key();
    let encryptor = context.encryptor(external_secret).unwrap();

    // Candidate ring messages use their own t=8 space at accumulator Q.
    let mut ring_client = context
        .accumulator_client(client_key.accumulator_ntru_secret_key(), 8)
        .unwrap();
    let lhs = ring_client.encrypt(&vec![1; poly_length], &mut rng);
    let rhs = ring_client.encrypt(&vec![3; poly_length], &mut rng);
    let mut input = context.allocate_lwe_ciphertext();
    let mut decoded = vec![0; poly_length];

    // Server: reserve one transformed NGSW per value in 0..4 and one ring result.
    let mut cbs = context.one_hot_evaluator(&server_key).unwrap();
    let mut selectors = cbs.allocate_ngsw_output();
    let mut selected = context.allocate_accumulator_ciphertext();

    for message in [TARGET as Word, 0] {
        // Client -> server: one padded two-bit input; the server never sees message.
        encryptor
            .encrypt_padded_to(message, input.as_mut_view(), &mut rng)
            .unwrap();

        // Server: selector r encrypts [message == r]; r=0 is included in this full batch.
        cbs.one_hot_ngsw_to(input.as_view(), &mut selectors);
        let control = cbs.ngsw_selectors(&selectors).selector(TARGET).unwrap();
        cbs.cmux_to(
            control,
            lhs.as_view(),
            rhs.as_view(),
            selected.as_mut_view(),
        );

        // Client: equality selects rhs=3; all other inputs select lhs=1.
        ring_client.decrypt_to(&selected, &mut decoded);
        let expected = if message == TARGET as Word { 3 } else { 1 };
        assert!(decoded.iter().all(|&value| value == expected));
        println!("input {message}: delta_{TARGET} selected {expected}");
    }
}
