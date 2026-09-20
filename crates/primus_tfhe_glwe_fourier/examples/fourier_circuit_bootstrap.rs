//! Use an encrypted LWE bit to select between two encrypted GLWE messages.
//! Fixed cost/demo parameters, not production parameters.

#[path = "support/circuit_bootstrap.rs"]
mod profile;

use primus_fft::TfheFftTable;
use primus_tfhe_glwe_fourier::PbsOrder;
use rand::{SeedableRng, rngs::StdRng};

fn main() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        run(order);
    }
}

fn run(order: PbsOrder) {
    let context = profile::context::<TfheFftTable>(order);
    // Client setup: generate paired keys and keep the decryption material local.
    let mut rng = StdRng::seed_from_u64(profile::SEED);
    let (client_key, server_key) = context
        .try_generate_keys(Some(profile::circuit_bootstrap()), &mut rng)
        .unwrap();
    let encryptor = context.encryptor(&client_key).unwrap();
    // The ring candidates and CBS control share the accumulator secret.
    let mut ring_client = context.accumulator_client(&client_key).unwrap();
    let lhs_message = vec![1u64; profile::N];
    let rhs_message = vec![3u64; profile::N];
    let lhs = ring_client.encrypt(&lhs_message, &mut rng);
    let rhs = ring_client.encrypt(&rhs_message, &mut rng);
    let mut input = context.allocate_lwe_ciphertext();
    let mut decoded = vec![0; profile::N];

    // Server setup: only public context, server key and ciphertexts are needed.
    let mut cbs = context.circuit_bootstrap_evaluator(&server_key).unwrap();
    let mut control = cbs.allocate_output();
    let mut selected = context.allocate_accumulator_ciphertext();

    for bit in [1u64, 0] {
        // Client sends the encrypted bit (the encrypted candidates can be reused).
        encryptor
            .encrypt_padded_to(bit, &mut input, &mut rng)
            .unwrap();

        // Server computes the control and returns the selected ciphertext.
        cbs.circuit_bootstrap_to(&input, &mut control);
        cbs.cmux_to(&control, &lhs, &rhs, &mut selected);

        // Client decrypts the response; all buffers survive the next request.
        ring_client.decrypt_to(&selected, &mut decoded);
        let expected = if bit == 0 { &lhs_message } else { &rhs_message };
        assert_eq!(&decoded, expected);
        println!("{order:?}: bit {bit} selected coefficients {}", expected[0]);
    }
}
