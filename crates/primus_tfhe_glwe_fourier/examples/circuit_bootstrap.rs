//! Use an encrypted LWE bit to select between two encrypted GLWE messages.
//! Fixed cost/demo parameters, not production parameters.
//! Pass `--sparse` to use bucketed fixed-weight binary blind rotation.

#[path = "support/circuit_bootstrap.rs"]
mod profile;

use primus_fft::TfheFftTable;
use primus_tfhe_glwe_fourier::{ClientKey, KeyGenerator, PbsOrder};
use rand::{SeedableRng, rngs::StdRng};

fn main() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let context = profile::context::<TfheFftTable>(order);
        let mut rng = StdRng::seed_from_u64(profile::SEED);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        let mut generator = KeyGenerator::new(&context);
        let config = Some(profile::circuit_bootstrap());
        let server = if std::env::args().any(|arg| arg == "--sparse") {
            generator.try_generate_sparse_server_key(
                &client,
                3,
                2 * profile::WEIGHT,
                config,
                &mut rng,
            )
        } else {
            generator.try_generate_server_key(&client, config, &mut rng)
        }
        .unwrap();

        // Candidate ring ciphertexts use the CBS output's accumulator secret.
        let mut accumulator = context.accumulator_client(&client).unwrap();
        let messages = [0u64, 1].map(|offset| {
            (0..profile::N)
                .map(|i| (i as u64 + offset) % 4)
                .collect::<Vec<_>>()
        });
        let choices = messages
            .each_ref()
            .map(|message| accumulator.encrypt(message, &mut rng));

        let encryptor = context.encryptor(&client).unwrap();
        let mut evaluator = context.circuit_bootstrap_evaluator(&server).unwrap();
        let mut control = evaluator.allocate_output();
        let mut selected = accumulator.allocate_ciphertext();
        let mut decoded = vec![0; profile::N];

        // Reuse the evaluator, GGSW and CMUX output, including nonzero → zero control.
        for bit in [1u64, 0] {
            let input = encryptor.encrypt_padded(bit, &mut rng).unwrap();
            evaluator.circuit_bootstrap_to(&input, &mut control);
            evaluator.cmux_to(&control, &choices[0], &choices[1], &mut selected);
            accumulator.decrypt_to(&selected, &mut decoded);
            assert_eq!(decoded, messages[bit as usize]);
            println!(
                "{order:?}: LWE bit {bit} selected message {bit}; all {} coefficients verified",
                profile::N
            );
        }
    }
}
