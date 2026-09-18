//! Use an encrypted LWE bit to select between two encrypted GLWE messages.
//! Fixed cost/demo parameters, not production parameters.

#[path = "support/circuit_bootstrap.rs"]
mod profile;

use primus_fft::TfheFftTable;
use primus_glwe::{FourierGlweDecryptContext, FourierGlweEncryptContext, FourierGlweSecretKey};
use primus_lattice::{
    context::FourierGlweExternalProductContext,
    ggsw::FourierGgsw,
    glwe::{FourierGlwe, Glwe},
};
use primus_poly::Polynomial;
use primus_tfhe_glwe_fourier::{ClientKey, KeyGenerator, PbsOrder};
use rand::{SeedableRng, rngs::StdRng};

fn main() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let context = profile::context::<TfheFftTable>(order);
        let parameters = profile::parameters(context.parameters());
        let mut rng = StdRng::seed_from_u64(profile::SEED);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        let mut generator = KeyGenerator::new(&context);
        let server = generator
            .try_generate_server_key(&client, &mut rng)
            .unwrap();
        let key = generator
            .try_generate_circuit_bootstrap_key(&client, &parameters, &mut rng)
            .unwrap();

        // Both candidate GLWEs and the CBS output use the accumulator secret.
        let glwe = context.parameters().accumulator_glwe();
        let mut fft = context.new_fft_engine();
        let secret =
            FourierGlweSecretKey::from_coeff_secret_key(client.glwe_secret_key(), &mut fft);
        let mut encrypt = FourierGlweEncryptContext::new(profile::N);
        let messages = [0u64, 1].map(|offset| {
            Polynomial::new(
                (0..profile::N)
                    .map(|i| (i as u64 + offset) % 4)
                    .collect::<Vec<_>>(),
            )
        });
        let choices = messages.each_ref().map(|message| {
            let encrypted = secret.encrypt(message, glwe, &mut fft, &mut rng, &mut encrypt);
            let mut coefficients = Glwe::<Vec<u64>>::zero(glwe.glwe_len());
            encrypted.write_torus_form(&mut coefficients, &mut fft);
            coefficients
        });

        let encryptor = context.encryptor(&client).unwrap();
        let mut evaluator = context
            .circuit_bootstrap_evaluator(&server, &parameters, &key)
            .unwrap();
        let mut control = FourierGgsw::<Vec<_>>::zero(parameters.output_size().fourier_ggsw_len());
        let mut selected = Glwe::<Vec<u64>>::zero(glwe.glwe_len());
        let mut external_product = FourierGlweExternalProductContext::new(parameters.output_size());
        let mut selected_fourier = FourierGlwe::<Vec<_>>::zero(glwe.size().fourier_glwe_len());
        let mut decrypt = FourierGlweDecryptContext::new(profile::N);

        // Reuse the evaluator, GGSW and CMUX output, including nonzero → zero control.
        for bit in [1u64, 0] {
            let input = encryptor.encrypt_padded(bit, &mut rng).unwrap();
            evaluator.circuit_bootstrap_to(&input, &mut control);
            control.cmux_to(
                &choices[0],
                &choices[1],
                &mut selected,
                parameters.output_basis(),
                &mut fft,
                &mut external_product,
            );
            selected.write_fourier_form(&mut selected_fourier, &mut fft);
            let decoded = secret.decrypt(&selected_fourier, glwe, &mut fft, &mut decrypt);
            assert_eq!(decoded.as_ref(), messages[bit as usize].as_ref());
            println!(
                "{order:?}: LWE bit {bit} selected message {bit}; all {} coefficients verified",
                profile::N
            );
        }
    }
}
