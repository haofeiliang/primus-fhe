//! GLWE Fourier parameter checks: Q is the native torus modulus 2^T::BITS.
//! The small/external LWE and accumulator share Q; both PBS orders are checked.

use super::metrics::ErrorMargin;
use primus_encoding::{PlaintextEmbedding, RoundedCodec, ScaledCodec};
use primus_fft::{FftTable, TorusFftValue};
use primus_glwe::SecretKeyDistr;
use primus_integer::AsInto;
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;
use primus_tfhe_glwe::PbsOrder;
use primus_tfhe_glwe_fourier::{ClientKey, KeyGenerator, TfheContext};
use primus_tfhe_test_support::{
    benchmark::PBS_WORKLOADS,
    parameters::{N, SPARSE_WEIGHT, glwe},
};
use rand::{SeedableRng, rngs::StdRng};

/// Runs both PBS orders, dense binary/ternary controls, sparse controls and MVB.
/// Each operation chooses its own profile; circuit products need finer decomposition.
pub fn validate<T, Table>(seed: u64, name: &str)
where
    T: TorusFftValue,
    Table: FftTable,
{
    let modulus = NativeModulus::new();
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        for workload in PBS_WORKLOADS {
            let parameters = glwe::fourier_pbs(order, workload);
            let context = TfheContext::<T, Table>::try_from_parameters(parameters).unwrap();
            pbs(
                &context,
                seed,
                &format!("{name}/{order:?}/{}", workload.name),
                false,
            );
        }
        for secret in [
            SecretKeyDistr::UniformBinary,
            SecretKeyDistr::UniformTernary,
        ] {
            let context =
                TfheContext::<T, Table>::try_from_parameters(glwe::circuit(modulus, order, secret))
                    .unwrap();
            pbs(
                &context,
                seed,
                &format!("{name}/{order:?}/{secret:?}"),
                false,
            );
            circuit(
                &context,
                seed,
                &format!("{name}/{order:?}/cbs/{secret:?}"),
                false,
            );
        }
        let context =
            TfheContext::<T, Table>::try_from_parameters(glwe::diagnostic(modulus, order, 8))
                .unwrap();
        pbs(
            &context,
            seed,
            &format!("{name}/{order:?}/fixed_weight"),
            false,
        );
        pbs(&context, seed, &format!("{name}/{order:?}/sparse"), true);
        let context =
            TfheContext::<T, Table>::try_from_parameters(glwe::diagnostic(modulus, order, 4))
                .unwrap();
        circuit(
            &context,
            seed,
            &format!("{name}/{order:?}/sparse_cbs"),
            true,
        );
        let context =
            TfheContext::<T, Table>::try_from_parameters(glwe::diagnostic(modulus, order, 128))
                .unwrap();
        thresholds(&context, seed, &format!("{name}/{order:?}/mvb"));
    }
}

/// Checks padded-domain endpoints, modular-affine PBS, three interleaved LUTs
/// and repeated output/workspace use. The Boolean profile also chains gate outputs.
fn pbs<T, Table>(context: &TfheContext<T, Table>, seed: u64, name: &str, sparse: bool)
where
    T: TorusFftValue,
    Table: FftTable,
{
    // Public setup: agree on the padded domain and the functions to evaluate.
    let modulus = context.parameters().small_lwe().cipher_modulus();
    let t = context.parameters().plain_modulus_value();
    let domain: usize = t.as_into();
    // Padded inputs occupy only the first half of the plaintext domain.
    let domain = domain / 2;
    let value = |m: usize| T::as_from((3 * m + 1) % domain);

    // Client: generate both keys; give only the evaluation key to the server.
    let mut rng = StdRng::seed_from_u64(seed);
    let client_key = ClientKey::generate(context.parameters(), &mut rng);
    let mut generator = KeyGenerator::new(context);
    let server_key = if sparse {
        generator.try_generate_sparse_server_key(&client_key, 3, 2 * SPARSE_WEIGHT, None, &mut rng)
    } else {
        generator.try_generate_server_key(&client_key, None, &mut rng)
    }
    .unwrap();

    let encryptor = context.encryptor(&client_key).unwrap();
    let decryptor = context.decryptor(&client_key).unwrap();
    let codec = RoundedCodec::new(t, modulus);
    let mut margin = ErrorMargin::new(name, seed);

    // Server: compile the public functions and allocate local evaluation storage.
    let lut = context.parameters().compile_lookup_table_fn(value).unwrap();
    // Three outputs force padding to four interleaved lanes.
    let many = context
        .parameters()
        .compile_interleaved_lookup_table_fn(3, |m, i| T::as_from((m + 2 * i) % domain))
        .unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let mut output = context.allocate_lwe_ciphertext();
    let mut outputs = vec![context.allocate_lwe_ciphertext(); 3];

    // Revisit zero after both interior and endpoint messages using the same evaluator.
    for m in [0, 1, domain / 2, domain - 1, 0] {
        // Client -> server: encrypt the input; keep m private to the client.
        let input = encryptor.encrypt_padded(T::as_from(m), &mut rng).unwrap();

        // Server: evaluate both programs using only the input ciphertext.
        evaluator.apply_lookup_table_to(&input, &lut, &mut output);
        evaluator.apply_interleaved_lookup_table_to(&input, &many, &mut outputs);

        // Server -> client: return the outputs for decryption and error checks.
        assert_eq!(
            decryptor.decrypt(&output).unwrap(),
            value(m),
            "{name},seed={seed},m={m}"
        );
        margin.decoded(
            decryptor.decrypt_phase(&output).unwrap(),
            codec.encode_value(value(m), PlaintextEmbedding::Unsigned),
            modulus,
            domain * 2,
        );
        for (i, output) in outputs.iter().enumerate() {
            let expected = T::as_from((m + 2 * i) % domain);
            assert_eq!(
                decryptor.decrypt(output).unwrap(),
                expected,
                "{name},seed={seed},m={m},many={i}"
            );
            margin.decoded(
                decryptor.decrypt_phase(output).unwrap(),
                codec.encode_value(expected, PlaintextEmbedding::Unsigned),
                modulus,
                domain * 2,
            );
        }
    }
    margin.report();

    if domain == 2 {
        // Client: prepare encrypted Boolean inputs and keep decryption local.
        let encryptor = context.boolean_encryptor(&client_key).unwrap();
        let decryptor = context.boolean_decryptor(&client_key).unwrap();
        let inputs = [false, true].map(|bit| encryptor.encrypt(bit, &mut rng).unwrap());

        // Server: own the gate evaluator and its reusable output buffers.
        let mut evaluator = context.boolean_evaluator(&server_key).unwrap();
        let mut output = context.allocate_lwe_ciphertext();
        let mut current = context.allocate_lwe_ciphertext();

        // Test driver alternates server gates and client checks. The decrypt
        // callback is client-side diagnostics, never part of server evaluation.
        primus_tfhe_test_support::boolean::check_truth_tables_and_chain(
            &mut evaluator,
            &inputs,
            &mut output,
            &mut current,
            |cipher| decryptor.decrypt(cipher).unwrap(),
        );
    }
}

/// Checks 17 factorized threshold outputs over a 64-message domain.
/// The chosen inputs straddle thresholds (2/3 and 31/32), include endpoints,
/// and revisit zero after other messages to detect stale reusable state.
fn thresholds<T, Table>(context: &TfheContext<T, Table>, seed: u64, name: &str)
where
    T: TorusFftValue,
    Table: FftTable,
{
    // Public setup: 64 padded inputs, 17 thresholds, binary output encoding.
    let modulus = context.parameters().small_lwe().cipher_modulus();
    let value = |m: usize, i: usize| T::as_from(usize::from(m >= (i + 1) * 64 / 18));

    // Client: generate both keys; give only the evaluation key to the server.
    let mut rng = StdRng::seed_from_u64(seed);
    let (client_key, server_key) = context.try_generate_keys(None, &mut rng).unwrap();

    let encryptor = context.encryptor(&client_key).unwrap();
    let decryptor = context.decryptor(&client_key).unwrap();
    let output_codec = ScaledCodec::new(T::as_from(2u32), modulus);
    let mut margin = ErrorMargin::new(name, seed);

    // Server: compile the public thresholds and allocate evaluation storage.
    let ring_codec = ScaledCodec::new(T::as_from(2u32), modulus);
    let program = context
        .compile_factorized_lookup_table_fn(&ring_codec, 64, 17, value)
        .unwrap();
    let mut evaluator = context.factorized_evaluator(&server_key).unwrap();
    let mut outputs = vec![context.allocate_lwe_ciphertext(); 17];

    for m in [0usize, 1, 2, 3, 31, 32, 63, 0] {
        // Client -> server: send one encrypted input for all thresholds.
        let input = encryptor.encrypt_padded(T::as_from(m), &mut rng).unwrap();

        // Server: produce all 17 encrypted results.
        evaluator.apply_lookup_table_to(&input, &program, &mut outputs);

        // Server -> client: decode the binary outputs and check their margins.
        for (i, output) in outputs.iter().enumerate() {
            let phase = decryptor.decrypt_phase(output).unwrap();
            assert_eq!(
                output_codec.decode_value(phase),
                value(m, i),
                "{name},seed={seed},m={m},threshold={i}"
            );
            margin.decoded(
                phase,
                output_codec.encode_value(value(m, i), PlaintextEmbedding::Unsigned),
                modulus,
                2,
            );
        }
    }
    margin.report();
}

/// Selects between two nonconstant GLWEs and checks every GGSW row/level phase.
/// The 0 -> 1 -> 0 sequence also checks output/workspace reuse for CBS and CMux.
fn circuit<T, Table>(context: &TfheContext<T, Table>, seed: u64, name: &str, sparse: bool)
where
    T: TorusFftValue,
    Table: FftTable,
{
    // Client: generate both keys; give only the evaluation key to the server.
    let mut rng = StdRng::seed_from_u64(seed);
    let client_key = ClientKey::generate(context.parameters(), &mut rng);
    let mut generator = KeyGenerator::new(context);
    let server_key = if sparse {
        generator.try_generate_sparse_server_key(
            &client_key,
            3,
            2 * SPARSE_WEIGHT,
            Some(glwe::cbs::<T>()),
            &mut rng,
        )
    } else {
        generator.try_generate_server_key(&client_key, Some(glwe::cbs::<T>()), &mut rng)
    }
    .unwrap();

    // Retain public output metadata for the client-side phase oracle.
    let cbs = server_key.circuit_bootstrap_key().unwrap().parameters();
    let size = cbs.output_size();

    // Client: encrypt both candidate messages; only choices go to the server.
    let encryptor = context.encryptor(&client_key).unwrap();
    let mut accumulator = context.accumulator_client(&client_key).unwrap();
    // Vary all coefficients so CMux cannot pass by selecting only a constant term.
    let messages = [0, 1].map(|offset| {
        (0..N)
            .map(|i| T::as_from((i + offset) % 4))
            .collect::<Vec<_>>()
    });
    let choices = messages
        .each_ref()
        .map(|m| accumulator.encrypt(m, &mut rng));

    // Client: allocate decryption and secret-dependent phase diagnostics.
    let mut decoded = vec![T::ZERO; N];
    let modulus = context.parameters().small_lwe().cipher_modulus();
    let mut phase = Polynomial::<Vec<T>>::zero(N);
    let mut fft = context.new_fft_engine();
    let secret = primus_glwe::FourierGlweSecretKey::from_coeff_secret_key(
        client_key.glwe_secret_key(),
        &mut fft,
    );
    let mut decrypt = primus_glwe::FourierGlweDecryptWorkspace::new(N);
    let mut margin = ErrorMargin::new(name, seed);

    // Server: bind the evaluation key and allocate CBS/CMux outputs locally.
    let mut evaluator = context.circuit_bootstrap_evaluator(&server_key).unwrap();
    let mut control = evaluator.allocate_output();
    let mut selected = context.allocate_accumulator_ciphertext();

    for bit in [0usize, 1, 0] {
        // Client -> server: send the encrypted selection bit.
        let input = encryptor.encrypt_padded(T::as_from(bit), &mut rng).unwrap();

        // Server: derive the control and select without seeing bit or messages.
        evaluator.circuit_bootstrap_to(&input, &mut control);
        evaluator.cmux_to(&control, &choices[0], &choices[1], &mut selected);

        // Server -> client: return the selected ciphertext for decryption.
        accumulator.decrypt_to(&selected, &mut decoded);
        for (i, (&actual, &expected)) in decoded.iter().zip(&messages[bit]).enumerate() {
            assert_eq!(actual, expected, "{name},seed={seed},bit={bit},coeff={i}");
        }

        // Test-only: inspect the intermediate control with the client secret.
        // A normal CBS -> CMux workflow keeps control on the server.
        for (row, glev) in control.iter_glev(size.fourier_glev_len()).enumerate() {
            // GGSW phases are -s_j*bit*gadget_scalar for mask rows; the
            // final body row has bit*gadget_scalar only at coefficient zero.
            let row_secret = client_key.glwe_secret_key().iter().nth(row);
            for (scalar, level) in cbs
                .output_basis()
                .scalar_iter()
                .zip(glev.iter_glwe(size.glwe_size().fourier_glwe_len()))
            {
                secret.phase_to(&level, &mut phase, &mut fft, &mut decrypt);
                let scalar: i128 = scalar.as_into();
                for (i, &actual) in phase.as_ref().iter().enumerate() {
                    let coefficient = row_secret.map_or(i128::from(i == 0), |s| {
                        let v: i128 = s[i].as_into();
                        -v
                    });
                    margin.gadget(actual, coefficient * scalar * bit as i128, modulus, scalar);
                }
            }
        }
    }
    margin.report();
}
