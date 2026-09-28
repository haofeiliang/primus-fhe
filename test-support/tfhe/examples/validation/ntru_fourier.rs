//! NTRU Fourier parameter checks: Q is the native torus modulus 2^T::BITS.
//! The external LWE uses an independent q=2^24; only ring values enter the transform.

use super::metrics::ErrorMargin;
use primus_encoding::{PlaintextEmbedding, RoundedCodec, ScaledCodec};
use primus_fft::{FftTable, TorusFftValue};
use primus_glwe::SecretKeyDistr;
use primus_integer::AsInto;
use primus_modulus::{NativeModulus, PowOf2Modulus};
use primus_tfhe_ntru_fourier::{ClientKey, KeyGenerator, ServerKey, TfheContext};
use primus_tfhe_ntru_lut::{
    FourierLookupTableEvaluator, HighPrecisionLookupTable, LookupTableConfig,
};
use primus_tfhe_test_support::parameters::{N, ntru};
use primus_tfhe_test_support::{benchmark::PBS_WORKLOADS, parameters::SPARSE_WEIGHT};
use rand::{SeedableRng, rngs::StdRng};

/// Runs binary/ternary classic profiles; fixed-weight diagnostics run once per seed.
pub fn validate<T: TorusFftValue, Table: FftTable>(seed: u64, name: &str) {
    let modulus = NativeModulus::new();
    for secret in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::UniformTernary,
    ] {
        eprintln!("checking {name}, seed={seed}, secret={secret:?}");
        validate_secret::<T, Table>(modulus, seed, secret, name);
    }
}

/// Selects PBS, sparse/MVB and circuit/lookup profiles for one external secret.
fn validate_secret<T: TorusFftValue, Table: FftTable>(
    modulus: NativeModulus<T>,
    seed: u64,
    secret: SecretKeyDistr,
    name: &str,
) {
    let name = &format!("{name}/{secret:?}");
    for workload in PBS_WORKLOADS {
        let context = TfheContext::<T, Table, PowOf2Modulus<T>>::try_from_parameters(ntru::pbs(
            modulus, workload, secret,
        ))
        .unwrap();
        pbs(&context, seed, &format!("{name}/{}", workload.name), false);
    }
    // Fixed-weight keys have their own binary distribution. Run them once,
    // instead of repeating identical diagnostics in the ternary branch.
    if secret == SecretKeyDistr::UniformBinary {
        let context = TfheContext::<T, Table, PowOf2Modulus<T>>::try_from_parameters(
            ntru::diagnostic(modulus, 16),
        )
        .unwrap();
        pbs(&context, seed, &format!("{name}/fixed_weight"), false);
        pbs(&context, seed, &format!("{name}/sparse"), true);
        let context = TfheContext::<T, Table, PowOf2Modulus<T>>::try_from_parameters(
            ntru::diagnostic(modulus, 128),
        )
        .unwrap();
        thresholds(&context, seed, &format!("{name}/mvb"));
    }
    circuit::<T, Table>(modulus, seed, secret, &format!("{name}/cbs"));
    one_hot_and_lookup::<T, Table>(modulus, seed, secret, name);
}

/// Shares one t=8 key setup between selector-phase checks and complete lookup.
/// Both checks consume one seeded RNG stream in order; keys are generated once.
fn one_hot_and_lookup<T: TorusFftValue, Table: FftTable>(
    modulus: NativeModulus<T>,
    seed: u64,
    secret: SecretKeyDistr,
    name: &str,
) {
    // Public setup: both checks use the same t=8 parameters and transform table.
    let parameters = ntru::circuit(modulus, 8, secret);
    let context =
        TfheContext::<T, Table, PowOf2Modulus<T>>::try_from_parameters(parameters).unwrap();

    // Client: generate both keys once; keep the secret key and RNG local.
    let mut rng = StdRng::seed_from_u64(seed);
    let (client_key, server_key) = context
        .try_generate_keys(Some(ntru::cbs::<T>()), &mut rng)
        .unwrap();

    // Test driver: run both roles with the same keys and sampling stream.
    // rotation_step is public LUT geometry, reused by client-side diagnostics.
    let rotation_step = one_hot(&context, &client_key, &server_key, &mut rng, name, seed);
    lookup(
        &context,
        &client_key,
        &server_key,
        rotation_step,
        &mut rng,
        name,
        seed,
    );
}

/// Checks every coefficient and gadget level of all four one-hot NGSWs.
/// Returns the packed LUT rotation step for the subsequent input-guard checks.
fn one_hot<T: TorusFftValue, Table: FftTable>(
    context: &TfheContext<T, Table, PowOf2Modulus<T>>,
    client_key: &ClientKey<T>,
    server_key: &ServerKey<T>,
    rng: &mut StdRng,
    name: &str,
    seed: u64,
) -> usize {
    // Public setup: selectors use the accumulator modulus and CBS output basis.
    let modulus = context.parameters().accumulator_ntru().cipher_modulus();

    // Client: prepare encryption and secret-dependent phase diagnostics.
    let encryptor = context.encryptor(client_key).unwrap();
    let format_name = format!("{name}/one_hot");
    let mut phase = primus_poly::Polynomial::<Vec<T>>::zero(N);
    let mut fft = context.new_fft_engine();
    let ring_secret = primus_ntru::FourierNtruSecretKey::try_from_coeff_secret_key(
        client_key.accumulator_ntru_secret_key(),
        &mut fft,
    )
    .unwrap();
    let mut decrypt = primus_ntru::FourierNtruDecryptWorkspace::new(N);
    let mut margin = ErrorMargin::new(&format_name, seed);
    // The client already knows these public parameters from key generation.
    let scalars: Vec<_> = server_key
        .circuit_bootstrap_key()
        .unwrap()
        .parameters()
        .output_basis()
        .scalar_iter()
        .collect();

    // Server: allocate the one-hot evaluator and encrypted selector storage.
    let mut one_hot =
        primus_tfhe_ntru_fourier::OneHotCircuitBootstrapEvaluator::try_new(context, server_key)
            .unwrap();
    let mut selectors = one_hot.allocate_ngsw_output();

    // Public LUT metadata needed by the client-side rotation guard.
    let rotation_step = one_hot.lookup_table().rotation_step();

    // Cover all selectors, including r=0, and overwrite previous nonzero results.
    for message in [0usize, 3, 1, 2, 0] {
        // Client: encrypt the message and check its quantized phase locally.
        let input = encryptor.encrypt_padded(T::as_from(message), rng).unwrap();
        // This diagnostic requires the secret; it is not a server precheck.
        super::metrics::one_hot_guard(
            &input,
            client_key.external_lwe_secret_key().as_ref(),
            context.parameters().external_lwe().cipher_modulus(),
            message,
            N,
            rotation_step,
            4,
            name,
            seed,
        );

        // Client -> server: send input; the server derives all encrypted selectors.
        one_hot.one_hot_ngsw_to(&input, &mut selectors);

        // Test-only server -> client: expose selectors for private phase checks.
        // Lookup evaluation normally consumes them entirely on the server.
        // The packed output is [selector][gadget level][polynomial]. Its raw
        // phase is f*gadget_scalar for the selected index and zero otherwise.
        for (j, row) in primus_poly::FourierPolynomialIter::new(&selectors, N / 2).enumerate() {
            let scalar: i128 = scalars[j % scalars.len()].as_into();
            ring_secret.phase_to(
                &primus_ntru::FourierNtruCiphertext::new(row.as_ref()),
                &mut phase,
                &mut fft,
                &mut decrypt,
            );
            for (&actual, &f) in phase
                .as_ref()
                .iter()
                .zip(client_key.accumulator_ntru_secret_key().as_slice())
            {
                let f: i128 = f.as_into();
                let expected = if j / scalars.len() == message {
                    scalar * f
                } else {
                    0
                };
                margin.gadget(actual, expected, modulus, scalar);
            }
        }
    }
    margin.report();
    rotation_step
}

/// Checks seven input chunks -> three output chunks through table selection,
/// multi-input blind rotation and Q-to-q return, with a fixed decoding margin.
fn lookup<T: TorusFftValue, Table: FftTable>(
    context: &TfheContext<T, Table, PowOf2Modulus<T>>,
    client_key: &ClientKey<T>,
    server_key: &ServerKey<T>,
    rotation_step: usize,
    rng: &mut StdRng,
    name: &str,
    seed: u64,
) {
    // Public setup: agree on chunk layout and the function to evaluate.
    // M^d=N fills the ring. Two further chunks exercise both public and encrypted
    // table selection; three outputs are independent of the seven input chunks.
    let config = LookupTableConfig {
        input_chunk_count: 7,
        coefficient_chunk_count: 5,
        output_chunk_count: 3,
    };
    // A nonlinear full-input oracle couples low and high chunks; each output
    // is one base-four digit of its low six bits.
    let digit =
        |x: usize, i: usize| T::as_from(((x * x + 3 * x + x / 17 + x / 257 + 7) >> (2 * i)) & 3);

    // Client: keep encryption, decryption and the error budget local.
    let encryptor = context.encryptor(client_key).unwrap();
    let decryptor = context.decryptor(client_key).unwrap();
    // This profile uses q=2^24 and padded t=8, so Delta=q/8. The accepted
    // error is Delta/4, half the decoding radius, in external LWE units.
    const LWE_MODULUS: u64 = 1 << 24;
    const ENCODING_SCALE: u64 = LWE_MODULUS / 8;
    const ERROR_LIMIT: u64 = ENCODING_SCALE / 4;
    let mut max_error = 0u64;

    // Server: compile the public function and allocate the evaluator and outputs.
    let table = HighPrecisionLookupTable::try_new(context.parameters(), config, digit).unwrap();
    let mut evaluator = FourierLookupTableEvaluator::try_new(context, server_key, &table).unwrap();
    let mut output = evaluator.allocate_output();

    // N-1/N crosses a table boundary; the maximum input exercises all chunks.
    for x in [0usize, 1, N - 1, N, 0x1234, (1 << 14) - 1, 0] {
        // Client: encrypt each base-four digit; keep the full input x private.
        let input: Vec<_> = (0..config.input_chunk_count)
            .map(|i| {
                encryptor
                    .encrypt_padded(T::as_from((x >> (2 * i)) & 3), rng)
                    .unwrap()
            })
            .collect();

        // Client-only diagnostic: the input guard needs the LWE secret.
        for (i, chunk) in input.iter().enumerate() {
            let message = (x >> (2 * i)) & 3;
            super::metrics::one_hot_guard(
                chunk,
                client_key.external_lwe_secret_key().as_ref(),
                context.parameters().external_lwe().cipher_modulus(),
                message,
                N,
                rotation_step,
                4,
                name,
                seed,
            );
        }

        // Client -> server: send only the chunks; lookup uses no plaintext x.
        evaluator.evaluate_to(&input, &mut output);

        // Server -> client: return the encrypted output chunks for local checks.
        for (i, result) in output.iter().enumerate() {
            assert_eq!(
                decryptor.decrypt(result).unwrap(),
                digit(x, i),
                "{name}, seed={seed}, x={x}, output={i}"
            );
            let phase: u64 = decryptor.decrypt_phase(result).unwrap().as_into();
            let expected: u64 = digit(x, i).as_into();
            let distance = (phase + LWE_MODULUS - expected * ENCODING_SCALE) % LWE_MODULUS;
            max_error = max_error.max(distance.min(LWE_MODULUS - distance));
        }
    }

    // Fixed before experiments: reserve at least half the decoding radius.
    assert!(max_error < ERROR_LIMIT, "{name}: lookup error={max_error}");
    println!(
        "{name},seed={seed},lookup,max_error={max_error},limit={}",
        ERROR_LIMIT
    );
}

/// Checks padded-domain endpoints, modular-affine PBS, three interleaved LUTs
/// and repeated output/workspace use. The Boolean profile also chains gate outputs.
fn pbs<T: TorusFftValue, Table: FftTable>(
    context: &TfheContext<T, Table, PowOf2Modulus<T>>,
    seed: u64,
    name: &str,
    sparse: bool,
) {
    // Public setup: agree on the padded domain and the functions to evaluate.
    let modulus = context.parameters().external_lwe().cipher_modulus();
    let t = context.parameters().plain_modulus_value();
    let domain: usize = t.as_into();
    // Padded inputs occupy only the first half of the plaintext domain.
    let domain = domain / 2;
    let value = |m: usize| T::as_from((3 * m + 1) % domain);

    // Client: generate both keys; give only the evaluation key to the server.
    let mut rng = StdRng::seed_from_u64(seed);
    let mut generator = KeyGenerator::new(context);
    let client_key = generator.try_generate_client_key(&mut rng).unwrap();
    let server_key = if sparse {
        generator.try_generate_sparse_server_key(&client_key, 3, 2 * SPARSE_WEIGHT, &mut rng)
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
    // For Boolean profiles the midpoint and final value both equal 1.
    // Keep one nonzero evaluation followed by zero to check workspace reuse.
    let messages: &[usize] = if domain == 2 {
        &[0, 1, 0]
    } else {
        &[0, 1, domain / 2, domain - 1, 0]
    };
    for &m in messages {
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
fn thresholds<T: TorusFftValue, Table: FftTable>(
    context: &TfheContext<T, Table, PowOf2Modulus<T>>,
    seed: u64,
    name: &str,
) {
    // Public setup: 64 padded inputs, 17 thresholds, binary output encoding.
    let modulus = context.parameters().external_lwe().cipher_modulus();
    let value = |m: usize, i: usize| T::as_from(usize::from(m >= (i + 1) * 64 / 18));

    // Client: generate both keys; give only the evaluation key to the server.
    let mut rng = StdRng::seed_from_u64(seed);
    let (client_key, server_key) = context.try_generate_keys(None, &mut rng).unwrap();

    let encryptor = context.encryptor(&client_key).unwrap();
    let decryptor = context.decryptor(&client_key).unwrap();
    let output_codec = ScaledCodec::new(T::as_from(2u32), modulus);
    let mut margin = ErrorMargin::new(name, seed);

    // Server: compile the public thresholds and allocate evaluation storage.
    // The LUT is encoded at ring Q, but returned phases are decoded at LWE q.
    let ring_codec = ScaledCodec::new(
        T::as_from(2u32),
        context.parameters().accumulator_ntru().cipher_modulus(),
    );
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

/// Checks ordinary t=4 CBS separately from t=8 one-hot: each NGSW level must
/// encrypt bit*f*gadget_scalar, and CMux must select the entire nonconstant message.
fn circuit<T: TorusFftValue, Table: FftTable>(
    modulus: NativeModulus<T>,
    seed: u64,
    secret: SecretKeyDistr,
    name: &str,
) {
    // Public setup: ordinary CBS uses t=4; one-hot uses a separate t=8 profile.
    let context = TfheContext::<T, Table, PowOf2Modulus<T>>::try_from_parameters(ntru::circuit(
        modulus, 4, secret,
    ))
    .unwrap();

    // Client: generate both keys; give only the evaluation key to the server.
    let mut rng = StdRng::seed_from_u64(seed);
    let (client_key, server_key) = context
        .try_generate_keys(Some(ntru::cbs::<T>()), &mut rng)
        .unwrap();

    // Retain public output metadata for the client-side phase oracle.
    let cbs_parameters = server_key.circuit_bootstrap_key().unwrap().parameters();

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
    let mut phase = primus_poly::Polynomial::<Vec<T>>::zero(N);
    let mut margin = ErrorMargin::new(name, seed);
    let mut fft = context.new_fft_engine();
    let ring_secret = primus_ntru::FourierNtruSecretKey::try_from_coeff_secret_key(
        client_key.accumulator_ntru_secret_key(),
        &mut fft,
    )
    .unwrap();
    let mut decrypt = primus_ntru::FourierNtruDecryptWorkspace::new(N);

    // Server: bind the evaluation key and allocate CBS/CMux outputs locally.
    let mut cbs = context.circuit_bootstrap_evaluator(&server_key).unwrap();
    let mut control = cbs.allocate_output();
    let mut selected = context.allocate_accumulator_ciphertext();

    for bit in [0usize, 1, 0] {
        // Client -> server: send the encrypted selection bit.
        let input = encryptor.encrypt_padded(T::as_from(bit), &mut rng).unwrap();

        // Server: derive the control and select without seeing bit or messages.
        cbs.circuit_bootstrap_to(&input, &mut control);
        cbs.cmux_to(&control, &choices[0], &choices[1], &mut selected);

        // Server -> client: return the selected ciphertext for decryption.
        accumulator.decrypt_to(&selected, &mut decoded);
        for (i, (&actual, &expected)) in decoded.iter().zip(&messages[bit]).enumerate() {
            assert_eq!(
                actual, expected,
                "{name},seed={seed},CBS bit={bit},coeff={i}"
            );
        }

        // Test-only: inspect the intermediate control with the client secret.
        // A normal CBS -> CMux workflow keeps control on the server.
        for (scalar, row) in cbs_parameters
            .output_basis()
            .scalar_iter()
            .zip(control.iter_ntru(N / 2))
        {
            ring_secret.phase_to(&row, &mut phase, &mut fft, &mut decrypt);
            let scalar: i128 = scalar.as_into();
            for (&actual, &f) in phase
                .as_ref()
                .iter()
                .zip(client_key.accumulator_ntru_secret_key().as_slice())
            {
                let f: i128 = f.as_into();
                margin.gadget(actual, scalar * f * bit as i128, modulus, scalar);
            }
        }
    }

    margin.report();
}
