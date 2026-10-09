use primus_decompose::DecompositionBaseLog;
use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_fft::{FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_lattice::LweDimension;
use primus_lwe::LweCiphertext;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::SecretKeyDistr;
use primus_poly::PolyLength;
use primus_reduce::{ReduceAdd, ReduceSub};
use primus_tfhe::{
    BivariateLookupTable, InterleavedLookupTable, LookupTable, Lwe, PbsMessageConfig,
    ProgrammableBootstrap, ProgrammableBootstrapInterleaved,
};
use primus_tfhe_ntru_fourier::{
    BlindRotationMethod, GadgetEncryptionConfig, PbsParameters, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

const N: usize = 128;

fn parameters<T: TorusFftValue>(distr: SecretKeyDistr, dimension: usize) -> PbsParameters<T> {
    let modulus = NativeModulus::new();

    PbsParameters::try_from_config(primus_tfhe_ntru::PbsConfig {
        external_lwe: primus_tfhe::LweConfig {
            dimension: LweDimension::new(dimension),
            cipher_modulus: modulus.into(),
            secret_key_distr: distr,
            noise_standard_deviation: 0.7,
        },
        acc_modulus: modulus.into(),
        bsk_poly_length: PolyLength::new(N),
        bsk_secret_distr: SecretKeyDistr::SparseTernary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: primus_tfhe::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: None,
            },
            noise_standard_deviation: 0.7,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: primus_tfhe_ntru::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: None,
            },
            noise_standard_deviation: 0.7,
        },
        algorithm: primus_tfhe::BlindRotationMethod::Classic,
        messages: PbsMessageConfig::new(T::as_from(15u32)).with_output_modulus(T::as_from(8u32)),
    })
    .unwrap()
}

fn value<T: TorusFftValue>(input: usize, output: usize) -> T {
    match output {
        0 => T::as_from(input % 4),
        1 => T::as_from(input / 4),
        2 => T::as_from(input),
        _ => T::as_from(7 - input),
    }
}

fn check_context<T: TorusFftValue, TABLE>(context_parameters: PbsParameters<T>, table: TABLE)
where
    TABLE: FftTable,
{
    let context = TfheContext::try_new(context_parameters.clone(), table).unwrap();
    let input_codec = RoundedCodec::new(
        T::as_from(15u32),
        context.parameters().external_lwe().cipher_modulus(),
    );
    let mut rng = StdRng::seed_from_u64(0x4d41_4e59_5042_5301);
    let (client_key, server_key) = context.try_generate_keys(&mut rng).unwrap();
    assert_eq!(
        server_key.blind_rotation_key().input_distribution(),
        context.parameters().external_lwe().secret_key_distr()
    );
    assert_eq!(client_key.external_lwe_dimension(), 4);
    let other_distribution = if server_key
        .blind_rotation_key()
        .input_distribution()
        .is_binary()
    {
        SecretKeyDistr::UniformTernary
    } else {
        SecretKeyDistr::UniformBinary
    };
    let incompatible_parameters = &parameters(other_distribution, 4);
    let incompatible = TfheContext::<_, TABLE>::from_parameters(incompatible_parameters.clone());
    assert_eq!(
        incompatible.evaluator(&server_key).err(),
        Some(primus_tfhe::TfheEvaluationError::IncompatibleBlindRotationKey)
    );
    // Re-import the generated coefficient secrets through the validation path.
    let imported = primus_tfhe_ntru_fourier::KeyGenerator::new(&context)
        .try_generate_server_key_with_parameters(
            context_parameters.key_switching(),
            &client_key,
            BlindRotationMethod::Classic,
            &mut rng,
        )
        .unwrap();
    assert!(context.evaluator(&imported).is_ok());
    let public = context
        .parameters()
        .try_generate_public_key(client_key.external_lwe_secret_key(), &mut rng)
        .unwrap();
    let public_encryptor = context.public_encryptor(&public).unwrap();
    let encryptor = context
        .encryptor(client_key.external_lwe_secret_key())
        .unwrap();
    let decryptor = context
        .pbs_decryptor(client_key.external_lwe_secret_key())
        .unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    // Input centers use t_in=15; output values use the independent t_out=8 scale.
    let output_codec = RoundedCodec::new(
        T::as_from(8u32),
        context.parameters().external_lwe().cipher_modulus(),
    );
    let compiler = context.pbs_lookup_table_compiler().unwrap();
    let single = compiler.compile_fn(|input| value(input, 0)).unwrap();
    let mut output = LweCiphertext::zero(context.parameters().external_lwe_dimension().get());
    // Noise-free masks exercise first fusion, leading zero and remaining CMUX parity.
    // Reuse the same evaluator across all paths to check the final buffer role.
    let modulus = context.parameters().external_lwe().cipher_modulus();
    for active in [
        0b0000, 0b0001, 0b0011, 0b0111, 0b0010, 0b0110, 0b1000, 0b0001, 0b0000,
    ] {
        let mut input = LweCiphertext::zero(context.parameters().external_lwe_dimension().get());
        for (i, mask) in input.a_mut().iter_mut().enumerate() {
            if active & (1 << i) != 0 {
                *mask = T::ONE << (T::BITS - 2);
            }
        }
        let mut body = input_codec.encode_value(T::as_from(3u32), PlaintextEmbedding::Unsigned);
        for (&mask, &secret) in input
            .a()
            .iter()
            .zip(client_key.external_lwe_secret_key().as_ref())
        {
            if secret == T::ONE {
                body = modulus.reduce_add(body, mask);
            } else if secret
                == context
                    .parameters()
                    .external_lwe()
                    .cipher_modulus_minus_one()
            {
                body = modulus.reduce_sub(body, mask);
            }
        }
        *input.b_mut() = body;
        evaluator.apply_lookup_table_to(input.as_view(), &single, output.as_mut_view());
        assert_eq!(
            decryptor.decrypt(output.as_view()).unwrap(),
            T::as_from(3u32)
        );
    }
    // Shared tests cover geometry; keep output counts 1, 3 (padded to 4), and 4 here.
    for output_count in [1, 3, 4] {
        let flat: Vec<_> = (0..8)
            .flat_map(|input| (0..output_count).map(move |output| value(input, output)))
            .collect();
        let lut = compiler
            .compile_interleaved_slice(output_count, &flat)
            .unwrap();
        let mut outputs =
            vec![
                LweCiphertext::zero(context.parameters().external_lwe_dimension().get());
                output_count
            ];
        for message in [0, 3, 4, 7] {
            let input = encryptor
                .encrypt_padded(T::as_from(message), &mut rng)
                .unwrap();
            ProgrammableBootstrapInterleaved::apply_interleaved_lookup_table_to(
                &mut evaluator,
                input.as_view(),
                &lut,
                &mut outputs,
            );
            if output_count == 3 && message == 3 {
                assert_eq!(
                    outputs,
                    evaluator.apply_interleaved_lookup_table(input.as_view(), &lut)
                );
            }
            for (index, output) in outputs.iter().enumerate() {
                assert_eq!(
                    decryptor.decrypt(output.as_view()).unwrap(),
                    value(message, index)
                );
            }
            if output_count == 1 && message == 3 {
                // Borrow boxed input and a dirty stack sub-slice. The same
                // PBS must overwrite every coefficient in the reused output.
                let input = Lwe::new(input.0.into_boxed_slice());
                let lwe_len = input.lwe_len();
                let mut storage = [T::ONE; N + 3];
                ProgrammableBootstrap::apply_lookup_table_to(
                    &mut evaluator,
                    input.as_view(),
                    &single,
                    Lwe::new(&mut storage[1..1 + lwe_len]),
                );
                assert_eq!(outputs[0].as_ref(), &storage[1..1 + lwe_len]);
                assert_eq!(storage[0], T::ONE);
                assert_eq!(storage[1 + lwe_len], T::ONE);
                assert_eq!(
                    outputs[0],
                    evaluator.apply_lookup_table(input.as_view(), &single)
                );
                let public_input = public_encryptor
                    .encrypt_padded(T::as_from(message), &mut rng)
                    .unwrap();
                evaluator.apply_lookup_table_to(
                    public_input.as_view(),
                    &single,
                    output.as_mut_view(),
                );
                assert_eq!(
                    decryptor.decrypt(output.as_view()).unwrap(),
                    value(message, 0)
                );
            }
        }
    }

    // Message encodings belong to programs: reuse one key and PBS workspace
    // at two additional plaintext moduli, including the interleaved path.
    for t in [4u32, 8] {
        let codecs = context
            .parameters()
            .pbs_codecs(PbsMessageConfig::new(T::as_from(t)))
            .unwrap();
        let compiler = context.parameters().lookup_table_compiler(&codecs).unwrap();
        let decryptor = context
            .parameters()
            .decryptor_with_codec(client_key.external_lwe_secret_key(), codecs.output_codec())
            .unwrap();
        let single = compiler.compile_fn(|m| T::as_from(m)).unwrap();
        let many = compiler
            .compile_interleaved_fn(2, |m, _| T::as_from(m))
            .unwrap();
        let input = context
            .parameters()
            .encryptor_with_codec(client_key.external_lwe_secret_key(), codecs.input_codec())
            .unwrap()
            .encrypt_padded(T::ONE, &mut rng)
            .unwrap();
        let mut outputs = vec![context.allocate_lwe_ciphertext(); 2];
        evaluator.apply_lookup_table_to(input.as_view(), &single, outputs[0].as_mut_view());
        assert_eq!(decryptor.decrypt(outputs[0].as_view()).unwrap(), T::ONE);
        evaluator.apply_interleaved_lookup_table_to(input.as_view(), &many, &mut outputs);
        for output in outputs {
            assert_eq!(decryptor.decrypt(output.as_view()).unwrap(), T::ONE);
        }
    }

    let input = encryptor
        .encrypt_padded(T::as_from(3u32), &mut rng)
        .unwrap();
    let good = compiler.compile_interleaved_fn(3, value).unwrap();
    let mut outputs = vec![input.clone(); 3];
    // Isolate each piece of LUT metadata, including equal-length wrong-domain tables.
    let mut mismatched_tables = vec![(
        LookupTable::try_new(
            2,
            PolyLength::new(N / 2),
            T::as_from(15u32),
            NativeModulus::new(),
            NativeModulus::new(),
            |_| Ok(T::ZERO),
        )
        .unwrap(),
        InterleavedLookupTable::try_new(
            2,
            PolyLength::new(N / 2),
            3,
            T::as_from(15u32),
            NativeModulus::new(),
            NativeModulus::new(),
            |_, _| Ok(T::ZERO),
        )
        .unwrap(),
    )];

    mismatched_tables.push((
        LookupTable::try_new(
            2,
            PolyLength::new(N),
            T::as_from(15u32),
            BarrettModulus::new(T::as_from(132_120_577u32)),
            NativeModulus::new(),
            |_| Ok(T::ZERO),
        )
        .unwrap(),
        InterleavedLookupTable::try_new(
            2,
            PolyLength::new(N),
            3,
            T::as_from(15u32),
            BarrettModulus::new(T::as_from(132_120_577u32)),
            NativeModulus::new(),
            |_, _| Ok(T::ZERO),
        )
        .unwrap(),
    ));
    mismatched_tables.push((
        LookupTable::try_new(
            2,
            PolyLength::new(N),
            T::as_from(15u32),
            NativeModulus::new(),
            BarrettModulus::new(T::as_from(132_120_577u32)),
            |_| Ok(T::ZERO),
        )
        .unwrap(),
        InterleavedLookupTable::try_new(
            2,
            PolyLength::new(N),
            3,
            T::as_from(15u32),
            NativeModulus::new(),
            BarrettModulus::new(T::as_from(132_120_577u32)),
            |_, _| Ok(T::ZERO),
        )
        .unwrap(),
    ));
    for (single, many) in mismatched_tables {
        let before = outputs.clone();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                evaluator.apply_lookup_table_to(input.as_view(), &single, outputs[0].as_mut_view());
            }))
            .is_err()
        );
        assert_eq!(outputs, before);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                evaluator.apply_interleaved_lookup_table_to(input.as_view(), &many, &mut outputs);
            }))
            .is_err()
        );
        assert_eq!(outputs, before);
    }
    let wrong = LweCiphertext::zero(input.dimension() - 1);
    for bad_input in [false, true] {
        let mut output = if bad_input {
            input.clone()
        } else {
            wrong.clone()
        };
        let before = output.clone();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                evaluator.apply_lookup_table_to(
                    if bad_input {
                        wrong.as_view()
                    } else {
                        input.as_view()
                    },
                    &single,
                    output.as_mut_view(),
                );
            }))
            .is_err()
        );
        assert_eq!(output, before);
    }
    // Four physical slots still require exactly three output ciphertexts.
    for case in 0..3 {
        let mut outputs = vec![input.clone(); if case == 0 { 4 } else { 3 }];
        if case == 1 {
            outputs[1] = wrong.clone();
        }
        let before = outputs.clone();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                evaluator.apply_interleaved_lookup_table_to(
                    if case == 2 {
                        wrong.as_view()
                    } else {
                        input.as_view()
                    },
                    &good,
                    &mut outputs,
                );
            }))
            .is_err()
        );
        assert_eq!(outputs, before);
    }
    // Rejected calls and message overrides leave the evaluator and original decoder usable.
    evaluator.apply_interleaved_lookup_table_to(input.as_view(), &good, &mut outputs);
    assert_eq!(
        decryptor.decrypt(outputs[0].as_view()).unwrap(),
        T::as_from(3u32)
    );
    assert_eq!(
        decryptor.decrypt(outputs[1].as_view()).unwrap(),
        T::as_from(0u32)
    );
    assert_eq!(
        decryptor.decrypt(outputs[2].as_view()).unwrap(),
        T::as_from(3u32)
    );

    // A non-power-of-two base and short domain share the same keys and PBS scratch.
    let bivariate = BivariateLookupTable::try_new(
        3,
        2,
        PolyLength::new(N),
        &input_codec,
        &output_codec,
        |x, y| T::as_from(x * x + y),
    )
    .unwrap();
    let mut packed = input.clone();
    let mut result = input;
    for (x, y) in [(T::as_from(2u32), T::ONE), (T::ONE, T::ZERO)] {
        let lhs = encryptor.encrypt_padded(x, &mut rng).unwrap();
        let rhs = encryptor.encrypt_padded(y, &mut rng).unwrap();
        bivariate.pack_to(lhs.as_view(), rhs.as_view(), packed.as_mut_view());
        evaluator.apply_lookup_table_to(
            packed.as_view(),
            bivariate.lookup_table(),
            result.as_mut_view(),
        );
        assert_eq!(decryptor.decrypt(result.as_view()).unwrap(), x * x + y);
    }

    // Reuse this odd-modulus fixture for the full domain, including the upper
    // half. Keep a distinct output scale and a function with f(0) != 0.
    let values: Vec<_> = (0..15).map(|m| T::as_from((m * m + 3) % 8)).collect();
    let full = compiler.compile_odd_full_domain_slice(&values).unwrap();
    // The shared LUT oracle covers all rotations. Encrypted evaluations keep
    // both sides of the fold, the final message and zero after dirty reuse.
    for message in [0, 1, 7, 8, 14, 0] {
        let expected = values[message];
        let input = encryptor.encrypt(T::as_from(message), &mut rng).unwrap();
        evaluator.apply_lookup_table_to(input.as_view(), &full, result.as_mut_view());
        assert_eq!(decryptor.decrypt(result.as_view()).unwrap(), expected);
    }
}

#[test]
fn pbs_u32_preserves_outputs_and_validates_domains() {
    for case in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::fixed_composition_ternary(4, 1, 2),
    ] {
        check_context(
            parameters::<u32>(case, 4),
            RustFftTable::new(PolyLength::new(N)),
        );
        check_context(
            parameters::<u32>(case, 4),
            TfheFftTable::new(PolyLength::new(N)),
        );
    }
}

#[test]
fn pbs_u64_preserves_outputs_and_validates_domains() {
    for case in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::fixed_composition_ternary(4, 1, 2),
    ] {
        check_context(
            parameters::<u64>(case, 4),
            RustFftTable::new(PolyLength::new(N)),
        );
        check_context(
            parameters::<u64>(case, 4),
            TfheFftTable::new(PolyLength::new(N)),
        );
    }
}

// Imported secrets fix the first selector independently of keygen randomness.
fn check_first_controls<T: TorusFftValue, Table: FftTable>(
    context_parameters: &PbsParameters<T>,
    context: TfheContext<T, Table>,
) {
    let input_codec = RoundedCodec::new(
        T::as_from(15u32),
        context.parameters().external_lwe().cipher_modulus(),
    );
    let parameters = context.parameters();
    let dimension = parameters.external_lwe_dimension().get();
    let distr = parameters.external_lwe().secret_key_distr();
    let mut rng = StdRng::seed_from_u64(0x4649_5253_545f_4252);
    let mut generator = primus_tfhe_ntru_fourier::KeyGenerator::new(&context);
    let generated = generator.try_generate_client_key(&mut rng).unwrap();
    for first in [
        T::ZERO.cast_to_signed(),
        T::ONE.cast_to_signed(),
        -T::ONE.cast_to_signed(),
    ] {
        if distr.is_binary() && first == -T::ONE.cast_to_signed() {
            continue;
        }
        let mut coefficients = vec![T::ZERO.cast_to_signed(); dimension];
        coefficients[0] = first;
        if dimension > 1 {
            coefficients[1] = T::ONE.cast_to_signed();
            if first != T::ZERO.cast_to_signed() {
                coefficients[2] = T::ONE.cast_to_signed();
            }
        }
        let client = primus_tfhe_ntru_fourier::ClientKey::new(
            primus_lwe::LweSecretKey::new(
                (coefficients)[..dimension]
                    .iter()
                    .map(|&s| primus_integer::SignedInteger::cast_to_unsigned(s))
                    .collect(),
                distr,
                context.parameters().external_lwe().cipher_modulus(),
            ),
            generated.accumulator_ntru_secret_key().clone(),
        );
        let server = generator
            .try_generate_server_key_with_parameters(
                context_parameters.key_switching(),
                &client,
                BlindRotationMethod::Classic,
                &mut rng,
            )
            .unwrap();
        let mut evaluator = context.evaluator(&server).unwrap();
        let decryptor = context
            .pbs_decryptor(client.external_lwe_secret_key())
            .unwrap();
        let lut = context
            .pbs_lookup_table_compiler()
            .unwrap()
            .compile_fn(|m| T::as_from((m + 1) % 8))
            .unwrap();
        let modulus = parameters.external_lwe().cipher_modulus();
        let mut input = LweCiphertext::zero(dimension);
        let mut output = input.clone();
        for active in [0b0001, 0b0010, 0b0011, 0b0110, 0b0111, 0b0000, 0b0001] {
            let mut body = input_codec.encode_value(T::as_from(2u32), PlaintextEmbedding::Unsigned);
            for (i, (mask, &secret)) in input
                .a_mut()
                .iter_mut()
                .zip(client.external_lwe_secret_key().as_ref())
                .enumerate()
            {
                *mask = if active & (1 << i) != 0 {
                    T::ONE << (T::BITS - 2)
                } else {
                    T::ZERO
                };
                if secret == T::ONE {
                    body = modulus.reduce_add(body, *mask);
                } else if secret
                    == context
                        .parameters()
                        .external_lwe()
                        .cipher_modulus_minus_one()
                {
                    body = modulus.reduce_sub(body, *mask);
                }
            }
            *input.b_mut() = body;
            evaluator.apply_lookup_table_to(input.as_view(), &lut, output.as_mut_view());
            assert_eq!(
                decryptor.decrypt(output.as_view()).unwrap(),
                T::as_from(3u32)
            );
        }
    }
}

#[test]
fn first_controls_cover_secret_values_and_single_coordinate_keys() {
    for dimension in [1, 4] {
        for distr in [
            SecretKeyDistr::UniformBinary,
            SecretKeyDistr::UniformTernary,
        ] {
            let params = parameters(distr, dimension).with_messages(PbsMessageConfig::new(15));
            check_first_controls(
                &params,
                TfheContext::<u32, RustFftTable>::from_parameters(params.clone()),
            );
            check_first_controls(
                &params,
                TfheContext::<u32, TfheFftTable>::from_parameters(params.clone()),
            );
        }
    }
}
