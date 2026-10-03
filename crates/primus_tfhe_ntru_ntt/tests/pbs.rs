use primus_decompose::DecompositionBaseLog;
use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_integer::FheUint;
use primus_lattice::LweDimension;
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::BarrettModulus;
use primus_ntru::NlevParameters;
use primus_ntru::{NtruParameters, SecretKeyDistr};
use primus_ntt::{MonomialNttTable, NttTable, U32NttTable, U64NttTable};
use primus_poly::PolyLength;
use primus_reduce::{ReduceAdd, ReduceSub};
use primus_test_allocations as allocations;
use primus_tfhe::{
    BivariateLookupTable, InterleavedLookupTable, LookupTable, Lwe, ProgrammableBootstrap,
    ProgrammableBootstrapInterleaved,
};
use primus_tfhe_ntru_ntt::{TfheContext, TfheParameters};
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

const N: usize = 128;

fn parameters<T: FheUint>(q: T, distr: SecretKeyDistr, dimension: usize) -> TfheParameters<T> {
    let modulus = BarrettModulus::new(q);
    let lwe = LweParameters::new(
        LweDimension::new(dimension),
        T::as_from(15u32),
        modulus,
        distr,
        0.7,
    );
    let acc = NtruParameters::new(
        N,
        T::as_from(15u32),
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let blind_rotation_basis = ApproxSignedBasis::new(
        acc.cipher_modulus_value(),
        DecompositionBaseLog::new(8),
        None,
    );

    TfheParameters::try_new(
        lwe.into_inner(),
        NlevParameters::try_with_basis(&acc, blind_rotation_basis).unwrap(),
        primus_tfhe_ntru::DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: None,
        },
        0.7,
    )
    .unwrap()
}

fn value<T: FheUint>(input: usize, output: usize) -> T {
    match output {
        0 => T::as_from(input % 4),
        1 => T::as_from(input / 4),
        2 => T::as_from(input),
        _ => T::as_from(7 - input),
    }
}

fn check_context<T: FheUint, TABLE>(context: TfheContext<T, TABLE>)
where
    TABLE: MonomialNttTable<ValueT = T>,
{
    let input_codec = RoundedCodec::new(
        T::as_from(15u32),
        context.parameters().external_lwe().cipher_modulus(),
    );
    let q = context
        .parameters()
        .external_lwe()
        .cipher_modulus_value()
        .unwrap();
    let mut rng = StdRng::seed_from_u64(0x4d41_4e59_5042_5301);
    let (client_key, server_key) = context.try_generate_keys(None, &mut rng).unwrap();
    assert_eq!(
        server_key.input_distribution(),
        context.parameters().external_lwe().secret_key_distr()
    );
    assert_eq!(client_key.external_lwe_dimension(), 4);
    let other_distribution = if server_key.input_distribution().is_binary() {
        SecretKeyDistr::UniformTernary
    } else {
        SecretKeyDistr::UniformBinary
    };
    let incompatible =
        TfheContext::<_, TABLE>::try_from_parameters(parameters(q, other_distribution, 4)).unwrap();
    assert_eq!(
        incompatible.evaluator(&server_key).err(),
        Some(primus_tfhe::TfheEvaluationError::IncompatibleServerKey)
    );
    // Re-import the generated coefficient secrets through the validation path.
    let imported = primus_tfhe_ntru_ntt::KeyGenerator::new(&context)
        .try_generate_server_key(&client_key, None, &mut rng)
        .unwrap();
    assert!(context.evaluator(&imported).is_ok());
    let public = context
        .parameters()
        .try_generate_public_key(client_key.external_lwe_secret_key(), &mut rng)
        .unwrap();
    let public_encryptor = context.public_encryptor(&public, &input_codec).unwrap();
    let encryptor = context
        .encryptor(client_key.external_lwe_secret_key(), &input_codec)
        .unwrap();
    let decryptor = context
        .decryptor(client_key.external_lwe_secret_key(), &input_codec)
        .unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    // Input centers use t_in=15; output values use the independent t_out=8 scale.
    let output_codec = RoundedCodec::new(
        T::as_from(8u32),
        context.parameters().external_lwe().cipher_modulus(),
    );
    let compiler = context
        .parameters()
        .lookup_table_compiler(&input_codec)
        .unwrap()
        .try_with_output_codec(&output_codec)
        .unwrap();
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
                *mask = q / T::as_from(4u32);
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
        let (_, allocation) = allocations::measure(|| {
            evaluator.apply_lookup_table_to(input.as_view(), &single, output.as_mut_view());
        });
        assert_eq!(
            allocation.count, 0,
            "PBS must reuse both accumulator buffers"
        );
        assert_eq!(
            output_codec.decode_value(decryptor.decrypt_phase(output.as_view()).unwrap()),
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
            let (_, allocation) = allocations::measure(|| {
                ProgrammableBootstrapInterleaved::apply_interleaved_lookup_table_to(
                    &mut evaluator,
                    input.as_view(),
                    &lut,
                    &mut outputs,
                );
            });
            assert_eq!(allocation.count, 0, "PBSManyLUT must reuse its workspace");
            if output_count == 3 && message == 3 {
                assert_eq!(
                    outputs,
                    evaluator.apply_interleaved_lookup_table(input.as_view(), &lut)
                );
            }
            for (index, output) in outputs.iter().enumerate() {
                assert_eq!(
                    output_codec.decode_value(decryptor.decrypt_phase(output.as_view()).unwrap()),
                    value(message, index)
                );
            }
            if output_count == 1 && message == 3 {
                // Borrow boxed input and a dirty stack sub-slice. The same
                // PBS must overwrite every coefficient without allocating.
                let input = Lwe::new(input.0.into_boxed_slice());
                let lwe_len = input.lwe_len();
                let mut storage = [T::ONE; N + 3];
                let (_, allocation) = allocations::measure(|| {
                    ProgrammableBootstrap::apply_lookup_table_to(
                        &mut evaluator,
                        input.as_view(),
                        &single,
                        Lwe::new(&mut storage[1..1 + lwe_len]),
                    );
                });
                assert_eq!(allocation.count, 0, "PBS must reuse its workspace");
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
                    output_codec.decode_value(decryptor.decrypt_phase(output.as_view()).unwrap()),
                    value(message, 0)
                );
            }
        }
    }

    // Message encodings belong to programs: reuse one key and PBS workspace
    // at two additional plaintext moduli, including the interleaved path.
    for t in [4u32, 8] {
        let codec = RoundedCodec::new(
            T::as_from(t),
            context.parameters().external_lwe().cipher_modulus(),
        );
        let compiler = context.parameters().lookup_table_compiler(&codec).unwrap();
        let single = compiler.compile_fn(|m| T::as_from(m)).unwrap();
        let many = compiler
            .compile_interleaved_fn(2, |m, _| T::as_from(m))
            .unwrap();
        let input = context
            .encryptor(client_key.external_lwe_secret_key(), &codec)
            .unwrap()
            .encrypt_padded(T::ONE, &mut rng)
            .unwrap();
        let mut outputs = vec![context.allocate_lwe_ciphertext(); 2];
        evaluator.apply_lookup_table_to(input.as_view(), &single, outputs[0].as_mut_view());
        assert_eq!(
            context
                .decryptor(client_key.external_lwe_secret_key(), &codec)
                .unwrap()
                .decrypt(outputs[0].as_view())
                .unwrap(),
            T::ONE
        );
        evaluator.apply_interleaved_lookup_table_to(input.as_view(), &many, &mut outputs);
        for output in outputs {
            assert_eq!(
                context
                    .decryptor(client_key.external_lwe_secret_key(), &codec)
                    .unwrap()
                    .decrypt(output.as_view())
                    .unwrap(),
                T::ONE
            );
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
            BarrettModulus::new(q),
            BarrettModulus::new(q),
            |_| Ok(T::ZERO),
        )
        .unwrap(),
        InterleavedLookupTable::try_new(
            2,
            PolyLength::new(N / 2),
            3,
            T::as_from(15u32),
            BarrettModulus::new(q),
            BarrettModulus::new(q),
            |_, _| Ok(T::ZERO),
        )
        .unwrap(),
    )];

    mismatched_tables.push((
        LookupTable::try_new(
            2,
            PolyLength::new(N),
            T::as_from(15u32),
            primus_modulus::NativeModulus::new(),
            BarrettModulus::new(q),
            |_| Ok(T::ZERO),
        )
        .unwrap(),
        InterleavedLookupTable::try_new(
            2,
            PolyLength::new(N),
            3,
            T::as_from(15u32),
            primus_modulus::NativeModulus::new(),
            BarrettModulus::new(q),
            |_, _| Ok(T::ZERO),
        )
        .unwrap(),
    ));
    mismatched_tables.push((
        LookupTable::try_new(
            2,
            PolyLength::new(N),
            T::as_from(15u32),
            BarrettModulus::new(q),
            BarrettModulus::new(T::as_from(104_857_601u32)),
            |_| Ok(T::ZERO),
        )
        .unwrap(),
        InterleavedLookupTable::try_new(
            2,
            PolyLength::new(N),
            3,
            T::as_from(15u32),
            BarrettModulus::new(q),
            BarrettModulus::new(T::as_from(104_857_601u32)),
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
    // Rejected calls leave the reusable evaluator usable.
    evaluator.apply_interleaved_lookup_table_to(input.as_view(), &good, &mut outputs);
    assert_eq!(
        output_codec.decode_value(decryptor.decrypt_phase(outputs[0].as_view()).unwrap()),
        T::as_from(3u32)
    );
    assert_eq!(
        output_codec.decode_value(decryptor.decrypt_phase(outputs[1].as_view()).unwrap()),
        T::as_from(0u32)
    );
    assert_eq!(
        output_codec.decode_value(decryptor.decrypt_phase(outputs[2].as_view()).unwrap()),
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
        let (_, allocation) = allocations::measure(|| {
            bivariate.pack_to(lhs.as_view(), rhs.as_view(), packed.as_mut_view());
            evaluator.apply_lookup_table_to(
                packed.as_view(),
                bivariate.lookup_table(),
                result.as_mut_view(),
            );
        });
        assert_eq!(allocation.count, 0, "packing and PBS must reuse storage");
        assert_eq!(
            output_codec.decode_value(decryptor.decrypt_phase(result.as_view()).unwrap()),
            x * x + y
        );
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
        let (_, allocation) = allocations::measure(|| {
            evaluator.apply_lookup_table_to(input.as_view(), &full, result.as_mut_view());
        });
        assert_eq!(allocation.count, 0, "full-domain PBS must reuse storage");
        assert_eq!(
            output_codec.decode_value(decryptor.decrypt_phase(result.as_view()).unwrap()),
            expected
        );
    }
}

#[test]
fn pbs_u32_preserves_outputs_and_validates_domains() {
    let q = 132_120_577u32;
    for case in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::fixed_composition_ternary(4, 1, 2),
    ] {
        let table = U32NttTable::new(PolyLength::new(N), BarrettModulus::new(q)).unwrap();
        check_context(TfheContext::try_new(parameters(q, case, 4), table).unwrap());
    }
}

#[test]
fn pbs_u64_preserves_outputs_and_validates_domains() {
    let q = 1_125_899_906_826_241u64;
    for case in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::fixed_composition_ternary(4, 1, 2),
    ] {
        let table = U64NttTable::new(PolyLength::new(N), BarrettModulus::new(q)).unwrap();
        check_context(TfheContext::try_new(parameters(q, case, 4), table).unwrap());
    }
}

// Imported secrets fix the first selector independently of keygen randomness.
fn check_first_controls<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
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
    let mut generator = primus_tfhe_ntru_ntt::KeyGenerator::new(&context);
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
        let client = primus_tfhe_ntru_ntt::ClientKey::new(
            primus_lwe::LweSecretKey::new(
                (coefficients)[..dimension]
                    .iter()
                    .map(|&s| {
                        if s < Default::default() {
                            context
                                .parameters()
                                .external_lwe()
                                .cipher_modulus_minus_one()
                        } else {
                            primus_integer::SignedInteger::cast_to_unsigned(s)
                        }
                    })
                    .collect(),
                distr,
                context.parameters().external_lwe().cipher_modulus(),
            ),
            generated.accumulator_ntru_secret_key().clone(),
        );
        let server = generator
            .try_generate_server_key(&client, None, &mut rng)
            .unwrap();
        let mut evaluator = context.evaluator(&server).unwrap();
        let decryptor = context
            .decryptor(client.external_lwe_secret_key(), &input_codec)
            .unwrap();
        let lut = parameters
            .lookup_table_compiler(&input_codec)
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
                    context
                        .parameters()
                        .external_lwe()
                        .cipher_modulus_value()
                        .unwrap()
                        / T::as_from(4u32)
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
            let (_, allocation) = allocations::measure(|| {
                evaluator.apply_lookup_table_to(input.as_view(), &lut, output.as_mut_view())
            });
            assert_eq!(allocation.count, 0);
            assert_eq!(
                decryptor.decrypt(output.as_view()).unwrap(),
                T::as_from(3u32)
            );
        }
    }
}

#[test]
fn first_controls_cover_secret_values_and_single_coordinate_keys() {
    let q = 132_120_577u32;
    for dimension in [1, 4] {
        for distr in [
            SecretKeyDistr::UniformBinary,
            SecretKeyDistr::UniformTernary,
        ] {
            let context =
                TfheContext::<_, U32NttTable>::try_from_parameters(parameters(q, distr, dimension))
                    .unwrap();
            check_first_controls(context);
        }
    }
}
