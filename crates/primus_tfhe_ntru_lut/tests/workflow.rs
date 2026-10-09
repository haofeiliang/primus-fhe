//! Small complete workflows cover integer clients, optional lift material and key reuse.
#![cfg(any(feature = "ntt", feature = "rustfft", feature = "tfhe-fft"))]

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_integer::FheUint;
use primus_lattice::LweDimension;
use primus_modulus::PowOf2Modulus;
use primus_ntru::SecretKeyDistr;
use primus_poly::PolyLength;
use primus_reduce::RingContext;
use primus_tfhe::{BlindRotationMethod, LweCiphertext, PbsMessageConfig};
use primus_tfhe_ntru::{
    CbsConfig, CbsGadgetConfig, DecompositionConfig, GadgetEncryptionConfig, PbsConfig,
};
use primus_tfhe_ntru_lut::{
    HighPrecLutClientError, HighPrecLutConfig, HighPrecLutDecryptor, HighPrecLutEncryptor,
    LookupTableError,
};
use rand::{Rng, SeedableRng, rngs::StdRng};

/// Keep full precision in BR/trace/return and three selector output levels.
fn config<T: FheUint, M: RingContext<T>>(
    modulus: M,
    sparse: bool,
) -> HighPrecLutConfig<T, M, PowOf2Modulus<T>> {
    let full = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };
    let gadget = GadgetEncryptionConfig {
        decomposition: full,
        noise_standard_deviation: 0.7,
    };
    HighPrecLutConfig {
        one_hot: CbsConfig {
            pbs: PbsConfig {
                external_lwe: primus_tfhe::LweConfig {
                    dimension: LweDimension::new(4),
                    cipher_modulus: PowOf2Modulus::new(T::ONE << 24u32).into(),
                    secret_key_distr: SecretKeyDistr::fixed_hamming_weight_binary(4, 2),
                    noise_standard_deviation: 0.7,
                },
                acc_modulus: modulus.into(),
                bsk_poly_length: PolyLength::new(64),
                bsk_secret_distr: SecretKeyDistr::SparseTernary,
                bsk_gadget: gadget,
                key_switching: gadget,
                algorithm: if sparse {
                    BlindRotationMethod::Sparse {
                        copy_count: 3,
                        bucket_count: 8,
                    }
                } else {
                    BlindRotationMethod::Classic
                },
                messages: PbsMessageConfig::new(T::as_from(8u32)),
            },
            gadget: CbsGadgetConfig {
                output: DecompositionConfig {
                    log_basis: DecompositionBaseLog::new(if T::BITS == 32 { 4 } else { 8 }),
                    level_count: Some(DecompositionLevelCount::new(3)),
                },
                trace: full,
                scheme_switch: full,
            },
        },
        input_chunk_count: 3,
        output_chunk_count: if sparse { 1 } else { 40 },
        coefficient_chunk_count: if sparse { Some(1) } else { None },
    }
}

/// Checks failure before writes/RNG, then compares integer and direct chunk encryption.
fn check_client_requests<T: FheUint>(
    encryptor: &HighPrecLutEncryptor<'_, T, PowOf2Modulus<T>>,
    decryptor: &HighPrecLutDecryptor<'_, T, PowOf2Modulus<T>>,
) {
    let mut input = encryptor.allocate_input();
    let before = input.clone();
    let mut rng = StdRng::seed_from_u64(0xBAD);
    let mut untouched = StdRng::seed_from_u64(0xBAD);
    assert!(matches!(
        encryptor.encrypt_to(64u64, &mut input, &mut rng),
        Err(HighPrecLutClientError::ValueOutOfRange)
    ));
    let last = input.len() - 1;
    input[last] = LweCiphertext::new(vec![T::ZERO; 2]);
    let malformed = input.clone();
    assert!(encryptor.encrypt_to(63u64, &mut input, &mut rng).is_err());
    assert_eq!(input, malformed);
    input = before.clone();
    assert!(matches!(
        encryptor.encrypt_to(63u64, &mut input[..last], &mut rng),
        Err(HighPrecLutClientError::ChunkCountMismatch { .. })
    ));
    assert!(matches!(
        encryptor.encrypt_chunks_to(&[T::ZERO, T::ZERO, T::as_from(4u32)], &mut input, &mut rng),
        Err(HighPrecLutClientError::ChunkOutOfRange { index: 2 })
    ));
    assert_eq!(input, before);
    assert_eq!(rng.next_u64(), untouched.next_u64());
    assert!(decryptor.decrypt::<u128>(&input[..last]).is_err());

    let mut first_rng = StdRng::seed_from_u64(51);
    let mut second_rng = StdRng::seed_from_u64(51);
    let mut chunks = encryptor.allocate_input();
    encryptor
        .encrypt_to(63u64, &mut input, &mut first_rng)
        .unwrap();
    encryptor
        .encrypt_chunks_to(&[T::as_from(3u32); 3], &mut chunks, &mut second_rng)
        .unwrap();
    assert_eq!(input, chunks);
    assert_eq!(first_rng.next_u64(), second_rng.next_u64());
}

/// Reuse both buffers across nonzero/zero requests; decoded words have a separate width.
fn exercise<T: FheUint>(
    encryptor: &HighPrecLutEncryptor<'_, T, PowOf2Modulus<T>>,
    decryptor: &HighPrecLutDecryptor<'_, T, PowOf2Modulus<T>>,
    mut output: Vec<LweCiphertext<T>>,
    function: impl Fn(u128) -> u128,
    mut evaluate: impl FnMut(&[LweCiphertext<T>], &mut [LweCiphertext<T>]),
) {
    check_client_requests(encryptor, decryptor);
    let mut input = encryptor.allocate_input();
    let mut rng = StdRng::seed_from_u64(43);
    for value in [63u64, 0] {
        encryptor.encrypt_to(value, &mut input, &mut rng).unwrap();
        evaluate(&input, &mut output);
        assert_eq!(
            decryptor.decrypt::<u128>(&output).unwrap(),
            function(value as u128)
        );
    }
    let mut digits = vec![T::ZERO; output.len()];
    decryptor.decrypt_chunks_to(&output, &mut digits).unwrap();
    if output.len() == 40 {
        assert!(matches!(
            decryptor.decrypt::<u64>(&output),
            Err(HighPrecLutClientError::WordCapacity {
                required: 80,
                available: 64
            })
        ));
        assert_eq!(digits[39], T::ONE);
    }
    // A trivial ciphertext at q/2 decodes to padded digit M. Do not mask it into 0.
    let last = output.last_mut().unwrap();
    last.as_mut().fill(T::ZERO);
    *last.as_mut().last_mut().unwrap() = T::ONE << 23u32;
    assert!(matches!(
        decryptor.decrypt::<u128>(&output),
        Err(HighPrecLutClientError::ChunkOutOfRange { .. })
    ));
}

#[cfg(feature = "ntt")]
#[test]
fn ntt_integer_workflow_and_sparse_lift_requirements() {
    use primus_modulus::BarrettModulus;
    use primus_tfhe_ntru_lut::{NttHighPrecLutContext, NttHighPrecLutServerKey};
    // u32 coefficients with up to 80 cleartext bits; coefficient width is not value width.
    for sparse in [false, true] {
        let context = NttHighPrecLutContext::<u32, primus_ntt::U32NttTable, _>::try_from_config(
            config(BarrettModulus::new(998_244_353u32), sparse),
        )
        .unwrap();
        let table = if sparse {
            context
                .compile_fn(|x: u128| ((x >> 2) + (x & 3)) & 3)
                .unwrap()
        } else {
            context.compile_fn(|x: u128| (1u128 << 78) | x).unwrap()
        };
        assert_eq!(table.needs_public_lift(), !sparse);
        let mut rng = StdRng::seed_from_u64(42);
        let (client, server) = context.try_generate_keys(&table, &mut rng).unwrap();
        assert!(server.public_lift().is_none()); // Classic initializer or sparse public choices.
        let encryptor = context.encryptor(&client).unwrap();
        let decryptor = context.decryptor(&client).unwrap();
        let mut evaluator = context.evaluator(&server, &table).unwrap();
        exercise(
            &encryptor,
            &decryptor,
            evaluator.allocate_output(),
            |x| {
                if sparse {
                    ((x >> 2) + (x & 3)) & 3
                } else {
                    (1u128 << 78) | x
                }
            },
            |input, output| evaluator.evaluate_to(input, output),
        );
        if !sparse {
            // Exact 64-bit output capacity must not perform a shift by 64.
            // Trivial phases isolate client joining from homomorphic noise.
            let mut exact_config = config(BarrettModulus::new(998_244_353u32), false);
            exact_config.output_chunk_count = 32;
            let exact = NttHighPrecLutContext::<u32, primus_ntt::U32NttTable, _>::try_from_config(
                exact_config,
            )
            .unwrap();
            let output: Vec<_> = (0..32)
                .map(|_| {
                    let mut ciphertext = LweCiphertext::zero(4);
                    *ciphertext.as_mut().last_mut().unwrap() = 3u32 << 21;
                    ciphertext
                })
                .collect();
            assert_eq!(
                exact
                    .decryptor(&client)
                    .unwrap()
                    .decrypt::<u64>(&output)
                    .unwrap(),
                u64::MAX
            );
        }
        if sparse {
            let lifting = context.compile_fn(|_: u128| 3).unwrap();
            assert!(matches!(
                context.evaluator(&server, &lifting),
                Err(LookupTableError::MissingPublicLiftKey)
            ));
            let (client, server) = context.try_generate_keys(&lifting, &mut rng).unwrap();
            assert!(server.public_lift().is_some());
            // A bundle generated with lift also serves a compatible table requiring none.
            context.evaluator(&server, &table).unwrap();
            let (circuit, lift) = server.into_parts();
            let server = NttHighPrecLutServerKey::new(circuit, lift);
            let mut evaluator = context.evaluator(&server, &lifting).unwrap();
            exercise(
                &context.encryptor(&client).unwrap(),
                &context.decryptor(&client).unwrap(),
                evaluator.allocate_output(),
                |_| 3,
                |input, output| evaluator.evaluate_to(input, output),
            );
        }
        // Public-table incompatibility must precede secret or key-row sampling.
        let mut foreign = context.layout();
        foreign.output_chunk_count += 1;
        let domain = context.backend_context().parameters();
        let codec = primus_encoding::RoundedCodec::new(8, domain.external_lwe().cipher_modulus());
        let table = primus_tfhe_ntru_lut::HighPrecisionLookupTable::try_from_parameters(
            domain,
            &codec,
            foreign,
            |_, _| 0,
        )
        .unwrap();
        rng = StdRng::seed_from_u64(0xBAD);
        let mut untouched = StdRng::seed_from_u64(0xBAD);
        assert!(context.try_generate_keys(&table, &mut rng).is_err());
        assert_eq!(rng.next_u64(), untouched.next_u64());
    }
}

#[cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
fn fourier<Table: primus_fft::FftTable>() {
    use primus_modulus::NativeModulus;
    use primus_tfhe_ntru_lut::{FourierHighPrecLutContext, FourierHighPrecLutServerKey};
    for sparse in [false, true] {
        let context = FourierHighPrecLutContext::<u64, Table, _>::try_from_config(config(
            NativeModulus::new(),
            sparse,
        ))
        .unwrap();
        let table = if sparse {
            context
                .compile_fn(|x: u128| ((x >> 2) + (x & 3)) & 3)
                .unwrap()
        } else {
            context.compile_fn(|x: u128| (1u128 << 78) | x).unwrap()
        };
        assert_eq!(table.needs_public_lift(), !sparse);
        let mut rng = StdRng::seed_from_u64(42);
        let (client, server) = context.try_generate_keys(&table, &mut rng).unwrap();
        assert!(server.public_lift().is_none());
        let mut evaluator = context.evaluator(&server, &table).unwrap();
        exercise(
            &context.encryptor(&client).unwrap(),
            &context.decryptor(&client).unwrap(),
            evaluator.allocate_output(),
            |x| {
                if sparse {
                    ((x >> 2) + (x & 3)) & 3
                } else {
                    (1u128 << 78) | x
                }
            },
            |input, output| evaluator.evaluate_to(input, output),
        );
        if sparse {
            let lifting = context.compile_fn(|_: u128| 3).unwrap();
            assert!(matches!(
                context.evaluator(&server, &lifting),
                Err(LookupTableError::MissingPublicLiftKey)
            ));
            let (client, server) = context.try_generate_keys(&lifting, &mut rng).unwrap();
            assert!(server.public_lift().is_some());
            context.evaluator(&server, &table).unwrap();
            let (circuit, lift) = server.into_parts();
            let server = FourierHighPrecLutServerKey::new(circuit, lift);
            let mut evaluator = context.evaluator(&server, &lifting).unwrap();
            exercise(
                &context.encryptor(&client).unwrap(),
                &context.decryptor(&client).unwrap(),
                evaluator.allocate_output(),
                |_| 3,
                |input, output| evaluator.evaluate_to(input, output),
            );
        }
    }
}

#[cfg(feature = "rustfft")]
#[test]
fn rustfft_integer_workflow_and_sparse_lift_requirements() {
    fourier::<primus_fft::RustFftTable>();
}

#[cfg(feature = "tfhe-fft")]
#[test]
fn tfhe_fft_integer_workflow_and_sparse_lift_requirements() {
    fourier::<primus_fft::TfheFftTable>();
}
