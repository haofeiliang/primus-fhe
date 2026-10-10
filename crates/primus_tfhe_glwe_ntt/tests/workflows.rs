//! Small deterministic consumers of the recommended public workflow.
//! n=8/N=128 are arithmetic regression parameters, not security profiles.

use primus_glwe::{GlweDimension, SecretKeyDistr};
use primus_integer::FheUint;
use primus_lwe::LweDimension;
use primus_ntt::{MonomialNttTable, U32NttTable, U64NttTable};
use primus_tfhe::{DecompositionBaseLog, DecompositionLevelCount, PolyLength};
use primus_tfhe_glwe_ntt::{
    BlindRotationMethod, CbsConfig, CbsGadgetConfig, DecompositionConfig, GadgetEncryptionConfig,
    LweConfig, ModulusConfig, PbsConfig, PbsMessageConfig, PbsOrder, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};

const SPARSE: BlindRotationMethod = BlindRotationMethod::Sparse {
    copy_count: 3,
    bucket_count: 8,
};

fn decomposition() -> DecompositionConfig {
    DecompositionConfig {
        log_basis: DecompositionBaseLog::new(4),
        level_count: None,
    }
}

/// Keep rounding and transform error far below the test message spacing.
/// Sparse needs fixed-weight binary secrets; classic cases select binary/ternary below.
fn config<T: FheUint>(method: BlindRotationMethod) -> PbsConfig<T> {
    let modulus = ModulusConfig::Explicit(T::as_from(if T::BITS == 32 {
        998_244_353u64
    } else {
        1_125_899_906_826_241u64
    }));
    let secret = SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 3 };
    PbsConfig {
        small_lwe: LweConfig {
            dimension: LweDimension::new(8),
            cipher_modulus: modulus,
            secret_key_distr: secret,
            noise_standard_deviation: 1.0,
        },
        bsk_dimension: GlweDimension::new(2),
        bsk_secret_distr: SecretKeyDistr::UniformTernary,
        method,
        order: PbsOrder::BootstrapKeyswitch,
        bsk_poly_length: PolyLength::new(128),
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: decomposition(),
            noise_standard_deviation: 0.7,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: decomposition(),
            noise_standard_deviation: 1.0,
        },
        messages: PbsMessageConfig::new(T::as_from(8)),
    }
}

/// The second PBS consumes the first result; both calls reuse one evaluator.
fn chained_pbs<T: FheUint, Table: MonomialNttTable<ValueT = T>>(config: PbsConfig<T>) {
    let context = TfheContext::<T, Table>::try_from_pbs_config(config).unwrap();
    let mut rng = StdRng::seed_from_u64(101);
    // Client: only encrypted inputs and the evaluation key leave this side.
    let (client, server) = context.try_generate_keys(&mut rng).unwrap();
    let secret = client.external_lwe_secret_key();
    let encryptor = context.encryptor(secret).unwrap();
    let decryptor = context.pbs_decryptor(secret).unwrap();
    let mut input = context.allocate_lwe_ciphertext();

    // Server: two nonidentity functions, whose intermediate stays in padded 0..4.
    let compiler = context.pbs_lookup_table_compiler().unwrap();
    let first = compiler.compile_fn(|x| T::as_from((x + 1) % 4)).unwrap();
    let second = compiler
        .compile_fn(|x| T::as_from((3 * x + 1) % 4))
        .unwrap();
    let mut evaluator = context.evaluator(&server).unwrap();
    let mut middle = context.allocate_lwe_ciphertext();
    let mut output = context.allocate_lwe_ciphertext();
    for x in [0, 3, 1, 2, 0] {
        encryptor
            .encrypt_padded_to(T::as_from(x), input.as_mut_view(), &mut rng)
            .unwrap();
        evaluator.apply_lookup_table_to(input.as_view(), &first, middle.as_mut_view());
        evaluator.apply_lookup_table_to(middle.as_view(), &second, output.as_mut_view());
        assert_eq!(
            decryptor.decrypt(output.as_view()).unwrap(),
            T::as_from((3 * ((x + 1) % 4) + 1) % 4),
            "input {x}"
        );
    }
}

/// Three ManyLUT output lanes require a fourth padding lane. MVB uses one
/// integer output scale, consumed through the Scaled client factory.
fn many_lut_and_mvb<T: FheUint, Table: MonomialNttTable<ValueT = T>>(mut config: PbsConfig<T>) {
    config.messages.output_modulus = T::as_from(4);
    let context = TfheContext::<T, Table>::try_from_pbs_config(config).unwrap();
    let mut rng = StdRng::seed_from_u64(102);
    // Client: t_in=8; both output clients use t_out=4 with different encodings.
    let (client, server) = context.try_generate_keys(&mut rng).unwrap();
    let secret = client.external_lwe_secret_key();
    let encryptor = context.encryptor(secret).unwrap();
    let rounded = context.pbs_decryptor(secret).unwrap();
    let scaled = context.mvb_decryptor(secret).unwrap();
    let mut input = context.allocate_lwe_ciphertext();

    // Server: input-dependent outputs, deliberately different in adjacent lanes.
    let function = |x: usize, lane: usize| T::as_from((x * (lane + 1) + lane + lane / 4) % 4);
    let lut = context
        .pbs_lookup_table_compiler()
        .unwrap()
        .compile_interleaved_fn(3, function)
        .unwrap();
    let program = context.compile_mvb_fn(4, 9, function).unwrap();
    let mut pbs = context.evaluator(&server).unwrap();
    let mut mvb = context.mvb_evaluator(&server).unwrap();
    let mut lanes = vec![context.allocate_lwe_ciphertext(); 3];
    let mut factors = vec![context.allocate_lwe_ciphertext(); 9];
    for x in [0, 3, 1, 2] {
        encryptor
            .encrypt_padded_to(T::as_from(x), input.as_mut_view(), &mut rng)
            .unwrap();
        pbs.apply_interleaved_lookup_table_to(input.as_view(), &lut, &mut lanes);
        mvb.apply_lookup_table_to(input.as_view(), &program, &mut factors);
        for (i, output) in lanes.iter().enumerate() {
            assert_eq!(
                rounded.decrypt(output.as_view()).unwrap(),
                function(x, i),
                "ManyLUT input {x}, lane {i}"
            );
        }
        for (i, output) in factors.iter().enumerate() {
            assert_eq!(
                scaled.decrypt(output.as_view()).unwrap(),
                function(x, i),
                "MVB input {x}, factor {i}"
            );
        }
    }
}

/// Consume the bootstrapped predicate in CMux, then check every coefficient.
fn circuit_selection<T: FheUint, Table: MonomialNttTable<ValueT = T>>(pbs: PbsConfig<T>) {
    let config = CbsConfig {
        pbs,
        gadget: CbsGadgetConfig {
            trace: decomposition(),
            scheme_switch: decomposition(),
            output: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(4),
                level_count: Some(DecompositionLevelCount::new(3)),
            },
        },
    };
    let context = TfheContext::<T, Table>::try_from_cbs_config(config).unwrap();
    let mut rng = StdRng::seed_from_u64(103);
    // Client: encrypt nonconstant candidate polynomials under the ring secret.
    let (client, server) = context
        .try_generate_circuit_bootstrap_keys(&mut rng)
        .unwrap();
    let encryptor = context.encryptor(client.external_lwe_secret_key()).unwrap();
    let mut ring_client = context
        .accumulator_client(client.glwe_secret_key(), T::as_from(8))
        .unwrap();
    // Avoid a short periodic pattern that could hide an incorrect coefficient rotation.
    let messages: Vec<Vec<T>> = (0..2)
        .map(|r| {
            (0..128)
                .map(|i| T::as_from(((i >> r) + i / 7 + r) % 4))
                .collect()
        })
        .collect();
    let candidates: Vec<_> = messages
        .iter()
        .map(|m| ring_client.encrypt(m, &mut rng))
        .collect();
    let mut input = context.allocate_lwe_ciphertext();
    let mut decoded = vec![T::ZERO; 128];

    // Server: custom F=[m>=2], then choose the encrypted branch.
    let program = context
        .compile_cbs_fn(|m| T::as_from(usize::from(m >= 2)))
        .unwrap();
    let mut cbs = context
        .circuit_bootstrap_evaluator_with_lookup_table(&server, program)
        .unwrap();
    let mut control = cbs.allocate_output();
    let mut selected = context.allocate_accumulator_ciphertext();
    for m in [0, 3, 1, 2] {
        encryptor
            .encrypt_padded_to(T::as_from(m), input.as_mut_view(), &mut rng)
            .unwrap();
        cbs.circuit_bootstrap_to(input.as_view(), control.as_mut_view());
        cbs.cmux_to(
            control.as_view(),
            candidates[0].as_view(),
            candidates[1].as_view(),
            selected.as_mut_view(),
        );
        ring_client.decrypt_to(&selected, &mut decoded);
        assert_eq!(decoded, messages[usize::from(m >= 2)], "CBS input {m}");
    }
}

#[test]
fn u32_classic_chain() {
    let mut config = config(BlindRotationMethod::Classic);
    config.small_lwe.secret_key_distr = SecretKeyDistr::UniformBinary;
    chained_pbs::<u32, U32NttTable>(config);
}

#[test]
fn u64_ternary_batches() {
    let mut config = config(BlindRotationMethod::Classic);
    config.small_lwe.secret_key_distr = SecretKeyDistr::UniformTernary;
    config.order = PbsOrder::KeyswitchBootstrap;
    many_lut_and_mvb::<u64, U64NttTable>(config);
}

#[test]
fn u32_sparse_batches() {
    let config = config(SPARSE);
    many_lut_and_mvb::<u32, U32NttTable>(config);
}

#[test]
fn u64_classic_cbs() {
    let mut config = config(BlindRotationMethod::Classic);
    config.small_lwe.secret_key_distr = SecretKeyDistr::UniformTernary;
    config.order = PbsOrder::KeyswitchBootstrap;
    circuit_selection::<u64, U64NttTable>(config);
}

#[test]
fn u32_sparse_cbs() {
    let config = config(SPARSE);
    circuit_selection::<u32, U32NttTable>(config);
}
