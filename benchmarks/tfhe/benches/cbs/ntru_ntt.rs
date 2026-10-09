//! One complete CBS into a reused gadget ciphertext; NTRU also measures full
//! and nonzero one-hot batches. Keygen, encryption, allocation and the CMux
//! correctness probe are outside timing. Ordinary CBS uses t4; one-hot uses t8.
//! Classic/sparse pairs share n728/h32/N1024 secrets and separately seeded inputs.
//! Parameters: primus_tfhe_benchmarks::parameters (arithmetic cost profiles).
//! Fixtures are initialized only for selected IDs, then reused across samples.
//! Run: cargo bench -p primus_tfhe_benchmarks --bench cbs --features ntru-ntt

use primus_encoding::ScaledCodec;
use primus_tfhe_benchmarks::measurement::{Case, Group, metadata};
use std::hint::black_box;

use primus_integer::FheUint;
use primus_modulus::PowOf2Modulus;
use primus_ntt::{MonomialNttTable, U64NttTable};
use primus_tfhe_benchmarks::parameters::ntt_circuit_modulus;
use primus_tfhe_benchmarks::parameters::{N, ntru};
use primus_tfhe_ntru_ntt::{
    CircuitBootstrapEvaluator, KeyGenerator, OneHotCircuitBootstrapEvaluator, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};

// CBS consumes a bit and emits a gadget control, not an LWE result. Verify
// that representation by selecting an encrypted ring message before timing.
fn ordinary<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    c: &mut Group<'_>,
    backend: &str,
    sparse: bool,
) {
    let kind = if sparse { "sparse" } else { "classic" };
    let parameters = ntru::diagnostic(ntt_circuit_modulus::<T>());
    let (input_codec, ring_message_codec) = parameters
        .as_ref()
        .circuit_bootstrap_codecs(T::as_from(4u32), T::as_from(4u32))
        .unwrap();
    let name = format!("{kind}/complete");
    let fixture = std::cell::LazyCell::new(|| {
        Fixture::<T, Table>::new(parameters, input_codec, ring_message_codec, sparse, T::ONE)
    });
    let mut verified = false;
    c.throughput(criterion::Throughput::Elements(1));
    let case = Case::new("ntru", backend, T::BITS, &name);
    c.bench_function(case.id(), |b| {
        let Fixture {
            parameters,
            context,
            client,
            server,
            input,
            lhs,
            rhs,
        } = &*fixture;
        let mut resources = context
            .bootstrap_resources(server.server_key().blind_rotation_key())
            .unwrap();
        let mut evaluator = CircuitBootstrapEvaluator::try_new(
            &resources,
            server.circuit_bootstrap_key(),
            &input_codec,
        )
        .unwrap();
        let mut output = evaluator.allocate_output();
        if !verified {
            evaluator.circuit_bootstrap_to(input.as_view(), &mut output, &mut resources);
            let mut selected = context.allocate_accumulator_ciphertext();
            evaluator.cmux_to(&output, lhs, rhs, &mut selected, &mut resources);
            let mut decoded = vec![T::ZERO; N];
            context
                .accumulator_client(
                    client.accumulator_ntru_secret_key(),
                    ring_message_codec,
                )
                .unwrap()
                .decrypt_to(&selected, &mut decoded);
            assert!(decoded.iter().all(|&value| value == T::ONE));
            verified = true;
        }

        metadata::record("cbs", &case, || {
            serde_json::json!({
                "parameters": metadata::ntru(parameters),
                "blind_rotation": metadata::blind_rotation(sparse),
                "cbs": metadata::cbs(ntru::cbs::<T>(), context.parameters().accumulator_ntru().noise_distribution().standard_deviation()),
                "encoding": "rounded_padded",
                "plaintext_modulus": 4,
                "outputs": 1,
                "output_kind": "gadget",
            })
        });
        b.iter(|| {
            evaluator.circuit_bootstrap_to(
                black_box(input.as_view()),
                black_box(&mut output),
                &mut resources,
            )
        });
    });
}

// The compact batch omits delta_0. Compare equal input geometry to isolate the
// saved selector work; one iteration produces M or M-1 complete NGSW controls.
fn one_hot<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    c: &mut Group<'_>,
    backend: &str,
    sparse: bool,
) {
    let parameters = ntru::diagnostic(ntt_circuit_modulus::<T>());
    let (input_codec, ring_message_codec) = parameters
        .as_ref()
        .circuit_bootstrap_codecs(T::as_from(8u32), T::as_from(8u32))
        .unwrap();
    let br = if sparse { "sparse" } else { "classic" };
    let fixture = std::cell::LazyCell::new(|| {
        Fixture::<T, Table>::new(parameters, input_codec, ring_message_codec, sparse, T::TWO)
    });
    for compact in [false, true] {
        let kind = if compact { "nonzero" } else { "full" };
        let mut verified = false;
        let name = format!("one_hot/{br}/M4/{kind}");
        c.throughput(criterion::Throughput::Elements(if compact { 3 } else { 4 }));
        let case = Case::new("ntru", backend, T::BITS, &name);
        c.bench_function(case.id(), |b| {
            let Fixture {
            parameters,
                context,
                server,
                input,
                ..
            } = &*fixture;
            let mut resources = context
                .bootstrap_resources(server.server_key().blind_rotation_key())
                .unwrap();
            let mut evaluator = OneHotCircuitBootstrapEvaluator::try_new(
                &resources,
                server.circuit_bootstrap_key(),
                &input_codec,
            )
            .unwrap();
            let mut output = if compact {
                evaluator.allocate_nonzero_ngsw_output()
            } else {
                evaluator.allocate_ngsw_output()
            };
            if !verified {
                if compact {
                    evaluator.one_hot_nonzero_ngsw_to(input.as_view(), &mut output, &mut resources);
                } else {
                    evaluator.one_hot_ngsw_to(input.as_view(), &mut output, &mut resources);
                }
                fixture.check_one_hot(&output, &evaluator, &mut resources, compact, ring_message_codec);
                verified = true;
            }
            metadata::record("cbs", &case, || {
                serde_json::json!({
                    "parameters": metadata::ntru(parameters),
                    "blind_rotation": metadata::blind_rotation(sparse),
                    "cbs": metadata::cbs(ntru::cbs::<T>(), context.parameters().accumulator_ntru().noise_distribution().standard_deviation()),
                    "encoding": "rounded_padded",
                    "plaintext_modulus": 8,
                    "outputs": if compact { 3 } else { 4 },
                    "output_kind": "one_hot_ngsw",
                    "omits_zero": compact,
                })
            });
            if compact {
                b.iter(|| {
                    evaluator.one_hot_nonzero_ngsw_to(
                        black_box(input.as_view()),
                        black_box(&mut output),
                        &mut resources,
                    )
                });
            } else {
                b.iter(|| {
                    evaluator.one_hot_ngsw_to(
                        black_box(input.as_view()),
                        black_box(&mut output),
                        &mut resources,
                    )
                });
            }
        });
    }
}

pub fn bench_cbs(c: &mut Group<'_>) {
    for sparse in [false, true] {
        ordinary::<u64, U64NttTable>(c, "ntt", sparse);
        one_hot::<u64, U64NttTable>(c, "ntt", sparse);
    }
}

/// Owned keys and request data. Evaluators borrow this fixture and own their
/// scratch separately; constructing it is deferred until Criterion selects a case.
struct Fixture<T: FheUint, Table: MonomialNttTable<ValueT = T>> {
    parameters: primus_tfhe_ntru_ntt::PbsParameters<T, PowOf2Modulus<T>>,
    context: TfheContext<T, Table, PowOf2Modulus<T>>,
    client: primus_tfhe_ntru_ntt::ClientKey<T>,
    server: primus_tfhe_ntru_ntt::CircuitBootstrapServerKey<T>,
    input: primus_lwe::LweCiphertext<T>,
    lhs: primus_ntru::NtruCiphertext<Vec<T>>,
    rhs: primus_ntru::NtruCiphertext<Vec<T>>,
}

impl<T: FheUint, Table: MonomialNttTable<ValueT = T>> Fixture<T, Table> {
    /// Builds the fixed-seed request outside timing; key-generation order is
    /// preserved so the baseline keeps identical client and encryption randomness.
    fn new(
        parameters: primus_tfhe_ntru_ntt::PbsParameters<T, PowOf2Modulus<T>>,
        input_codec: primus_encoding::RoundedCodec<T, PowOf2Modulus<T>>,
        ring_message_codec: primus_encoding::ScaledCodec<T, primus_modulus::BarrettModulus<T>>,
        sparse: bool,
        message: T,
    ) -> Self {
        let context_parameters = &parameters;
        let context = TfheContext::<T, Table, PowOf2Modulus<T>>::try_from_parameters(
            context_parameters.clone(),
        )
        .unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        let mut generator = KeyGenerator::new(&context);
        let client = generator.try_generate_client_key(&mut rng).unwrap();
        let blind_rotation = primus_tfhe_benchmarks::benchmark::blind_rotation(sparse);
        let server = generator
            .try_generate_circuit_bootstrap_server_key_with_parameters(
                context_parameters.key_switching(),
                &client,
                blind_rotation,
                &primus_tfhe_ntru::CbsGadgetParameters::try_from_config(
                    context.parameters(),
                    ntru::cbs::<T>(),
                )
                .unwrap(),
                &mut rng,
            )
            .unwrap();
        // Input/candidate encryption is identical across the two BR choices.
        let mut rng = StdRng::seed_from_u64(43);
        let input = context
            .encryptor(client.external_lwe_secret_key(), &input_codec)
            .unwrap()
            .encrypt_padded(message, &mut rng)
            .unwrap();
        let mut ring = context
            .accumulator_client(client.accumulator_ntru_secret_key(), ring_message_codec)
            .unwrap();
        let lhs = ring.encrypt(&[T::ZERO; N], &mut rng);
        let rhs = ring.encrypt(&[T::ONE; N], &mut rng);
        Self {
            parameters,
            context,
            client,
            server,
            input,
            lhs,
            rhs,
        }
    }

    /// Check each selector through a CMux, including the compact r-1 indexing.
    fn check_one_hot<'a>(
        &self,
        output: &[T],
        evaluator: &OneHotCircuitBootstrapEvaluator<'a, T, Table, PowOf2Modulus<T>>,
        resources: &mut primus_tfhe_ntru_ntt::BootstrapResources<'a, T, Table, PowOf2Modulus<T>>,
        compact: bool,
        ring_message_codec: ScaledCodec<T, primus_modulus::BarrettModulus<T>>,
    ) {
        let Self {
            context,
            client,
            lhs,
            rhs,
            ..
        } = self;
        let mut selected = context.allocate_accumulator_ciphertext();
        let mut decoded = vec![T::ZERO; N];
        let mut ring = context
            .accumulator_client(client.accumulator_ntru_secret_key(), ring_message_codec)
            .unwrap();
        // Both views iterate mathematical r, even when storage omits delta_0.
        let selectors = if compact {
            evaluator.nonzero_ngsw_selectors(output)
        } else {
            evaluator.ngsw_selectors(output)
        };
        for (r, control) in selectors.iter() {
            evaluator.cmux_to(&control, lhs, rhs, &mut selected, resources);
            ring.decrypt_to(&selected, &mut decoded);
            let expected = if r == 2 { T::ONE } else { T::ZERO };
            assert!(decoded.iter().all(|&value| value == expected));
        }
    }
}
