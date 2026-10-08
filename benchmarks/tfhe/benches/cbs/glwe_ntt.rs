//! One complete CBS into a reused gadget ciphertext. Keygen, encryption,
//! allocation and the CMux correctness probe are outside timing; t=4.
//! Classic/sparse share n728/h32/N1024, client seed and input randomness.
//! Parameters: primus_tfhe_benchmarks::parameters (arithmetic cost profiles).
//! Fixtures are initialized only for selected IDs, then reused across samples.
//! Run: cargo bench -p primus_tfhe_benchmarks --bench cbs --features glwe-ntt

use primus_tfhe_benchmarks::measurement::{Case, Group, metadata};
use std::hint::black_box;

use primus_integer::FheUint;
use primus_ntt::{MonomialNttTable, U64NttTable};
use primus_tfhe_benchmarks::parameters::ntt_circuit_modulus;
use primus_tfhe_benchmarks::parameters::{N, glwe};
use primus_tfhe_glwe_ntt::{
    CircuitBootstrapEvaluator, ClientKey, KeyGenerator, PbsOrder, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};

// CBS consumes a bit and emits a gadget control, not an LWE result. Verify
// that representation by selecting an encrypted ring message before timing.
fn ordinary<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    c: &mut Group<'_>,
    backend: &str,
    order: PbsOrder,
    sparse: bool,
) {
    let kind = if sparse { "sparse" } else { "classic" };
    // Pair classic and sparse BR using identical parameters and client seed.
    let parameters = glwe::diagnostic(ntt_circuit_modulus::<T>(), order);
    let (input_codec, ring_message_codec) = parameters
        .circuit_bootstrap_codecs(T::as_from(4u32), T::as_from(4u32))
        .unwrap();
    let name = format!("{kind}/{order:?}/complete");
    let fixture = std::cell::LazyCell::new(|| {
        Fixture::<T, Table>::new(parameters, input_codec, ring_message_codec, sparse, T::ONE)
    });
    let mut verified = false;
    c.throughput(criterion::Throughput::Elements(1));
    let case = Case::new("glwe", backend, T::BITS, &name);
    c.bench_function(case.id(), |b| {
        let Fixture {
            context,
            client,
            server,
            input,
            lhs,
            rhs,
        } = &*fixture;
        let mut resources = context.bootstrap_resources_from_server_key(server).unwrap();
        let circuit_key = server.circuit_bootstrap_key().unwrap();
        let mut evaluator =
            CircuitBootstrapEvaluator::try_new(&resources, circuit_key, &input_codec).unwrap();
        let mut output = evaluator.allocate_output();
        if !verified {
            evaluator.circuit_bootstrap_to(input.as_view(), &mut output, &mut resources);
            let mut selected = context.allocate_accumulator_ciphertext();
            evaluator.cmux_to(&output, lhs, rhs, &mut selected, &mut resources);
            let mut decoded = vec![T::ZERO; N];
            context
                .accumulator_client(
                    client.glwe_secret_key(),
                    ring_message_codec,
                )
                .unwrap()
                .decrypt_to(&selected, &mut decoded);
            assert!(decoded.iter().all(|&value| value == T::ONE));
            verified = true;
        }

        metadata::record("cbs", &case, || {
            serde_json::json!({
                "parameters": metadata::glwe(context.parameters()),
                "blind_rotation": metadata::blind_rotation(sparse),
                "cbs": metadata::cbs(glwe::cbs::<T>(), context.parameters().blind_rotation_ggsw().noise_standard_deviation()),
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

pub fn bench_cbs(c: &mut Group<'_>) {
    for sparse in [false, true] {
        ordinary::<u64, U64NttTable>(c, "ntt", PbsOrder::KeyswitchBootstrap, sparse);
    }
}

/// Owned keys and request data. Evaluators borrow this fixture and own their
/// scratch separately; constructing it is deferred until Criterion selects a case.
struct Fixture<T: FheUint, Table: MonomialNttTable<ValueT = T>> {
    context: TfheContext<T, Table>,
    client: primus_tfhe_glwe_ntt::ClientKey<T>,
    server: primus_tfhe_glwe_ntt::ServerKey<T>,
    input: primus_lwe::LweCiphertext<T>,
    lhs: primus_glwe::GlweCiphertext<Vec<T>>,
    rhs: primus_glwe::GlweCiphertext<Vec<T>>,
}

impl<T: FheUint, Table: MonomialNttTable<ValueT = T>> Fixture<T, Table> {
    /// Builds the fixed-seed request outside timing; key-generation order is
    /// preserved so the baseline keeps identical client and encryption randomness.
    fn new(
        parameters: primus_tfhe_glwe_ntt::TfheParameters<T>,
        input_codec: primus_encoding::RoundedCodec<T, primus_modulus::BarrettModulus<T>>,
        ring_message_codec: primus_encoding::ScaledCodec<T, primus_modulus::BarrettModulus<T>>,
        sparse: bool,
        message: T,
    ) -> Self {
        let context = TfheContext::<T, Table>::try_from_parameters(parameters).unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        let mut generator = KeyGenerator::new(&context);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        let blind_rotation = primus_tfhe_benchmarks::benchmark::blind_rotation(sparse);
        let server = generator
            .try_generate_server_key(&client, blind_rotation, Some(glwe::cbs::<T>()), &mut rng)
            .unwrap();
        // Separate input randomness from scheme-dependent key generation.
        let mut rng = StdRng::seed_from_u64(43);
        let input = context
            .encryptor(client.external_lwe_secret_key(), &input_codec)
            .unwrap()
            .encrypt_padded(message, &mut rng)
            .unwrap();
        let mut ring = context
            .accumulator_client(client.glwe_secret_key(), ring_message_codec)
            .unwrap();
        let lhs = ring.encrypt(&[T::ZERO; N], &mut rng);
        let rhs = ring.encrypt(&[T::ONE; N], &mut rng);
        Self {
            context,
            client,
            server,
            input,
            lhs,
            rhs,
        }
    }
}
