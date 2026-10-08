//! NTT evaluation uses the public API and shared representative parameters.

use std::hint::black_box;

use criterion::Throughput;
use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_modulus::PowOf2Modulus;
use primus_ntru::SecretKeyDistr;
use primus_ntt::MonomialNttTable;
use primus_tfhe_benchmarks::measurement::{Case, Group, metadata};
use primus_tfhe_benchmarks::parameters::{ntru, ntt_circuit_modulus};
use primus_tfhe_ntru_lut::{HighPrecisionLookupTable, NttLookupTableEvaluator};
use primus_tfhe_ntru_ntt::{KeyGenerator, TfheContext};
use rand::{SeedableRng, rngs::StdRng};

use super::{
    CHUNKS, CONFIG, INPUT, Workload, benchmark_lut_creation, check_repetition,
    diagnostics::report_phase_error,
};

// Registers repeated, dense and cross-output shared LUT workloads for this backend and word width.
pub fn benchmark<T: FheUint, Table: MonomialNttTable<ValueT = T>>(c: &mut Group<'_>) {
    for sparse in [false, true] {
        for workload in [Workload::Polynomial, Workload::Dense, Workload::Shared] {
            benchmark_workload::<T, Table>(c, workload, sparse);
        }
    }
}

// Measures LUT construction and evaluation separately. Criterion filters defer costly
// evaluation fixtures until needed; setup and validation remain outside timed iterations.
fn benchmark_workload<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    c: &mut Group<'_>,
    workload: Workload,
    sparse: bool,
) {
    let backend = "ntt";
    let parameters = ntru::circuit(
        ntt_circuit_modulus::<T>(),
        SecretKeyDistr::fixed_hamming_weight_binary(800, 32),
    );
    let input_codec = RoundedCodec::new(
        CHUNKS.plaintext_modulus(),
        parameters.external_lwe().cipher_modulus(),
    );
    let kind = if sparse { "sparse" } else { "classic" };
    let name = format!("{kind}/c8_d5_o8{}", workload.suffix());
    if !sparse {
        benchmark_lut_creation(
            c,
            &Case::new(
                "lookup",
                backend,
                T::BITS,
                format!("{name}/create_lut_and_drop"),
            ),
            &parameters,
            workload,
        );
    }
    let case = Case::new("lookup", backend, T::BITS, format!("{name}/evaluate"));
    let diagnostic_name = case.full_id("high_precision_lut");
    let fixture = std::cell::LazyCell::new(|| {
        Fixture::<T, Table>::new(parameters, input_codec, workload, sparse)
    });
    let mut verified = false;

    c.throughput(Throughput::Elements(CONFIG.output_chunk_count as u64));
    c.bench_function(case.id(), |b| {
        let Fixture {
            context,
            client,
            server,
            table,
            lift,
            input,
        } = &*fixture;
        let mut evaluator = match lift {
            Some(key) => NttLookupTableEvaluator::try_with_public_lift(
                context,
                server,
                table,
                (key.as_view(), context.parameters().blind_rotation()),
            ),
            None => NttLookupTableEvaluator::try_new(context, server, table),
        }
        .unwrap();
        let mut output = evaluator.allocate_output();
        if !verified {
            evaluator.evaluate_to(input, &mut output);
            let decryptor = context
                .decryptor(client.external_lwe_secret_key(), &input_codec)
                .unwrap();
            for (i, chunk) in output.iter().enumerate() {
                assert_eq!(
                    decryptor.decrypt(chunk.as_view()).unwrap(),
                    workload.digit::<T>(INPUT, i)
                );
            }
            report_phase_error(
                &diagnostic_name,
                output.iter().enumerate().map(|(i, chunk)| {
                    (
                        decryptor.decrypt_phase(chunk.as_view()).unwrap().as_into(),
                        workload.digit::<T>(INPUT, i).as_into(),
                    )
                }),
            );
            verified = true;
        }
        metadata::record("high_precision_lut", &case, || {
            serde_json::json!({
                "parameters": metadata::ntru(context.parameters()),
                "blind_rotation": metadata::blind_rotation(sparse),
                "cbs": metadata::cbs(ntru::cbs::<T>(), context.parameters().accumulator_ntru().noise_distribution().standard_deviation()),
                "lut": workload.metadata(),
                "unique_polynomials": table.unique_polynomial_count(),
                "needs_public_lift": table.needs_public_lift(),
                "outputs": CONFIG.output_chunk_count,
            })
        });
        b.iter(|| evaluator.evaluate_to(black_box(input), black_box(&mut output)));
    });
}

/// Owned keys and request data. Evaluators borrow this fixture and own their
/// scratch separately; constructing it is deferred until Criterion selects a case.
struct Fixture<T: FheUint, Table: MonomialNttTable<ValueT = T>> {
    context: TfheContext<T, Table, PowOf2Modulus<T>>,
    client: primus_tfhe_ntru_ntt::ClientKey<T>,
    server: primus_tfhe_ntru_ntt::ServerKey<T>,
    table: HighPrecisionLookupTable<T>,
    lift: Option<primus_lattice::nlev::NttNlev<Vec<T>>>,
    input: Vec<primus_lwe::LweCiphertext<T>>,
}

impl<T: FheUint, Table: MonomialNttTable<ValueT = T>> Fixture<T, Table> {
    /// Builds the fixed-seed request outside timing; key-generation order is
    /// preserved so the baseline keeps identical client and encryption randomness.
    fn new(
        parameters: primus_tfhe_ntru_ntt::PbsParameters<T, PowOf2Modulus<T>>,
        input_codec: primus_encoding::RoundedCodec<T, PowOf2Modulus<T>>,
        workload: Workload,
        sparse: bool,
    ) -> Self {
        let context =
            TfheContext::<T, Table, PowOf2Modulus<T>>::try_from_parameters(parameters).unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        let (client, server) = {
            let mut generator = KeyGenerator::new(&context);
            let client = generator.try_generate_client_key(&mut rng).unwrap();
            let blind_rotation = primus_tfhe_benchmarks::benchmark::blind_rotation(sparse);
            let server = generator
                .try_generate_server_key(&client, blind_rotation, Some(ntru::cbs::<T>()), &mut rng)
                .unwrap();
            (client, server)
        };
        let table = HighPrecisionLookupTable::try_new(
            context.parameters().poly_length(),
            context.parameters().accumulator_ntru().cipher_modulus(),
            &input_codec,
            CONFIG,
            |x, output| workload.digit::<T>(x, output),
        )
        .unwrap();
        check_repetition(&table, workload);
        // Lift generation is independent of sparse buckets and only paid by
        // plans that need it. This fixture selects BR's basis and sigma=0.7.
        let lift = if sparse && table.needs_public_lift() {
            Some(
                KeyGenerator::new(&context)
                    .try_generate_public_lift_key(
                        client.accumulator_ntru_secret_key(),
                        context.parameters().blind_rotation(),
                        &mut rng,
                    )
                    .unwrap(),
            )
        } else {
            None
        };
        // Identical encrypted input for classic/sparse over the same fixed client.
        let mut rng = StdRng::seed_from_u64(43);
        let encryptor = context
            .encryptor(client.external_lwe_secret_key(), &input_codec)
            .unwrap();
        let input: Vec<_> = (0..CONFIG.input_chunk_count)
            .map(|i| {
                encryptor
                    .encrypt_padded(T::as_from(CHUNKS.chunk(INPUT, i)), &mut rng)
                    .unwrap()
            })
            .collect();
        Self {
            context,
            client,
            server,
            table,
            lift,
            input,
        }
    }
}
