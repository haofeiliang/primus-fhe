//! Fourier evaluation uses the public API and shared representative parameters.

use std::hint::black_box;

use criterion::Throughput;
use primus_fft::{FftTable, TorusFftValue};
use primus_modulus::{NativeModulus, PowOf2Modulus};
use primus_ntru::SecretKeyDistr;
use primus_tfhe_benchmarks::measurement::{Case, Group, metadata};
use primus_tfhe_benchmarks::parameters::ntru;
use primus_tfhe_ntru::CbsParameters;
use primus_tfhe_ntru_lut::{
    FourierHighPrecLutContext, FourierHighPrecLutServerKey, HighPrecLutParameters,
    HighPrecisionLookupTable,
};
use rand::{SeedableRng, rngs::StdRng};

use super::{
    CHUNKS, CONFIG, INPUT, Workload, benchmark_lut_creation, check_repetition,
    diagnostics::report_phase_error,
};

// Registers repeated, dense and cross-output shared LUT workloads for this backend and word width.
pub fn benchmark<T: TorusFftValue, Table: FftTable>(c: &mut Group<'_>, backend: &str) {
    for sparse in [false, true] {
        for workload in [Workload::Polynomial, Workload::Dense, Workload::Shared] {
            benchmark_workload::<T, Table>(c, backend, workload, sparse);
        }
    }
}

// Measures LUT construction and evaluation separately. Criterion filters defer costly
// evaluation fixtures until needed; setup and validation remain outside timed iterations.
fn benchmark_workload<T: TorusFftValue, Table: FftTable>(
    c: &mut Group<'_>,
    backend: &str,
    workload: Workload,
    sparse: bool,
) {
    let parameters = ntru::circuit(
        NativeModulus::<T>::new(),
        SecretKeyDistr::fixed_hamming_weight_binary(800, 32),
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
    let fixture =
        std::cell::LazyCell::new(|| Fixture::<T, Table>::new(parameters, workload, sparse));
    let mut verified = false;

    c.throughput(Throughput::Elements(CONFIG.output_chunk_count as u64));
    c.bench_function(case.id(), |b| {
        let Fixture {
            context,
            client,
            server,
            table,
            input,
        } = &*fixture;
        let mut evaluator = context.evaluator(server, table).unwrap();
        let mut output = evaluator.allocate_output();
        if !verified {
            evaluator.evaluate_to(input, &mut output);
            let decryptor = context.backend_context()
                .pbs_decryptor(client.external_lwe_secret_key())
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
                "parameters": metadata::ntru(context.backend_context().parameters()),
                "blind_rotation": metadata::blind_rotation(sparse),
                "cbs": metadata::cbs(ntru::cbs::<T>(), context.backend_context().parameters().accumulator_ntru().noise_distribution().standard_deviation()),
                "lut": workload.metadata(),
                "unique_polynomials": table.unique_polynomial_count(),
                "needs_public_lift": table.needs_public_lift(),
                "outputs": CONFIG.output_chunk_count,
                "fft_layout_fingerprint": metadata::fft_layout(context.backend_context().table()),
            })
        });
        b.iter(|| evaluator.evaluate_to(black_box(input), black_box(&mut output)));
    });
}

/// Owned keys and request data. Evaluators borrow this fixture and own their
/// scratch separately; constructing it is deferred until Criterion selects a case.
struct Fixture<T: TorusFftValue, Table: FftTable> {
    context: FourierHighPrecLutContext<T, Table, PowOf2Modulus<T>>,
    client: primus_tfhe_ntru::ClientKey<T>,
    server: FourierHighPrecLutServerKey<T>,
    table: HighPrecisionLookupTable<T>,
    input: Vec<primus_lwe::LweCiphertext<T>>,
}

impl<T: TorusFftValue, Table: FftTable> Fixture<T, Table> {
    /// Prepares a complete operation once; only its selected plan can request lift material.
    /// Keys and client encryption retain separate fixed seeds outside evaluation timing.
    fn new(
        parameters: primus_tfhe_ntru_fourier::PbsParameters<T, PowOf2Modulus<T>>,
        workload: Workload,
        sparse: bool,
    ) -> Self {
        let parameters = parameters
            .with_messages(primus_tfhe::PbsMessageConfig::new(
                CHUNKS.plaintext_modulus(),
            ))
            .with_algorithm(primus_tfhe_benchmarks::benchmark::blind_rotation(sparse));
        let cbs = CbsParameters::try_with_config(parameters, ntru::cbs::<T>()).unwrap();
        let parameters = HighPrecLutParameters::try_new(cbs, CONFIG).unwrap();
        let context = FourierHighPrecLutContext::<T, Table, _>::from_parameters(parameters);
        let table = context
            .compile_chunks_fn(|x, output| workload.digit::<T>(x, output))
            .unwrap();
        check_repetition(&table, workload);
        let mut rng = StdRng::seed_from_u64(42);
        let (client, server) = context.try_generate_keys(&table, &mut rng).unwrap();
        // Independent seed keeps encrypted inputs identical across classic/sparse,
        // even when a sparse plan requests independently generated lift rows.
        let mut rng = StdRng::seed_from_u64(43);
        let encryptor = context.encryptor(&client).unwrap();
        let mut input = encryptor.allocate_input();
        encryptor.encrypt_to(INPUT, &mut input, &mut rng).unwrap();
        Self {
            context,
            client,
            server,
            table,
            input,
        }
    }
}
