//! Produce k threshold bits from one encrypted input. D8/k3 compares independent
//! PBS, interleaved ManyLUT and factorized MVB; D64/k17 exceeds interleaved
//! capacity. One iteration produces all k outputs, with no setup or allocation.
//! D8/k3 pairs classic/sparse for all three paths; D64/k17 keeps classic only.
//! Parameters: primus_tfhe_benchmarks::parameters (arithmetic cost profiles).
//! Fixtures are initialized only for selected IDs, then reused across samples.
//! Run: cargo bench -p primus_tfhe_benchmarks --bench mvb --features glwe-ntt

use primus_tfhe::{FactorizedPbsCodecs, PbsMessageConfig};
use primus_tfhe_benchmarks::measurement::{Case, Group, metadata};
use std::hint::black_box;

use criterion::Throughput;
use primus_encoding::PlaintextEmbedding;
use primus_integer::FheUint;
use primus_lwe::LweCiphertext;
use primus_ntt::{MonomialNttTable, U64NttTable};
use primus_tfhe_benchmarks::benchmark::{MVB_WORKLOADS, MvbPath, ThresholdWorkload};
use primus_tfhe_benchmarks::parameters::glwe;
use primus_tfhe_benchmarks::parameters::ntt_modulus;
use primus_tfhe_glwe_ntt::{
    ClientKey, InterleavedLookupTable, KeyGenerator, LookupTable, PbsOrder, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};

// The same fixture serves all paths for a workload. Lazy construction keeps
// --list and filtered-out cases free of key generation and encryption.
fn backend<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    c: &mut Group<'_>,
    backend: &str,
    order: PbsOrder,
) {
    for workload in MVB_WORKLOADS {
        let ThresholdWorkload {
            domain,
            outputs: count,
            sparse,
        } = workload;
        let parameters = glwe::diagnostic(ntt_modulus::<T>(), order);
        let codecs = parameters
            .factorized_pbs_codecs(
                PbsMessageConfig::new(T::as_from(2 * domain)).with_output_modulus(T::TWO),
            )
            .unwrap();
        let fixture =
            std::cell::LazyCell::new(|| Fixture::<T, Table>::new(parameters, codecs, workload));
        let kind = if sparse { "sparse" } else { "classic" };
        c.throughput(Throughput::Elements(count as u64));
        for &path in workload.paths() {
            let case = Case::new(
                "glwe",
                backend,
                T::BITS,
                format!("{kind}/{order:?}/D{domain}_k{count}/{}", path.name()),
            );
            let mut verified = false;
            c.bench_function(case.id(), |b| {
                metadata::record("mvb", &case, || {
                    serde_json::json!({
                        "parameters": metadata::glwe(fixture.context.parameters()),
                        "blind_rotation": metadata::blind_rotation(sparse),
                        "encoding": "rounded_padded_input_scaled_bit_output",
                        "plaintext_modulus": 2 * domain, "outputs": count,
                        "function": "threshold (i+1)*domain/(count+1)", "path": path.name(),

                    })
                });
                // Dispatch before b.iter; each method prepares just its own LUT/workspace.
                match path {
                    MvbPath::Independent => fixture.independent(b, &mut verified),
                    MvbPath::Interleaved => fixture.interleaved(b, &mut verified),
                    MvbPath::Factorized => fixture.factorized(b, &mut verified),
                }
            });
        }
    }
}

pub fn bench_mvb(c: &mut Group<'_>) {
    backend::<u64, U64NttTable>(c, "ntt", PbsOrder::KeyswitchBootstrap);
}

/// Owned request shared by the algorithms, with explicit input, ring-table and
/// returned-phase codecs. Evaluator scratch/output remain local to each callback.
struct Fixture<T: FheUint, Table: MonomialNttTable<ValueT = T>> {
    context: TfheContext<T, Table>,
    client: primus_tfhe_glwe_ntt::ClientKey<T>,
    server: primus_tfhe_glwe_ntt::ServerKey<T>,
    input: LweCiphertext<T>,
    workload: ThresholdWorkload,
    codecs: FactorizedPbsCodecs<T, primus_modulus::BarrettModulus<T>>,
}

impl<T: FheUint, Table: MonomialNttTable<ValueT = T>> Fixture<T, Table> {
    /// Preserve the seed and key-generation sequence of the matched workloads.
    fn new(
        parameters: primus_tfhe_glwe_ntt::TfheParameters<T>,
        codecs: FactorizedPbsCodecs<T, primus_modulus::BarrettModulus<T>>,
        workload: ThresholdWorkload,
    ) -> Self {
        let context = TfheContext::<T, Table>::try_from_parameters(parameters).unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        let mut generator = KeyGenerator::new(&context);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        let blind_rotation = primus_tfhe_benchmarks::benchmark::blind_rotation(workload.sparse);
        let server = generator
            .try_generate_server_key(&client, blind_rotation, None, &mut rng)
            .unwrap();
        let input = context
            .encryptor(client.external_lwe_secret_key(), codecs.input_codec())
            .unwrap()
            .encrypt_padded(T::as_from(workload.domain / 2), &mut rng)
            .unwrap();
        Self {
            codecs,
            workload,
            context,
            client,
            server,
            input,
        }
    }

    /// Decode at the return modulus, which can differ from the public LUT's ring modulus.
    fn check_outputs(&self, outputs: &[LweCiphertext<T>], verified: &mut bool) {
        if *verified {
            return;
        }
        let decryptor = self
            .context
            .decryptor(
                self.client.external_lwe_secret_key(),
                self.codecs.output_codec(),
            )
            .unwrap();
        for (i, output) in outputs.iter().enumerate() {
            assert_eq!(
                decryptor.decrypt(output.as_view()).unwrap(),
                self.workload.value(self.workload.domain / 2, i)
            );
        }
        *verified = true;
    }

    /// One iteration runs k independent PBS calls, one for each threshold output.
    /// Raw LUT construction preserves the MVB Scaled centers for a matched comparison.
    fn independent(&self, b: &mut criterion::Bencher, verified: &mut bool) {
        let w = self.workload;
        let luts: Vec<_> = (0..w.outputs)
            .map(|i| {
                LookupTable::try_new(
                    w.domain,
                    self.context
                        .parameters()
                        .blind_rotation_ggsw()
                        .poly_length(),
                    T::as_from(2 * w.domain),
                    self.codecs.input_codec().ciphertext_modulus(),
                    self.codecs.lut_output_codec().ciphertext_modulus(),
                    |m| {
                        Ok(self
                            .codecs
                            .lut_output_codec()
                            .encode_value(w.value(m, i), PlaintextEmbedding::Unsigned))
                    },
                )
                .unwrap()
            })
            .collect();
        let mut outputs: Vec<_> = (0..w.outputs)
            .map(|_| self.context.allocate_lwe_ciphertext())
            .collect();
        let mut evaluator = self.context.evaluator(&self.server).unwrap();
        let mut run = |outputs: &mut [LweCiphertext<T>]| {
            for (lut, output) in luts.iter().zip(outputs) {
                evaluator.apply_lookup_table_to(
                    black_box(self.input.as_view()),
                    black_box(lut),
                    output.as_mut_view(),
                );
            }
        };
        run(&mut outputs);
        self.check_outputs(&outputs, verified);
        b.iter(|| run(black_box(&mut outputs)));
    }

    /// One packed accumulator returns k values; the workload matrix excludes overflow shapes.
    fn interleaved(&self, b: &mut criterion::Bencher, verified: &mut bool) {
        let w = self.workload;
        let lut = InterleavedLookupTable::try_new(
            w.domain,
            self.context
                .parameters()
                .blind_rotation_ggsw()
                .poly_length(),
            w.outputs,
            T::as_from(2 * w.domain),
            self.codecs.input_codec().ciphertext_modulus(),
            self.codecs.lut_output_codec().ciphertext_modulus(),
            |m, i| {
                Ok(self
                    .codecs
                    .lut_output_codec()
                    .encode_value(w.value(m, i), PlaintextEmbedding::Unsigned))
            },
        )
        .unwrap();
        let mut outputs: Vec<_> = (0..w.outputs)
            .map(|_| self.context.allocate_lwe_ciphertext())
            .collect();
        let mut evaluator = self.context.evaluator(&self.server).unwrap();
        evaluator.apply_interleaved_lookup_table_to(self.input.as_view(), &lut, &mut outputs);
        self.check_outputs(&outputs, verified);
        b.iter(|| {
            evaluator.apply_interleaved_lookup_table_to(
                black_box(self.input.as_view()),
                black_box(&lut),
                black_box(&mut outputs),
            )
        });
    }

    /// Reuse one PBS's factorization across k outputs, including its return-key work.
    fn factorized(&self, b: &mut criterion::Bencher, verified: &mut bool) {
        let w = self.workload;
        let lut = self
            .context
            .compile_factorized_lookup_table_fn(&self.codecs, w.domain, w.outputs, |m, i| {
                w.value(m, i)
            })
            .unwrap();
        let mut outputs: Vec<_> = (0..w.outputs)
            .map(|_| self.context.allocate_lwe_ciphertext())
            .collect();
        let mut pbs = self.context.evaluator(&self.server).unwrap();
        let mut evaluator = primus_tfhe_glwe_ntt::FactorizedEvaluator::new(&pbs);
        evaluator.apply_lookup_table_to(self.input.as_view(), &lut, &mut outputs, &mut pbs);
        self.check_outputs(&outputs, verified);
        b.iter(|| {
            evaluator.apply_lookup_table_to(
                black_box(self.input.as_view()),
                black_box(&lut),
                black_box(&mut outputs),
                &mut pbs,
            )
        });
    }
}
